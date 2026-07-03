import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from 'node:crypto';
import { dirname, resolve } from 'node:path';
import { gzipSync, gunzipSync } from 'node:zlib';

type VaultData = Record<string, string>;

type VaultProvider = 'internal' | 'external';

type VaultConfig = {
  provider: VaultProvider;
  address: string | null;
  token: string | null;
  namespace: string | null;
  kvMount: string;
  kvVersion: 1 | 2;
  internalBinaryPath: string;
  exportIntervalSeconds: number;
  internalEncryptionKey: string | null;
};

const INTERNAL_ENCRYPTED_MAGIC = Buffer.from('AKY1', 'ascii');
const INTERNAL_ENCRYPTION_SALT_LENGTH = 16;
const INTERNAL_ENCRYPTION_IV_LENGTH = 12;
const INTERNAL_ENCRYPTION_TAG_LENGTH = 16;

const internalStore = new Map<string, VaultData>();
let internalExportTimer: NodeJS.Timeout | null = null;

function getVaultConfig(): VaultConfig {
  const providerEnv = (process.env.VAULT_PROVIDER ?? 'external').toLowerCase();
  const provider: VaultProvider = providerEnv === 'internal' ? 'internal' : 'external';
  const kvVersionEnv = process.env.VAULT_KV_VERSION ?? '2';
  const kvVersion = kvVersionEnv === '1' ? 1 : 2;
  const intervalEnv = process.env.VAULT_EXPORT_INTERVAL_SECONDS ?? '900';
  const parsedInterval = Number.parseInt(intervalEnv, 10);
  const exportIntervalSeconds = Number.isFinite(parsedInterval) && parsedInterval > 0 ? parsedInterval : 900;
  const internalBinaryPath = resolve(process.env.VAULT_INTERNAL_BINARY_PATH ?? './.vault-internal.bin');
  const internalEncryptionKeyRaw = process.env.VAULT_INTERNAL_ENCRYPTION_KEY ?? '';
  const internalEncryptionKey = internalEncryptionKeyRaw.trim().length > 0 ? internalEncryptionKeyRaw : null;

  return {
    provider,
    address: process.env.VAULT_ADDR ?? null,
    token: process.env.VAULT_TOKEN ?? null,
    namespace: process.env.VAULT_NAMESPACE ?? null,
    kvMount: process.env.VAULT_KV_MOUNT ?? 'secret',
    kvVersion,
    internalBinaryPath,
    exportIntervalSeconds,
    internalEncryptionKey
  };
}

export class VaultService {
  private readonly config: VaultConfig;
  private internalImportStatus: 'not-applicable' | 'not-found' | 'empty' | 'success' | 'error' = 'not-applicable';
  private internalRestoredPaths = 0;

  constructor() {
    this.config = getVaultConfig();

    if (this.config.provider === 'internal') {
      this.importInternalStore();
      this.startInternalExporter();
    }
  }

  public getConnectionInfo() {
    return {
      VAULT_PROVIDER: this.config.provider,
      VAULT_ADDR: this.config.address,
      VAULT_TOKEN: this.config.token ? 'set' : null,
      VAULT_NAMESPACE: this.config.namespace ?? null,
      VAULT_KV_MOUNT: this.config.kvMount,
      VAULT_KV_VERSION: this.config.kvVersion,
      VAULT_INTERNAL_BINARY_PATH: this.config.internalBinaryPath,
      VAULT_EXPORT_INTERVAL_SECONDS: this.config.exportIntervalSeconds,
      VAULT_INTERNAL_ENCRYPTION_KEY: this.config.internalEncryptionKey ? 'set' : null,
      VAULT_INTERNAL_IMPORT_STATUS: this.internalImportStatus,
      VAULT_INTERNAL_RESTORED_PATHS: this.internalRestoredPaths
    };
  }

  public isConfigured(): boolean {
    if (this.config.provider === 'internal') {
      return true;
    }

    return Boolean(this.config.address && this.config.token);
  }

  public async setVariable(secretPath: string, key: string, value: string): Promise<void> {
    this.ensureConfigured();

    if (this.config.provider === 'internal') {
      const normalizedPath = this.normalizePath(secretPath);
      const current = internalStore.get(normalizedPath) ?? {};
      internalStore.set(normalizedPath, { ...current, [key]: value });
      this.exportInternalStore();
      return;
    }

    const current = await this.readSecret(secretPath);
    const merged: VaultData = { ...current, [key]: value };
    await this.writeSecret(secretPath, merged);
  }

  public async getVariable(secretPath: string, key: string): Promise<string | null> {
    this.ensureConfigured();

    if (this.config.provider === 'internal') {
      const normalizedPath = this.normalizePath(secretPath);
      const current = internalStore.get(normalizedPath) ?? {};
      return current[key] ?? null;
    }

    const current = await this.readSecret(secretPath);
    return current[key] ?? null;
  }

  public async listVariables(secretPath: string): Promise<string[]> {
    this.ensureConfigured();

    if (this.config.provider === 'internal') {
      const normalizedPath = this.normalizePath(secretPath);
      const current = internalStore.get(normalizedPath) ?? {};
      return Object.keys(current).sort();
    }

    const current = await this.readSecret(secretPath);
    return Object.keys(current).sort();
  }

  public async deleteVariable(secretPath: string, key: string): Promise<boolean> {
    this.ensureConfigured();

    if (this.config.provider === 'internal') {
      const normalizedPath = this.normalizePath(secretPath);
      const current = internalStore.get(normalizedPath) ?? {};
      if (!(key in current)) {
        return false;
      }

      delete current[key];
      if (Object.keys(current).length === 0) {
        internalStore.delete(normalizedPath);
        this.exportInternalStore();
        return true;
      }

      internalStore.set(normalizedPath, current);
      this.exportInternalStore();
      return true;
    }

    const current = await this.readSecret(secretPath);
    if (!(key in current)) {
      return false;
    }

    delete current[key];

    if (Object.keys(current).length === 0) {
      await this.deleteSecret(secretPath);
      return true;
    }

    await this.writeSecret(secretPath, current);
    return true;
  }

  private ensureConfigured(): void {
    if (this.config.provider === 'internal') {
      return;
    }

    if (!this.config.address || !this.config.token) {
      throw new Error('Vault is not configured. Set VAULT_ADDR and VAULT_TOKEN.');
    }
  }

  private importInternalStore(): void {
    try {
      if (!existsSync(this.config.internalBinaryPath)) {
        this.internalImportStatus = 'not-found';
        this.internalRestoredPaths = 0;
        return;
      }

      const binaryContent = readFileSync(this.config.internalBinaryPath);
      if (binaryContent.length === 0) {
        this.internalImportStatus = 'empty';
        this.internalRestoredPaths = 0;
        return;
      }

      const payloadBuffer = gunzipSync(this.decryptIfEncrypted(binaryContent));
      const payloadText = payloadBuffer.toString('utf8');
      const parsed = JSON.parse(payloadText) as Record<string, Record<string, unknown>>;

      internalStore.clear();
      for (const [path, values] of Object.entries(parsed)) {
        internalStore.set(path, this.ensureStringRecord(values));
      }

      this.internalImportStatus = 'success';
      this.internalRestoredPaths = internalStore.size;
    } catch {
      this.internalImportStatus = 'error';
      this.internalRestoredPaths = 0;
      internalStore.clear();
    }
  }

  private exportInternalStore(): void {
    if (this.config.provider !== 'internal') {
      return;
    }

    const payload: Record<string, VaultData> = {};
    for (const [path, values] of internalStore.entries()) {
      payload[path] = values;
    }

    const serialized = JSON.stringify(payload);
    const compressed = gzipSync(Buffer.from(serialized, 'utf8'));
    const persistedBuffer = this.encryptIfConfigured(compressed);

    const outputPath = this.config.internalBinaryPath;
    const tmpPath = `${outputPath}.tmp`;
    mkdirSync(dirname(outputPath), { recursive: true });
    writeFileSync(tmpPath, persistedBuffer);
    renameSync(tmpPath, outputPath);
  }

  private encryptIfConfigured(content: Buffer): Buffer {
    if (!this.config.internalEncryptionKey) {
      return content;
    }

    const salt = randomBytes(INTERNAL_ENCRYPTION_SALT_LENGTH);
    const iv = randomBytes(INTERNAL_ENCRYPTION_IV_LENGTH);
    const key = scryptSync(this.config.internalEncryptionKey, salt, 32);
    const cipher = createCipheriv('aes-256-gcm', key, iv);
    const ciphertext = Buffer.concat([cipher.update(content), cipher.final()]);
    const authTag = cipher.getAuthTag();

    return Buffer.concat([INTERNAL_ENCRYPTED_MAGIC, salt, iv, authTag, ciphertext]);
  }

  private decryptIfEncrypted(content: Buffer): Buffer {
    if (!this.isEncryptedInternalSnapshot(content)) {
      return content;
    }

    if (!this.config.internalEncryptionKey) {
      throw new Error('Internal Vault snapshot is encrypted but VAULT_INTERNAL_ENCRYPTION_KEY is not set.');
    }

    const headerLength =
      INTERNAL_ENCRYPTED_MAGIC.length +
      INTERNAL_ENCRYPTION_SALT_LENGTH +
      INTERNAL_ENCRYPTION_IV_LENGTH +
      INTERNAL_ENCRYPTION_TAG_LENGTH;

    if (content.length <= headerLength) {
      throw new Error('Internal Vault snapshot is encrypted but payload is invalid.');
    }

    let offset = INTERNAL_ENCRYPTED_MAGIC.length;
    const salt = content.subarray(offset, offset + INTERNAL_ENCRYPTION_SALT_LENGTH);
    offset += INTERNAL_ENCRYPTION_SALT_LENGTH;

    const iv = content.subarray(offset, offset + INTERNAL_ENCRYPTION_IV_LENGTH);
    offset += INTERNAL_ENCRYPTION_IV_LENGTH;

    const authTag = content.subarray(offset, offset + INTERNAL_ENCRYPTION_TAG_LENGTH);
    offset += INTERNAL_ENCRYPTION_TAG_LENGTH;

    const ciphertext = content.subarray(offset);
    const key = scryptSync(this.config.internalEncryptionKey, salt, 32);
    const decipher = createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(authTag);

    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  }

  private isEncryptedInternalSnapshot(content: Buffer): boolean {
    if (content.length < INTERNAL_ENCRYPTED_MAGIC.length) {
      return false;
    }

    return content.subarray(0, INTERNAL_ENCRYPTED_MAGIC.length).equals(INTERNAL_ENCRYPTED_MAGIC);
  }

  private startInternalExporter(): void {
    if (internalExportTimer) {
      return;
    }

    const intervalMs = this.config.exportIntervalSeconds * 1000;
    internalExportTimer = setInterval(() => {
      this.exportInternalStore();
    }, intervalMs);
    internalExportTimer.unref();
  }

  private normalizePath(path: string): string {
    return path.replace(/^\/+/, '').trim();
  }

  private kvReadPath(secretPath: string): string {
    const normalizedPath = this.normalizePath(secretPath);
    if (this.config.kvVersion === 1) {
      return `${this.config.kvMount}/${normalizedPath}`;
    }

    return `${this.config.kvMount}/data/${normalizedPath}`;
  }

  private kvWritePath(secretPath: string): string {
    return this.kvReadPath(secretPath);
  }

  private kvDeletePath(secretPath: string): string {
    return this.kvReadPath(secretPath);
  }

  private async readSecret(secretPath: string): Promise<VaultData> {
    const result = await this.request('GET', this.kvReadPath(secretPath), undefined, true);
    if (!result) {
      return {};
    }

    const payload = result as { data?: { data?: VaultData } & VaultData };
    if (this.config.kvVersion === 1) {
      const data = payload.data;
      if (!data || typeof data !== 'object') {
        return {};
      }
      return this.ensureStringRecord(data as Record<string, unknown>);
    }

    const nested = payload.data?.data;
    if (!nested || typeof nested !== 'object') {
      return {};
    }

    return this.ensureStringRecord(nested as Record<string, unknown>);
  }

  private async writeSecret(secretPath: string, values: VaultData): Promise<void> {
    if (this.config.kvVersion === 1) {
      await this.request('POST', this.kvWritePath(secretPath), values);
      return;
    }

    await this.request('POST', this.kvWritePath(secretPath), { data: values });
  }

  private async deleteSecret(secretPath: string): Promise<void> {
    await this.request('DELETE', this.kvDeletePath(secretPath));
  }

  private ensureStringRecord(input: Record<string, unknown>): VaultData {
    const output: VaultData = {};
    for (const [key, value] of Object.entries(input)) {
      output[key] = typeof value === 'string' ? value : JSON.stringify(value);
    }
    return output;
  }

  private async request(
    method: 'GET' | 'POST' | 'DELETE',
    path: string,
    body?: unknown,
    allowNotFound = false
  ): Promise<unknown | null> {
    const baseAddress = this.config.address!.replace(/\/$/, '');
    const url = `${baseAddress}/v1/${path}`;

    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'X-Vault-Token': this.config.token!
    };

    if (this.config.namespace) {
      headers['X-Vault-Namespace'] = this.config.namespace;
    }

    const response = await fetch(url, {
      method,
      headers,
      body: body ? JSON.stringify(body) : undefined
    });

    if (allowNotFound && response.status === 404) {
      return null;
    }

    if (!response.ok) {
      const message = await response.text();
      throw new Error(`Vault request failed (${response.status}): ${message || response.statusText}`);
    }

    if (response.status === 204) {
      return null;
    }

    const raw = await response.text();
    if (!raw) {
      return null;
    }

    return JSON.parse(raw) as unknown;
  }
}

import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { VaultService } from '../src/services/vaultService.js';

function configureInternalVaultEnv(snapshotPath: string, encryptionKey: string): void {
  process.env.VAULT_PROVIDER = 'internal';
  process.env.VAULT_INTERNAL_BINARY_PATH = snapshotPath;
  process.env.VAULT_EXPORT_INTERVAL_SECONDS = '900';
  process.env.VAULT_INTERNAL_ENCRYPTION_KEY = encryptionKey;
}

test('internal snapshot is encrypted and restores with correct key', async () => {
  const snapshotPath = join(tmpdir(), `akoya-mcp-vault-encrypted-${randomUUID()}.bin`);
  configureInternalVaultEnv(snapshotPath, 'correct-horse-battery-staple');

  const writer = new VaultService();
  await writer.setVariable('tests/persistence', 'api_token', 'super-secret-token');

  const snapshotContent = readFileSync(snapshotPath);
  assert.equal(snapshotContent.includes(Buffer.from('super-secret-token', 'utf8')), false);

  const reader = new VaultService();
  const restored = await reader.getVariable('tests/persistence', 'api_token');
  assert.equal(restored, 'super-secret-token');

  const info = reader.getConnectionInfo() as Record<string, unknown>;
  assert.equal(info.VAULT_INTERNAL_ENCRYPTION_KEY, 'set');
  assert.equal(info.VAULT_INTERNAL_IMPORT_STATUS, 'success');
});

test('internal snapshot import fails safely with wrong encryption key', async () => {
  const snapshotPath = join(tmpdir(), `akoya-mcp-vault-wrong-key-${randomUUID()}.bin`);
  configureInternalVaultEnv(snapshotPath, 'first-key');

  const writer = new VaultService();
  await writer.setVariable('tests/persistence', 'id_token', 'persisted-token');

  configureInternalVaultEnv(snapshotPath, 'second-key');
  const wrongKeyReader = new VaultService();

  const restored = await wrongKeyReader.getVariable('tests/persistence', 'id_token');
  assert.equal(restored, null);

  const info = wrongKeyReader.getConnectionInfo() as Record<string, unknown>;
  assert.equal(info.VAULT_INTERNAL_IMPORT_STATUS, 'error');
  assert.equal(info.VAULT_INTERNAL_RESTORED_PATHS, 0);
});

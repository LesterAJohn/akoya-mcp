import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { AkoyaService } from '../src/services/akoyaService.js';
import { VaultService } from '../src/services/vaultService.js';

type MockCall = {
  url: URL;
  method: string;
  headers: Headers;
  bodyText: string;
};

function setRequiredTestEnv(): void {
  process.env.VAULT_PROVIDER = 'internal';
  process.env.VAULT_INTERNAL_BINARY_PATH = join(tmpdir(), `akoya-mcp-test-${randomUUID()}.bin`);
  process.env.VAULT_EXPORT_INTERVAL_SECONDS = '900';
  process.env.VAULT_INTERNAL_ENCRYPTION_KEY = 'emulator-test-encryption-key';
}

function clearAkoyaUrlEnv(): void {
  delete process.env.AKOYA_SANDBOX_IDP_URL;
  delete process.env.AKOYA_LIVE_IDP_URL;
  delete process.env.AKOYA_SANDBOX_PRODUCTS_URL;
  delete process.env.AKOYA_LIVE_PRODUCTS_URL;
  delete process.env.AKOYA_SANDBOX_STS_URL;
  delete process.env.AKOYA_LIVE_STS_URL;
  delete process.env.AKOYA_SANDBOX_SERVICE_API_URL;
  delete process.env.AKOYA_LIVE_SERVICE_API_URL;
}

function installAkoyaEmulator(calls: MockCall[]): () => void {
  const originalFetch = globalThis.fetch;

  globalThis.fetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const requestUrl = new URL(typeof input === 'string' ? input : input.toString());
    const requestHeaders = new Headers(init?.headers ?? {});
    const requestBody = typeof init?.body === 'string' ? init.body : '';
    const method = (init?.method ?? 'GET').toUpperCase();

    calls.push({
      url: requestUrl,
      method,
      headers: requestHeaders,
      bodyText: requestBody
    });

    if (requestUrl.pathname.includes('/token')) {
      return new Response(
        JSON.stringify({
          id_token: 'emulated-id-token',
          refresh_token: 'emulated-refresh-token',
          token_type: 'bearer',
          expires_in: 3600
        }),
        {
          status: 200,
          headers: { 'content-type': 'application/json' }
        }
      );
    }

    if (requestUrl.pathname.includes('/accounts-info/')) {
      return new Response(
        JSON.stringify({
          accountId: 'demo-account',
          provider: requestUrl.pathname.split('/').at(-1)
        }),
        {
          status: 200,
          headers: { 'content-type': 'application/json' }
        }
      );
    }

    return new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: { 'content-type': 'application/json' }
    });
  };

  return () => {
    globalThis.fetch = originalFetch;
  };
}

async function createService(): Promise<{ vault: VaultService; akoya: AkoyaService }> {
  setRequiredTestEnv();
  const vault = new VaultService();
  const akoya = new AkoyaService(vault);
  return { vault, akoya };
}

test('uses env URL first and writes it to Vault', async () => {
  clearAkoyaUrlEnv();
  process.env.AKOYA_SANDBOX_PRODUCTS_URL = 'https://env-products.example';

  const calls: MockCall[] = [];
  const restoreFetch = installAkoyaEmulator(calls);

  try {
    const { vault, akoya } = await createService();
    await vault.setVariable('akoya/institutions/mikomo/tokens', 'id_token', 'institution-token');

    await akoya.accountInfo({
      test: true,
      providerId: 'mikomo'
    });

    assert.equal(calls.length > 0, true);
    assert.equal(calls[0].url.origin, 'https://env-products.example');

    const seeded = await vault.getVariable('akoya/general/config', 'sandbox_products');
    assert.equal(seeded, 'https://env-products.example');
  } finally {
    restoreFetch();
    clearAkoyaUrlEnv();
  }
});

test('uses Vault URL when env URL is not set', async () => {
  clearAkoyaUrlEnv();

  const calls: MockCall[] = [];
  const restoreFetch = installAkoyaEmulator(calls);

  try {
    const { vault, akoya } = await createService();
    await vault.setVariable('akoya/general/config', 'sandbox_products', 'https://vault-products.example');
    await vault.setVariable('akoya/institutions/mikomo/tokens', 'id_token', 'institution-token');

    await akoya.accountInfo({ test: true, providerId: 'mikomo' });

    assert.equal(calls.length > 0, true);
    assert.equal(calls[0].url.origin, 'https://vault-products.example');
  } finally {
    restoreFetch();
    clearAkoyaUrlEnv();
  }
});

test('uses config-file default URL when env and Vault are missing, then seeds Vault', async () => {
  clearAkoyaUrlEnv();

  const calls: MockCall[] = [];
  const restoreFetch = installAkoyaEmulator(calls);

  try {
    const { vault, akoya } = await createService();
    await vault.deleteVariable('akoya/general/config', 'sandbox_products');
    await vault.setVariable('akoya/institutions/mikomo/tokens', 'id_token', 'institution-token');

    await akoya.accountInfo({ test: true, providerId: 'mikomo' });

    assert.equal(calls.length > 0, true);
    assert.equal(calls[0].url.origin, 'https://sandbox-products.ddp.akoya.com');

    const seeded = await vault.getVariable('akoya/general/config', 'sandbox_products');
    assert.equal(seeded, 'https://sandbox-products.ddp.akoya.com');
  } finally {
    restoreFetch();
    clearAkoyaUrlEnv();
  }
});

test('separates institution-scoped tokens for requests', async () => {
  clearAkoyaUrlEnv();

  const calls: MockCall[] = [];
  const restoreFetch = installAkoyaEmulator(calls);

  try {
    const { vault, akoya } = await createService();
    await vault.setVariable('akoya/institutions/mikomo/tokens', 'id_token', 'mikomo-id-token');
    await vault.setVariable('akoya/institutions/chase/tokens', 'id_token', 'chase-id-token');

    await akoya.accountInfo({ test: true, providerId: 'mikomo' });
    await akoya.accountInfo({ test: true, providerId: 'chase' });

    assert.equal(calls.length >= 2, true);
    assert.equal(calls[0].headers.get('authorization'), 'Bearer mikomo-id-token');
    assert.equal(calls[1].headers.get('authorization'), 'Bearer chase-id-token');
  } finally {
    restoreFetch();
    clearAkoyaUrlEnv();
  }
});

test('stores refreshed tokens under institution-specific Vault path', async () => {
  clearAkoyaUrlEnv();

  const calls: MockCall[] = [];
  const restoreFetch = installAkoyaEmulator(calls);

  try {
    const { vault, akoya } = await createService();

    await akoya.token({
      test: true,
      providerId: 'mikomo',
      grantType: 'refresh_token',
      clientId: 'client',
      clientSecret: 'secret',
      refreshToken: 'refresh-token-value'
    });

    const idToken = await vault.getVariable('akoya/institutions/mikomo/tokens', 'id_token');
    const refreshToken = await vault.getVariable('akoya/institutions/mikomo/tokens', 'refresh_token');
    assert.equal(idToken, 'emulated-id-token');
    assert.equal(refreshToken, 'emulated-refresh-token');
    assert.equal(calls[0].method, 'POST');
  } finally {
    restoreFetch();
    clearAkoyaUrlEnv();
  }
});

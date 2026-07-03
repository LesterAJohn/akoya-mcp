import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { InMemoryTransport, LATEST_PROTOCOL_VERSION } from '@modelcontextprotocol/server';
import { buildServer } from '../src/index.js';

type JsonRpcMessage = {
  jsonrpc: '2.0';
  id?: number;
  method?: string;
  params?: Record<string, unknown>;
  result?: unknown;
  error?: { code: number; message: string; data?: unknown };
};

function configureTestEnvironment(): void {
  process.env.VAULT_PROVIDER = 'internal';
  process.env.VAULT_INTERNAL_BINARY_PATH = join(tmpdir(), `akoya-mcp-mcp-tools-${randomUUID()}.bin`);
  process.env.VAULT_EXPORT_INTERVAL_SECONDS = '900';
  process.env.MCP_ALLOW_SENSITIVE_OUTPUT = 'false';
}

async function createConnectedPair() {
  const server = buildServer();
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();

  const pending = new Map<number, (message: JsonRpcMessage) => void>();
  let nextId = 1;

  clientTransport.onmessage = (message) => {
    const typed = message as JsonRpcMessage;
    if (typed.id !== undefined && pending.has(typed.id)) {
      const resolve = pending.get(typed.id)!;
      pending.delete(typed.id);
      resolve(typed);
    }
  };

  await clientTransport.start();
  await server.connect(serverTransport);

  const request = async (method: string, params: Record<string, unknown>) => {
    const id = nextId++;
    const payload: JsonRpcMessage = {
      jsonrpc: '2.0',
      id,
      method,
      params
    };

    const responsePromise = new Promise<JsonRpcMessage>((resolve, reject) => {
      pending.set(id, resolve);
      setTimeout(() => {
        if (pending.has(id)) {
          pending.delete(id);
          reject(new Error(`Timed out waiting for response to ${method}`));
        }
      }, 3000);
    });

    await clientTransport.send(payload);
    const response = await responsePromise;
    if (response.error) {
      throw new Error(`${response.error.code}: ${response.error.message}`);
    }

    return response.result;
  };

  const notify = async (method: string, params: Record<string, unknown>) => {
    const payload: JsonRpcMessage = {
      jsonrpc: '2.0',
      method,
      params
    };
    await clientTransport.send(payload);
  };

  return {
    server,
    clientTransport,
    request,
    notify,
    close: async () => {
      await clientTransport.close();
      await server.close();
    }
  };
}

test('MCP server registers expected tool names', async () => {
  configureTestEnvironment();
  const pair = await createConnectedPair();

  try {
    await pair.request('initialize', {
      protocolVersion: LATEST_PROTOCOL_VERSION,
      capabilities: {},
      clientInfo: {
        name: 'test-client',
        version: '1.0.0'
      }
    });
    await pair.notify('notifications/initialized', {});

    const listResult = (await pair.request('tools/list', {})) as {
      tools?: Array<{ name: string }>;
    };

    const names = (listResult.tools ?? []).map((tool) => tool.name);
    const expectedToolNames = [
      'akoya_connection_info',
      'akoya_oauth_create_state',
      'akoya_oauth_validate_state',
      'akoya_auth_url',
      'akoya_token_exchange',
      'akoya_refresh_token',
      'akoya_revoke_refresh_token',
      'akoya_service_token',
      'akoya_account_info',
      'akoya_accounts',
      'akoya_balances',
      'akoya_transactions',
      'akoya_taxlots',
      'akoya_customer_info',
      'akoya_account_holder_info',
      'akoya_payments',
      'akoya_statement_list',
      'akoya_statement',
      'akoya_search_tax_forms',
      'akoya_retrieve_tax_form',
      'akoya_create_app',
      'akoya_update_app',
      'akoya_get_all_apps',
      'akoya_get_purchased_products',
      'akoya_get_valid_providers_for_products',
      'akoya_get_subscriptions_for_app',
      'akoya_list_notification_subscriptions',
      'akoya_create_notification_subscription',
      'akoya_get_notification_subscription_by_id',
      'akoya_update_notification_subscription',
      'akoya_delete_notification_subscription',
      'akoya_send_sandbox_test_event',
      'akoya_consent_grant',
      'vault_connection_info',
      'vault_set_variable',
      'vault_get_variable',
      'vault_list_variables',
      'vault_delete_variable'
    ];

    for (const toolName of expectedToolNames) {
      assert.equal(names.includes(toolName), true);
    }
  } finally {
    await pair.close();
  }
});

test('MCP vault tools can set/get/list/delete variables in integration flow', async () => {
  configureTestEnvironment();
  const pair = await createConnectedPair();

  try {
    await pair.request('initialize', {
      protocolVersion: LATEST_PROTOCOL_VERSION,
      capabilities: {},
      clientInfo: {
        name: 'test-client',
        version: '1.0.0'
      }
    });
    await pair.notify('notifications/initialized', {});

    await pair.request('tools/call', {
      name: 'vault_set_variable',
      arguments: {
        secretPath: 'tests/mcp',
        key: 'sample',
        value: 'hello'
      }
    });

    const getResult = (await pair.request('tools/call', {
      name: 'vault_get_variable',
      arguments: {
        secretPath: 'tests/mcp',
        key: 'sample',
        revealValue: true
      }
    })) as {
      content?: Array<{ text?: string }>;
    };
    const getPayload = JSON.parse(getResult.content?.[0]?.text ?? '{}') as { found?: boolean; value?: string };
    assert.equal(getPayload.found, true);
    assert.equal(getPayload.value, 'set');

    const listResult = (await pair.request('tools/call', {
      name: 'vault_list_variables',
      arguments: {
        secretPath: 'tests/mcp'
      }
    })) as {
      content?: Array<{ text?: string }>;
    };
    const listPayload = JSON.parse(listResult.content?.[0]?.text ?? '{}') as { keys?: string[] };
    assert.equal(Array.isArray(listPayload.keys), true);
    assert.equal(listPayload.keys?.includes('sample'), true);

    const deleteResult = (await pair.request('tools/call', {
      name: 'vault_delete_variable',
      arguments: {
        secretPath: 'tests/mcp',
        key: 'sample'
      }
    })) as {
      content?: Array<{ text?: string }>;
    };
    const deletePayload = JSON.parse(deleteResult.content?.[0]?.text ?? '{}') as { deleted?: boolean };
    assert.equal(deletePayload.deleted, true);
  } finally {
    await pair.close();
  }
});

test('MCP OAuth state tools create and validate one-time state values', async () => {
  configureTestEnvironment();
  const pair = await createConnectedPair();

  try {
    await pair.request('initialize', {
      protocolVersion: LATEST_PROTOCOL_VERSION,
      capabilities: {},
      clientInfo: {
        name: 'test-client',
        version: '1.0.0'
      }
    });
    await pair.notify('notifications/initialized', {});

    const createResult = (await pair.request('tools/call', {
      name: 'akoya_oauth_create_state',
      arguments: {
        userId: 'user-123',
        providerId: 'mikomo',
        ttlSeconds: 120
      }
    })) as {
      content?: Array<{ text?: string }>;
    };

    const created = JSON.parse(createResult.content?.[0]?.text ?? '{}') as {
      state?: string;
      userId?: string;
    };
    assert.equal(created.userId, 'user-123');
    assert.equal(typeof created.state, 'string');
    assert.equal((created.state ?? '').length > 0, true);

    const validateResult = (await pair.request('tools/call', {
      name: 'akoya_oauth_validate_state',
      arguments: {
        state: created.state,
        userId: 'user-123',
        providerId: 'mikomo',
        consume: true
      }
    })) as {
      content?: Array<{ text?: string }>;
    };
    const validated = JSON.parse(validateResult.content?.[0]?.text ?? '{}') as { valid?: boolean };
    assert.equal(validated.valid, true);
  } finally {
    await pair.close();
  }
});

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
    assert.equal(names.includes('akoya_connection_info'), true);
    assert.equal(names.includes('vault_connection_info'), true);
    assert.equal(names.includes('vault_set_variable'), true);
    assert.equal(names.includes('vault_get_variable'), true);
    assert.equal(names.includes('vault_list_variables'), true);
    assert.equal(names.includes('vault_delete_variable'), true);
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
    assert.equal(getPayload.value, 'hello');

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

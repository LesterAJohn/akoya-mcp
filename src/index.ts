import { McpServer } from '@modelcontextprotocol/server';
import { serveStdio } from '@modelcontextprotocol/server/stdio';
import * as z from 'zod/v4';
import { VaultService } from './services/vaultService.js';

function buildServer(): McpServer {
  const server = new McpServer({ name: 'akoya-mcp', version: '0.1.0' });
  const vaultService = new VaultService();

  server.registerTool(
    'akoya_connection_info',
    {
      description: 'Return the local Akoya MCP starter configuration.',
      inputSchema: z.object({})
    },
    async () => ({
      content: [
        {
          type: 'text',
          text: JSON.stringify(
            {
              service: 'akoya',
              mode: 'local-starter',
              environment: {
                AKOYA_BASE_URL: process.env.AKOYA_BASE_URL ?? null,
                AKOYA_CLIENT_ID: process.env.AKOYA_CLIENT_ID ? 'set' : null,
                AKOYA_CLIENT_SECRET: process.env.AKOYA_CLIENT_SECRET ? 'set' : null,
                ...vaultService.getConnectionInfo()
              },
              vaultConfigured: vaultService.isConfigured()
            },
            null,
            2
          )
        }
      ]
    })
  );

  server.registerTool(
    'vault_connection_info',
    {
      description: 'Return Vault provider and connectivity configuration for variable storage.',
      inputSchema: z.object({})
    },
    async () => ({
      content: [
        {
          type: 'text',
          text: JSON.stringify(
            {
              vault: vaultService.getConnectionInfo(),
              configured: vaultService.isConfigured()
            },
            null,
            2
          )
        }
      ]
    })
  );

  server.registerTool(
    'vault_set_variable',
    {
      description: 'Store a variable in Vault at a given secret path and key.',
      inputSchema: z.object({
        secretPath: z.string().min(1),
        key: z.string().min(1),
        value: z.string()
      })
    },
    async ({ secretPath, key, value }) => {
      await vaultService.setVariable(secretPath, key, value);
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify({ stored: true, secretPath, key }, null, 2)
          }
        ]
      };
    }
  );

  server.registerTool(
    'vault_get_variable',
    {
      description: 'Get a variable from Vault by secret path and key.',
      inputSchema: z.object({
        secretPath: z.string().min(1),
        key: z.string().min(1),
        revealValue: z.boolean().optional()
      })
    },
    async ({ secretPath, key, revealValue }) => {
      const value = await vaultService.getVariable(secretPath, key);
      const found = value !== null;
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(
              {
                secretPath,
                key,
                found,
                value: revealValue ? value : found ? 'set' : null
              },
              null,
              2
            )
          }
        ]
      };
    }
  );

  server.registerTool(
    'vault_list_variables',
    {
      description: 'List all variable keys stored at a Vault secret path.',
      inputSchema: z.object({
        secretPath: z.string().min(1)
      })
    },
    async ({ secretPath }) => {
      const keys = await vaultService.listVariables(secretPath);
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify({ secretPath, keys }, null, 2)
          }
        ]
      };
    }
  );

  server.registerTool(
    'vault_delete_variable',
    {
      description: 'Delete a variable key from a Vault secret path.',
      inputSchema: z.object({
        secretPath: z.string().min(1),
        key: z.string().min(1)
      })
    },
    async ({ secretPath, key }) => {
      const deleted = await vaultService.deleteVariable(secretPath, key);
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify({ secretPath, key, deleted }, null, 2)
          }
        ]
      };
    }
  );

  return server;
}

serveStdio(buildServer);

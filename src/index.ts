import { McpServer } from '@modelcontextprotocol/server';
import { serveStdio } from '@modelcontextprotocol/server/stdio';
import * as z from 'zod/v4';
import { VaultService } from './services/vaultService.js';
import { fileURLToPath } from 'node:url';
import { AkoyaService } from './services/akoyaService.js';
import { randomUUID } from 'node:crypto';

const OAUTH_STATE_PATH = 'akoya/oauth/states';

function toTextResponse(data: unknown) {
  return {
    content: [
      {
        type: 'text' as const,
        text: JSON.stringify(data, null, 2)
      }
    ]
  };
}

function buildUserTokenPath(userId: string, providerId?: string): string {
  const normalizedUser = userId.trim().toLowerCase().replace(/[^a-z0-9_-]/g, '-');
  const normalizedProvider = (providerId ?? 'default').trim().toLowerCase().replace(/[^a-z0-9_-]/g, '-');
  return `akoya/users/${normalizedUser}/providers/${normalizedProvider}/tokens`;
}

function parseTokenPayload(payload: unknown): {
  id_token?: string;
  refresh_token?: string;
  expires_in?: number;
  token_type?: string;
} {
  return payload as {
    id_token?: string;
    refresh_token?: string;
    expires_in?: number;
    token_type?: string;
  };
}

export function buildServer(): McpServer {
  const server = new McpServer({ name: 'akoya-mcp', version: '0.1.0' });
  const vaultService = new VaultService();
  const akoyaService = new AkoyaService(vaultService);

  server.registerTool(
    'akoya_connection_info',
    {
      description: 'Return the local Akoya MCP starter configuration.',
      inputSchema: z.object({})
    },
    async () =>
      toTextResponse({
        service: 'akoya',
        mode: 'local-starter',
        transport: 'stdio',
        environment: {
          AKOYA_BASE_URL: process.env.AKOYA_BASE_URL ?? null,
          AKOYA_CLIENT_ID: process.env.AKOYA_CLIENT_ID ? 'set' : null,
          AKOYA_CLIENT_SECRET: process.env.AKOYA_CLIENT_SECRET ? 'set' : null,
          ...vaultService.getConnectionInfo()
        },
        vaultConfigured: vaultService.isConfigured(),
        oauth: {
          callbackRouteAvailable: false,
          notes: 'This MCP server runs over stdio. OAuth redirect handling must be implemented by the caller, then exchanged via MCP tools.'
        }
      })
  );

  server.registerTool(
    'akoya_oauth_create_state',
    {
      description: 'Create and persist a one-time OAuth state value for CSRF protection.',
      inputSchema: z.object({
        userId: z.string().min(1),
        providerId: z.string().min(1).optional(),
        ttlSeconds: z.number().int().positive().max(3600).optional()
      })
    },
    async ({ userId, providerId, ttlSeconds }) => {
      const state = randomUUID();
      const now = Date.now();
      const ttl = ttlSeconds ?? 600;
      const expiresAt = now + ttl * 1000;
      await vaultService.setVariable(
        OAUTH_STATE_PATH,
        state,
        JSON.stringify({ userId, providerId: providerId ?? null, createdAt: new Date(now).toISOString(), expiresAt })
      );

      return toTextResponse({
        state,
        userId,
        providerId: providerId ?? null,
        ttlSeconds: ttl,
        expiresAt: new Date(expiresAt).toISOString()
      });
    }
  );

  server.registerTool(
    'akoya_oauth_validate_state',
    {
      description: 'Validate a stored OAuth state and optionally consume it.',
      inputSchema: z.object({
        state: z.string().min(1),
        userId: z.string().min(1),
        providerId: z.string().min(1).optional(),
        consume: z.boolean().optional()
      })
    },
    async ({ state, userId, providerId, consume }) => {
      const raw = await vaultService.getVariable(OAUTH_STATE_PATH, state);
      if (!raw) {
        return toTextResponse({ valid: false, reason: 'state_not_found' });
      }

      const parsed = JSON.parse(raw) as {
        userId?: string;
        providerId?: string | null;
        expiresAt?: number;
      };

      if (!parsed.expiresAt || Date.now() > parsed.expiresAt) {
        await vaultService.deleteVariable(OAUTH_STATE_PATH, state);
        return toTextResponse({ valid: false, reason: 'state_expired' });
      }

      if (parsed.userId !== userId) {
        return toTextResponse({ valid: false, reason: 'user_mismatch' });
      }

      if (providerId && parsed.providerId && parsed.providerId !== providerId) {
        return toTextResponse({ valid: false, reason: 'provider_mismatch' });
      }

      if (consume ?? true) {
        await vaultService.deleteVariable(OAUTH_STATE_PATH, state);
      }

      return toTextResponse({ valid: true, consumed: consume ?? true });
    }
  );

  server.registerTool(
    'akoya_auth_url',
    {
      description: 'Build Akoya authorization URL for an OAuth code flow redirect.',
      inputSchema: z.object({
        test: z.boolean().optional(),
        providerId: z.string().min(1).optional(),
        clientId: z.string().min(1).optional(),
        redirectUri: z.string().url().optional(),
        state: z.string().min(1),
        scope: z.string().min(1).optional(),
        responseType: z.enum(['code']).optional(),
        connector: z.string().min(1).optional()
      })
    },
    async (input) => toTextResponse(await akoyaService.buildAuthorizationUrl(input))
  );

  server.registerTool(
    'akoya_token_exchange',
    {
      description: 'Exchange OAuth authorization code for tokens and optionally store per user/provider.',
      inputSchema: z.object({
        test: z.boolean().optional(),
        userId: z.string().min(1).optional(),
        providerId: z.string().min(1).optional(),
        code: z.string().min(1),
        redirectUri: z.string().url().optional(),
        clientId: z.string().min(1).optional(),
        clientSecret: z.string().min(1).optional()
      })
    },
    async ({ userId, providerId, ...input }) => {
      const response = await akoyaService.token({
        ...input,
        providerId,
        grantType: 'authorization_code'
      });

      let userScopedPath: string | null = null;
      if (userId) {
        userScopedPath = buildUserTokenPath(userId, providerId);
        const payload = parseTokenPayload(response);
        if (payload.id_token) {
          await vaultService.setVariable(userScopedPath, 'id_token', payload.id_token);
        }
        if (payload.refresh_token) {
          await vaultService.setVariable(userScopedPath, 'refresh_token', payload.refresh_token);
        }
        if (payload.expires_in !== undefined) {
          await vaultService.setVariable(userScopedPath, 'expires_in', String(payload.expires_in));
        }
        if (payload.token_type) {
          await vaultService.setVariable(userScopedPath, 'token_type', payload.token_type);
        }
      }

      return toTextResponse({ response, userScopedPath });
    }
  );

  server.registerTool(
    'akoya_refresh_token',
    {
      description: 'Refresh Akoya tokens using refresh token from input or user-scoped vault path.',
      inputSchema: z.object({
        test: z.boolean().optional(),
        userId: z.string().min(1).optional(),
        providerId: z.string().min(1).optional(),
        refreshToken: z.string().min(1).optional(),
        clientId: z.string().min(1).optional(),
        clientSecret: z.string().min(1).optional()
      })
    },
    async ({ userId, providerId, refreshToken, ...input }) => {
      let resolvedRefreshToken = refreshToken;
      const userScopedPath = userId ? buildUserTokenPath(userId, providerId) : null;
      if (!resolvedRefreshToken && userScopedPath) {
        resolvedRefreshToken = (await vaultService.getVariable(userScopedPath, 'refresh_token')) ?? undefined;
      }

      const response = await akoyaService.token({
        ...input,
        providerId,
        refreshToken: resolvedRefreshToken,
        grantType: 'refresh_token'
      });

      if (userScopedPath) {
        const payload = parseTokenPayload(response);
        if (payload.id_token) {
          await vaultService.setVariable(userScopedPath, 'id_token', payload.id_token);
        }
        if (payload.refresh_token) {
          await vaultService.setVariable(userScopedPath, 'refresh_token', payload.refresh_token);
        }
        if (payload.expires_in !== undefined) {
          await vaultService.setVariable(userScopedPath, 'expires_in', String(payload.expires_in));
        }
        if (payload.token_type) {
          await vaultService.setVariable(userScopedPath, 'token_type', payload.token_type);
        }
      }

      return toTextResponse({ response, userScopedPath });
    }
  );

  server.registerTool(
    'akoya_accounts',
    {
      description: 'Call Akoya accounts endpoint.',
      inputSchema: z.object({
        test: z.boolean().optional(),
        version: z.string().min(1).optional(),
        providerId: z.string().min(1).optional(),
        mode: z.string().min(1).optional(),
        accountIds: z.string().min(1).optional(),
        offset: z.number().int().nonnegative().optional(),
        limit: z.number().int().positive().optional(),
        idToken: z.string().min(1).optional(),
        userId: z.string().min(1).optional(),
        interactionType: z.enum(['USER', 'BATCH']).optional(),
        intentType: z.enum(['payments', 'nonpayments']).optional(),
        lastAccess: z.string().min(1).optional()
      })
    },
    async ({ userId, providerId, idToken, ...input }) => {
      const resolvedIdToken =
        idToken ??
        (userId ? (await vaultService.getVariable(buildUserTokenPath(userId, providerId), 'id_token')) ?? undefined : undefined);

      return toTextResponse(await akoyaService.accounts({ ...input, providerId, idToken: resolvedIdToken }));
    }
  );

  server.registerTool(
    'akoya_balances',
    {
      description: 'Call Akoya balances endpoint.',
      inputSchema: z.object({
        test: z.boolean().optional(),
        version: z.string().min(1).optional(),
        providerId: z.string().min(1).optional(),
        mode: z.string().min(1).optional(),
        accountIds: z.string().min(1).optional(),
        idToken: z.string().min(1).optional(),
        userId: z.string().min(1).optional(),
        interactionType: z.enum(['USER', 'BATCH']).optional(),
        intentType: z.enum(['payments', 'nonpayments']).optional(),
        lastAccess: z.string().min(1).optional()
      })
    },
    async ({ userId, providerId, idToken, ...input }) => {
      const resolvedIdToken =
        idToken ??
        (userId ? (await vaultService.getVariable(buildUserTokenPath(userId, providerId), 'id_token')) ?? undefined : undefined);

      return toTextResponse(await akoyaService.balances({ ...input, providerId, idToken: resolvedIdToken }));
    }
  );

  server.registerTool(
    'akoya_transactions',
    {
      description: 'Call Akoya transactions endpoint.',
      inputSchema: z.object({
        test: z.boolean().optional(),
        version: z.string().min(1).optional(),
        providerId: z.string().min(1).optional(),
        accountId: z.string().min(1).optional(),
        mode: z.string().min(1).optional(),
        startTime: z.string().min(1).optional(),
        endTime: z.string().min(1).optional(),
        offset: z.number().int().nonnegative().optional(),
        limit: z.number().int().positive().optional(),
        idToken: z.string().min(1).optional(),
        userId: z.string().min(1).optional(),
        interactionType: z.enum(['USER', 'BATCH']).optional(),
        intentType: z.enum(['payments', 'nonpayments']).optional(),
        lastAccess: z.string().min(1).optional()
      })
    },
    async ({ userId, providerId, idToken, ...input }) => {
      const resolvedIdToken =
        idToken ??
        (userId ? (await vaultService.getVariable(buildUserTokenPath(userId, providerId), 'id_token')) ?? undefined : undefined);

      return toTextResponse(await akoyaService.transactions({ ...input, providerId, idToken: resolvedIdToken }));
    }
  );

  server.registerTool(
    'akoya_consent_grant',
    {
      description: 'Get consent grant details by consent id (service API).',
      inputSchema: z.object({
        test: z.boolean().optional(),
        version: z.string().min(1).optional(),
        consentId: z.string().min(1).optional(),
        serviceToken: z.string().min(1).optional()
      })
    },
    async (input) => toTextResponse(await akoyaService.getConsentGrant(input))
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

const isEntrypoint = process.argv[1] === fileURLToPath(import.meta.url);
if (isEntrypoint) {
  serveStdio(buildServer);
}

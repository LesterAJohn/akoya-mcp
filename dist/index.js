import { randomUUID } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { McpServer } from '@modelcontextprotocol/server';
import { serveStdio } from '@modelcontextprotocol/server/stdio';
import * as z from 'zod/v4';
import { AkoyaService } from './services/akoyaService.js';
import { VaultService } from './services/vaultService.js';
const OAUTH_STATE_PATH = 'akoya/oauth/states';
const SENSITIVE_OUTPUT_ENV = 'MCP_ALLOW_SENSITIVE_OUTPUT';
function isSensitiveOutputAllowed() {
    return String(process.env[SENSITIVE_OUTPUT_ENV] ?? '').toLowerCase() === 'true';
}
function toTextResponse(data) {
    return {
        content: [
            {
                type: 'text',
                text: JSON.stringify(data, null, 2)
            }
        ]
    };
}
function maskSensitiveTokenFields(payload) {
    if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
        return payload;
    }
    const sensitiveKeys = new Set(['id_token', 'refresh_token', 'access_token']);
    const output = {};
    for (const [key, value] of Object.entries(payload)) {
        output[key] = sensitiveKeys.has(key) ? 'redacted' : value;
    }
    return output;
}
function buildUserTokenPath(userId, providerId) {
    const normalizedUser = userId.trim().toLowerCase().replace(/[^a-z0-9_-]/g, '-');
    const normalizedProvider = (providerId ?? 'default').trim().toLowerCase().replace(/[^a-z0-9_-]/g, '-');
    return `akoya/users/${normalizedUser}/providers/${normalizedProvider}/tokens`;
}
function parseTokenPayload(payload) {
    return payload;
}
async function resolveUserIdToken(vaultService, userId, providerId, idToken) {
    if (idToken) {
        return idToken;
    }
    if (!userId) {
        return undefined;
    }
    return (await vaultService.getVariable(buildUserTokenPath(userId, providerId), 'id_token')) ?? undefined;
}
export function buildServer() {
    const server = new McpServer({ name: 'akoya-mcp', version: '0.1.0' });
    const vaultService = new VaultService();
    const akoyaService = new AkoyaService(vaultService);
    const allowSensitiveOutput = isSensitiveOutputAllowed();
    server.registerTool('akoya_connection_info', {
        description: 'Return local Akoya MCP configuration and scope information.',
        inputSchema: z.object({})
    }, async () => toTextResponse({
        service: 'akoya',
        mode: 'full-endpoint-coverage',
        scope: 'All endpoints listed in the Akoya endpoint catalog are mapped to MCP tools in this server.',
        transport: 'stdio',
        environment: {
            AKOYA_BASE_URL: process.env.AKOYA_BASE_URL ?? null,
            AKOYA_CLIENT_ID: process.env.AKOYA_CLIENT_ID ? 'set' : null,
            AKOYA_CLIENT_SECRET: process.env.AKOYA_CLIENT_SECRET ? 'set' : null,
            MCP_ALLOW_SENSITIVE_OUTPUT: allowSensitiveOutput,
            ...vaultService.getConnectionInfo()
        },
        vaultConfigured: vaultService.isConfigured(),
        oauth: {
            callbackRouteAvailable: false,
            notes: 'This MCP server runs over stdio. OAuth redirect handling must be implemented by the caller, then exchanged via MCP tools.'
        }
    }));
    server.registerTool('akoya_oauth_create_state', {
        description: 'Create and persist a one-time OAuth state value for CSRF protection.',
        inputSchema: z.object({
            userId: z.string().min(1),
            providerId: z.string().min(1).optional(),
            ttlSeconds: z.number().int().positive().max(3600).optional()
        })
    }, async ({ userId, providerId, ttlSeconds }) => {
        const state = randomUUID();
        const now = Date.now();
        const ttl = ttlSeconds ?? 600;
        const expiresAt = now + ttl * 1000;
        await vaultService.setVariable(OAUTH_STATE_PATH, state, JSON.stringify({ userId, providerId: providerId ?? null, createdAt: new Date(now).toISOString(), expiresAt }));
        return toTextResponse({
            state,
            userId,
            providerId: providerId ?? null,
            ttlSeconds: ttl,
            expiresAt: new Date(expiresAt).toISOString()
        });
    });
    server.registerTool('akoya_oauth_validate_state', {
        description: 'Validate a stored OAuth state and optionally consume it.',
        inputSchema: z.object({
            state: z.string().min(1),
            userId: z.string().min(1),
            providerId: z.string().min(1).optional(),
            consume: z.boolean().optional()
        })
    }, async ({ state, userId, providerId, consume }) => {
        const raw = await vaultService.getVariable(OAUTH_STATE_PATH, state);
        if (!raw) {
            return toTextResponse({ valid: false, reason: 'state_not_found' });
        }
        const parsed = JSON.parse(raw);
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
    });
    server.registerTool('akoya_auth_url', {
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
    }, async (input) => toTextResponse(await akoyaService.buildAuthorizationUrl(input)));
    server.registerTool('akoya_token_exchange', {
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
    }, async ({ userId, providerId, ...input }) => {
        const response = await akoyaService.token({
            ...input,
            providerId,
            grantType: 'authorization_code'
        });
        let userScopedPath = null;
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
        return toTextResponse({
            response: allowSensitiveOutput ? response : maskSensitiveTokenFields(response),
            sensitiveOutputIncluded: allowSensitiveOutput,
            userScopedPath
        });
    });
    server.registerTool('akoya_refresh_token', {
        description: 'Refresh Akoya tokens using refresh token from input or user-scoped vault path.',
        inputSchema: z.object({
            test: z.boolean().optional(),
            userId: z.string().min(1).optional(),
            providerId: z.string().min(1).optional(),
            refreshToken: z.string().min(1).optional(),
            clientId: z.string().min(1).optional(),
            clientSecret: z.string().min(1).optional()
        })
    }, async ({ userId, providerId, refreshToken, ...input }) => {
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
        return toTextResponse({
            response: allowSensitiveOutput ? response : maskSensitiveTokenFields(response),
            sensitiveOutputIncluded: allowSensitiveOutput,
            userScopedPath
        });
    });
    server.registerTool('akoya_revoke_refresh_token', {
        description: 'Revoke refresh token with Akoya IDP revoke endpoint.',
        inputSchema: z.object({
            test: z.boolean().optional(),
            providerId: z.string().min(1).optional(),
            token: z.string().min(1).optional(),
            clientId: z.string().min(1).optional(),
            clientSecret: z.string().min(1).optional(),
            tokenTypeHint: z.enum(['refresh_token']).optional()
        })
    }, async (input) => toTextResponse(await akoyaService.revoke(input)));
    server.registerTool('akoya_service_token', {
        description: 'Request service token using client credentials from Akoya STS.',
        inputSchema: z.object({
            test: z.boolean().optional(),
            clientId: z.string().min(1).optional(),
            clientSecret: z.string().min(1).optional(),
            scope: z.string().min(1)
        })
    }, async (input) => toTextResponse({
        response: allowSensitiveOutput
            ? await akoyaService.serviceToken(input)
            : maskSensitiveTokenFields(await akoyaService.serviceToken(input)),
        sensitiveOutputIncluded: allowSensitiveOutput
    }));
    server.registerTool('akoya_account_info', {
        description: 'Call Akoya account information endpoint.',
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
    }, async ({ userId, providerId, idToken, ...input }) => toTextResponse(await akoyaService.accountInfo({
        ...input,
        providerId,
        idToken: await resolveUserIdToken(vaultService, userId, providerId, idToken)
    })));
    server.registerTool('akoya_accounts', {
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
    }, async ({ userId, providerId, idToken, ...input }) => toTextResponse(await akoyaService.accounts({
        ...input,
        providerId,
        idToken: await resolveUserIdToken(vaultService, userId, providerId, idToken)
    })));
    server.registerTool('akoya_balances', {
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
    }, async ({ userId, providerId, idToken, ...input }) => toTextResponse(await akoyaService.balances({
        ...input,
        providerId,
        idToken: await resolveUserIdToken(vaultService, userId, providerId, idToken)
    })));
    server.registerTool('akoya_transactions', {
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
    }, async ({ userId, providerId, idToken, ...input }) => toTextResponse(await akoyaService.transactions({
        ...input,
        providerId,
        idToken: await resolveUserIdToken(vaultService, userId, providerId, idToken)
    })));
    server.registerTool('akoya_taxlots', {
        description: 'Call Akoya taxlots endpoint.',
        inputSchema: z.object({
            test: z.boolean().optional(),
            version: z.string().min(1).optional(),
            providerId: z.string().min(1).optional(),
            accountId: z.string().min(1).optional(),
            holdingId: z.string().min(1).optional(),
            offset: z.number().int().nonnegative().optional(),
            limit: z.number().int().positive().optional(),
            idToken: z.string().min(1).optional(),
            userId: z.string().min(1).optional(),
            interactionType: z.enum(['USER', 'BATCH']).optional(),
            intentType: z.enum(['payments', 'nonpayments']).optional(),
            lastAccess: z.string().min(1).optional()
        })
    }, async ({ userId, providerId, idToken, ...input }) => toTextResponse(await akoyaService.taxlots({
        ...input,
        providerId,
        idToken: await resolveUserIdToken(vaultService, userId, providerId, idToken)
    })));
    server.registerTool('akoya_customer_info', {
        description: 'Call Akoya customer information endpoint.',
        inputSchema: z.object({
            test: z.boolean().optional(),
            version: z.string().min(1).optional(),
            providerId: z.string().min(1).optional(),
            mode: z.string().min(1).optional(),
            idToken: z.string().min(1).optional(),
            userId: z.string().min(1).optional(),
            interactionType: z.enum(['USER', 'BATCH']).optional(),
            intentType: z.enum(['payments', 'nonpayments']).optional(),
            lastAccess: z.string().min(1).optional()
        })
    }, async ({ userId, providerId, idToken, ...input }) => toTextResponse(await akoyaService.customerInfo({
        ...input,
        providerId,
        idToken: await resolveUserIdToken(vaultService, userId, providerId, idToken)
    })));
    server.registerTool('akoya_account_holder_info', {
        description: 'Call Akoya account holder information endpoint.',
        inputSchema: z.object({
            test: z.boolean().optional(),
            version: z.string().min(1).optional(),
            providerId: z.string().min(1).optional(),
            accountId: z.string().min(1).optional(),
            mode: z.string().min(1).optional(),
            idToken: z.string().min(1).optional(),
            userId: z.string().min(1).optional(),
            interactionType: z.enum(['USER', 'BATCH']).optional(),
            intentType: z.enum(['payments', 'nonpayments']).optional(),
            lastAccess: z.string().min(1).optional()
        })
    }, async ({ userId, providerId, idToken, ...input }) => toTextResponse(await akoyaService.accountHolderInfo({
        ...input,
        providerId,
        idToken: await resolveUserIdToken(vaultService, userId, providerId, idToken)
    })));
    server.registerTool('akoya_payments', {
        description: 'Call Akoya payments endpoint.',
        inputSchema: z.object({
            test: z.boolean().optional(),
            version: z.string().min(1).optional(),
            providerId: z.string().min(1).optional(),
            accountId: z.string().min(1).optional(),
            idToken: z.string().min(1).optional(),
            userId: z.string().min(1).optional(),
            interactionType: z.enum(['USER', 'BATCH']).optional(),
            intentType: z.enum(['payments', 'nonpayments']).optional(),
            lastAccess: z.string().min(1).optional()
        })
    }, async ({ userId, providerId, idToken, ...input }) => toTextResponse(await akoyaService.payments({
        ...input,
        providerId,
        idToken: await resolveUserIdToken(vaultService, userId, providerId, idToken)
    })));
    server.registerTool('akoya_statement_list', {
        description: 'Call Akoya statement list endpoint.',
        inputSchema: z.object({
            test: z.boolean().optional(),
            version: z.string().min(1).optional(),
            providerId: z.string().min(1).optional(),
            accountId: z.string().min(1).optional(),
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
    }, async ({ userId, providerId, idToken, ...input }) => toTextResponse(await akoyaService.statementList({
        ...input,
        providerId,
        idToken: await resolveUserIdToken(vaultService, userId, providerId, idToken)
    })));
    server.registerTool('akoya_statement', {
        description: 'Call Akoya statement retrieval endpoint.',
        inputSchema: z.object({
            test: z.boolean().optional(),
            version: z.string().min(1).optional(),
            providerId: z.string().min(1).optional(),
            accountId: z.string().min(1).optional(),
            statementId: z.string().min(1).optional(),
            accept: z.string().min(1).optional(),
            idToken: z.string().min(1).optional(),
            userId: z.string().min(1).optional(),
            interactionType: z.enum(['USER', 'BATCH']).optional(),
            intentType: z.enum(['payments', 'nonpayments']).optional(),
            lastAccess: z.string().min(1).optional()
        })
    }, async ({ userId, providerId, idToken, ...input }) => toTextResponse(await akoyaService.statement({
        ...input,
        providerId,
        idToken: await resolveUserIdToken(vaultService, userId, providerId, idToken)
    })));
    server.registerTool('akoya_search_tax_forms', {
        description: 'Call Akoya search tax forms endpoint.',
        inputSchema: z.object({
            test: z.boolean().optional(),
            version: z.string().min(1).optional(),
            providerId: z.string().min(1).optional(),
            taxYear: z.string().min(1).optional(),
            taxForms: z.string().min(1).optional(),
            accountId: z.string().min(1).optional(),
            accept: z.string().min(1).optional(),
            interactionId: z.string().min(1).optional(),
            idToken: z.string().min(1).optional(),
            userId: z.string().min(1).optional(),
            interactionType: z.enum(['USER', 'BATCH']).optional(),
            intentType: z.enum(['payments', 'nonpayments']).optional(),
            lastAccess: z.string().min(1).optional()
        })
    }, async ({ userId, providerId, idToken, ...input }) => toTextResponse(await akoyaService.searchTaxForms({
        ...input,
        providerId,
        idToken: await resolveUserIdToken(vaultService, userId, providerId, idToken)
    })));
    server.registerTool('akoya_retrieve_tax_form', {
        description: 'Call Akoya retrieve tax form endpoint.',
        inputSchema: z.object({
            test: z.boolean().optional(),
            version: z.string().min(1).optional(),
            providerId: z.string().min(1).optional(),
            taxFormId: z.string().min(1).optional(),
            taxDataType: z.enum(['JSON', 'BASE64_PDF']).optional(),
            accept: z.string().min(1).optional(),
            interactionId: z.string().min(1).optional(),
            idToken: z.string().min(1).optional(),
            userId: z.string().min(1).optional(),
            interactionType: z.enum(['USER', 'BATCH']).optional(),
            intentType: z.enum(['payments', 'nonpayments']).optional(),
            lastAccess: z.string().min(1).optional()
        })
    }, async ({ userId, providerId, idToken, ...input }) => toTextResponse(await akoyaService.retrieveTaxForm({
        ...input,
        providerId,
        idToken: await resolveUserIdToken(vaultService, userId, providerId, idToken)
    })));
    server.registerTool('akoya_create_app', {
        description: 'Call Akoya create app endpoint.',
        inputSchema: z.object({
            test: z.boolean().optional(),
            version: z.string().min(1).optional(),
            serviceToken: z.string().min(1).optional(),
            body: z.record(z.string(), z.unknown())
        })
    }, async (input) => toTextResponse(await akoyaService.createApp(input)));
    server.registerTool('akoya_update_app', {
        description: 'Call Akoya update app endpoint.',
        inputSchema: z.object({
            test: z.boolean().optional(),
            version: z.string().min(1).optional(),
            recipientId: z.string().min(1).optional(),
            appId: z.string().min(1).optional(),
            serviceToken: z.string().min(1).optional(),
            operations: z.array(z.record(z.string(), z.unknown())).min(1)
        })
    }, async (input) => toTextResponse(await akoyaService.updateApp(input)));
    server.registerTool('akoya_get_all_apps', {
        description: 'Call Akoya get all apps endpoint.',
        inputSchema: z.object({
            test: z.boolean().optional(),
            version: z.string().min(1).optional(),
            recipientId: z.string().min(1).optional(),
            offset: z.number().int().nonnegative().optional(),
            limit: z.number().int().positive().optional(),
            serviceToken: z.string().min(1).optional()
        })
    }, async (input) => toTextResponse(await akoyaService.getAllApps(input)));
    server.registerTool('akoya_get_purchased_products', {
        description: 'Call Akoya get purchased products endpoint.',
        inputSchema: z.object({
            test: z.boolean().optional(),
            version: z.string().min(1).optional(),
            recipientId: z.string().min(1).optional(),
            serviceToken: z.string().min(1).optional()
        })
    }, async (input) => toTextResponse(await akoyaService.getPurchasedProducts(input)));
    server.registerTool('akoya_get_valid_providers_for_products', {
        description: 'Call Akoya get valid providers for products endpoint.',
        inputSchema: z.object({
            test: z.boolean().optional(),
            version: z.string().min(1).optional(),
            recipientId: z.string().min(1).optional(),
            products: z.string().min(1),
            serviceToken: z.string().min(1).optional()
        })
    }, async (input) => toTextResponse(await akoyaService.getValidProvidersForProducts(input)));
    server.registerTool('akoya_get_subscriptions_for_app', {
        description: 'Call Akoya subscriptions for app endpoint.',
        inputSchema: z.object({
            test: z.boolean().optional(),
            version: z.string().min(1).optional(),
            appId: z.string().min(1).optional(),
            status: z.enum(['ACTIVE', 'PENDING', 'PROCESSING', 'TERMINATED', 'DENIED']).optional(),
            offset: z.number().int().nonnegative().optional(),
            limit: z.number().int().positive().optional(),
            serviceToken: z.string().min(1).optional()
        })
    }, async (input) => toTextResponse(await akoyaService.getSubscriptionsForApp(input)));
    server.registerTool('akoya_list_notification_subscriptions', {
        description: 'Call Akoya list notification subscriptions endpoint.',
        inputSchema: z.object({
            test: z.boolean().optional(),
            version: z.string().min(1).optional(),
            serviceToken: z.string().min(1).optional()
        })
    }, async (input) => toTextResponse(await akoyaService.listNotificationSubscriptions(input)));
    server.registerTool('akoya_create_notification_subscription', {
        description: 'Call Akoya create notification subscription endpoint.',
        inputSchema: z.object({
            test: z.boolean().optional(),
            version: z.string().min(1).optional(),
            category: z.string().min(1),
            type: z.string().min(1),
            callbackUrl: z.string().url(),
            effectiveDate: z.string().min(1).optional(),
            callbackEmail: z.string().email().optional(),
            serviceToken: z.string().min(1).optional()
        })
    }, async (input) => toTextResponse(await akoyaService.createNotificationSubscription(input)));
    server.registerTool('akoya_get_notification_subscription_by_id', {
        description: 'Call Akoya get notification subscription by id endpoint.',
        inputSchema: z.object({
            test: z.boolean().optional(),
            version: z.string().min(1).optional(),
            subscriptionId: z.string().min(1).optional(),
            serviceToken: z.string().min(1).optional()
        })
    }, async (input) => toTextResponse(await akoyaService.getNotificationSubscriptionById(input)));
    server.registerTool('akoya_update_notification_subscription', {
        description: 'Call Akoya update notification subscription endpoint.',
        inputSchema: z.object({
            test: z.boolean().optional(),
            version: z.string().min(1).optional(),
            subscriptionId: z.string().min(1).optional(),
            callbackUrl: z.string().url().optional(),
            effectiveDate: z.string().min(1).optional(),
            callbackEmail: z.string().email().optional(),
            serviceToken: z.string().min(1).optional()
        })
    }, async (input) => toTextResponse(await akoyaService.updateNotificationSubscription(input)));
    server.registerTool('akoya_delete_notification_subscription', {
        description: 'Call Akoya delete notification subscription endpoint.',
        inputSchema: z.object({
            test: z.boolean().optional(),
            version: z.string().min(1).optional(),
            subscriptionId: z.string().min(1).optional(),
            serviceToken: z.string().min(1).optional()
        })
    }, async (input) => toTextResponse(await akoyaService.deleteNotificationSubscription(input)));
    server.registerTool('akoya_send_sandbox_test_event', {
        description: 'Call Akoya send sandbox test event endpoint.',
        inputSchema: z.object({
            test: z.boolean().optional(),
            version: z.string().min(1).optional(),
            id: z.string().min(1),
            serviceToken: z.string().min(1).optional()
        })
    }, async (input) => toTextResponse(await akoyaService.sendSandboxTestEvent(input)));
    server.registerTool('akoya_consent_grant', {
        description: 'Call Akoya consent grant endpoint.',
        inputSchema: z.object({
            test: z.boolean().optional(),
            version: z.string().min(1).optional(),
            consentId: z.string().min(1).optional(),
            serviceToken: z.string().min(1).optional()
        })
    }, async (input) => toTextResponse(await akoyaService.getConsentGrant(input)));
    server.registerTool('vault_connection_info', {
        description: 'Return Vault provider and connectivity configuration for variable storage.',
        inputSchema: z.object({})
    }, async () => toTextResponse({
        vault: vaultService.getConnectionInfo(),
        configured: vaultService.isConfigured()
    }));
    server.registerTool('vault_set_variable', {
        description: 'Store a variable in Vault at a given secret path and key.',
        inputSchema: z.object({
            secretPath: z.string().min(1),
            key: z.string().min(1),
            value: z.string()
        })
    }, async ({ secretPath, key, value }) => {
        await vaultService.setVariable(secretPath, key, value);
        return toTextResponse({ stored: true, secretPath, key });
    });
    server.registerTool('vault_get_variable', {
        description: 'Get a variable from Vault by secret path and key.',
        inputSchema: z.object({
            secretPath: z.string().min(1),
            key: z.string().min(1),
            revealValue: z.boolean().optional()
        })
    }, async ({ secretPath, key, revealValue }) => {
        const value = await vaultService.getVariable(secretPath, key);
        const found = value !== null;
        const sensitiveRevealAllowed = revealValue === true && allowSensitiveOutput;
        return toTextResponse({
            secretPath,
            key,
            found,
            sensitiveOutputIncluded: sensitiveRevealAllowed,
            value: sensitiveRevealAllowed ? value : found ? 'set' : null
        });
    });
    server.registerTool('vault_list_variables', {
        description: 'List all variable keys stored at a Vault secret path.',
        inputSchema: z.object({
            secretPath: z.string().min(1)
        })
    }, async ({ secretPath }) => {
        const keys = await vaultService.listVariables(secretPath);
        return toTextResponse({ secretPath, keys });
    });
    server.registerTool('vault_delete_variable', {
        description: 'Delete a variable key from a Vault secret path.',
        inputSchema: z.object({
            secretPath: z.string().min(1),
            key: z.string().min(1)
        })
    }, async ({ secretPath, key }) => {
        const deleted = await vaultService.deleteVariable(secretPath, key);
        return toTextResponse({ secretPath, key, deleted });
    });
    return server;
}
const isEntrypoint = process.argv[1] === fileURLToPath(import.meta.url);
if (isEntrypoint) {
    serveStdio(buildServer);
}

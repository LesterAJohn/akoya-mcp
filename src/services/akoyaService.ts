import { VaultService } from './vaultService.js';
import {
  AKOYA_CREDENTIAL_ENV,
  AKOYA_CREDENTIAL_KEYS,
  AKOYA_GENERAL_CONFIG_ENV,
  AKOYA_GENERAL_CONFIG_KEYS,
  AKOYA_TOKEN_ENV,
  AKOYA_TOKEN_KEYS,
  AKOYA_URL_ENV,
  AKOYA_URL_KEYS,
  DEFAULT_AKOYA_CREDENTIALS,
  DEFAULT_AKOYA_GENERAL_CONFIG,
  DEFAULT_AKOYA_TOKENS,
  DEFAULT_AKOYA_URLS,
  type AkoyaCredentialKey,
  type AkoyaGeneralConfigKey,
  type AkoyaTokenKey,
  type AkoyaUrlConfigKey
} from '../config/akoyaUrls.js';

type ApiDomain = 'idp' | 'products' | 'serviceToken' | 'serviceApi';

type DataHeadersInput = {
  interactionType?: 'USER' | 'BATCH';
  intentType?: 'payments' | 'nonpayments';
  lastAccess?: string;
  interactionId?: string;
  accept?: string;
};

type RequestOptions = {
  method: 'GET' | 'POST' | 'PATCH' | 'DELETE';
  domain: ApiDomain;
  path: string;
  test?: boolean;
  bearerToken?: string;
  headers?: Record<string, string>;
  query?: Record<string, string | number | boolean | undefined>;
  jsonBody?: unknown;
  formBody?: Record<string, string | undefined>;
  parseAs?: 'json' | 'text' | 'binary';
};

const GENERAL_CONFIG_PATH = 'akoya/general/config';
const GENERAL_CREDENTIALS_PATH = 'akoya/general/credentials';
const GENERAL_TOKENS_PATH = 'akoya/general/tokens';
const INSTITUTIONS_ROOT_PATH = 'akoya/institutions';

function compactObject(input: Record<string, unknown>): Record<string, unknown> {
  const output: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(input)) {
    if (value !== undefined && value !== null && value !== '') {
      output[key] = value;
    }
  }
  return output;
}

export class AkoyaService {
  private readonly vault: VaultService;
  private urlConfigLoaded = false;
  private startupSeedLoaded = false;
  private readonly urlConfigCache: Partial<Record<AkoyaUrlConfigKey, string>> = {};

  constructor(vault: VaultService) {
    this.vault = vault;
  }

  public async buildAuthorizationUrl(input: {
    test?: boolean;
    providerId?: string;
    clientId?: string;
    redirectUri?: string;
    state: string;
    scope?: string;
    responseType?: 'code';
    connector?: string;
  }): Promise<{ url: string; test: boolean }> {
    const test = input.test ?? false;
    const providerId = await this.resolveConfigValue('provider_id', input.providerId, 'mikomo');
    const clientId = await this.resolveCredentialValue('client_id', input.clientId, true, providerId);
    const redirectUri = await this.resolveConfigValue('redirect_uri', input.redirectUri, undefined, true, providerId);
    const responseType = input.responseType ?? 'code';
    const scope = input.scope ?? 'openid profile offline_access';
    const connector = input.connector ?? providerId;

    const baseUrl = await this.getBaseUrl('idp', test);
    const params = new URLSearchParams({
      connector,
      client_id: clientId,
      redirect_uri: redirectUri,
      response_type: responseType,
      scope,
      state: input.state
    });

    return { url: `${baseUrl}/auth?${params.toString()}`, test };
  }

  public async token(input: {
    test?: boolean;
    providerId?: string;
    grantType: 'authorization_code' | 'refresh_token';
    code?: string;
    refreshToken?: string;
    redirectUri?: string;
    clientId?: string;
    clientSecret?: string;
  }): Promise<unknown> {
    const providerId = await this.resolveConfigValue('provider_id', input.providerId, undefined, false);
    const clientId = await this.resolveCredentialValue('client_id', input.clientId, true, providerId || undefined);
    const clientSecret = await this.resolveCredentialValue(
      'client_secret',
      input.clientSecret,
      true,
      providerId || undefined
    );

    if (input.grantType === 'authorization_code') {
      const redirectUri = await this.resolveConfigValue(
        'redirect_uri',
        input.redirectUri,
        undefined,
        true,
        providerId || undefined
      );
      if (!input.code) {
        throw new Error('code is required for authorization_code grant type.');
      }

      const auth = Buffer.from(`${clientId}:${clientSecret}`).toString('base64');
      const response = await this.request({
        method: 'POST',
        domain: 'idp',
        path: '/token',
        test: input.test,
        headers: {
          Authorization: `Basic ${auth}`
        },
        formBody: {
          grant_type: 'authorization_code',
          redirect_uri: redirectUri,
          code: input.code
        },
        parseAs: 'json'
      });

      await this.persistTokenResponse(response, providerId || undefined);
      return response;
    }

    const refreshToken = await this.resolveTokenValue(
      'refresh_token',
      input.refreshToken,
      true,
      providerId || undefined
    );
    const response = await this.request({
      method: 'POST',
      domain: 'idp',
      path: '/token',
      test: input.test,
      formBody: {
        grant_type: 'refresh_token',
        refresh_token: refreshToken,
        client_id: clientId,
        client_secret: clientSecret
      },
      parseAs: 'json'
    });

    await this.persistTokenResponse(response, providerId || undefined);
    return response;
  }

  public async revoke(input: {
    test?: boolean;
    providerId?: string;
    token?: string;
    clientId?: string;
    clientSecret?: string;
    tokenTypeHint?: 'refresh_token';
  }): Promise<unknown> {
    const providerId = await this.resolveConfigValue('provider_id', input.providerId, undefined, false);
    const clientId = await this.resolveCredentialValue('client_id', input.clientId, true, providerId || undefined);
    const clientSecret = await this.resolveCredentialValue(
      'client_secret',
      input.clientSecret,
      true,
      providerId || undefined
    );
    const refreshToken = await this.resolveTokenValue(
      'refresh_token',
      input.token,
      true,
      providerId || undefined
    );

    return this.request({
      method: 'POST',
      domain: 'idp',
      path: '/revoke',
      test: input.test,
      formBody: {
        client_id: clientId,
        client_secret: clientSecret,
        token: refreshToken,
        token_type_hint: input.tokenTypeHint ?? 'refresh_token'
      },
      parseAs: 'json'
    });
  }

  public async serviceToken(input: {
    test?: boolean;
    clientId?: string;
    clientSecret?: string;
    scope: string;
  }): Promise<unknown> {
    const clientId = await this.resolveCredentialValue('client_id', input.clientId, true);
    const clientSecret = await this.resolveCredentialValue('client_secret', input.clientSecret, true);
    const auth = Buffer.from(`${clientId}:${clientSecret}`).toString('base64');

    const response = await this.request({
      method: 'POST',
      domain: 'serviceToken',
      path: '/token',
      test: input.test,
      headers: {
        Authorization: `Basic ${auth}`
      },
      formBody: {
        grant_type: 'client_credentials',
        scope: input.scope
      },
      parseAs: 'json'
    });

    const payload = response as { access_token?: string };
    if (payload.access_token) {
      await this.vault.setVariable(GENERAL_TOKENS_PATH, 'service_token', payload.access_token);
      await this.vault.setVariable(GENERAL_TOKENS_PATH, 'service_scope', input.scope);
    }

    return response;
  }

  public async accountInfo(input: {
    test?: boolean;
    version?: string;
    providerId?: string;
    mode?: string;
    accountIds?: string;
    idToken?: string;
    interactionType?: 'USER' | 'BATCH';
    intentType?: 'payments' | 'nonpayments';
    lastAccess?: string;
  }): Promise<unknown> {
    const { version, providerId } = await this.resolveDataPath(input.version, input.providerId);
    const token = await this.resolveTokenValue('id_token', input.idToken, true, providerId);

    return this.request({
      method: 'GET',
      domain: 'products',
      path: `/accounts-info/${version}/${providerId}`,
      test: input.test,
      bearerToken: token,
      headers: this.buildDataHeaders(input),
      query: {
        mode: input.mode,
        accountIds: input.accountIds
      },
      parseAs: 'json'
    });
  }

  public async balances(input: {
    test?: boolean;
    version?: string;
    providerId?: string;
    mode?: string;
    accountIds?: string;
    idToken?: string;
    interactionType?: 'USER' | 'BATCH';
    intentType?: 'payments' | 'nonpayments';
    lastAccess?: string;
  }): Promise<unknown> {
    const { version, providerId } = await this.resolveDataPath(input.version, input.providerId);
    const token = await this.resolveTokenValue('id_token', input.idToken, true, providerId);

    return this.request({
      method: 'GET',
      domain: 'products',
      path: `/balances/${version}/${providerId}`,
      test: input.test,
      bearerToken: token,
      headers: this.buildDataHeaders(input),
      query: {
        mode: input.mode,
        accountIds: input.accountIds
      },
      parseAs: 'json'
    });
  }

  public async transactions(input: {
    test?: boolean;
    version?: string;
    providerId?: string;
    accountId?: string;
    mode?: string;
    startTime?: string;
    endTime?: string;
    offset?: number;
    limit?: number;
    idToken?: string;
    interactionType?: 'USER' | 'BATCH';
    intentType?: 'payments' | 'nonpayments';
    lastAccess?: string;
  }): Promise<unknown> {
    const { version, providerId } = await this.resolveDataPath(input.version, input.providerId);
    const accountId = await this.resolveConfigValue('account_id', input.accountId, undefined, true, providerId);
    const token = await this.resolveTokenValue('id_token', input.idToken, true, providerId);

    return this.request({
      method: 'GET',
      domain: 'products',
      path: `/transactions/${version}/${providerId}/${accountId}`,
      test: input.test,
      bearerToken: token,
      headers: this.buildDataHeaders(input),
      query: {
        mode: input.mode,
        startTime: input.startTime,
        endTime: input.endTime,
        offset: input.offset,
        limit: input.limit
      },
      parseAs: 'json'
    });
  }

  public async accounts(input: {
    test?: boolean;
    version?: string;
    providerId?: string;
    mode?: string;
    accountIds?: string;
    offset?: number;
    limit?: number;
    idToken?: string;
    interactionType?: 'USER' | 'BATCH';
    intentType?: 'payments' | 'nonpayments';
    lastAccess?: string;
  }): Promise<unknown> {
    const { version, providerId } = await this.resolveDataPath(input.version, input.providerId);
    const token = await this.resolveTokenValue('id_token', input.idToken, true, providerId);

    return this.request({
      method: 'GET',
      domain: 'products',
      path: `/accounts/${version}/${providerId}`,
      test: input.test,
      bearerToken: token,
      headers: this.buildDataHeaders(input),
      query: {
        mode: input.mode,
        accountIds: input.accountIds,
        offset: input.offset,
        limit: input.limit
      },
      parseAs: 'json'
    });
  }

  public async taxlots(input: {
    test?: boolean;
    version?: string;
    providerId?: string;
    accountId?: string;
    holdingId?: string;
    offset?: number;
    limit?: number;
    idToken?: string;
    interactionType?: 'USER' | 'BATCH';
    intentType?: 'payments' | 'nonpayments';
    lastAccess?: string;
  }): Promise<unknown> {
    const { version, providerId } = await this.resolveDataPath(input.version, input.providerId);
    const accountId = await this.resolveConfigValue('account_id', input.accountId, undefined, true, providerId);
    const holdingId = await this.resolveConfigValue('holding_id', input.holdingId, undefined, true, providerId);
    const token = await this.resolveTokenValue('id_token', input.idToken, true, providerId);

    return this.request({
      method: 'GET',
      domain: 'products',
      path: `/taxlots/${version}/${providerId}/${accountId}/${holdingId}`,
      test: input.test,
      bearerToken: token,
      headers: this.buildDataHeaders(input),
      query: {
        offset: input.offset,
        limit: input.limit
      },
      parseAs: 'json'
    });
  }

  public async customerInfo(input: {
    test?: boolean;
    version?: string;
    providerId?: string;
    mode?: string;
    idToken?: string;
    interactionType?: 'USER' | 'BATCH';
    intentType?: 'payments' | 'nonpayments';
    lastAccess?: string;
  }): Promise<unknown> {
    const { version, providerId } = await this.resolveDataPath(input.version, input.providerId);
    const token = await this.resolveTokenValue('id_token', input.idToken, true, providerId);

    return this.request({
      method: 'GET',
      domain: 'products',
      path: `/customers/${version}/${providerId}/current`,
      test: input.test,
      bearerToken: token,
      headers: this.buildDataHeaders(input),
      query: {
        mode: input.mode
      },
      parseAs: 'json'
    });
  }

  public async accountHolderInfo(input: {
    test?: boolean;
    version?: string;
    providerId?: string;
    accountId?: string;
    mode?: string;
    idToken?: string;
    interactionType?: 'USER' | 'BATCH';
    intentType?: 'payments' | 'nonpayments';
    lastAccess?: string;
  }): Promise<unknown> {
    const { version, providerId } = await this.resolveDataPath(input.version, input.providerId);
    const accountId = await this.resolveConfigValue('account_id', input.accountId, undefined, true, providerId);
    const token = await this.resolveTokenValue('id_token', input.idToken, true, providerId);

    return this.request({
      method: 'GET',
      domain: 'products',
      path: `/contacts/${version}/${providerId}/${accountId}`,
      test: input.test,
      bearerToken: token,
      headers: this.buildDataHeaders(input),
      query: {
        mode: input.mode
      },
      parseAs: 'json'
    });
  }

  public async payments(input: {
    test?: boolean;
    version?: string;
    providerId?: string;
    accountId?: string;
    idToken?: string;
    interactionType?: 'USER' | 'BATCH';
    intentType?: 'payments' | 'nonpayments';
    lastAccess?: string;
  }): Promise<unknown> {
    const { version, providerId } = await this.resolveDataPath(input.version, input.providerId);
    const accountId = await this.resolveConfigValue('account_id', input.accountId, undefined, true, providerId);
    const token = await this.resolveTokenValue('id_token', input.idToken, true, providerId);

    return this.request({
      method: 'GET',
      domain: 'products',
      path: `/payments/${version}/${providerId}/${accountId}/payment-networks`,
      test: input.test,
      bearerToken: token,
      headers: this.buildDataHeaders(input),
      parseAs: 'json'
    });
  }

  public async statementList(input: {
    test?: boolean;
    version?: string;
    providerId?: string;
    accountId?: string;
    startTime?: string;
    endTime?: string;
    offset?: number;
    limit?: number;
    idToken?: string;
    interactionType?: 'USER' | 'BATCH';
    intentType?: 'payments' | 'nonpayments';
    lastAccess?: string;
  }): Promise<unknown> {
    const { version, providerId } = await this.resolveDataPath(input.version, input.providerId);
    const accountId = await this.resolveConfigValue('account_id', input.accountId, undefined, true, providerId);
    const token = await this.resolveTokenValue('id_token', input.idToken, true, providerId);

    return this.request({
      method: 'GET',
      domain: 'products',
      path: `/statements/${version}/${providerId}/${accountId}`,
      test: input.test,
      bearerToken: token,
      headers: this.buildDataHeaders(input),
      query: {
        startTime: input.startTime,
        endTime: input.endTime,
        offset: input.offset,
        limit: input.limit
      },
      parseAs: 'json'
    });
  }

  public async statement(input: {
    test?: boolean;
    version?: string;
    providerId?: string;
    accountId?: string;
    statementId?: string;
    accept?: string;
    idToken?: string;
    interactionType?: 'USER' | 'BATCH';
    intentType?: 'payments' | 'nonpayments';
    lastAccess?: string;
  }): Promise<unknown> {
    const { version, providerId } = await this.resolveDataPath(input.version, input.providerId);
    const accountId = await this.resolveConfigValue('account_id', input.accountId, undefined, true, providerId);
    const statementId = await this.resolveConfigValue('statement_id', input.statementId, undefined, true, providerId);
    const token = await this.resolveTokenValue('id_token', input.idToken, true, providerId);
    const accept = input.accept ?? 'application/pdf';

    return this.request({
      method: 'GET',
      domain: 'products',
      path: `/statements/${version}/${providerId}/${accountId}/${statementId}`,
      test: input.test,
      bearerToken: token,
      headers: this.buildDataHeaders({ ...input, accept }),
      parseAs: accept.includes('json') ? 'json' : 'binary'
    });
  }

  public async searchTaxForms(input: {
    test?: boolean;
    version?: string;
    providerId?: string;
    taxYear?: string;
    taxForms?: string;
    accountId?: string;
    accept?: string;
    interactionId?: string;
    idToken?: string;
    interactionType?: 'USER' | 'BATCH';
    intentType?: 'payments' | 'nonpayments';
    lastAccess?: string;
  }): Promise<unknown> {
    const { version, providerId } = await this.resolveDataPath(input.version, input.providerId);
    const token = await this.resolveTokenValue('id_token', input.idToken, true, providerId);

    return this.request({
      method: 'GET',
      domain: 'products',
      path: `/tax-forms/${version}/${providerId}`,
      test: input.test,
      bearerToken: token,
      headers: this.buildDataHeaders({ ...input, accept: input.accept ?? 'application/json' }),
      query: {
        taxYear: input.taxYear,
        taxForms: input.taxForms,
        accountId: input.accountId
      },
      parseAs: (input.accept ?? 'application/json').includes('pdf') ? 'binary' : 'json'
    });
  }

  public async retrieveTaxForm(input: {
    test?: boolean;
    version?: string;
    providerId?: string;
    taxFormId?: string;
    taxDataType?: 'JSON' | 'BASE64_PDF';
    accept?: string;
    interactionId?: string;
    idToken?: string;
    interactionType?: 'USER' | 'BATCH';
    intentType?: 'payments' | 'nonpayments';
    lastAccess?: string;
  }): Promise<unknown> {
    const { version, providerId } = await this.resolveDataPath(input.version, input.providerId);
    const taxFormId = await this.resolveConfigValue('tax_form_id', input.taxFormId, undefined, true, providerId);
    const token = await this.resolveTokenValue('id_token', input.idToken, true, providerId);
    const accept = input.accept ?? 'application/json';

    return this.request({
      method: 'GET',
      domain: 'products',
      path: `/tax-forms/${version}/${providerId}/${taxFormId}`,
      test: input.test,
      bearerToken: token,
      headers: this.buildDataHeaders({ ...input, accept }),
      query: {
        taxDataType: input.taxDataType
      },
      parseAs: accept.includes('pdf') ? 'binary' : 'json'
    });
  }

  public async createApp(input: {
    test?: boolean;
    version?: string;
    serviceToken?: string;
    body: Record<string, unknown>;
  }): Promise<unknown> {
    const version = await this.resolveConfigValue('management_version', input.version, 'v2');
    const token = await this.resolveTokenValue('service_token', input.serviceToken, true);

    return this.request({
      method: 'POST',
      domain: 'serviceApi',
      path: `/manage/${version}/apps/register`,
      test: input.test,
      bearerToken: token,
      jsonBody: input.body,
      parseAs: 'json'
    });
  }

  public async updateApp(input: {
    test?: boolean;
    version?: string;
    recipientId?: string;
    appId?: string;
    serviceToken?: string;
    operations: Array<Record<string, unknown>>;
  }): Promise<unknown> {
    const version = await this.resolveConfigValue('management_version', input.version, 'v2');
    const recipientId = await this.resolveConfigValue('recipient_id', input.recipientId, undefined, true);
    const appId = await this.resolveConfigValue('app_id', input.appId, undefined, true);
    const token = await this.resolveTokenValue('service_token', input.serviceToken, true);

    return this.request({
      method: 'PATCH',
      domain: 'serviceApi',
      path: `/manage/${version}/recipients/${recipientId}/apps/${appId}`,
      test: input.test,
      bearerToken: token,
      jsonBody: input.operations,
      parseAs: 'json'
    });
  }

  public async getAllApps(input: {
    test?: boolean;
    version?: string;
    recipientId?: string;
    offset?: number;
    limit?: number;
    serviceToken?: string;
  }): Promise<unknown> {
    const version = await this.resolveConfigValue('management_version', input.version, 'v2');
    const recipientId = await this.resolveConfigValue('recipient_id', input.recipientId, undefined, true);
    const token = await this.resolveTokenValue('service_token', input.serviceToken, true);

    return this.request({
      method: 'GET',
      domain: 'serviceApi',
      path: `/manage/${version}/recipients/${recipientId}/apps`,
      test: input.test,
      bearerToken: token,
      query: {
        offset: input.offset,
        limit: input.limit
      },
      parseAs: 'json'
    });
  }

  public async getPurchasedProducts(input: {
    test?: boolean;
    version?: string;
    recipientId?: string;
    serviceToken?: string;
  }): Promise<unknown> {
    const version = await this.resolveConfigValue('management_version', input.version, 'v2');
    const recipientId = await this.resolveConfigValue('recipient_id', input.recipientId, undefined, true);
    const token = await this.resolveTokenValue('service_token', input.serviceToken, true);

    return this.request({
      method: 'GET',
      domain: 'serviceApi',
      path: `/manage/${version}/recipients/${recipientId}/products`,
      test: input.test,
      bearerToken: token,
      parseAs: 'json'
    });
  }

  public async getValidProvidersForProducts(input: {
    test?: boolean;
    version?: string;
    recipientId?: string;
    products: string;
    serviceToken?: string;
  }): Promise<unknown> {
    const version = await this.resolveConfigValue('management_version', input.version, 'v2');
    const recipientId = await this.resolveConfigValue('recipient_id', input.recipientId, undefined, true);
    const token = await this.resolveTokenValue('service_token', input.serviceToken, true);

    return this.request({
      method: 'GET',
      domain: 'serviceApi',
      path: `/manage/${version}/recipients/${recipientId}/providers`,
      test: input.test,
      bearerToken: token,
      query: {
        products: input.products
      },
      parseAs: 'json'
    });
  }

  public async getSubscriptionsForApp(input: {
    test?: boolean;
    version?: string;
    appId?: string;
    status?: 'ACTIVE' | 'PENDING' | 'PROCESSING' | 'TERMINATED' | 'DENIED';
    offset?: number;
    limit?: number;
    serviceToken?: string;
  }): Promise<unknown> {
    const version = await this.resolveConfigValue('management_version', input.version, 'v2');
    const appId = await this.resolveConfigValue('app_id', input.appId, undefined, true);
    const token = await this.resolveTokenValue('service_token', input.serviceToken, true);
    const path = input.status
      ? `/manage/${version}/subscriptions/${appId}/status`
      : `/manage/${version}/subscriptions/${appId}`;

    return this.request({
      method: 'GET',
      domain: 'serviceApi',
      path,
      test: input.test,
      bearerToken: token,
      query: {
        status: input.status,
        offset: input.offset,
        limit: input.limit
      },
      parseAs: 'json'
    });
  }

  public async listNotificationSubscriptions(input: {
    test?: boolean;
    version?: string;
    serviceToken?: string;
  }): Promise<unknown> {
    const version = await this.resolveConfigValue('notifications_version', input.version, 'v1');
    const token = await this.resolveTokenValue('service_token', input.serviceToken, true);

    return this.request({
      method: 'GET',
      domain: 'serviceApi',
      path: `/notifications/${version}/subscriptions`,
      test: input.test,
      bearerToken: token,
      parseAs: 'json'
    });
  }

  public async createNotificationSubscription(input: {
    test?: boolean;
    version?: string;
    category: string;
    type: string;
    callbackUrl: string;
    effectiveDate?: string;
    callbackEmail?: string;
    serviceToken?: string;
  }): Promise<unknown> {
    const version = await this.resolveConfigValue('notifications_version', input.version, 'v1');
    const token = await this.resolveTokenValue('service_token', input.serviceToken, true);

    return this.request({
      method: 'POST',
      domain: 'serviceApi',
      path: `/notifications/${version}/subscriptions`,
      test: input.test,
      bearerToken: token,
      jsonBody: compactObject({
        category: input.category,
        type: input.type,
        callbackUrl: input.callbackUrl,
        effectiveDate: input.effectiveDate,
        callbackEmail: input.callbackEmail
      }),
      parseAs: 'json'
    });
  }

  public async getNotificationSubscriptionById(input: {
    test?: boolean;
    version?: string;
    subscriptionId?: string;
    serviceToken?: string;
  }): Promise<unknown> {
    const version = await this.resolveConfigValue('notifications_version', input.version, 'v1');
    const subscriptionId = await this.resolveConfigValue('subscription_id', input.subscriptionId, undefined, true);
    const token = await this.resolveTokenValue('service_token', input.serviceToken, true);

    return this.request({
      method: 'GET',
      domain: 'serviceApi',
      path: `/notifications/${version}/subscriptions/${subscriptionId}`,
      test: input.test,
      bearerToken: token,
      parseAs: 'json'
    });
  }

  public async updateNotificationSubscription(input: {
    test?: boolean;
    version?: string;
    subscriptionId?: string;
    callbackUrl?: string;
    effectiveDate?: string;
    callbackEmail?: string;
    serviceToken?: string;
  }): Promise<unknown> {
    const version = await this.resolveConfigValue('notifications_version', input.version, 'v1');
    const subscriptionId = await this.resolveConfigValue('subscription_id', input.subscriptionId, undefined, true);
    const token = await this.resolveTokenValue('service_token', input.serviceToken, true);

    return this.request({
      method: 'PATCH',
      domain: 'serviceApi',
      path: `/notifications/${version}/subscriptions/${subscriptionId}`,
      test: input.test,
      bearerToken: token,
      jsonBody: compactObject({
        callbackUrl: input.callbackUrl,
        effectiveDate: input.effectiveDate,
        callbackEmail: input.callbackEmail
      }),
      parseAs: 'json'
    });
  }

  public async deleteNotificationSubscription(input: {
    test?: boolean;
    version?: string;
    subscriptionId?: string;
    serviceToken?: string;
  }): Promise<unknown> {
    const version = await this.resolveConfigValue('notifications_version', input.version, 'v1');
    const subscriptionId = await this.resolveConfigValue('subscription_id', input.subscriptionId, undefined, true);
    const token = await this.resolveTokenValue('service_token', input.serviceToken, true);

    return this.request({
      method: 'DELETE',
      domain: 'serviceApi',
      path: `/notifications/${version}/subscriptions/${subscriptionId}`,
      test: input.test,
      bearerToken: token,
      parseAs: 'text'
    });
  }

  public async sendSandboxTestEvent(input: {
    test?: boolean;
    version?: string;
    id: string;
    serviceToken?: string;
  }): Promise<unknown> {
    const version = await this.resolveConfigValue('notifications_version', input.version, 'v1');
    const token = await this.resolveTokenValue('service_token', input.serviceToken, true);

    return this.request({
      method: 'POST',
      domain: 'serviceApi',
      path: `/notifications/${version}/test`,
      test: input.test,
      bearerToken: token,
      jsonBody: {
        id: input.id
      },
      parseAs: 'json'
    });
  }

  public async getConsentGrant(input: {
    test?: boolean;
    version?: string;
    consentId?: string;
    serviceToken?: string;
  }): Promise<unknown> {
    const version = await this.resolveConfigValue('consent_version', input.version, 'v1');
    const consentId = await this.resolveConfigValue('consent_id', input.consentId, undefined, true);
    const token = await this.resolveTokenValue('service_token', input.serviceToken, true);

    return this.request({
      method: 'GET',
      domain: 'serviceApi',
      path: `/consents/${version}/${consentId}`,
      test: input.test,
      bearerToken: token,
      parseAs: 'json'
    });
  }

  public async saveConfig(input: Record<string, string>, institution?: string): Promise<Record<string, string>> {
    const entries = Object.entries(input).filter(([, value]) => value.length > 0);
    for (const [key, value] of entries) {
      await this.vault.setVariable(GENERAL_CONFIG_PATH, key, value);
      if (institution) {
        await this.vault.setVariable(this.getInstitutionPath(institution, 'config'), key, value);
      }
    }

    return Object.fromEntries(entries);
  }

  private async persistTokenResponse(response: unknown, institution?: string): Promise<void> {
    const payload = response as {
      id_token?: string;
      refresh_token?: string;
      expires_in?: number;
      token_type?: string;
    };

    if (payload.id_token) {
      await this.setScopedVariable('tokens', 'id_token', payload.id_token, institution);
    }
    if (payload.refresh_token) {
      await this.setScopedVariable('tokens', 'refresh_token', payload.refresh_token, institution);
    }
    if (payload.expires_in !== undefined) {
      await this.setScopedVariable('tokens', 'expires_in', String(payload.expires_in), institution);
    }
    if (payload.token_type) {
      await this.setScopedVariable('tokens', 'token_type', payload.token_type, institution);
    }
  }

  private buildDataHeaders(input: DataHeadersInput): Record<string, string> {
    const headers: Record<string, string> = {
      'x-akoya-interaction-type': input.interactionType ?? 'USER',
      'x-akoya-last-access': input.lastAccess ?? new Date().toISOString(),
      'x-akoya-intent-type': input.intentType ?? 'nonpayments'
    };

    if (input.accept) {
      headers.accept = input.accept;
    }
    if (input.interactionId) {
      headers['x-akoya-interaction-id'] = input.interactionId;
    }

    return headers;
  }

  private async resolveDataPath(
    versionInput?: string,
    providerInput?: string
  ): Promise<{ version: string; providerId: string }> {
    const version = await this.resolveConfigValue('data_version', versionInput, 'v3');
    const providerId = await this.resolveConfigValue('provider_id', providerInput, 'mikomo');
    return { version, providerId };
  }

  private async resolveCredentialValue(
    key: string,
    explicitValue?: string,
    required = false,
    institution?: string
  ): Promise<string> {
    if (explicitValue && explicitValue.length > 0) {
      await this.setScopedVariable('credentials', key, explicitValue, institution);
      return explicitValue;
    }

    const storedValue = await this.getScopedVariable('credentials', key, institution);
    if (storedValue && storedValue.length > 0) {
      return storedValue;
    }

    if (required) {
      throw new Error(`Missing required credential: ${key}. Pass it in this tool call or store it in Vault.`);
    }

    return '';
  }

  private async resolveTokenValue(
    key: string,
    explicitValue?: string,
    required = false,
    institution?: string
  ): Promise<string> {
    if (explicitValue && explicitValue.length > 0) {
      await this.setScopedVariable('tokens', key, explicitValue, institution);
      return explicitValue;
    }

    const storedValue = await this.getScopedVariable('tokens', key, institution);
    if (storedValue && storedValue.length > 0) {
      return storedValue;
    }

    if (required) {
      throw new Error(`Missing required token: ${key}. Pass it in this tool call or store it in Vault.`);
    }

    return '';
  }

  private async resolveConfigValue(
    key: string,
    explicitValue?: string,
    fallbackValue?: string,
    required = false,
    institution?: string
  ): Promise<string> {
    if (explicitValue && explicitValue.length > 0) {
      await this.setScopedVariable('config', key, explicitValue, institution);
      return explicitValue;
    }

    const storedValue = await this.getScopedVariable('config', key, institution);
    if (storedValue && storedValue.length > 0) {
      return storedValue;
    }

    if (fallbackValue !== undefined) {
      await this.setScopedVariable('config', key, fallbackValue, institution);
      return fallbackValue;
    }

    if (required) {
      throw new Error(`Missing required config value: ${key}. Pass it in this tool call or store it in Vault.`);
    }

    return '';
  }

  private getInstitutionPath(institution: string, scope: 'config' | 'credentials' | 'tokens'): string {
    return `${INSTITUTIONS_ROOT_PATH}/${this.normalizeInstitution(institution)}/${scope}`;
  }

  private normalizeInstitution(institution: string): string {
    return institution.trim().toLowerCase().replace(/[^a-z0-9_-]/g, '-');
  }

  private async setScopedVariable(
    scope: 'config' | 'credentials' | 'tokens',
    key: string,
    value: string,
    institution?: string
  ): Promise<void> {
    const generalPath = this.getGeneralPath(scope);
    if (institution && institution.length > 0) {
      await this.vault.setVariable(this.getInstitutionPath(institution, scope), key, value);
      if (scope === 'credentials') {
        await this.vault.setVariable(generalPath, key, value);
      }
      return;
    }

    await this.vault.setVariable(generalPath, key, value);
  }

  private async getScopedVariable(
    scope: 'config' | 'credentials' | 'tokens',
    key: string,
    institution?: string
  ): Promise<string | null> {
    if (institution && institution.length > 0) {
      const fromInstitution = await this.vault.getVariable(this.getInstitutionPath(institution, scope), key);
      if (fromInstitution) {
        return fromInstitution;
      }
    }

    return this.vault.getVariable(this.getGeneralPath(scope), key);
  }

  private getGeneralPath(scope: 'config' | 'credentials' | 'tokens'): string {
    if (scope === 'config') {
      return GENERAL_CONFIG_PATH;
    }
    if (scope === 'credentials') {
      return GENERAL_CREDENTIALS_PATH;
    }
    return GENERAL_TOKENS_PATH;
  }

  private async getBaseUrl(domain: ApiDomain, test: boolean): Promise<string> {
    await this.ensureUrlConfigLoaded();

    const mode = test ? 'sandbox' : 'live';
    const key = `${mode}_${domain}` as AkoyaUrlConfigKey;
    const value = this.urlConfigCache[key];
    if (!value) {
      throw new Error(`Missing URL configuration for ${key}.`);
    }

    return value.replace(/\/$/, '');
  }

  private async ensureUrlConfigLoaded(): Promise<void> {
    if (this.urlConfigLoaded) {
      return;
    }

    await this.ensureStartupSeedLoaded();

    for (const key of AKOYA_URL_KEYS) {
      const vaultValue = await this.vault.getVariable(GENERAL_CONFIG_PATH, key);
      if (vaultValue && vaultValue.length > 0) {
        this.urlConfigCache[key] = vaultValue;
        continue;
      }

      const envName = AKOYA_URL_ENV[key];
      const envValue = process.env[envName];
      const fallback = envValue && envValue.length > 0 ? envValue : DEFAULT_AKOYA_URLS[key];
      await this.vault.setVariable(GENERAL_CONFIG_PATH, key, fallback);
      this.urlConfigCache[key] = fallback;
    }

    this.urlConfigLoaded = true;
  }

  private async ensureStartupSeedLoaded(): Promise<void> {
    if (this.startupSeedLoaded) {
      return;
    }

    for (const key of AKOYA_GENERAL_CONFIG_KEYS) {
      await this.seedIfMissing(
        GENERAL_CONFIG_PATH,
        key,
        DEFAULT_AKOYA_GENERAL_CONFIG[key],
        AKOYA_GENERAL_CONFIG_ENV[key]
      );
    }

    for (const key of AKOYA_CREDENTIAL_KEYS) {
      await this.seedIfMissing(
        GENERAL_CREDENTIALS_PATH,
        key,
        DEFAULT_AKOYA_CREDENTIALS[key],
        AKOYA_CREDENTIAL_ENV[key]
      );
    }

    for (const key of AKOYA_TOKEN_KEYS) {
      await this.seedIfMissing(
        GENERAL_TOKENS_PATH,
        key,
        DEFAULT_AKOYA_TOKENS[key],
        AKOYA_TOKEN_ENV[key]
      );
    }

    this.startupSeedLoaded = true;
  }

  private async seedIfMissing(
    secretPath: string,
    key: AkoyaGeneralConfigKey | AkoyaCredentialKey | AkoyaTokenKey,
    defaultValue: string,
    envName: string | null
  ): Promise<void> {
    const existing = await this.vault.getVariable(secretPath, key);
    if (existing !== null) {
      return;
    }

    const envValue = envName ? process.env[envName] : undefined;
    const value = envValue && envValue.length > 0 ? envValue : defaultValue;
    await this.vault.setVariable(secretPath, key, value);
  }

  private async request(options: RequestOptions): Promise<unknown> {
    const baseUrl = await this.getBaseUrl(options.domain, options.test ?? false);
    const params = new URLSearchParams();
    if (options.query) {
      for (const [key, value] of Object.entries(options.query)) {
        if (value !== undefined && value !== null && value !== '') {
          params.append(key, String(value));
        }
      }
    }

    const queryString = params.toString();
    const url = `${baseUrl}${options.path}${queryString ? `?${queryString}` : ''}`;

    const headers: Record<string, string> = {
      accept: 'application/json',
      ...(options.headers ?? {})
    };

    let body: string | undefined;
    if (options.formBody) {
      const form = new URLSearchParams();
      for (const [key, value] of Object.entries(options.formBody)) {
        if (value !== undefined) {
          form.append(key, value);
        }
      }
      body = form.toString();
      headers['content-type'] = 'application/x-www-form-urlencoded';
    }

    if (options.jsonBody !== undefined) {
      body = JSON.stringify(options.jsonBody);
      headers['content-type'] = 'application/json';
    }

    if (options.bearerToken) {
      headers.authorization = `Bearer ${options.bearerToken}`;
    }

    const response = await fetch(url, {
      method: options.method,
      headers,
      body
    });

    const parseAs = options.parseAs ?? 'json';
    const responseHeaders = Object.fromEntries(response.headers.entries());

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Akoya request failed (${response.status}) ${options.method} ${url}: ${errorText || response.statusText}`);
    }

    if (response.status === 204) {
      return {
        ok: true,
        status: response.status,
        headers: responseHeaders
      };
    }

    if (parseAs === 'binary') {
      const bytes = Buffer.from(await response.arrayBuffer());
      return {
        ok: true,
        status: response.status,
        headers: responseHeaders,
        contentType: response.headers.get('content-type') ?? null,
        dataBase64: bytes.toString('base64')
      };
    }

    if (parseAs === 'text') {
      const text = await response.text();
      return {
        ok: true,
        status: response.status,
        headers: responseHeaders,
        text
      };
    }

    const text = await response.text();
    if (!text) {
      return {
        ok: true,
        status: response.status,
        headers: responseHeaders,
        data: null
      };
    }

    return JSON.parse(text) as unknown;
  }
}

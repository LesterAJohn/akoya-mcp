export type AkoyaUrlConfigKey =
  | 'sandbox_idp'
  | 'live_idp'
  | 'sandbox_products'
  | 'live_products'
  | 'sandbox_serviceToken'
  | 'live_serviceToken'
  | 'sandbox_serviceApi'
  | 'live_serviceApi';

export type AkoyaGeneralConfigKey =
  | 'provider_id'
  | 'data_version'
  | 'management_version'
  | 'notifications_version'
  | 'consent_version'
  | 'redirect_uri'
  | 'recipient_id'
  | 'app_id'
  | 'account_id'
  | 'holding_id'
  | 'statement_id'
  | 'tax_form_id'
  | 'subscription_id'
  | 'consent_id';

export type AkoyaCredentialKey = 'client_id' | 'client_secret';

export type AkoyaTokenKey =
  | 'id_token'
  | 'refresh_token'
  | 'service_token'
  | 'service_scope'
  | 'token_type'
  | 'expires_in';

export const DEFAULT_AKOYA_URLS: Record<AkoyaUrlConfigKey, string> = {
  sandbox_idp: 'https://sandbox-idp.ddp.akoya.com',
  live_idp: 'https://idp.ddp.akoya.com',
  sandbox_products: 'https://sandbox-products.ddp.akoya.com',
  live_products: 'https://products.ddp.akoya.com',
  sandbox_serviceToken: 'https://sandbox-sts.ddp.akoya.com/oauth2',
  live_serviceToken: 'https://sts.ddp.akoya.com/oauth2',
  sandbox_serviceApi: 'https://sandbox-api.akoya.com',
  live_serviceApi: 'https://api.akoya.com'
};

export const AKOYA_URL_ENV: Record<AkoyaUrlConfigKey, string> = {
  sandbox_idp: 'AKOYA_SANDBOX_IDP_URL',
  live_idp: 'AKOYA_LIVE_IDP_URL',
  sandbox_products: 'AKOYA_SANDBOX_PRODUCTS_URL',
  live_products: 'AKOYA_LIVE_PRODUCTS_URL',
  sandbox_serviceToken: 'AKOYA_SANDBOX_STS_URL',
  live_serviceToken: 'AKOYA_LIVE_STS_URL',
  sandbox_serviceApi: 'AKOYA_SANDBOX_SERVICE_API_URL',
  live_serviceApi: 'AKOYA_LIVE_SERVICE_API_URL'
};

export const AKOYA_URL_KEYS: AkoyaUrlConfigKey[] = [
  'sandbox_idp',
  'live_idp',
  'sandbox_products',
  'live_products',
  'sandbox_serviceToken',
  'live_serviceToken',
  'sandbox_serviceApi',
  'live_serviceApi'
];

export const DEFAULT_AKOYA_GENERAL_CONFIG: Record<AkoyaGeneralConfigKey, string> = {
  provider_id: 'mikomo',
  data_version: 'v3',
  management_version: 'v2',
  notifications_version: 'v1',
  consent_version: 'v1',
  redirect_uri: '',
  recipient_id: '',
  app_id: '',
  account_id: '',
  holding_id: '',
  statement_id: '',
  tax_form_id: '',
  subscription_id: '',
  consent_id: ''
};

export const AKOYA_GENERAL_CONFIG_ENV: Record<AkoyaGeneralConfigKey, string | null> = {
  provider_id: 'AKOYA_PROVIDER_ID',
  data_version: 'AKOYA_DATA_VERSION',
  management_version: 'AKOYA_MANAGEMENT_VERSION',
  notifications_version: 'AKOYA_NOTIFICATIONS_VERSION',
  consent_version: 'AKOYA_CONSENT_VERSION',
  redirect_uri: 'AKOYA_REDIRECT_URI',
  recipient_id: 'AKOYA_RECIPIENT_ID',
  app_id: 'AKOYA_APP_ID',
  account_id: 'AKOYA_ACCOUNT_ID',
  holding_id: 'AKOYA_HOLDING_ID',
  statement_id: 'AKOYA_STATEMENT_ID',
  tax_form_id: 'AKOYA_TAX_FORM_ID',
  subscription_id: 'AKOYA_SUBSCRIPTION_ID',
  consent_id: 'AKOYA_CONSENT_ID'
};

export const AKOYA_GENERAL_CONFIG_KEYS: AkoyaGeneralConfigKey[] = [
  'provider_id',
  'data_version',
  'management_version',
  'notifications_version',
  'consent_version',
  'redirect_uri',
  'recipient_id',
  'app_id',
  'account_id',
  'holding_id',
  'statement_id',
  'tax_form_id',
  'subscription_id',
  'consent_id'
];

export const DEFAULT_AKOYA_CREDENTIALS: Record<AkoyaCredentialKey, string> = {
  client_id: '',
  client_secret: ''
};

export const AKOYA_CREDENTIAL_ENV: Record<AkoyaCredentialKey, string | null> = {
  client_id: 'AKOYA_CLIENT_ID',
  client_secret: 'AKOYA_CLIENT_SECRET'
};

export const AKOYA_CREDENTIAL_KEYS: AkoyaCredentialKey[] = ['client_id', 'client_secret'];

export const DEFAULT_AKOYA_TOKENS: Record<AkoyaTokenKey, string> = {
  id_token: '',
  refresh_token: '',
  service_token: '',
  service_scope: 'app_management_v2',
  token_type: 'bearer',
  expires_in: ''
};

export const AKOYA_TOKEN_ENV: Record<AkoyaTokenKey, string | null> = {
  id_token: 'AKOYA_ID_TOKEN',
  refresh_token: 'AKOYA_REFRESH_TOKEN',
  service_token: 'AKOYA_SERVICE_TOKEN',
  service_scope: 'AKOYA_SERVICE_SCOPE',
  token_type: null,
  expires_in: null
};

export const AKOYA_TOKEN_KEYS: AkoyaTokenKey[] = [
  'id_token',
  'refresh_token',
  'service_token',
  'service_scope',
  'token_type',
  'expires_in'
];

# akoya-mcp

MCP server for Akoya integrations with full endpoint coverage from the catalog in this repository, plus Vault-backed variable storage.

## Scope

This project maps all endpoints listed in the Akoya Endpoint Catalog section to MCP tools.

## Vault Variable Storage

This project supports two Vault provider modes selected by environment variable:

- `VAULT_PROVIDER=external` (default): Uses an external HashiCorp Vault instance.
- `VAULT_PROVIDER=internal`: Uses an in-memory Vault-like store inside the Node.js process with binary persistence.

Akoya values are stored in Vault with both institution-scoped and general paths:

- Institution-scoped paths (provider-separated):
	- `akoya/institutions/{institution}/config`
	- `akoya/institutions/{institution}/credentials`
	- `akoya/institutions/{institution}/tokens`
- General paths (shared across MCP/Akoya operations):
	- `akoya/general/config`
	- `akoya/general/credentials`
	- `akoya/general/tokens`

Akoya base URLs are managed as config items in `akoya/general/config` with Vault-first lookup:

- `sandbox_idp`
- `live_idp`
- `sandbox_products`
- `live_products`
- `sandbox_serviceToken`
- `live_serviceToken`
- `sandbox_serviceApi`
- `live_serviceApi`

Additional startup seed keys are also initialized into Vault when missing:

- General config (`akoya/general/config`):
	- `provider_id`, `data_version`, `management_version`, `notifications_version`, `consent_version`
	- `redirect_uri`, `recipient_id`, `app_id`, `account_id`, `holding_id`, `statement_id`, `tax_form_id`, `subscription_id`, `consent_id`
- Credentials (`akoya/general/credentials`):
	- `client_id`, `client_secret`
- Tokens (`akoya/general/tokens`):
	- `id_token`, `refresh_token`, `service_token`, `service_scope`, `token_type`, `expires_in`

Behavior:

- Hydration order for startup config items is: environment variable -> Vault -> configuration file defaults.
- If an environment value is present, it is used and written to Vault.
- If no environment value exists, the server uses Vault.
- If Vault is missing the key, the server seeds from configuration file defaults.
- This works the same for both internal and external Vault providers.

### Internal Vault Environment Variables

- `VAULT_INTERNAL_BINARY_PATH` (optional, default `./.vault-internal.bin`): Binary snapshot file loaded on startup and updated by exports.
- `VAULT_EXPORT_INTERVAL_SECONDS` (optional, default `900`): Automatic export interval for internal Vault snapshots.

### External Vault Environment Variables

- `VAULT_ADDR`: External Vault base URL (for example, `http://127.0.0.1:8200`).
- `VAULT_TOKEN`: Vault token used for API requests.
- `VAULT_NAMESPACE` (optional): Vault namespace header.
- `VAULT_KV_MOUNT` (optional, default `secret`): KV mount path.
- `VAULT_KV_VERSION` (optional, default `2`): `1` or `2`.

### MCP Tools

- `akoya_connection_info`: Returns Akoya and Vault configuration status.
- `akoya_oauth_create_state`: Generates a one-time OAuth state value and stores it in Vault for CSRF checks.
- `akoya_oauth_validate_state`: Validates (and optionally consumes) a stored OAuth state.
- `akoya_auth_url`: Builds Akoya OAuth authorization URL (`/auth`).
- `akoya_token_exchange`: Exchanges authorization code for tokens; supports optional per-user token storage.
- `akoya_refresh_token`: Refreshes tokens; can read/write user-scoped refresh/id tokens.
- `akoya_revoke_refresh_token`: Revokes refresh token (`/revoke`).
- `akoya_service_token`: Requests service token (`/oauth2/token`).
- `akoya_account_info`: Calls account information endpoint.
- `akoya_accounts`: Calls Akoya investments accounts endpoint.
- `akoya_balances`: Calls Akoya balances endpoint.
- `akoya_transactions`: Calls Akoya transactions endpoint.
- `akoya_taxlots`: Calls Akoya taxlots endpoint.
- `akoya_customer_info`: Calls Akoya customer information endpoint.
- `akoya_account_holder_info`: Calls Akoya account holder information endpoint.
- `akoya_payments`: Calls Akoya payments endpoint.
- `akoya_statement_list`: Calls Akoya statement list endpoint.
- `akoya_statement`: Calls Akoya statement retrieval endpoint.
- `akoya_search_tax_forms`: Calls Akoya search tax forms endpoint.
- `akoya_retrieve_tax_form`: Calls Akoya retrieve tax form endpoint.
- `akoya_create_app`: Calls create app endpoint.
- `akoya_update_app`: Calls update app endpoint.
- `akoya_get_all_apps`: Calls get all apps endpoint.
- `akoya_get_purchased_products`: Calls get purchased products endpoint.
- `akoya_get_valid_providers_for_products`: Calls get valid providers for products endpoint.
- `akoya_get_subscriptions_for_app`: Calls get subscriptions for app endpoint.
- `akoya_list_notification_subscriptions`: Calls list notification subscriptions endpoint.
- `akoya_create_notification_subscription`: Calls create notification subscription endpoint.
- `akoya_get_notification_subscription_by_id`: Calls get notification subscription by id endpoint.
- `akoya_update_notification_subscription`: Calls update notification subscription endpoint.
- `akoya_delete_notification_subscription`: Calls delete notification subscription endpoint.
- `akoya_send_sandbox_test_event`: Calls sandbox test event endpoint.
- `akoya_consent_grant`: Calls Akoya consent grant endpoint.
- `vault_connection_info`: Returns Vault provider and connection details, including startup import status and restored internal secret-path count.
- `vault_set_variable`: Stores a value at `secretPath` + `key`.
- `vault_get_variable`: Reads a value at `secretPath` + `key` (masked by default; plaintext only if sensitive output is explicitly enabled).
- `vault_list_variables`: Lists stored keys at a path.
- `vault_delete_variable`: Deletes a key at a path.

Sensitive output controls:

- `MCP_ALLOW_SENSITIVE_OUTPUT` (optional, default `false`)
- When `false`, token-exchange and refresh tools return token fields redacted, and `vault_get_variable` does not return plaintext values even if `revealValue=true`.
- When `true`, sensitive values are included in tool responses. Use only in trusted local/operator-controlled contexts.

User-scoped OAuth tokens are stored under:

- `akoya/users/{userId}/providers/{providerId}/tokens`

## Akoya Endpoint Catalog

Use `test=true` to target Akoya sandbox endpoints. When `test=false` (or omitted), calls are treated as live.

### Authentication APIs

- POST `/token` (IDP): Obtain tokens (`authorization_code`) and refresh tokens (`refresh_token`)
- POST `/revoke` (IDP): Revoke refresh token
- POST `/oauth2/token` (STS): Obtain service token (`client_credentials`)
- GET `/auth` (IDP): Authorization URL entrypoint (browser redirect flow)

### Data APIs

- GET `/accounts-info/{version}/{providerId}`: Account Information
- GET `/balances/{version}/{providerId}`: Balances
- GET `/transactions/{version}/{providerId}/{accountId}`: Transactions
- GET `/accounts/{version}/{providerId}`: Investments Accounts
- GET `/taxlots/{version}/{providerId}/{accountId}/{holdingId}`: Taxlots
- GET `/customers/{version}/{providerId}/current`: Customer Information
- GET `/contacts/{version}/{providerId}/{accountId}`: Account Holder Information
- GET `/payments/{version}/{providerId}/{accountId}/payment-networks`: Payments
- GET `/statements/{version}/{providerId}/{accountId}`: Statement List
- GET `/statements/{version}/{providerId}/{accountId}/{statementId}`: Statement (PDF or JSON if supported)
- GET `/tax-forms/{version}/{providerId}`: Search Tax Forms
- GET `/tax-forms/{version}/{providerId}/{taxFormId}`: Retrieve Tax Form

### Service APIs

#### Apps Management

- POST `/manage/{version}/apps/register`: Create App
- PATCH `/manage/{version}/recipients/{recipientId}/apps/{appId}`: Update App
- GET `/manage/{version}/recipients/{recipientId}/apps`: Get All Apps
- GET `/manage/{version}/recipients/{recipientId}/products`: Get Purchased Products
- GET `/manage/{version}/recipients/{recipientId}/providers`: Get Valid Providers For Products
- GET `/manage/{version}/subscriptions/{appId}`: Get Subscriptions For App
- GET `/manage/{version}/subscriptions/{appId}/status`: Get Subscriptions For App (filter by status)

#### Notifications

- GET `/notifications/{version}/subscriptions`: List Notification Subscriptions
- POST `/notifications/{version}/subscriptions`: Create Notification Subscription
- GET `/notifications/{version}/subscriptions/{subscriptionId}`: Get Notification Subscription By Id
- PATCH `/notifications/{version}/subscriptions/{subscriptionId}`: Update Notification Subscription
- DELETE `/notifications/{version}/subscriptions/{subscriptionId}`: Delete Notification Subscription
- POST `/notifications/{version}/test`: Send Sandbox Test Event

#### Consent

- GET `/consents/{version}/{consentId}`: Get Consent Grant

## Startup

### NPM

1. Install dependencies:

```bash
npm install
```

2. Run in development mode (watch):

```bash
npm run dev
```

3. Or build and run production:

```bash
npm run build
npm run start
```

4. Optional type-check:

```bash
npm run check
```

### Docker (Compose)

Use this `docker-compose.yml` to run with internal Vault persistence.

Important: this server uses stdio transport (`serveStdio`), not HTTP. Do not expose port `3000` unless you add a separate HTTP/SSE/streamable-HTTP wrapper process.

```yaml
version: "3.9"

services:
	akoya-mcp:
		image: node:22-alpine
		container_name: akoya-mcp
		working_dir: /app
		command: sh -c "npm install && npm run dev"
		volumes:
			- ./:/app
		environment:
			VAULT_PROVIDER: internal
			VAULT_INTERNAL_BINARY_PATH: /data/.vault-internal.bin
			VAULT_EXPORT_INTERVAL_SECONDS: "900"
			AKOYA_PROVIDER_ID: mikomo
			AKOYA_DATA_VERSION: v3
			AKOYA_MANAGEMENT_VERSION: v2
			AKOYA_NOTIFICATIONS_VERSION: v1
			AKOYA_CONSENT_VERSION: v1
		stdin_open: true
		tty: true
		restart: unless-stopped
```

Start with:

```bash
docker compose up
```

## Testing

Run the emulated Akoya test suite (no live Akoya dependency):

```bash
npm test
```

Watch mode:

```bash
npm run test:watch
```

Run MCP tool integration tests using in-process MCP transport:

```bash
npm run test:mcp
```

What it validates:

- MCP service-side Akoya request flow without external connectivity.
- Startup hydration precedence (`env -> vault -> configuration defaults`).
- Institution-scoped token separation.
- Token refresh persistence into institution Vault paths.
- URL resolution and Vault seeding behavior.
- MCP `tools/list` and `tools/call` behavior for registered tools.

## OAuth Integration Notes

- This MCP server does not host OAuth callback routes because it runs over stdio.
- OpenWebUI or another host app must own the browser redirect, callback endpoint, and session lifecycle.
- Use `akoya_oauth_create_state` before redirect and `akoya_oauth_validate_state` on callback to enforce state checks.
- Use `akoya_token_exchange` and `akoya_refresh_token` with `userId` to keep token lifecycles separated per user/provider.
- Use `akoya_consent_grant` to fetch consent details after consent completion in the host app.
- Keep `MCP_ALLOW_SENSITIVE_OUTPUT=false` for autonomous LLM tool execution unless strict policy guardrails and runtime approvals are in place.

## Action Log

- 2026-07-03: Added Node.js Vault service for variable storage.
- 2026-07-03: Added `VAULT_PROVIDER` mode switch to use `internal` or `external` Vault.
- 2026-07-03: Added MCP Vault tools and documented setup and usage.
- 2026-07-03: Added internal Vault binary import-on-startup and periodic export via `VAULT_EXPORT_INTERVAL_SECONDS` (default 900).
- 2026-07-03: Added startup import status and restored-path count to Vault connection info output.
- 2026-07-03: Updated Akoya Vault storage to namespace keys/tokens by institution while retaining shared general Vault paths.
- 2026-07-03: Added Akoya endpoint catalog to README for Authentication, Data, Service, Notifications, and Consent APIs.
- 2026-07-03: Added Akoya URL config seeding with Vault-first resolution and fallback from env/default config file.
- 2026-07-03: Added startup seed defaults for Akoya general config keys, credentials, and tokens when missing in Vault.
- 2026-07-03: Added startup section with npm commands and Docker Compose YAML example.
- 2026-07-03: Updated startup hydration order to environment variable -> Vault -> configuration file defaults.
- 2026-07-03: Added emulated Akoya test suite and npm test scripts for no-live-connection validation.
- 2026-07-03: Added MCP stdio integration tests for tool listing and tool execution behavior.
- 2026-07-03: Exposed Akoya auth/data consent tools (`akoya_auth_url`, `akoya_token_exchange`, `akoya_refresh_token`, `akoya_accounts`, `akoya_balances`, `akoya_transactions`, `akoya_consent_grant`) and added OAuth state/user-token guidance for host apps.
- 2026-07-03: Clarified focused MCP scope (transaction/account workflows) and added sensitive-output guardrail (`MCP_ALLOW_SENSITIVE_OUTPUT`) for token/secret exposure.
- 2026-07-03: Expanded MCP tool registration to full Akoya endpoint catalog coverage across auth, data, apps management, notifications, and consent APIs.


# akoya-mcp

MCP server for Akoya integrations with Vault-backed variable storage.

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
- `vault_connection_info`: Returns Vault provider and connection details, including startup import status and restored internal secret-path count.
- `vault_set_variable`: Stores a value at `secretPath` + `key`.
- `vault_get_variable`: Reads a value at `secretPath` + `key` (masked unless `revealValue=true`).
- `vault_list_variables`: Lists stored keys at a path.
- `vault_delete_variable`: Deletes a key at a path.

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

Use this `docker-compose.yml` to run with internal Vault persistence:

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
		ports:
			- "3000:3000"
		stdin_open: true
		tty: true
		restart: unless-stopped
```

Start with:

```bash
docker compose up
```

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


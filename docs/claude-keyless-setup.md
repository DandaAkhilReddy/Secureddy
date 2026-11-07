# Claude without an API key (Workload Identity Federation)

Secureddy can call Claude with no API key stored anywhere. Each Container App
already has a managed identity in Microsoft Entra. Anthropic trusts that
identity, and trades a short-lived Entra token for a short-lived Claude token.
If someone stole every file and secret we have, there would be no Claude key
to steal.

How it works at run time (`src/reddysec/core/anthropic_auth.py`):

1. The app asks its managed identity for an Entra token for our audience
   (`$IDENTITY_ENDPOINT?api-version=2019-08-01&resource=api://5c08b3d9-…&client_id=<identity>`).
2. It posts that token to `https://api.anthropic.com/v1/oauth/token`
   (`grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer`) with our
   federation rule, organization and service account ids.
3. Anthropic checks the token against the rule and returns an access token
   (`sk-ant-oat01-…`) that lives about an hour. The app keeps it in memory,
   sends it as `Authorization: Bearer`, and gets a new one two minutes before
   it expires.

## Our values

| What | Value |
|------|-------|
| Entra tenant | `76596b76-3c41-40ee-a8a3-bf6930301838` |
| Issuer URL | `https://login.microsoftonline.com/76596b76-3c41-40ee-a8a3-bf6930301838/v2.0` |
| Audience (Entra app id) | `5c08b3d9-f257-4add-b919-e10afac41f5b` (identifier URI `api://5c08b3d9-f257-4add-b919-e10afac41f5b`, v2 tokens) |
| Web app identity | object id `b23f7370-c676-4a3f-841d-b373254ade5f`, client id `3fe1eeb3-c455-427c-ac16-0720d8d783ed` |
| Worker identity | object id `f8348ccf-aa65-4daf-a3d7-8efb25822427`, client id `8cda4cf9-7b1a-49b8-be2c-b0b91a51f7ad` |

These are identifiers, not secrets. They can sit in the repository.

## Steps in the Claude Console

Sign in to the Claude Console as an organization admin, then open
**Settings → Workload identity**.

1. **Add an issuer.** Choose the **Microsoft Entra ID** tile.
   - Issuer URL: `https://login.microsoftonline.com/76596b76-3c41-40ee-a8a3-bf6930301838/v2.0`
     (exactly this, no trailing slash; it must match the token's `iss`).
   - Token version: **v2.0**.
   - Keys: **Discovery** (the console reads Entra's public keys itself).
   - Maximum JWT lifetime: **86400** seconds (managed-identity tokens can
     live up to 24 hours).
   - Save.
2. **Create a service account** (**Service accounts → New**), for example
   `secureddy-prod`. Copy its id (`svac_…`).
3. **Create a workspace** for Secureddy if you do not have one
   (**Workspaces → New**, for example `secureddy`). Copy its id (`wrkspc_…`).
   Give it a monthly spend limit you are comfortable with.
4. **Create the rule for the web app** (**Federation rules → New**):
   - Issuer: the one from step 1.
   - Match → Audience: `5c08b3d9-f257-4add-b919-e10afac41f5b`
     (v2 tokens carry the app id, not the `api://` URI, in `aud`).
   - Match → Claims: `oid` = `b23f7370-c676-4a3f-841d-b373254ade5f` and
     `tid` = `76596b76-3c41-40ee-a8a3-bf6930301838`.
   - Service account: the one from step 2. Scope: `workspace:inference`.
   - Workspace: the one from step 3. Token lifetime: 3600.
   - Save and copy the rule id (`fdrl_…`).
5. **Create the rule for the worker**: the same as step 4, with
   `oid` = `f8348ccf-aa65-4daf-a3d7-8efb25822427`. Copy its rule id.
6. Copy your **organization id** (Settings → Organization; a UUID).

## Steps in this repository

Put the ids in `infra/azure/main.dev.bicepparam` (or `main.prod.bicepparam`):

```bicep
param anthropicWifAudience = 'api://5c08b3d9-f257-4add-b919-e10afac41f5b'
param anthropicWebFederationRuleId = 'fdrl_...'
param anthropicWorkerFederationRuleId = 'fdrl_...'
param anthropicOrganizationId = '<organization uuid>'
param anthropicServiceAccountId = 'svac_...'
param anthropicWorkspaceId = 'wrkspc_...'
```

Deploy as usual. Each app gets `RS_ANTHROPIC_FEDERATION_RULE_ID` (its own
rule), `RS_ANTHROPIC_ORGANIZATION_ID`, `RS_ANTHROPIC_SERVICE_ACCOUNT_ID`,
`RS_ANTHROPIC_WORKSPACE_ID`, `RS_ANTHROPIC_WIF_AUDIENCE` and
`RS_AZURE_IDENTITY_CLIENT_ID` (its identity's client id) as plain environment
variables.

When these are set, keyless is used even if an API key is also present.

## Check it works

1. Open **Ask Secureddy** and ask "Show me the most suspicious emails". You
   should get an answer with a list of emails.
2. In Log Analytics, look for `anthropic.token_exchanged` from the web app.
   If you see `assistant_llm_auth_failed` instead, its message names the
   problem (for example `HTTP 401 invalid_grant (check the federation rule's
   audience and claims)`). The Console's **Workload identity → Authentication
   events** page shows which claim did not match.

## Remove the static key afterwards

Once the assistant has answered with keyless auth:

1. Set `param anthropicEnabled = false` in the bicepparam file and deploy.
   The apps stop receiving `RS_ANTHROPIC_API_KEY`.
2. Delete the Key Vault secret: `az keyvault secret delete --vault-name <vault> --name rs-anthropic-api-key`
   (and purge it after the soft-delete period if you want it gone at once).
3. In the Claude Console, **API keys**: disable, then delete, the old key.
4. Until then the app logs `anthropic.static_api_key_in_use` once at start-up
   as a reminder.

## Background reviewer

The fraud second opinion (`analysis/bec.py`) still sends its own `x-api-key`.
Switching it to `get_anthropic_auth_headers()` from
`reddysec.core.anthropic_auth` makes it keyless too; until then keep the key
only if you use `RS_LLM_PROVIDER=anthropic`.

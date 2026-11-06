# Deploying Secureddy on Azure

Everything is in `infra/azure`. One Bicep entry point (`main.bicep`), one
parameter file per environment, one bootstrap script. Region: West US 2.

```
                 Internet
                    |
          Azure Front Door Premium  (WAF: DRS 2.1, bot manager, rate limit, managed TLS)
                    |  Private Link
   +----------------v-----------------------------------------------------+
   | VNet 10.40.0.0/16                                                     |
   |  apps 10.40.0.0/23  Container Apps env (internal)                     |
   |     web x2  --- worker x1-3 --- deadman x1       --> NAT (1 IP) ----> Google/IMAP
   |  data 10.40.2.0/24  private endpoints: Key Vault, Blob, Postgres, ACR |
   |  detonation 10.40.8.0/22  ACI container group per detonation          |
   |     NSG: deny RFC1918 + IMDS, allow 80/443/53 out, 443 to ACR PE only |
   |                                                 --> NAT (2 IPs) ----> phishing sites
   +-----------------------------------------------------------------------+
   Service Bus (Standard, Entra auth)   Log Analytics + App Insights   Azure Policy on the detonation RG
```

Two resource groups: `rg-secureddy-<env>` (everything) and
`rg-secureddy-<env>-detonations` (empty; container groups come and go).

## Prerequisites

- Azure subscription where you are **Owner** (role assignments and a policy
  definition at subscription scope are part of the deployment).
- Azure CLI 2.60+ (`az version`), `openssl`, `curl`, `python3`, `git`. No local
  Docker: images build in ACR.
- Quotas in the region: 2 Standard public IPs + 1 NAT gateway are fine by
  default. **ACI**: default is 100 container groups per region per subscription
  and a per-subscription core limit; request more before client 20
  (`operations-runbook.md`).
- Resource providers registered once per subscription:

      az provider register -n Microsoft.App -n Microsoft.ContainerInstance -n Microsoft.Cdn \
        -n Microsoft.DBforPostgreSQL -n Microsoft.ServiceBus -n Microsoft.ContainerRegistry \
        -n Microsoft.OperationalInsights -n Microsoft.Insights -n Microsoft.KeyVault \
        -n Microsoft.Network -n Microsoft.PolicyInsights

- A domain you control (for `app.<domain>`), and the Google OAuth client
  (`google-oauth-setup.md`). Both can come after the first deployment.

## 1. Edit the parameter file

`infra/azure/main.prod.bicepparam` (or `main.dev.bicepparam`). Lines marked
`// CHANGE`:

| Parameter | What to put |
|-----------|-------------|
| `baseUrl`, `customDomain` | `https://app.<domain>` and `app.<domain>`. Leave `customDomain = ''` on the first run if DNS is not ready; the `*.azurefd.net` host works meanwhile. |
| `keyVaultName`, `storageAccountName`, `acrName`, `postgresServerName`, `serviceBusNamespaceName` | globally unique names, or `''` to derive them |
| `googleClientId`, `googlePubsubTopic` | from the GCP project (can be empty at first) |
| `alertEmails`, `notificationFrom` | your addresses |
| `githubRepository` | `owner/repo` to enable OIDC deploys |
| `monthlyBudgetUsd` | budget alert threshold |

## 2. Bootstrap

    infra/azure/bootstrap.sh prod

It asks once to confirm the subscription, then runs for 25-40 minutes the first
time (Front Door and Postgres HA are slow). What happens:

1. Creates both resource groups.
2. **Stage 1** deployment (`deployApps=false`): network, identities, Key Vault
   (your public IP allowed), Postgres, Storage, Service Bus, ACR, policy
   definitions + assignments, Log Analytics.
3. Seeds Key Vault secrets that do not exist yet. Existing values are never
   overwritten:

   | Secret | Source |
   |--------|--------|
   | `rs-token-kek` | `openssl rand -base64 32` |
   | `rs-secret-key` | `openssl rand -base64 48` |
   | `rs-pubsub-token` | `openssl rand -hex 24` |
   | `postgres-admin-password` | `openssl rand -hex 24` |
   | `rs-database-url` | composed: `postgresql+asyncpg://rsadmin:<pw>@<fqdn>:5432/reddysec?ssl=require` |
   | `rs-google-client-secret` | prompted; placeholder `not-configured` if skipped |
   | `acr-chamber-pull-password` | `az acr token credential generate` (1-year expiry; see runbook) |

4. Builds `reddysec-app` and `reddysec-chamber` in ACR (`az acr build`).
5. **Stage 2** deployment (`deployApps=true`): Container Apps, Front Door, alerts.
6. Approves the Front Door private endpoint connection on the Container Apps
   environment.
7. Prints DNS records, egress IPs and the GitHub OIDC values.

Re-running is safe. `--skip-images` skips the ACR builds; `--lockdown` removes
your IP from Key Vault once you are done writing secrets.

## 3. DNS and Front Door

From the bootstrap output:

    CNAME  app.<domain>            ->  rsec-prod-edge-xxxx.z01.azurefd.net
    TXT    _dnsauth.app.<domain>   ->  <validation token>

Front Door validates the TXT record, then issues a managed certificate (5-20
minutes). Check:

    az afd custom-domain list -g rg-secureddy-prod --profile-name rsec-prod-afd \
      --query "[].{host:hostName,validation:domainValidationState,cert:tlsSettings.certificateType}" -o table

Until `domainValidationState` is `Approved` the domain returns a Front Door
error page; the `*.azurefd.net` endpoint works the whole time.

Apex domains (`<domain>` without `app.`) need an ALIAS/ANAME record; most
registrars do not offer one. Use a subdomain.

The web app is only reachable through Front Door. Optional hardening in the
app: reject requests whose `X-Azure-FDID` header is not the `frontDoorId`
output.

## 4. First admin user

The CLI creates the first account; after that admins invite users from the
dashboard. Run it inside the web container (it has the database URL and Key
Vault access):

    az containerapp exec -g rg-secureddy-prod -n rsec-prod-web \
      --command "reddysec add-user --email you@example.com --name 'Reddy' --role admin"

Then sign in with Google using that address. Other roles: `principal`
(a client), `family`, `assistant`, `concierge`. IMAP mailboxes can also be
attached from the CLI (`reddysec add-imap-mailbox --help`).

## 5. Verify the detonation network

Start a throwaway container group in the detonation resource group, in the
detonation subnet, with the chamber image (it has python, no curl), and probe
from inside:

    SUBNET=$(az deployment group show -g rg-secureddy-prod -n rsec-prod-stage2 --query properties.outputs.detonationSubnetId.value -o tsv)
    ACR=$(az deployment group show -g rg-secureddy-prod -n rsec-prod-stage2 --query properties.outputs.acrLoginServer.value -o tsv)
    KV=$(az deployment group show -g rg-secureddy-prod -n rsec-prod-stage2 --query properties.outputs.keyVaultName.value -o tsv)
    PW=$(az keyvault secret show --vault-name $KV --name acr-chamber-pull-password --query value -o tsv)

    az container create -g rg-secureddy-prod-detonations -n nsg-probe \
      --image $ACR/reddysec-chamber:latest --registry-login-server $ACR \
      --registry-username chamber-pull --registry-password "$PW" \
      --subnet $SUBNET --restart-policy Never --cpu 1 --memory 1 --os-type Linux \
      --command-line "/opt/venv/bin/python -c \"
    import socket, urllib.request
    def tcp(h, p, t=4):
        s = socket.socket(); s.settimeout(t)
        try: s.connect((h, p)); return 'OPEN'
        except Exception as e: return 'blocked: %s' % type(e).__name__
        finally: s.close()
    print('10.40.0.4:443 (apps)  ', tcp('10.40.0.4', 443))
    print('10.40.2.4:443 (data)  ', tcp('10.40.2.4', 443))
    print('169.254.169.254:80    ', tcp('169.254.169.254', 80))
    print('1.1.1.1:443 (internet)', tcp('1.1.1.1', 443))
    print('1.1.1.1:22  (ssh)     ', tcp('1.1.1.1', 22))
    print('egress IP:', urllib.request.urlopen('https://api.ipify.org', timeout=10).read().decode())
    \""
    az container logs -g rg-secureddy-prod-detonations -n nsg-probe
    az container delete -g rg-secureddy-prod-detonations -n nsg-probe --yes

Expected: everything private `blocked: timeout`, `1.1.1.1:443 OPEN`,
`1.1.1.1:22 blocked`, and the egress IP equal to one of the two
`detonationEgressIps`. The policy assignments also mean this command fails if
you add `--ip-address Public` or `--assign-identity`; that is the test of the
policy.

## 6. Detonation container group (what the worker creates)

`chamber/backends/azure_aci.py` builds this and sends it with
`azure-mgmt-containerinstance`, authenticated as the worker's managed identity
(`AZURE_CLIENT_ID`). The environment it reads: `RS_ACI_SUBSCRIPTION_ID`,
`RS_ACI_RESOURCE_GROUP`, `RS_ACI_LOCATION`, `RS_ACI_SUBNET_ID`,
`RS_CHAMBER_IMAGE`. The template sets all of them on the worker app.

```json
{
  "location": "westus2",
  "tags": { "reddysec": "detonation", "job_id": "<job_id>" },
  "properties": {
    "osType": "Linux",
    "sku": "Standard",
    "restartPolicy": "Never",
    "subnetIds": [ { "id": "<RS_ACI_SUBNET_ID>" } ],
    "volumes": [ { "name": "work", "emptyDir": {} } ],
    "imageRegistryCredentials": [
      { "server": "<RS_ACI_REGISTRY_SERVER>", "username": "<RS_ACI_REGISTRY_USERNAME>", "password": "<RS_ACI_REGISTRY_PASSWORD>" }
    ],
    "containers": [
      {
        "name": "chamber",
        "properties": {
          "image": "<RS_CHAMBER_IMAGE>",
          "command": [ "python", "-m", "reddysec.chamber.detonate", "--env", "--workdir", "/work", "--max-file-bytes", "..." ],
          "environmentVariables": [
            { "name": "RS_JOB", "secureValue": "<job envelope JSON>" },
            { "name": "RS_CHAMBER", "value": "1" }
          ],
          "resources": { "requests": { "cpu": 1.5, "memoryInGB": 2 } },
          "volumeMounts": [ { "name": "work", "mountPath": "/work" } ]
        }
      }
    ]
  }
}
```

`imageRegistryCredentials` is the one block the backend does not send yet. The
registry has no admin user and no anonymous pull, and Azure Policy forbids a
managed identity on the group, so the pull must use the repository-scoped
token: the template puts it on the worker as `RS_ACI_REGISTRY_SERVER`,
`RS_ACI_REGISTRY_USERNAME` (`chamber-pull`) and `RS_ACI_REGISTRY_PASSWORD`
(Key Vault `acr-chamber-pull-password`). Until `build_group_spec` adds the
block, container groups fail with an image pull error.

Rules the worker follows (the policies in `aci-detonation.bicep` enforce the
first four): no `ipAddress` (no public IP); `restartPolicy: Never`; a
`subnetIds` entry; no `identity`; the job travels in `secureValue`, never in
logs or the portal; nothing in the job identifies the client
(`models/jobs.py`); the result is read from the container's stdout through the
logs API, then the group is deleted, always. Groups older than 15 minutes with
tag `reddysec=detonation` are leftovers: delete them (runbook, section 2).

ACI start-up (schedule + pull of a ~1 GB image) adds 20-60 s to a detonation;
`RS_DETONATION_TIMEOUT_S` (45) is the browser budget only.

## 6a. What the template hands the application

Environment variables on web, worker and deadman. `config.py` ignores names it
does not know (`extra="ignore"`), so the ones marked *ready* are harmless until
the code reads them.

| Variable | Value | Status |
|----------|-------|--------|
| `RS_ENV`, `RS_BASE_URL`, `RS_LOG_LEVEL` | `prod`, `https://app.<domain>`, `INFO` | used |
| `RS_SECRET_KEY`, `RS_TOKEN_KEK`, `RS_DATABASE_URL`, `RS_GOOGLE_CLIENT_ID`, `RS_GOOGLE_CLIENT_SECRET`, `RS_GOOGLE_PUBSUB_TOPIC` | Key Vault references / params | used |
| `RS_SANDBOX_BACKEND=aci`, `RS_ACI_SUBSCRIPTION_ID`, `RS_ACI_RESOURCE_GROUP`, `RS_ACI_LOCATION`, `RS_ACI_SUBNET_ID`, `RS_CHAMBER_IMAGE` | worker only | used by `chamber/backends` |
| `RS_ACI_REGISTRY_SERVER`, `RS_ACI_REGISTRY_USERNAME`, `RS_ACI_REGISTRY_PASSWORD` | worker only, pull token for the chamber image | ready (section 6) |
| `AZURE_CLIENT_ID` | the app's user-assigned identity client id | used by `DefaultAzureCredential` |
| `RS_PUBSUB_TOKEN` | shared token in the Gmail push URL | ready |
| `RS_STORAGE_ACCOUNT_URL`, `RS_ARTIFACTS_CONTAINER`, `RS_QUARANTINE_CONTAINER` | `https://<account>.blob.core.windows.net`, `artifacts`, `quarantine-originals` | ready: there is no Blob `ArtifactStore` yet |
| `RS_SERVICEBUS_NAMESPACE`, `RS_SERVICEBUS_QUEUE_DETONATIONS`, `RS_SERVICEBUS_QUEUE_NOTIFICATIONS` | `<ns>.servicebus.windows.net`, `detonations`, `notifications` | ready: no Service Bus `JobQueue` yet |
| `RS_HOLD_DEAD_MAN_MINUTES`, `RS_DETONATION_TIMEOUT_S`, `RS_DETONATION_MAX_CONCURRENCY`, `RS_INTEL_ONLINE=true`, `RS_DEV_LOGIN_ENABLED=false` | from the bicepparam | used |
| `RS_TOKEN_KEK_PREVIOUS` | only during a KEK rotation (section 7) | ready |
| `APPLICATIONINSIGHTS_CONNECTION_STRING` | workspace-based App Insights | ready |

Two consequences until the *ready* pieces land in `src/`:

- Artifacts (screenshots, sanitized files) are written by `LocalArtifactStore`
  to `RS_ARTIFACTS_DIR` inside the replica that produced them. Replicas do not
  share a disk, so the dashboard (web) cannot show a screenshot the worker
  took. Fix: a Blob-backed `ArtifactStore` using the three `RS_STORAGE_*`
  variables and the identities' Blob Data Contributor role. Stop-gap if needed
  sooner: an NFS Azure Files share mounted into all three apps at
  `/var/lib/reddysec/artifacts` (Premium FileStorage account + environment
  storage; not in this template).
- The worker's queue-length scale rule watches the `detonations` queue; while
  nothing publishes to it the worker simply stays at `workerMinReplicas`.

## 7. Rotating RS_TOKEN_KEK (dual-key window)

Ciphertexts carry a key id (`v1.<kid>.<data>`, `core/crypto.py`), so rotation
is: add the new key as current, keep the old one for reads, re-encrypt, drop
the old one.

1. New key version in Key Vault (the old version stays readable):

       OLD_VER=$(az keyvault secret show --vault-name $KV --name rs-token-kek --query id -o tsv | awk -F/ '{print $NF}')
       az keyvault secret set --vault-name $KV --name rs-token-kek --value "$(openssl rand -base64 32)" -o none

2. Deploy with the old version pinned as the previous key. The apps receive
   `RS_TOKEN_KEK` (latest) and `RS_TOKEN_KEK_PREVIOUS` (pinned):

       az deployment group create -g rg-secureddy-prod --template-file infra/azure/main.bicep \
         --parameters @params.json --parameters tokenKekPreviousVersion=$OLD_VER

   The application must build `TokenCipher({"k2": new, "k1": previous}, "k2")`
   when `RS_TOKEN_KEK_PREVIOUS` is set. Today `TokenCipher.from_settings` reads
   one key; that small change belongs to `core/crypto.py` + `config.py`.

3. Re-encrypt every `mailbox_secrets` row (`TokenCipher.needs_rotation`):

       az containerapp exec -g rg-secureddy-prod -n rsec-prod-worker --command "reddysec rotate-tokens"

4. Verify no row still uses the old kid, then redeploy with
   `tokenKekPreviousVersion=''` and disable the old secret version:

       az keyvault secret set-attributes --vault-name $KV --name rs-token-kek --version $OLD_VER --enabled false

Rotate yearly, or at once if a worker or web container is suspected
compromised. Rotating `rs-secret-key` just signs everyone out.

## 8. GitHub Actions (OIDC)

`bootstrap.sh` prints the values. In the repository: **Settings ->
Environments**, create `dev` and `prod`.

Per environment:

- Secrets: `AZURE_CLIENT_ID` (the deploy identity's client id),
  `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID`. These are identifiers, not
  credentials; login uses the GitHub OIDC token.
- Variables: `AZURE_RESOURCE_GROUP`, `ACR_NAME`, `APP_BASE_URL`.
- `prod` protection rules: **Required reviewers** (yourself plus one),
  **Deployment branches and tags** -> selected -> `main` and `v*`.

The federated credential subject is `repo:<owner>/<repo>:environment:<env>`,
so a run can only get a token while it runs inside that GitHub environment,
which is what makes the reviewer gate enforceable.

Deploy: push a tag `v1.2.3` (prod, full) or **Actions -> deploy -> Run
workflow** (choose environment, optionally "apps only").

## 9. Cost toggles

| Toggle | Where | Saves |
|--------|-------|-------|
| `postgresHighAvailability = false`, Burstable SKU | bicepparam | ~USD 280/mo |
| `deployAppsNatGateway = false` | bicepparam | ~USD 36/mo (platform egress IP becomes dynamic) |
| `webMinReplicas = 1` | bicepparam | ~USD 45/mo (no zero-downtime deploys) |
| `logRetentionDays = 30`, `logDailyQuotaGb = 2` | bicepparam | ingestion/retention |
| `zoneRedundant = false` | bicepparam | ACR/Storage/ACA zone redundancy, small |
| Slimmer chamber image (`python:3.12-slim` + `playwright install chromium`) | docker/ | halves per-detonation pull cost and start-up time |
| Front Door Standard instead of Premium | not supported by this template | USD 295/mo, but loses managed WAF rules, bot manager and Private Link; would need a public origin |

See `cost-estimate.md` for the numbers.

## 10. Tearing down

    az group delete -n rg-secureddy-dev-detonations --yes --no-wait
    az group delete -n rg-secureddy-dev --yes --no-wait
    az policy definition delete -n rsec-dev-aci-deny-public-ip   # and the other three rsec-dev-aci-* definitions

Key Vault has purge protection: the name is reserved for 90 days after
deletion. Postgres geo-backups are deleted with the server.

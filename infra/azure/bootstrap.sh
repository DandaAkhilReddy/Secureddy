#!/usr/bin/env bash
# Bootstrap Secureddy on Azure. Idempotent: run it again any time.
#
#   infra/azure/bootstrap.sh dev
#   infra/azure/bootstrap.sh prod
#   infra/azure/bootstrap.sh prod --lockdown      # close Key Vault's public endpoint
#   infra/azure/bootstrap.sh prod --skip-images   # don't rebuild/push images
#
# What it does, in order:
#   1. checks az login and the target subscription
#   2. creates the core and detonation resource groups
#   3. stage 1 deployment: network, identities, Key Vault, data tier, ACR, policy
#   4. seeds Key Vault secrets that do not exist yet (random where possible)
#   5. builds and pushes the app and chamber images with ACR Tasks
#   6. stage 2 deployment: Container Apps, Front Door, alerts
#   7. approves the Front Door -> Container Apps private link
#   8. prints DNS records, GitHub OIDC values and next steps
#
# Requirements: az (>= 2.60), openssl, curl, python3, git. No local Docker.

set -euo pipefail

ENV_NAME="${1:-}"
shift || true
LOCKDOWN=0
SKIP_IMAGES=0
ASSUME_YES=0
for arg in "$@"; do
  case "$arg" in
    --lockdown) LOCKDOWN=1 ;;
    --skip-images) SKIP_IMAGES=1 ;;
    -y|--yes) ASSUME_YES=1 ;;
    *) echo "unknown flag: $arg" >&2; exit 2 ;;
  esac
done

if [[ "$ENV_NAME" != "dev" && "$ENV_NAME" != "staging" && "$ENV_NAME" != "prod" ]]; then
  echo "usage: $0 <dev|staging|prod> [--lockdown] [--skip-images] [-y]" >&2
  exit 2
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
INFRA_DIR="$REPO_ROOT/infra/azure"
PARAM_FILE="$INFRA_DIR/main.$ENV_NAME.bicepparam"
TEMPLATE="$INFRA_DIR/main.bicep"
[[ -f "$PARAM_FILE" ]] || { echo "missing $PARAM_FILE" >&2; exit 1; }

# Read a scalar param out of the .bicepparam file: the quoted string if there is
# one (URLs contain //, so no naive comment stripping), else the bare token.
param_value() {
  python3 - "$PARAM_FILE" "$1" <<'PY'
import re, sys
text = open(sys.argv[1], encoding="utf-8").read()
m = re.search(r"^param\s+%s\s*=\s*(?:'([^']*)'|([^\s/]+))" % re.escape(sys.argv[2]), text, re.M)
print("" if not m else (m.group(1) if m.group(1) is not None else m.group(2)))
PY
}

LOCATION="${LOCATION:-$(param_value location)}"
CORE_RG="${CORE_RG:-rg-secureddy-$ENV_NAME}"
DET_RG="${DET_RG:-$(param_value detonationResourceGroupName)}"
CUSTOM_DOMAIN="$(param_value customDomain)"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

log()  { printf '\n\033[1;34m==> %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m!! %s\033[0m\n' "$*" >&2; }
die()  { printf '\033[1;31mxx %s\033[0m\n' "$*" >&2; exit 1; }

need() { command -v "$1" >/dev/null 2>&1 || die "missing dependency: $1"; }
need az; need openssl; need curl; need python3; need git

# ---------------------------------------------------------------------------
# 1. login + subscription
# ---------------------------------------------------------------------------
log "Checking Azure login"
if ! az account show >/dev/null 2>&1; then
  az login --use-device-code >/dev/null
fi
SUB_ID="$(az account show --query id -o tsv)"
SUB_NAME="$(az account show --query name -o tsv)"
TENANT_ID="$(az account show --query tenantId -o tsv)"
echo "subscription: $SUB_NAME ($SUB_ID)"
echo "environment : $ENV_NAME   location: $LOCATION"
echo "core RG     : $CORE_RG"
echo "detonation  : $DET_RG"
if [[ "$ASSUME_YES" != "1" ]]; then
  read -r -p "Continue? [y/N] " ans
  [[ "$ans" == "y" || "$ans" == "Y" ]] || exit 1
fi

az config set extension.use_dynamic_install=yes_without_prompt >/dev/null 2>&1 || true
az extension add --name containerapp --upgrade --only-show-errors >/dev/null 2>&1 || true
az bicep install >/dev/null 2>&1 || az bicep upgrade >/dev/null 2>&1 || true

OPERATOR_ID="$(az ad signed-in-user show --query id -o tsv 2>/dev/null || true)"
OPERATOR_UPN="$(az ad signed-in-user show --query userPrincipalName -o tsv 2>/dev/null || true)"
[[ -n "$OPERATOR_ID" ]] || warn "could not resolve the signed-in user; Postgres Entra admin and operator Key Vault access will be skipped"

MY_IP="$(curl -fsS --max-time 10 https://api.ipify.org || true)"
if [[ "$LOCKDOWN" == "1" ]]; then
  ADMIN_IPS='[]'
  warn "lockdown: Key Vault public endpoint will be disabled after this run"
elif [[ -n "$MY_IP" ]]; then
  ADMIN_IPS="[\"$MY_IP\"]"
  echo "operator IP : $MY_IP (allowed on Key Vault's public endpoint until --lockdown)"
else
  ADMIN_IPS='[]'
  warn "could not detect public IP; Key Vault secrets can only be written from inside the VNet"
fi

# ---------------------------------------------------------------------------
# 2. resource groups
# ---------------------------------------------------------------------------
log "Resource groups"
az group create -n "$CORE_RG" -l "$LOCATION" --tags product=reddysec env="$ENV_NAME" -o none
az group create -n "$DET_RG" -l "$LOCATION" --tags product=reddysec env="$ENV_NAME" role=detonation -o none

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
log "Compiling parameters"
az bicep build-params --file "$PARAM_FILE" --outfile "$WORK_DIR/params.json" >/dev/null

KV_NAME_PARAM="$(param_value keyVaultName)"
existing_kv() {
  # Key Vault name from a previous deployment, if any.
  az deployment group show -g "$CORE_RG" -n "rsec-$ENV_NAME-stage1" --query properties.outputs.keyVaultName.value -o tsv 2>/dev/null || true
}

kv_secret_exists() { az keyvault secret show --vault-name "$1" --name "$2" --query id -o tsv >/dev/null 2>&1; }

kv_set_with_retry() {
  # RBAC propagation and the IP rule can take a minute or two.
  local vault="$1" name="$2" value="$3" i
  for i in $(seq 1 12); do
    if az keyvault secret set --vault-name "$vault" --name "$name" --value "$value" -o none 2>/dev/null; then
      return 0
    fi
    echo "   waiting for Key Vault access ($i/12)..."; sleep 15
  done
  die "could not write secret $name to $vault"
}

ensure_secret() {
  # ensure_secret <vault> <name> <value-if-absent> [label]
  local vault="$1" name="$2" value="$3" label="${4:-$2}"
  if kv_secret_exists "$vault" "$name"; then
    echo "   $label: exists"
  else
    kv_set_with_retry "$vault" "$name" "$value"
    echo "   $label: created"
  fi
}

deploy() {
  # deploy <deployment-name> <deployApps true|false> [extra az params...]
  local name="$1" apps="$2"; shift 2
  az deployment group create \
    --resource-group "$CORE_RG" \
    --name "$name" \
    --template-file "$TEMPLATE" \
    --parameters "@$WORK_DIR/params.json" \
    --parameters deployApps="$apps" \
                 adminIpAllowList="$ADMIN_IPS" \
                 operatorObjectId="$OPERATOR_ID" \
                 operatorLogin="$OPERATOR_UPN" \
                 "$@" \
    --query properties.outputs -o json
}

# ---------------------------------------------------------------------------
# 3. stage 1
# ---------------------------------------------------------------------------
log "Stage 1: foundation + data tier (this takes 10-15 minutes the first time)"
PG_PASSWORD=""
KV_EXISTING="$(existing_kv)"
if [[ -z "$KV_EXISTING" ]]; then
  # First run: the server is about to be created and needs a password.
  # hex: URL-safe, no escaping needed in the database URL
  PG_PASSWORD="$(openssl rand -hex 24)"
elif kv_secret_exists "$KV_EXISTING" postgres-admin-password; then
  PG_PASSWORD="$(az keyvault secret show --vault-name "$KV_EXISTING" --name postgres-admin-password --query value -o tsv)"
else
  # Re-run from a machine that cannot read Key Vault yet. Pass no password:
  # the template then leaves the existing server password untouched.
  warn "cannot read postgres-admin-password from $KV_EXISTING yet; keeping the server's current password"
fi

STAGE1="$(deploy "rsec-$ENV_NAME-stage1" false postgresAdministratorPassword="$PG_PASSWORD")"
out() { python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get(sys.argv[1],{}).get("value",""))' "$1" <<<"$2"; }

KV_NAME="$(out keyVaultName "$STAGE1")"
ACR_NAME="$(out acrName "$STAGE1")"
ACR_LOGIN="$(out acrLoginServer "$STAGE1")"
PG_FQDN="$(out postgresFqdn "$STAGE1")"
PG_DB="$(out postgresDatabase "$STAGE1")"
PG_ADMIN="$(out postgresAdministratorLogin "$STAGE1")"
TOKEN_NAME="$(out acrChamberPullTokenName "$STAGE1")"
DEPLOY_CLIENT_ID="$(out deployIdentityClientId "$STAGE1")"
echo "Key Vault: $KV_NAME   ACR: $ACR_LOGIN   Postgres: $PG_FQDN"

# ---------------------------------------------------------------------------
# 4. secrets
# ---------------------------------------------------------------------------
log "Seeding Key Vault secrets (existing values are never overwritten)"
if [[ -n "$PG_PASSWORD" ]]; then
  ensure_secret "$KV_NAME" postgres-admin-password "$PG_PASSWORD"
  ensure_secret "$KV_NAME" rs-database-url \
    "postgresql+asyncpg://$PG_ADMIN:$PG_PASSWORD@$PG_FQDN:5432/$PG_DB?ssl=require" "rs-database-url (RS_DATABASE_URL)"
elif kv_secret_exists "$KV_NAME" rs-database-url; then
  echo "   postgres-admin-password / rs-database-url: exist"
else
  die "Key Vault has no postgres-admin-password and the server already exists. Reset it: az postgres flexible-server update -g $CORE_RG -n <server> --admin-password <new>, store it as postgres-admin-password and rs-database-url, then re-run."
fi
ensure_secret "$KV_NAME" rs-token-kek "$(openssl rand -base64 32)" "rs-token-kek (RS_TOKEN_KEK)"
ensure_secret "$KV_NAME" rs-secret-key "$(openssl rand -base64 48)" "rs-secret-key (RS_SECRET_KEY)"
ensure_secret "$KV_NAME" rs-pubsub-token "$(openssl rand -hex 24)" "rs-pubsub-token (Gmail push URL token)"

if ! kv_secret_exists "$KV_NAME" rs-google-client-secret; then
  echo
  echo "Google OAuth client secret (docs/google-oauth-setup.md). Press Enter to skip for now;"
  echo "a placeholder is stored so the apps can start. Replace it later with:"
  echo "  az keyvault secret set --vault-name $KV_NAME --name rs-google-client-secret --value <secret>"
  read -r -s -p "RS_GOOGLE_CLIENT_SECRET: " GOOGLE_SECRET; echo
  ensure_secret "$KV_NAME" rs-google-client-secret "${GOOGLE_SECRET:-not-configured}"
else
  echo "   rs-google-client-secret: exists"
fi

if ! kv_secret_exists "$KV_NAME" acr-chamber-pull-password; then
  echo "   generating repository-scoped pull token for the chamber image"
  TOKEN_PW="$(az acr token credential generate --name "$TOKEN_NAME" --registry "$ACR_NAME" \
      --expiration-in-days 365 --password1 --query 'passwords[0].value' -o tsv)"
  ensure_secret "$KV_NAME" acr-chamber-pull-password "$TOKEN_PW"
else
  echo "   acr-chamber-pull-password: exists"
fi

# ---------------------------------------------------------------------------
# 5. images
# ---------------------------------------------------------------------------
GIT_SHA="$(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null || date +%Y%m%d%H%M)"
if [[ "$SKIP_IMAGES" == "1" ]]; then
  log "Skipping image build (--skip-images)"
else
  log "Building images in ACR ($ACR_NAME), tag $GIT_SHA + latest"
  az acr build --registry "$ACR_NAME" --platform linux/amd64 \
    --image "reddysec-app:$GIT_SHA" --image reddysec-app:latest \
    --file "$REPO_ROOT/docker/Dockerfile.app" "$REPO_ROOT"
  az acr build --registry "$ACR_NAME" --platform linux/amd64 \
    --image "reddysec-chamber:$GIT_SHA" --image reddysec-chamber:latest \
    --file "$REPO_ROOT/docker/Dockerfile.chamber" "$REPO_ROOT"
fi

# ---------------------------------------------------------------------------
# 6. stage 2
# ---------------------------------------------------------------------------
log "Stage 2: Container Apps, Front Door, alerts"
STAGE2="$(deploy "rsec-$ENV_NAME-stage2" true)"
ENV_ID="$(out containerAppsEnvironmentId "$STAGE2")"
AFD_HOST="$(out frontDoorEndpointHostName "$STAGE2")"
AFD_ID="$(out frontDoorId "$STAGE2")"
DNS_TOKEN="$(out customDomainValidationToken "$STAGE2")"
WEB_FQDN="$(out webFqdn "$STAGE2")"
DET_IPS="$(python3 -c 'import json,sys; print(", ".join(json.load(sys.stdin)["detonationEgressIps"]["value"]))' <<<"$STAGE2")"

# ---------------------------------------------------------------------------
# 7. approve Front Door private link to the Container Apps environment
# ---------------------------------------------------------------------------
log "Approving the Front Door private endpoint connection"
for i in $(seq 1 20); do
  PENDING="$(az network private-endpoint-connection list --id "$ENV_ID" \
      --query "[?properties.privateLinkServiceConnectionState.status=='Pending'].id" -o tsv 2>/dev/null || true)"
  if [[ -n "$PENDING" ]]; then
    while read -r conn; do
      [[ -z "$conn" ]] && continue
      az network private-endpoint-connection approve --id "$conn" --description "Secureddy Front Door" -o none
      echo "   approved $conn"
    done <<<"$PENDING"
    break
  fi
  APPROVED="$(az network private-endpoint-connection list --id "$ENV_ID" \
      --query "[?properties.privateLinkServiceConnectionState.status=='Approved'] | length(@)" -o tsv 2>/dev/null || echo 0)"
  if [[ "$APPROVED" != "0" ]]; then echo "   already approved"; break; fi
  echo "   waiting for the connection request ($i/20)..."; sleep 15
done

# ---------------------------------------------------------------------------
# 8. next steps
# ---------------------------------------------------------------------------
log "Done. Next steps"
cat <<EOF

Edge
  Front Door endpoint : https://$AFD_HOST
  Front Door id       : $AFD_ID   (web may check the X-Azure-FDID header against this)
  Web origin (private): $WEB_FQDN
EOF
if [[ -n "$CUSTOM_DOMAIN" ]]; then
cat <<EOF
  DNS records for $CUSTOM_DOMAIN (at your DNS provider):
    CNAME  $CUSTOM_DOMAIN  ->  $AFD_HOST
    TXT    _dnsauth.$CUSTOM_DOMAIN  ->  $DNS_TOKEN
  The managed certificate issues a few minutes after the TXT record is visible.
EOF
else
cat <<EOF
  No custom domain yet. Set 'customDomain' and 'baseUrl' in $PARAM_FILE and re-run.
EOF
fi
cat <<EOF

Detonation egress IPs (what phishing sites see): $DET_IPS

Google OAuth (docs/google-oauth-setup.md)
  Authorized redirect URI: $(param_value baseUrl)/auth/google/callback
  Pub/Sub push endpoint  : $(param_value baseUrl)/hooks/gmail/pubsub?token=\$(az keyvault secret show --vault-name $KV_NAME --name rs-pubsub-token --query value -o tsv)

GitHub Actions (OIDC). Create environments 'dev' and 'prod' in the repo and set per environment:
  secrets : AZURE_CLIENT_ID=$DEPLOY_CLIENT_ID  AZURE_TENANT_ID=$TENANT_ID  AZURE_SUBSCRIPTION_ID=$SUB_ID
  vars    : AZURE_RESOURCE_GROUP=$CORE_RG  ACR_NAME=$ACR_NAME  APP_BASE_URL=$(param_value baseUrl)

First admin user: see docs/azure-deploy.md ("First admin user").

Key Vault public endpoint is $( [[ "$LOCKDOWN" == "1" ]] && echo "DISABLED" || echo "open to $MY_IP only" ).
  Lock it down when you no longer need to write secrets from this machine:
    $0 $ENV_NAME --lockdown --skip-images
EOF

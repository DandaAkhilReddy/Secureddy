#!/usr/bin/env bash
# Build + push both images to ACR and roll them out to web, worker and deadman.
# This is the manual equivalent of .github/workflows/deploy.yml.
#
#   infra/azure/deploy-apps.sh dev
#   infra/azure/deploy-apps.sh prod --infra       # also redeploy main.bicep with the new tag
#   infra/azure/deploy-apps.sh prod --tag abc1234 # roll an image that is already in ACR
#
# Requires: az logged in with rights on the core resource group.

set -euo pipefail

ENV_NAME="${1:-}"
shift || true
WITH_INFRA=0
TAG=""
for ((i = 1; i <= $#; i++)); do
  arg="${!i}"
  case "$arg" in
    --infra) WITH_INFRA=1 ;;
    --tag) j=$((i + 1)); TAG="${!j}"; i=$j ;;
    *) echo "unknown flag: $arg" >&2; exit 2 ;;
  esac
done
[[ "$ENV_NAME" == "dev" || "$ENV_NAME" == "staging" || "$ENV_NAME" == "prod" ]] || {
  echo "usage: $0 <dev|staging|prod> [--infra] [--tag <tag>]" >&2; exit 2; }

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
INFRA_DIR="$REPO_ROOT/infra/azure"
PARAM_FILE="$INFRA_DIR/main.$ENV_NAME.bicepparam"
CORE_RG="${CORE_RG:-rg-secureddy-$ENV_NAME}"
PREFIX="${PREFIX:-rsec}"

log() { printf '\n\033[1;34m==> %s\033[0m\n' "$*"; }

# Names come from the last deployment's outputs so this script has no hard-coded resource names.
log "Reading deployment outputs from $CORE_RG"
LAST_DEPLOYMENT="$(az deployment group list -g "$CORE_RG" --query "sort_by([?properties.provisioningState=='Succeeded'], &properties.timestamp)[-1].name" -o tsv)"
[[ -n "$LAST_DEPLOYMENT" ]] || { echo "no successful deployment in $CORE_RG; run bootstrap.sh first" >&2; exit 1; }
OUTPUTS="$(az deployment group show -g "$CORE_RG" -n "$LAST_DEPLOYMENT" --query properties.outputs -o json)"
out() { python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get(sys.argv[1],{}).get("value",""))' "$1" <<<"$OUTPUTS"; }
ACR_NAME="$(out acrName)"
ACR_LOGIN="$(out acrLoginServer)"
WEB_APP="$(out webAppName)";       WEB_APP="${WEB_APP:-$PREFIX-$ENV_NAME-web}"
WORKER_APP="$(out workerAppName)"; WORKER_APP="${WORKER_APP:-$PREFIX-$ENV_NAME-worker}"
DEADMAN_APP="$(out deadmanAppName)"; DEADMAN_APP="${DEADMAN_APP:-$PREFIX-$ENV_NAME-deadman}"
AFD_HOST="$(out frontDoorEndpointHostName)"

if [[ -z "$TAG" ]]; then
  TAG="$(git -C "$REPO_ROOT" rev-parse --short HEAD)"
  if [[ -n "$(git -C "$REPO_ROOT" status --porcelain)" ]]; then TAG="$TAG-dirty"; fi
  log "Building reddysec-app:$TAG and reddysec-chamber:$TAG in $ACR_NAME"
  az acr build --registry "$ACR_NAME" --platform linux/amd64 \
    --image "reddysec-app:$TAG" --file "$REPO_ROOT/docker/Dockerfile.app" "$REPO_ROOT"
  az acr build --registry "$ACR_NAME" --platform linux/amd64 \
    --image "reddysec-chamber:$TAG" --file "$REPO_ROOT/docker/Dockerfile.chamber" "$REPO_ROOT"
else
  log "Using existing tag $TAG"
fi

if [[ "$WITH_INFRA" == "1" ]]; then
  log "Deploying main.bicep with imageTag=$TAG"
  WORK_DIR="$(mktemp -d)"; trap 'rm -rf "$WORK_DIR"' EXIT
  az bicep build-params --file "$PARAM_FILE" --outfile "$WORK_DIR/params.json" >/dev/null
  az deployment group create -g "$CORE_RG" --name "rsec-$ENV_NAME-$(date -u +%Y%m%d%H%M%S)" \
    --template-file "$INFRA_DIR/main.bicep" --parameters "@$WORK_DIR/params.json" \
    --parameters imageTag="$TAG" deployApps=true -o none
else
  log "Rolling images to Container Apps"
  # Order matters: deadman last, so the safety net keeps running while the
  # others restart. --image creates a new revision; single-revision mode
  # switches traffic once the new revision is healthy.
  az containerapp update -g "$CORE_RG" -n "$WORKER_APP" --image "$ACR_LOGIN/reddysec-app:$TAG" \
    --set-env-vars "RS_CHAMBER_IMAGE=$ACR_LOGIN/reddysec-chamber:$TAG" -o none
  az containerapp update -g "$CORE_RG" -n "$WEB_APP" --image "$ACR_LOGIN/reddysec-app:$TAG" -o none
  az containerapp update -g "$CORE_RG" -n "$DEADMAN_APP" --image "$ACR_LOGIN/reddysec-app:$TAG" -o none
fi

BASE_URL="${APP_BASE_URL:-https://$AFD_HOST}"
log "Smoke test $BASE_URL/healthz"
for i in $(seq 1 20); do
  if curl -fsS --max-time 10 "$BASE_URL/healthz" >/dev/null; then
    echo "healthy after $i attempt(s)"; exit 0
  fi
  sleep 10
done
echo "smoke test failed: $BASE_URL/healthz not healthy after 200 s" >&2
exit 1

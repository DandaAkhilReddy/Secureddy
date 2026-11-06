# Operations runbook

Short version of everything you need at 2 a.m. Resource names below are for
prod (`rsec-prod-*`, `rg-secureddy-prod`); swap for dev.

```
export RG=rg-secureddy-prod DRG=rg-secureddy-prod-detonations
export KV=$(az deployment group show -g $RG -n rsec-prod-stage2 --query properties.outputs.keyVaultName.value -o tsv)
alias logs='az containerapp logs show -g $RG --follow --tail 100 -n'
```

## 1. The dead man's switch

**What it is.** Hold mode parks new mail under `Secureddy/Checking`
until a verdict exists. If our pipeline dies, the client's mail would stay
parked forever. The `deadman` app (one replica, always) checks the
`hold_heartbeats` table: the worker updates `beat_at` for every HOLD mailbox on
each successful cycle. If a beat is older than `RS_HOLD_DEAD_MAN_MINUTES`
(10), deadman calls `release_all_pending()` for that mailbox, which moves
everything in `Checking` to the inbox, removes the Hold rule, logs
`deadman.released`, sets the mailbox to `error` and writes a `deadman_release`
audit row. **This is the designed behaviour, not a bug**: the client getting
unchecked mail beats the client getting no mail. If the release itself fails
(credentials dead) it logs `deadman.release_failed` and emails the concierge:
mail may be trapped.

**What you see.** Severity-0 alert "Dead man's switch fired" (email), usually
preceded by severity-1 "worker-missing" (no worker replica) or
"worker-restarts" (crash loop).

**What to do.**

1. Is the worker running?
   `az containerapp replica list -g $RG -n rsec-prod-worker -o table`;
   `logs rsec-prod-worker`.
2. Common causes, in order of frequency: a bad deploy (roll back, section 7),
   Postgres unavailable (section 8), Service Bus auth error (role assignment
   removed?), Gmail API quota exhausted (section 4).
3. Once the worker is healthy, the released mailbox is in `error` state with
   the Hold rule removed. Re-activate it from the dashboard (Admin ->
   Mailboxes -> Activate); the worker re-runs setup and re-arms Hold. Released
   messages were not analysed: the worker picks them up as normal "scan"
   messages from the inbox and labels them afterwards.
4. Tell the client: "For N minutes between X and Y, mail reached your inbox
   without being checked first. It has since been checked; nothing was found
   / these messages were flagged."

**Manual release** (planned maintenance, or deadman itself is down). It is
per mailbox; list them first:

    az containerapp exec -g $RG -n rsec-prod-worker --command "reddysec list-mailboxes"
    az containerapp exec -g $RG -n rsec-prod-worker --command "reddysec release-all --mailbox-id <id> --reason 'maintenance'"

For every HOLD mailbox at once, run the second command in a loop over the ids
from the first. Each release puts the mailbox in `error` state; re-activate
afterwards.

Before maintenance longer than 10 minutes, switch mailboxes to Scan mode in the
dashboard instead; it tears down the Hold filter cleanly.

## 2. On-call checklist (daily, 5 minutes)

- Alerts fired in the last 24 h: Azure Monitor -> Alerts, resource group `$RG`.
- Worker alive: `az containerapp replica list -g $RG -n rsec-prod-worker -o table` shows at least one
  running replica; heartbeat age is in the dashboard (Admin -> Mailboxes, "last beat") and must be under 2 minutes for HOLD mailboxes.
- Queue depth: `az servicebus queue show --namespace-name <ns> -g $RG -n detonations --query countDetails`.
  `activeMessageCount` above 50 for more than 10 minutes means detonations are
  slower than arrivals; `deadLetterMessageCount` above 0 means failures (section 5).
- Leftover container groups: `az container list -g $DRG -o table` should be
  empty or show groups younger than 5 minutes. Older ones (tag
  `reddysec=detonation`): `az container delete -g $DRG -n <name> --yes` and
  read the worker log (`chamber.aci.*` events) for why they were left.
- Mailbox health: dashboard -> Admin -> Mailboxes; anything in `error` or
  `disconnected` needs the client (section 3).
- Yesterday's cost: Cost Management -> `$RG`. Anything above the daily budget
  (budget / 30) is usually ACI (runaway detonations) or Log Analytics (a log loop).

## 3. Google tokens expire or are revoked

Symptoms: mailbox status `error` with `AuthExpired`; the worker logs
`mailbox_auth_expired`; the client gets an email "Reconnect your Gmail".

Causes:

- **App still in Testing**: refresh tokens die after 7 days. Only the fix is
  verification (`google-oauth-setup.md`, section 6). Until then the client
  reconnects weekly.
- Client changed their Google password or removed the app under
  myaccount.google.com -> Security -> Third-party access.
- Google Advanced Protection Program enrolled with an unverified app: APP
  blocks it. Verification again.
- Our client secret rotated in GCP but not in Key Vault: every mailbox fails at
  once. Update `rs-google-client-secret`, restart web and worker.

Fix: the client clicks Reconnect (Google sign-in, consent). Hold mode is
suspended for that mailbox while disconnected: the worker tears down the Hold
filter when it sees `AuthExpired`, so mail flows. If teardown itself failed
(token already dead), mail is stuck in `Checking`: the client must move it by
hand or temporarily disable the Gmail filter under Settings -> Filters.

## 4. Gmail API quota

Error `429 rateLimitExceeded` / `userRateLimitExceeded` in the worker log.
Check APIs & Services -> Gmail API -> Quotas. Per-user quota (250 units/s)
comes from a single very busy mailbox or a sync loop; per-project quota
(1,000,000 units/day) from too many mailboxes or too short a poll interval.
Immediate relief: raise `RS_GMAIL_POLL_SECONDS` (env on the worker app),
confirm Pub/Sub push is working (then polling is only a backstop). Longer term:
request a quota increase in the GCP console (takes days, free).

## 5. Detonations failing

**ACI quota hit**: activity-log alert "aci-create-failed", worker logs
`aci_create_failed` with `QuotaExceeded` or `RegionCapacity`.

- Default quota is 100 container groups per region. See
  `az vm list-usage -l westus2 -o table | grep -i container` or Subscription ->
  Usage + quotas -> filter "Container Instances".
- Request an increase: Help + support -> New support request -> Service and
  subscription limits -> Container Instances. Ask for 300 groups and matching
  cores; usually granted within hours.
- Meanwhile the worker queues jobs; messages in Hold mode release after
  `hold_timeout_s` (120 s) with "still checking" verdicts, exactly as designed.
  Lower `RS_DETONATION_MAX_CONCURRENCY` on the worker if the failures are
  `RegionCapacity`.

**Image pull failures** (`ImagePullBackOff`, `unauthorized`): the ACR chamber
pull token expired (1-year). Regenerate and update Key Vault, then restart the
worker:

    az acr token credential generate --name chamber-pull --registry <acr> --expiration-in-days 365 --password1 --query 'passwords[0].value' -o tsv \
      | xargs -I{} az keyvault secret set --vault-name $KV --name acr-chamber-pull-password --value {} -o none
    az containerapp revision restart -g $RG -n rsec-prod-worker --revision $(az containerapp revision list -g $RG -n rsec-prod-worker --query '[0].name' -o tsv)

Put a calendar reminder at 11 months. (Policy denies giving the container
group an identity, so a token it is.)

Lean profile (dev): there is no token; the secret holds the ACR admin
password, which does not expire. If someone regenerates it
(`az acr credential renew`), re-run `bootstrap.sh dev --skip-images`, which
copies the live password into Key Vault, then restart the worker.

**Dead-letter queue** growing: `az servicebus queue show ... --query countDetails.deadLetterMessageCount`.
Peek with Service Bus Explorer in the portal. Dead-letters are jobs that failed
3 times; the message id is the detonation job id. Usually a target that hangs
Chromium or an oversized file. Fix the cause, then re-submit from the Explorer
("Re-send") or purge.

**Timeouts**: `RS_DETONATION_TIMEOUT_S` (45) is the browser budget; ACI
start-up (20-60 s) is on top. If many jobs end in `timeout`, check whether the
chamber image got bigger (pull time) before raising the budget.

## 6. A client reports a false positive

1. Dashboard -> the message -> **Evidence**: signals, redirect chain,
   screenshot, forms seen. Decide whether the verdict was wrong or merely
   cautious.
2. Release: the client can do it themselves (**Restore** moves the message
   back and labels it `Released by you`); you can do it as concierge. Both are
   audit-logged.
3. If the sender is legitimate and recurring: add the domain to the mailbox's
   `trusted_domains` (policy), or the sender to the contact history.
4. If a detector misfired (lookalike-domain rule on a legitimate brand
   subdomain, QR code on a restaurant menu, "wire" vocabulary in a lawyer's
   mail): open an issue with the evidence export, tag `false-positive`. Fix the
   rule; add the mail (minus personal data) to `tests/fixtures`.
5. Never lower `quarantine_at` for everyone because of one client.

## 7. Bad deploy, rollback

Container Apps keeps the last revisions. Roll back one app:

    az containerapp revision list -g $RG -n rsec-prod-web -o table
    az containerapp revision activate -g $RG -n rsec-prod-web --revision <previous-revision>
    az containerapp ingress traffic set -g $RG -n rsec-prod-web --revision-weight <previous-revision>=100

Or redeploy a known-good image tag for all three:

    infra/azure/deploy-apps.sh prod --tag <previous-sha>

Infrastructure rollback: `git revert` the Bicep change and run the deploy
workflow; Bicep is declarative and `what-if` shows what will change.

## 8. Postgres

- **Unavailable**: HA fails over by itself (30-120 s). Check Activity log for
  "Server failover". The apps reconnect; the worker misses heartbeats for a
  minute. No action unless it does not come back.
- **Storage > 85%** alert: autogrow is on; find the table
  (`pg_total_relation_size`). `audit_log` and `messages` grow forever by
  design; archive rows older than a year.
- **Connect as a human** (break glass): the server is private. Use
  `az containerapp exec` into the web container and the Python driver, or a
  temporary jump VM in the data subnet. Entra admin is your own account
  (`operatorLogin`); the password admin is `rsadmin` with the Key Vault
  password.

### Backup and restore drill (quarterly)

1. Point-in-time restore to a new server (the original keeps running):

       az postgres flexible-server restore -g $RG --name pg-reddysec-restore-test \
         --source-server pg-reddysec-prod --restore-time "$(date -u -d '-1 hour' +%Y-%m-%dT%H:%M:%SZ)"

   For geo-restore after a regional outage: `az postgres flexible-server geo-restore --location westus3 ...`.
2. The restored server has public access disabled and no private endpoint.
   Add one in the data subnet (copy the `private-endpoint.bicep` call) or test
   from a jump VM.
3. Verify: row counts of `users`, `mailboxes`, `mailbox_secrets`, `messages`;
   decrypt one `mailbox_secrets` row with the current KEK (`reddysec
   check-tokens` from a container with the restore URL in `RS_DATABASE_URL`).
4. Record date, restore time and result in the ops log. Delete the test server.
5. To actually fail over: update `rs-database-url` in Key Vault to the new
   server, restart web/worker/deadman. Expected data loss: up to 5 minutes
   (PITR granularity).

## 9. Incident response

Severity: **S1** client data exposure or a compromised identity; **S2** the
product is down or releasing unchecked mail; **S3** degraded (slow verdicts,
one provider broken).

1. **Contain** (first 15 minutes).
   - Compromised worker/web suspected: `az containerapp update -g $RG -n <app> --min-replicas 0 --max-replicas 0`
     for the affected app; switch all mailboxes to Scan or run `reddysec release-all`
     so mail keeps flowing.
   - Compromised identity: `az identity federated-credential delete` for the
     GitHub identity; for app identities remove role assignments on Key Vault
     first (`az role assignment delete`), the token dies within the hour.
   - Rotate `rs-token-kek` (azure-deploy.md section 7) and `rs-secret-key`.
     Rotating the KEK and re-encrypting takes minutes; do it whenever the
     database or a container is suspected compromised.
   - Leaked Google client secret: GCP console -> Credentials -> reset secret; update Key Vault; restart.
2. **Preserve evidence**: Log Analytics is already there (90 days). Export
   the relevant tables (`ContainerAppConsoleLogs`, `AzureDiagnostics` for Key
   Vault, `AzureActivity`) to the storage account before anything is deleted.
   Leftover container groups in `$DRG`: do not delete; `az container logs` and
   `az container export`.
3. **Communicate**: clients whose mailboxes were affected get a plain email
   from you within 24 h: what happened, what data, what we did, what they
   should do (usually: nothing, or reconnect Gmail). Google must be told
   within 72 h if Gmail user data was exposed (OAuth program policy); the
   CASA assessor at the next review.
4. **Recover**: redeploy from a known-good tag, re-enable apps, confirm
   heartbeats, re-arm Hold mode.
5. **Write it up** within a week: timeline, root cause, what we change.
   Keep it in `docs/incidents/` (create the folder).

## 10. Routine maintenance calendar

| When | What |
|------|------|
| weekly | review alerts, dead-letter queue, leftover container groups, cost |
| monthly | `pip-audit` results from CI; patch and redeploy; check the Playwright base image for a newer `v1.x-noble` and bump `.github/constraints.txt` + both Dockerfiles together |
| quarterly | backup restore drill; review WAF logs for false positives; review audit log access patterns |
| 11 months | regenerate the ACR chamber pull token; renew CASA assessment; rotate `rs-token-kek` |
| yearly | review Azure Policy assignments and role assignments against `security-model.md` |

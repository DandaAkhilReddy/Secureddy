# Cost estimate

Pay-as-you-go list prices in USD for **West US 2**, read from the Azure Retail
Prices API (`https://prices.azure.com/api/retail/prices`) on **2026-11-05**.
Three items the API does not expose (Private Link, private DNS zones, alert
rules) are marked **MEM** and come from memory of the public price list; treat
them as approximate. No reservations or savings plans are applied; Postgres
compute alone would drop ~35% with a 1-year reservation.

The arithmetic is in one script, so you can re-run it with new prices:
`python3 docs/cost-model.py` (same formulas as below).

## 1. Unit prices used

| Meter | Price | Source |
|-------|-------|--------|
| ACI Standard vCPU | 0.0405 / vCPU-hour | API |
| ACI Standard memory | 0.00445 / GB-hour | API |
| NAT Gateway | 0.045 / hour + 0.045 / GB processed | API |
| Standard public IP | 0.005 / hour | API |
| Container Apps Consumption vCPU, active / idle | 0.000034 / 0.000004 per vCPU-second | API |
| Container Apps Consumption memory | 0.000004 / GiB-second | API |
| Container Apps environment management | 0.10 / hour (meter effective 2026-09-01) | API |
| Container Apps environment private endpoint | 0.10 / hour (meter effective 2026-09-01) | API |
| Front Door Premium base fee | 330.00 / month | API |
| Front Door Premium requests (Zone 1) | 0.015 / 10k | API |
| Postgres Flexible GP D2ds_v5 | 0.178 / hour | API |
| Postgres Flexible Burstable B1ms | 0.017 / hour | API |
| Postgres storage / backup storage | 0.115 / 0.095 per GB-month | API |
| Service Bus Standard base | 10.00 / month | API |
| ACR Premium | 1.6666 / day | API |
| Key Vault operations | 0.03 / 10k | API |
| Log Analytics ingestion / retention beyond 31 days | 2.30 / GB, 0.10 / GB-month | API |
| Blob Hot LRS | 0.0184 / GB-month | API |
| Private endpoint | 0.01 / hour + 0.01 / GB processed | MEM |
| Private DNS zone | 0.50 / zone-month | MEM |
| Log alert (5-min), metric alert | 1.50, 0.10 / month | MEM |

## 2. Per detonation

Assumptions: 1.5 vCPU, 2 GB, 90 s of browsing, plus ~30 s of ACI start-up
and image pull that is also billed. The chamber image (Playwright base, ~1 GB
compressed) is pulled over the ACR private endpoint for every container group.

| Item | Formula | USD |
|------|---------|-----|
| ACI compute, 90 s | (1.5 x 0.0405 + 2 x 0.00445) / 3600 x 90 | 0.0017 |
| ACI compute, 120 s (with start-up) | same x 120 s | 0.0023 |
| image pull over Private Link | 1.0 GB x 0.01 | 0.0100 (MEM) |
| NAT data processed | 0.005 GB x 0.045 | 0.0002 |
| **Total per detonation** | | **0.0125** |

The compute is a rounding error; the image pull is 80% of the cost. A
Chromium-only chamber image built from `python:3.12-slim` (~0.4 GB compressed)
brings a detonation to about **0.007** and starts faster. That is the first
optimization worth doing.

## 3. Per Reading Room session

v1 runs sessions inside the web replicas. Marginal cost of one 10-minute
session at 0.5 vCPU / 0.5 GiB active:

    0.5 x 600 x 0.000034 + 0.5 x 600 x 0.000004 = 0.0114

While the two always-on web replicas have spare capacity the marginal cost is
effectively zero; the figure above is what a session costs once the app
scales out.

## 4. Per client-month

60 detonations/day and 10 Reading Room sessions/day, 30.4 days:

| Item | Formula | USD |
|------|---------|-----|
| detonations | 1,824 x 0.0125 | 22.9 |
| Reading Room sessions | 304 x 0.0114 | 3.5 |
| logs (~0.2 GB) | 0.2 x 2.30 | 0.5 |
| screenshots stored (30-day rolling, 150 KB each) | 0.27 GB x 0.0184 | 0.0 |
| **Variable cost per client-month** | | **26.8** |

With the slim chamber image: about **17**.

## 5. Fixed platform cost per month (prod)

| Item | USD / month |
|------|-------------|
| Front Door Premium base fee | 330.00 |
| Front Door requests (~2M/month) | 3.00 |
| Postgres GP D2ds_v5, zone-redundant HA (compute billed twice) | 259.88 |
| Postgres storage 128 GB x2 (HA) + ~50 GB backup beyond the free allowance | 34.19 |
| Container Apps: web, 2 replicas 1 vCPU / 2 GiB, ~20% active | 94.61 |
| Container Apps: worker, 1 replica 1 vCPU / 2 GiB, ~30% active | 55.19 |
| Container Apps: deadman, 0.5 vCPU / 1 GiB, idle | 16.56 |
| Container Apps: environment management (new meter) | 73.00 |
| Container Apps: environment private endpoint for Front Door (new meter) | 73.00 |
| NAT gateways x2 (detonation egress, apps egress) | 65.70 |
| Public IPs x3 | 10.95 |
| Private endpoints x4: Key Vault, Blob, Postgres, ACR (MEM) | 29.20 |
| Private DNS zones x5 (MEM) | 2.50 |
| Service Bus Standard | 10.00 |
| ACR Premium | 50.66 |
| Key Vault (~100k operations) | 0.30 |
| Log Analytics: ~10 GB platform logs/month, 90-day retention | 25.00 |
| Alert rules: 3 log + 4 metric (MEM) | 4.90 |
| Storage account (platform data, < 5 GB) | 0.09 |
| **Fixed total, prod** | **1,138.73** |

Three lines are worth a second look:

- **Front Door Premium (330)** is 29% of the fixed cost. Standard is 35 but has
  no managed WAF rule sets, no bot manager and no Private Link origin, so the
  web app would need a public IP. For a security product that is the wrong
  saving. Application Gateway WAF_v2 is 263 fixed + capacity units, so it is
  not cheaper either.
- **Postgres HA (260 + 34)** doubles compute and storage. The dev file turns it
  off; for prod the question is whether a 30-120 s automatic failover is worth
  ~150/month. For a product whose failure mode is "mail is released
  unchecked", yes.
- **The two new Container Apps environment meters (146)** appeared in the price
  list in September 2026. Confirm on the first invoice whether both apply to a
  Consumption-only workload-profile environment; if they do not, the fixed
  total drops to ~990.

**Fixed total, dev** (Burstable Postgres, no HA, one replica each, no apps NAT
gateway, 30-day logs): about **720 / month**, of which 330 is Front Door. If dev
does not need the edge, deploy it with `deployApps=true` but skip the `edge`
module (set `customDomain=''` and remove the module in a dev-only copy), or
simply tear dev down when idle: `az group delete`. Everything comes back from
`bootstrap.sh dev` in 30 minutes.

## 6. Totals

Fixed + N x variable, plus extra web/worker replicas as load grows (roughly one
more worker per 40 clients, one more web replica per 50):

| Clients | Variable | Scale-out | **Total / month** | Per client |
|--------:|---------:|----------:|------------------:|-----------:|
| 1 | 27 | 0 | **1,166** | 1,166 |
| 10 | 268 | 0 | **1,407** | 141 |
| 100 | 2,682 | 221 | **4,041** | 40 |

At 100 clients the detonation volume is 6,000/day (~4/minute), well inside the
default ACI quota after a one-time increase to 300 container groups, and the
worker runs 3 replicas.

## 7. What is not in these numbers

- Egress from Front Door to clients (0.0085-0.112 / GB in Zone 1 after the
  free 5 GB): a dashboard is kilobytes; the Reading Room streams pixels, call
  it 0.5-1 GB per hour of use. At 10 sessions/day of 10 minutes that is ~25
  GB/month per client, about 2.50.
- Google Cloud: Gmail API and Pub/Sub are free at this volume.
- Third-party intel APIs (Safe Browsing is free; others are not).
- CASA Tier 2 assessment: a few hundred to a few thousand USD per year
  depending on the assessor.
- Your time.

## 8. Re-running the numbers

The Retail Prices API is public and needs no login. Example for ACI:

    curl -s "https://prices.azure.com/api/retail/prices?\$filter=serviceName%20eq%20%27Container%20Instances%27%20and%20armRegionName%20eq%20%27westus2%27" \
      | python3 -c "import json,sys; [print(i['productName'],'|',i['meterName'],'|',i['retailPrice'],'|',i['unitOfMeasure']) for i in json.load(sys.stdin)['Items'] if i['type']=='Consumption']"

Other filters used: `serviceName eq 'Azure Container Apps'`, `serviceName eq
'Azure Database for PostgreSQL'`, `contains(serviceName, 'Front Door')`,
`serviceName eq 'NAT Gateway'` (listed under region `Global`), `serviceName eq
'Service Bus'`, `serviceName eq 'Container Registry'`, `serviceName eq 'Key
Vault'`, `serviceName eq 'Log Analytics'`. The API rate-limits aggressively;
wait a few seconds between calls.

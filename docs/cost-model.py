"""Cost model behind docs/cost-estimate.md.

Unit prices: Azure Retail Prices API, region westus2, USD, read 2026-11-05.
Items marked MEM are not exposed by the API and come from the public price
list as remembered; treat them as approximate.

Run:  python3 docs/cost-model.py
Update the constants when prices change and paste the output into the doc.
"""

H = 730  # hours per month
D = 30.4  # days per month

# --- unit prices (API unless noted) -----------------------------------------
aci_vcpu_hr = 0.0405
aci_gb_hr = 0.00445
nat_gw_hr = 0.045
nat_gb = 0.045
pip_hr = 0.005
aca_vcpu_active_s = 0.000034
aca_vcpu_idle_s = 0.000004
aca_gib_s = 0.000004
aca_env_mgmt_hr = 0.10  # "Environment Management Hour", effective 2026-09-01
aca_env_pe_hr = 0.10  # "Environment Private Endpoint", effective 2026-09-01
afd_premium_month = 330.0
afd_req_per_10k = 0.015  # Zone 1 premium requests
pg_d2ds_v5_hr = 0.178
pg_b1ms_hr = 0.017
pg_storage_gb = 0.115
pg_backup_gb = 0.095
sb_standard_month = 10.0
acr_premium_day = 1.6666
acr_basic_day = 0.1666
kv_ops_10k = 0.03
law_gb = 2.30
law_retention_gb_month = 0.10
blob_gb = 0.0184
pe_hr = 0.01  # MEM: Private Link standard endpoint
pe_gb = 0.01  # MEM: Private Link data processed
dns_zone_month = 0.50  # MEM: private DNS zone
log_alert_month = 1.50  # MEM: scheduled query rule at 5-min frequency
metric_alert_month = 0.10  # MEM: per time series

# --- per detonation ----------------------------------------------------------
vcpu, gb = 1.5, 2
run_s, startup_s = 90, 30
img_gb_compressed = 1.0  # chamber image pulled per container group (Playwright base)
traffic_gb = 0.005


def aci_cost(seconds):
    return (vcpu * aci_vcpu_hr + gb * aci_gb_hr) * seconds / 3600


det_compute_90 = aci_cost(run_s)
det_compute_120 = aci_cost(run_s + startup_s)
det_pull = img_gb_compressed * pe_gb
det_nat = traffic_gb * nat_gb
det_total = det_compute_120 + det_pull + det_nat

# --- per Reading Room session (marginal, 10 min, 0.5 vCPU / 0.5 GiB active) ---
rr_s = 600
rr_cost = 0.5 * rr_s * aca_vcpu_active_s + 0.5 * rr_s * aca_gib_s

# --- per client-month ---------------------------------------------------------
det_per_month = 60 * D
rr_per_month = 10 * D
client_logs_gb = 0.2
client_blob_gb = det_per_month * 0.00015  # 150 KB screenshot each, 30-day rolling
client_month = (
    det_per_month * det_total + rr_per_month * rr_cost + client_logs_gb * law_gb + client_blob_gb * blob_gb
)


# --- fixed platform (prod) ----------------------------------------------------
def aca_app(vcpu, gib, replicas, active_frac):
    idle = vcpu * aca_vcpu_idle_s * (1 - active_frac)
    active = vcpu * aca_vcpu_active_s * active_frac
    mem = gib * aca_gib_s
    return replicas * (idle + active + mem) * 3600 * H


fixed = {
    "Front Door Premium (base fee)": afd_premium_month,
    "Front Door requests (~2M/mo)": 200 * afd_req_per_10k,
    "Postgres GP D2ds_v5, zone-redundant HA (2x compute)": 2 * pg_d2ds_v5_hr * H,
    "Postgres storage 128 GB x2 (HA) + ~50 GB backup": 2 * 128 * pg_storage_gb + 50 * pg_backup_gb,
    "Container Apps: web 2 replicas 1 vCPU/2 GiB (~20% active)": aca_app(1, 2, 2, 0.2),
    "Container Apps: worker 1 replica 1 vCPU/2 GiB (~30% active)": aca_app(1, 2, 1, 0.3),
    "Container Apps: deadman 0.5 vCPU/1 GiB (idle)": aca_app(0.5, 1, 1, 0.02),
    "Container Apps: environment management (new meter)": aca_env_mgmt_hr * H,
    "Container Apps: environment private endpoint for Front Door (new meter)": aca_env_pe_hr * H,
    "NAT gateways x2 (detonation + apps)": 2 * nat_gw_hr * H,
    "Public IPs x3 (Standard static)": 3 * pip_hr * H,
    "Private endpoints x4 (KV, blob, Postgres, ACR) [MEM]": 4 * pe_hr * H,
    "Private DNS zones x5 [MEM]": 5 * dns_zone_month,
    "Service Bus Standard": sb_standard_month,
    "ACR Premium": acr_premium_day * D,
    "Key Vault (~100k ops)": 10 * kv_ops_10k,
    "Log Analytics: ~10 GB platform logs + 90-day retention": 10 * law_gb + 10 * 2 * law_retention_gb_month,
    "Alerts: 3 log + 4 metric [MEM]": 3 * log_alert_month + 4 * metric_alert_month,
    "Storage account (platform, <5 GB)": 5 * blob_gb,
}
fixed_total = sum(fixed.values())

dev = {
    "Front Door Premium": afd_premium_month,
    "Postgres B1ms, 32 GB, no HA": pg_b1ms_hr * H + 32 * pg_storage_gb,
    "Container Apps: web 1 + worker 1 + deadman 1 (mostly idle)": aca_app(1, 2, 1, 0.05)
    + aca_app(1, 2, 1, 0.05)
    + aca_app(0.5, 1, 1, 0.02),
    "Container Apps: env management + env private endpoint": 2 * aca_env_mgmt_hr * H,
    "NAT gateway x1 + 2 IPs": nat_gw_hr * H + 2 * pip_hr * H,
    "Private endpoints x4 + DNS zones [MEM]": 4 * pe_hr * H + 5 * dns_zone_month,
    "Service Bus + ACR Premium + Key Vault": sb_standard_month + acr_premium_day * D + 0.3,
    "Log Analytics (~3 GB, 30 days)": 3 * law_gb,
}
dev_total = sum(dev.values())

# --- dev, costProfile=lean (infra/azure/main.dev.bicepparam) --------------------
# No Front Door, Consumption-only Container Apps environment (no environment
# meters), no Service Bus, no apps NAT gateway, ACR Basic, private endpoint
# only for Postgres. Alerts: 2 log + 5 metric (the two edge alerts are gone).
lean = {
    "Postgres B1ms, 32 GB, no HA": pg_b1ms_hr * H + 32 * pg_storage_gb,
    "Container Apps: web 1 + worker 1 + deadman 1 (mostly idle)": aca_app(1, 2, 1, 0.05)
    + aca_app(1, 2, 1, 0.05)
    + aca_app(0.5, 1, 1, 0.02),
    "NAT gateway x1 (detonation) + 2 IPs": nat_gw_hr * H + 2 * pip_hr * H,
    "Private endpoint x1 (Postgres) + 1 DNS zone [MEM]": pe_hr * H + dns_zone_month,
    "ACR Basic": acr_basic_day * D,
    "Key Vault (~100k ops)": 10 * kv_ops_10k,
    "Log Analytics (~3 GB, 30 days, 1 GB/day cap)": 3 * law_gb,
    "Alerts: 2 log + 5 metric [MEM]": 2 * log_alert_month + 5 * metric_alert_month,
    "Storage account (platform, <5 GB)": 5 * blob_gb,
}
lean_total = sum(lean.values())


def scale_extra(clients):
    # more clients -> more web/worker replicas. Rough: +1 worker per 40 clients, +1 web per 50.
    extra_workers = max(0, (clients - 1) // 40)
    extra_web = max(0, (clients - 1) // 50)
    return extra_workers * aca_app(1, 2, 1, 0.6) + extra_web * aca_app(1, 2, 1, 0.4)


print(f"per detonation compute 90s   : {det_compute_90:.5f}")
print(f"per detonation compute 120s  : {det_compute_120:.5f}")
print(f"per detonation image pull PL : {det_pull:.5f}")
print(f"per detonation NAT data      : {det_nat:.5f}")
print(f"per detonation total         : {det_total:.5f}")
print(f"per reading room session     : {rr_cost:.5f}")
print(f"detonations / client-month   : {det_per_month:.0f}")
print(f"per client-month variable    : {client_month:.2f}")
print()
for k, v in fixed.items():
    print(f"{k:<72} {v:9.2f}")
print(f"{'FIXED TOTAL (prod)':<72} {fixed_total:9.2f}")
print()
for k, v in dev.items():
    print(f"{k:<72} {v:9.2f}")
print(f"{'FIXED TOTAL (dev)':<72} {dev_total:9.2f}")
print()
for k, v in lean.items():
    print(f"{k:<72} {v:9.2f}")
print(f"{'FIXED TOTAL (dev, lean profile)':<72} {lean_total:9.2f}")
print()
for n in (1, 10, 100):
    extra = scale_extra(n)
    total = fixed_total + n * client_month + extra
    print(
        f"clients={n:3d}  variable={n * client_month:8.2f}  scale-extra={extra:7.2f}  total={total:9.2f}  per-client={total / n:7.2f}"
    )

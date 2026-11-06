// Development environment: small, single-zone, cheap to leave running.
// Values marked CHANGE are placeholders you must set before the first deploy.
using './main.bicep'

param envName = 'dev'
param location = 'eastus'
param postgresLocation = 'centralus'
param prefix = 'rsec'
param detonationResourceGroupName = 'Secureddy-detonations'

// Lean: no Front Door, Consumption-only Container Apps environment with public
// ingress, no Service Bus, public endpoints (RBAC-gated) for Key Vault / Blob /
// ACR Basic. Postgres stays private. ~USD 150/month instead of ~720.
// See docs/azure-deploy.md "Cost profiles". Prod uses 'standard'.
param costProfile = 'lean'

// Empty = https://<web app FQDN> (rsec-dev-web.<env default domain>), computed by
// the template because the FQDN only exists after the environment is created.
// Set it only if dev gets its own domain.
param baseUrl = ''
param customDomain = ''

// Leave empty to derive unique names from the resource group id.
param keyVaultName = ''
param storageAccountName = ''
param acrName = ''
param postgresServerName = ''
param serviceBusNamespaceName = ''

// Network (the lean profile forces this off anyway)
param deployAppsNatGateway = false

// Data tier: burstable Postgres, no HA, 7-day local backups
param postgresSkuName = 'Standard_B1ms'
param postgresSkuTier = 'Burstable'
param postgresStorageGb = 32
param postgresHighAvailability = false
param postgresBackupRetentionDays = 7
param postgresGeoRedundantBackup = false
param storageSku = 'Standard_LRS'
param serviceBusSku = 'Standard' // unused in the lean profile
param acrPublicNetworkAccess = 'Enabled'

// Compute
param zoneRedundant = false
param dedicatedWorkloadProfileType = ''
param imageTag = 'latest'
param webMinReplicas = 1
param webMaxReplicas = 3
param workerMinReplicas = 1
param workerMaxReplicas = 2
param detonationMaxConcurrency = 4
param holdDeadManMinutes = 10
param logLevel = 'DEBUG'

// Integrations (CHANGE when you have them; secrets live in Key Vault)
param googleClientId = ''
param googlePubsubTopic = ''
param safeBrowsingEnabled = false
param azureOpenAiEnabled = false
param smtpEnabled = false
param notificationFrom = 'alerts-dev@example.com' // CHANGE
param notifyWebhookUrl = ''

// Edge: unused in the lean profile (no Front Door); kept for a 'standard' dev
param wafMode = 'Detection'
param rateLimitPerMinute = 600

// Observability
param alertEmails = ['reddy@example.com'] // CHANGE
param logRetentionDays = 30
param logDailyQuotaGb = 1
param monthlyBudgetUsd = 200

// CI/CD (CHANGE to your GitHub owner/repo to enable OIDC deploys)
param githubRepository = 'DandaAkhilReddy/Secureddy'

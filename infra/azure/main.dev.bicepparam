// Development environment: small, single-zone, cheap to leave running.
// Values marked CHANGE are placeholders you must set before the first deploy.
using './main.bicep'

param envName = 'dev'
param location = 'eastus'
param postgresLocation = 'centralus'
param prefix = 'rsec'
param detonationResourceGroupName = 'Secureddy-detonations'

// CHANGE: the *.azurefd.net host is printed by the first deployment; put it here
// (or your dev domain) so OAuth redirects and notification links are right.
param baseUrl = 'https://rsec-dev-edge.z01.azurefd.net'
param customDomain = ''

// Leave empty to derive unique names from the resource group id.
param keyVaultName = ''
param storageAccountName = ''
param acrName = ''
param postgresServerName = ''
param serviceBusNamespaceName = ''

// Network
param deployAppsNatGateway = false

// Data tier: burstable Postgres, no HA, 7-day local backups
param postgresSkuName = 'Standard_B1ms'
param postgresSkuTier = 'Burstable'
param postgresStorageGb = 32
param postgresHighAvailability = false
param postgresBackupRetentionDays = 7
param postgresGeoRedundantBackup = false
param storageSku = 'Standard_LRS'
param serviceBusSku = 'Standard'
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

// Edge: detection-only in dev so WAF false positives are visible, not blocking
param wafMode = 'Detection'
param rateLimitPerMinute = 600

// Observability
param alertEmails = ['reddy@example.com'] // CHANGE
param logRetentionDays = 30
param logDailyQuotaGb = 2
param monthlyBudgetUsd = 400

// CI/CD (CHANGE to your GitHub owner/repo to enable OIDC deploys)
param githubRepository = 'DandaAkhilReddy/Secureddy'

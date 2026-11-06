// Production: zone-redundant where the service offers it, HA Postgres with
// 35-day geo-redundant backups, WAF in Prevention mode, two web replicas.
// Values marked CHANGE are placeholders you must set before the first deploy.
using './main.bicep'

param envName = 'prod'
param location = 'westus2'
param prefix = 'rsec'
param detonationResourceGroupName = 'rg-secureddy-prod-detonations'

param baseUrl = 'https://app.secureddy.example' // CHANGE
param customDomain = 'app.secureddy.example' // CHANGE (empty for the first deploy if DNS is not ready)

// Explicit names are easier to find in the portal and in runbooks. Must be globally unique.
param keyVaultName = 'kv-reddysec-prod' // CHANGE if taken
param storageAccountName = 'streddysecprod' // CHANGE if taken
param acrName = 'crreddysecprod' // CHANGE if taken
param postgresServerName = 'pg-reddysec-prod' // CHANGE if taken
param serviceBusNamespaceName = 'sb-reddysec-prod' // CHANGE if taken

// Network
param deployAppsNatGateway = true

// Data tier
param postgresSkuName = 'Standard_D2ds_v5'
param postgresSkuTier = 'GeneralPurpose'
param postgresStorageGb = 128
param postgresHighAvailability = true
param postgresBackupRetentionDays = 35
param postgresGeoRedundantBackup = true
param storageSku = 'Standard_ZRS'
param serviceBusSku = 'Standard'
param acrPublicNetworkAccess = 'Enabled'

// Compute
param zoneRedundant = true
param dedicatedWorkloadProfileType = '' // e.g. 'D4' to pin apps to dedicated nodes
param imageTag = 'latest' // the deploy workflow overrides this with the git sha
param webMinReplicas = 2
param webMaxReplicas = 10
param workerMinReplicas = 1
param workerMaxReplicas = 3
param detonationMaxConcurrency = 8
param holdDeadManMinutes = 10
param logLevel = 'INFO'

// Integrations
param googleClientId = '' // CHANGE: from the GCP OAuth client (docs/google-oauth-setup.md)
param googlePubsubTopic = '' // CHANGE: projects/<gcp-project>/topics/reddysec-gmail
param safeBrowsingEnabled = false
param azureOpenAiEnabled = false
param azureOpenAiEndpoint = ''
param azureOpenAiDeployment = ''
param smtpEnabled = false
param smtpHost = ''
param smtpUsername = ''
param notificationFrom = 'alerts@secureddy.example' // CHANGE
param notifyWebhookUrl = ''

// Edge
param wafMode = 'Prevention'
param rateLimitPerMinute = 300

// Observability
param alertEmails = ['reddy@example.com'] // CHANGE
param logRetentionDays = 90
param logDailyQuotaGb = 5
param monthlyBudgetUsd = 1500

// CI/CD
param githubRepository = 'DandaAkhilReddy/Secureddy'

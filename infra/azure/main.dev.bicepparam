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
param googleClientId = '533261991462-713nthol9j37igot6g9r03v62al0vrsb.apps.googleusercontent.com'
param googlePubsubTopic = ''
// Entra app "Secureddy" (multi-tenant + personal accounts). Certificate auth:
// Key Vault secrets rs-microsoft-client-cert (PEM key + cert) and
// rs-microsoft-cert-thumbprint must exist.
param microsoftClientId = '8cc0907f-7f8e-45ec-9758-102eea8c1a00'
// Claude for the assistant and the second-opinion reviewer. Turn on once Key
// Vault secret rs-anthropic-api-key exists.
param anthropicEnabled = true
param llmProvider = 'anthropic'
param assistantProvider = 'anthropic'
// Keyless Claude (Workload Identity Federation). Fill in the ids the Claude
// Console shows (docs/claude-keyless-setup.md), then set anthropicEnabled =
// false and delete Key Vault secret rs-anthropic-api-key. Identifiers only.
param anthropicWifAudience = 'api://5c08b3d9-f257-4add-b919-e10afac41f5b'
param anthropicWebFederationRuleId = ''
param anthropicWorkerFederationRuleId = ''
param anthropicOrganizationId = ''
param anthropicServiceAccountId = ''
param anthropicWorkspaceId = ''
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

// Who may use it: free, invite-only, at most 5 people. The owner's account
// becomes the first admin (Admin -> People to invite the others).
param bootstrapAdminEmail = 'akhilreddydanda3@gmail.com'
param maxUsers = 5
param signupMode = 'invite_only'

param yahooClientId = 'dj0yJmk9T3JiQWxQdnFaNjR0JmQ9WVdrOWVEUXdVbmRqYWxJbWNHbzlNQT09JnM9Y29uc3VtZXJzZWNyZXQmc3Y9MCZ4PThi'

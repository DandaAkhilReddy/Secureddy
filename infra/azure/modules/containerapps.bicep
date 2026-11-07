// Container Apps environment (workload profiles, VNet-injected, INTERNAL) and
// the three apps: web, worker, deadman.
//
// The environment is internal and has public network access disabled. The only
// way in is Azure Front Door Premium through a private link to the environment
// (see edge.bicep). web is "external" only in the Container Apps sense: it is
// published on the environment's internal load balancer.
//
// lean=true (dev cost profile): Consumption-only environment (no workload
// profiles, so no environment-management or private-endpoint meters), external
// with public ingress on the free *.azurecontainerapps.io certificate, no Front
// Door in front of it, no Service Bus (the scale rule that watched the queue is
// dropped; the worker runs a fixed replica count). RS_BASE_URL is computed from
// the environment's default domain because the FQDN is only known after deploy.
//
// Secrets are Key Vault references resolved by each app's own managed
// identity. The template never sees a secret value.
//
// Contract with the application (all read through RS_* settings; config.py
// ignores variables it does not know yet, so adding them here is safe):
//   AZURE_CLIENT_ID             the app's user-assigned identity (DefaultAzureCredential)
//   RS_STORAGE_ACCOUNT_URL      https://<account>.blob.core.windows.net
//   RS_ARTIFACTS_CONTAINER      artifacts
//   RS_QUARANTINE_CONTAINER     quarantine-originals
//   RS_SERVICEBUS_NAMESPACE     <ns>.servicebus.windows.net
//   RS_SERVICEBUS_QUEUE_*       detonations / notifications
//   RS_ACI_*, RS_CHAMBER_IMAGE  everything the worker needs to create container groups

param location string
param namePrefix string
param tags object = {}

@allowed(['dev', 'staging', 'prod'])
param envName string

@description('Public base URL of the product (https://app.example.com). Used for OAuth redirects and links in notifications. Empty in the lean profile = https://<web app FQDN>.')
param baseUrl string = ''

@description('Lean cost profile. See the header comment.')
param lean bool = false

@description('Deploy Service Bus env vars and the queue-length scale rule. False in the lean profile (no namespace).')
param useServiceBus bool = true

param zoneRedundant bool = false

@description('Dedicated workload profile for prod (e.g. D4). Empty = Consumption profile only.')
param dedicatedWorkloadProfileType string = ''
param dedicatedWorkloadProfileMin int = 1
param dedicatedWorkloadProfileMax int = 3

param appsSubnetId string
param logAnalyticsWorkspaceId string
param appInsightsConnectionString string

param acrLoginServer string
param appImage string
param chamberImage string

param keyVaultUri string

param webIdentityId string
param webClientId string
param workerIdentityId string
param workerClientId string
param deadmanIdentityId string
param deadmanClientId string

param storageBlobEndpoint string
param artifactsContainer string
param quarantineContainer string

param serviceBusNamespaceName string = ''
param serviceBusNamespaceFqdn string = ''
param detonationsQueueName string = ''
param notificationsQueueName string = ''

param detonationResourceGroupName string
param detonationSubnetId string

@description('Username the detonation container groups pull the chamber image with (repository-scoped token, or the ACR admin user in the lean profile). The password is the Key Vault secret acr-chamber-pull-password either way.')
param acrChamberPullUsername string

param webMinReplicas int = 2
param webMaxReplicas int = 10
param workerMinReplicas int = 1
param workerMaxReplicas int = 3

@description('Messages in the detonations queue per worker replica before scaling out.')
param workerQueueLengthPerReplica int = 5

param detonationTimeoutSeconds int = 45
param detonationMaxConcurrency int = 8
param holdDeadManMinutes int = 10
param logLevel string = 'INFO'

@description('Optional integrations. Each one needs its Key Vault secret to exist before enabling.')
param safeBrowsingEnabled bool = false
param azureOpenAiEnabled bool = false
param azureOpenAiEndpoint string = ''
param azureOpenAiDeployment string = ''
param smtpEnabled bool = false
param smtpHost string = ''
param smtpPort int = 587
param smtpUsername string = ''
param notificationFrom string = ''
param notifyWebhookUrl string = ''
param googleClientId string = ''
param googlePubsubTopic string = ''

@description('Entra app (client) id for "Sign in with Microsoft" + Graph mail. Empty = Microsoft sign-in off and no Microsoft Key Vault references (the certificate secrets need not exist).')
param microsoftClientId string = ''

@description('Yahoo OpenID Connect client id (sign-in only). Empty = Yahoo button hidden.')
param yahooClientId string = ''

@description('Adds RS_ANTHROPIC_API_KEY from Key Vault secret rs-anthropic-api-key. The secret must exist before this is turned on.')
param anthropicEnabled bool = false

@description('RS_LLM_PROVIDER when Azure OpenAI is off: none | anthropic | azure_foundry | azure_openai. Empty = none.')
param llmProvider string = ''

@description('RS_ASSISTANT_PROVIDER for "Ask Secureddy": empty follows RS_LLM_PROVIDER.')
param assistantProvider string = ''

@description('Claude model for the in-app assistant.')
param assistantModel string = 'claude-sonnet-5-5'

@description('Claude model for the background fraud reviewer.')
param anthropicModel string = 'claude-haiku-5-5'

// Keyless Claude (Workload Identity Federation): identifiers only, never
// secrets. When the rule, organization and service account are set, the apps
// trade their managed identity's Entra token for a short-lived Claude token
// and RS_ANTHROPIC_API_KEY is not needed (set anthropicEnabled=false).
@description('Anthropic federation rule (fdrl_...) matching the web app identity (oid).')
param anthropicWebFederationRuleId string = ''
@description('Anthropic federation rule (fdrl_...) matching the worker identity (oid).')
param anthropicWorkerFederationRuleId string = ''
@description('Anthropic organization id (UUID).')
param anthropicOrganizationId string = ''
@description('Anthropic service account (svac_...) the rules mint tokens for.')
param anthropicServiceAccountId string = ''
@description('Anthropic workspace (wrkspc_...); needed when a rule covers several workspaces.')
param anthropicWorkspaceId string = ''
@description('Audience the managed identities request an Entra token for: api://<Entra app id>.')
param anthropicWifAudience string = ''

@description('KEK rotation: Key Vault version id of the PREVIOUS rs-token-kek. While set, the apps get it as RS_TOKEN_KEK_PREVIOUS so old ciphertexts still decrypt. Empty = single key.')
param tokenKekPreviousVersion string = ''

var useDedicated = !empty(dedicatedWorkloadProfileType)
var appProfileName = useDedicated ? 'dedicated' : 'Consumption'

// The environment name carries the profile: 'internal' and workload-profile
// mode are immutable, so switching profiles means a new environment next to
// the old one rather than an in-place update.
var environmentName = lean ? '${namePrefix}-cae-lean' : '${namePrefix}-cae'
var webAppName = '${namePrefix}-web'

var workloadProfiles = concat(
  [
    {
      name: 'Consumption'
      workloadProfileType: 'Consumption'
    }
  ],
  useDedicated
    ? [
        {
          name: 'dedicated'
          workloadProfileType: dedicatedWorkloadProfileType
          minimumCount: dedicatedWorkloadProfileMin
          maximumCount: dedicatedWorkloadProfileMax
        }
      ]
    : []
)

// ---------------------------------------------------------------------------
// Environment
// ---------------------------------------------------------------------------

// Consumption-only (lean) environments reject workloadProfiles and peer
// traffic encryption, and need a /23 subnet delegated to Microsoft.App/environments
// (network.bicep; the same delegation serves both environment types).
var standardEnvProperties = {
  appLogsConfiguration: {
    destination: 'azure-monitor'
  }
  vnetConfiguration: {
    infrastructureSubnetId: appsSubnetId
    internal: true
  }
  workloadProfiles: workloadProfiles
  zoneRedundant: zoneRedundant
  publicNetworkAccess: 'Disabled'
  peerTrafficConfiguration: {
    encryption: { enabled: true }
  }
}

var leanEnvProperties = {
  appLogsConfiguration: {
    destination: 'azure-monitor'
  }
  vnetConfiguration: {
    infrastructureSubnetId: appsSubnetId
    internal: false
  }
  zoneRedundant: false
  publicNetworkAccess: 'Enabled'
}

resource managedEnv 'Microsoft.App/managedEnvironments@2025-07-01' = {
  name: environmentName
  location: location
  tags: tags
  properties: lean ? leanEnvProperties : standardEnvProperties
}

// lean: https://rsec-dev-web.<default domain>; the web app below is named
// webAppName, so this is its FQDN.
var effectiveBaseUrl = empty(baseUrl) ? 'https://${webAppName}.${managedEnv.properties.defaultDomain}' : baseUrl

resource environmentDiag 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'to-law'
  scope: managedEnv
  properties: {
    workspaceId: logAnalyticsWorkspaceId
    logs: [{ categoryGroup: 'allLogs', enabled: true }]
    metrics: [{ category: 'AllMetrics', enabled: true }]
  }
}

// ---------------------------------------------------------------------------
// Shared pieces
// ---------------------------------------------------------------------------

func kvRef(vaultUri string, secretName string) string => '${vaultUri}secrets/${secretName}'

var commonEnv = [
  { name: 'RS_ENV', value: envName }
  { name: 'RS_BASE_URL', value: effectiveBaseUrl }
  { name: 'RS_LOG_LEVEL', value: logLevel }
  { name: 'RS_SECRET_KEY', secretRef: 'rs-secret-key' }
  { name: 'RS_TOKEN_KEK', secretRef: 'rs-token-kek' }
  { name: 'RS_DATABASE_URL', secretRef: 'rs-database-url' }
  { name: 'RS_GOOGLE_CLIENT_ID', value: googleClientId }
  { name: 'RS_GOOGLE_CLIENT_SECRET', secretRef: 'rs-google-client-secret' }
  { name: 'RS_GOOGLE_PUBSUB_TOPIC', value: googlePubsubTopic }
  { name: 'RS_PUBSUB_TOKEN', secretRef: 'rs-pubsub-token' }
  { name: 'RS_STORAGE_ACCOUNT_URL', value: storageBlobEndpoint }
  { name: 'RS_ARTIFACTS_CONTAINER', value: artifactsContainer }
  { name: 'RS_QUARANTINE_CONTAINER', value: quarantineContainer }
  // empty strings when useServiceBus=false (lean)
  { name: 'RS_SERVICEBUS_NAMESPACE', value: useServiceBus ? serviceBusNamespaceFqdn : '' }
  { name: 'RS_SERVICEBUS_QUEUE_DETONATIONS', value: useServiceBus ? detonationsQueueName : '' }
  { name: 'RS_SERVICEBUS_QUEUE_NOTIFICATIONS', value: useServiceBus ? notificationsQueueName : '' }
  { name: 'RS_HOLD_DEAD_MAN_MINUTES', value: string(holdDeadManMinutes) }
  { name: 'RS_INTEL_ONLINE', value: 'true' }
  { name: 'RS_DEV_LOGIN_ENABLED', value: 'false' }
  { name: 'RS_NOTIFICATION_FROM', value: notificationFrom }
  { name: 'RS_NOTIFY_WEBHOOK_URL', value: notifyWebhookUrl }
  { name: 'APPLICATIONINSIGHTS_CONNECTION_STRING', value: appInsightsConnectionString }
]

var safeBrowsingEnv = safeBrowsingEnabled ? [{ name: 'RS_SAFE_BROWSING_API_KEY', secretRef: 'rs-safe-browsing-api-key' }] : []

var azureOpenAiEnv = azureOpenAiEnabled
  ? [
      { name: 'RS_LLM_PROVIDER', value: 'azure_openai' }
      { name: 'RS_AZURE_OPENAI_ENDPOINT', value: azureOpenAiEndpoint }
      { name: 'RS_AZURE_OPENAI_DEPLOYMENT', value: azureOpenAiDeployment }
      { name: 'RS_AZURE_OPENAI_API_KEY', secretRef: 'rs-azure-openai-api-key' }
    ]
  : [{ name: 'RS_LLM_PROVIDER', value: empty(llmProvider) ? 'none' : llmProvider }]

var assistantEnv = concat(
  [
    { name: 'RS_ASSISTANT_PROVIDER', value: assistantProvider }
    { name: 'RS_ASSISTANT_MODEL', value: assistantModel }
    { name: 'RS_ANTHROPIC_MODEL', value: anthropicModel }
  ],
  [
    { name: 'RS_ANTHROPIC_ORGANIZATION_ID', value: anthropicOrganizationId }
    { name: 'RS_ANTHROPIC_SERVICE_ACCOUNT_ID', value: anthropicServiceAccountId }
    { name: 'RS_ANTHROPIC_WORKSPACE_ID', value: anthropicWorkspaceId }
    { name: 'RS_ANTHROPIC_WIF_AUDIENCE', value: anthropicWifAudience }
  ],
  anthropicEnabled ? [{ name: 'RS_ANTHROPIC_API_KEY', secretRef: 'rs-anthropic-api-key' }] : []
)

// Microsoft (Outlook.com / Microsoft 365 via Graph). Wired like the Google
// client secret, but only when a client id is set: the certificate lives in
// Key Vault (rs-microsoft-client-cert, PEM key + cert) because the tenant
// forbids client secrets. Every app gets it: the worker and the dead man's
// switch build Graph connectors, the web app runs the sign-in.
var microsoftEnabled = !empty(microsoftClientId)
var microsoftEnv = microsoftEnabled
  ? [
      { name: 'RS_MICROSOFT_CLIENT_ID', value: microsoftClientId }
      { name: 'RS_MICROSOFT_CLIENT_CERT', secretRef: 'rs-microsoft-client-cert' }
      { name: 'RS_MICROSOFT_CERT_THUMBPRINT', secretRef: 'rs-microsoft-cert-thumbprint' }
    ]
  : []

// Yahoo: sign-in only (Yahoo Mail itself is connected with an app password).
var yahooEnabled = !empty(yahooClientId)
var yahooEnv = yahooEnabled
  ? [
      { name: 'RS_YAHOO_CLIENT_ID', value: yahooClientId }
      { name: 'RS_YAHOO_CLIENT_SECRET', secretRef: 'rs-yahoo-client-secret' }
    ]
  : []

var smtpEnv = smtpEnabled
  ? [
      { name: 'RS_SMTP_HOST', value: smtpHost }
      { name: 'RS_SMTP_PORT', value: string(smtpPort) }
      { name: 'RS_SMTP_USERNAME', value: smtpUsername }
      { name: 'RS_SMTP_PASSWORD', secretRef: 'rs-smtp-password' }
    ]
  : []

var kekPreviousEnv = empty(tokenKekPreviousVersion) ? [] : [{ name: 'RS_TOKEN_KEK_PREVIOUS', secretRef: 'rs-token-kek-previous' }]

var optionalEnv = concat(safeBrowsingEnv, azureOpenAiEnv, assistantEnv, microsoftEnv, yahooEnv, smtpEnv, kekPreviousEnv)

// Key Vault references. Every secret listed here must exist or the revision
// fails to provision. Optional ones are only listed when enabled.
func baseSecrets(vaultUri string, identityId string) array => [
  { name: 'rs-secret-key', keyVaultUrl: kvRef(vaultUri, 'rs-secret-key'), identity: identityId }
  { name: 'rs-token-kek', keyVaultUrl: kvRef(vaultUri, 'rs-token-kek'), identity: identityId }
  { name: 'rs-database-url', keyVaultUrl: kvRef(vaultUri, 'rs-database-url'), identity: identityId }
  { name: 'rs-google-client-secret', keyVaultUrl: kvRef(vaultUri, 'rs-google-client-secret'), identity: identityId }
  { name: 'rs-pubsub-token', keyVaultUrl: kvRef(vaultUri, 'rs-pubsub-token'), identity: identityId }
]

// Pinned to a specific secret version: the key being rotated out.
func kekPreviousSecret(vaultUri string, identityId string, version string) array => empty(version)
  ? []
  : [{ name: 'rs-token-kek-previous', keyVaultUrl: '${kvRef(vaultUri, 'rs-token-kek')}/${version}', identity: identityId }]

func optionalSecrets(vaultUri string, identityId string, safeBrowsing bool, openAi bool, smtp bool) array => concat(
  safeBrowsing ? [{ name: 'rs-safe-browsing-api-key', keyVaultUrl: kvRef(vaultUri, 'rs-safe-browsing-api-key'), identity: identityId }] : [],
  openAi ? [{ name: 'rs-azure-openai-api-key', keyVaultUrl: kvRef(vaultUri, 'rs-azure-openai-api-key'), identity: identityId }] : [],
  smtp ? [{ name: 'rs-smtp-password', keyVaultUrl: kvRef(vaultUri, 'rs-smtp-password'), identity: identityId }] : []
)

func microsoftSecrets(vaultUri string, identityId string, enabled bool) array => enabled
  ? [
      { name: 'rs-microsoft-client-cert', keyVaultUrl: kvRef(vaultUri, 'rs-microsoft-client-cert'), identity: identityId }
      { name: 'rs-microsoft-cert-thumbprint', keyVaultUrl: kvRef(vaultUri, 'rs-microsoft-cert-thumbprint'), identity: identityId }
    ]
  : []

func yahooSecrets(vaultUri string, identityId string, enabled bool) array => enabled
  ? [{ name: 'rs-yahoo-client-secret', keyVaultUrl: kvRef(vaultUri, 'rs-yahoo-client-secret'), identity: identityId }]
  : []

func anthropicSecrets(vaultUri string, identityId string, enabled bool) array => enabled
  ? [{ name: 'rs-anthropic-api-key', keyVaultUrl: kvRef(vaultUri, 'rs-anthropic-api-key'), identity: identityId }]
  : []

var webSecrets = concat(
  baseSecrets(keyVaultUri, webIdentityId),
  optionalSecrets(keyVaultUri, webIdentityId, safeBrowsingEnabled, azureOpenAiEnabled, smtpEnabled),
  microsoftSecrets(keyVaultUri, webIdentityId, microsoftEnabled),
  yahooSecrets(keyVaultUri, webIdentityId, yahooEnabled),
  anthropicSecrets(keyVaultUri, webIdentityId, anthropicEnabled),
  kekPreviousSecret(keyVaultUri, webIdentityId, tokenKekPreviousVersion)
)
var workerSecrets = concat(
  baseSecrets(keyVaultUri, workerIdentityId),
  optionalSecrets(keyVaultUri, workerIdentityId, safeBrowsingEnabled, azureOpenAiEnabled, smtpEnabled),
  microsoftSecrets(keyVaultUri, workerIdentityId, microsoftEnabled),
  yahooSecrets(keyVaultUri, workerIdentityId, yahooEnabled),
  anthropicSecrets(keyVaultUri, workerIdentityId, anthropicEnabled),
  kekPreviousSecret(keyVaultUri, workerIdentityId, tokenKekPreviousVersion),
  [{ name: 'acr-chamber-pull-password', keyVaultUrl: kvRef(keyVaultUri, 'acr-chamber-pull-password'), identity: workerIdentityId }]
)
var deadmanSecrets = concat(
  baseSecrets(keyVaultUri, deadmanIdentityId),
  optionalSecrets(keyVaultUri, deadmanIdentityId, false, false, smtpEnabled),
  microsoftSecrets(keyVaultUri, deadmanIdentityId, microsoftEnabled),
  yahooSecrets(keyVaultUri, deadmanIdentityId, yahooEnabled),
  kekPreviousSecret(keyVaultUri, deadmanIdentityId, tokenKekPreviousVersion)
)

var httpProbes = [
  {
    type: 'Startup'
    httpGet: { path: '/healthz', port: 8000 }
    periodSeconds: 3
    failureThreshold: 20
  }
  {
    type: 'Liveness'
    httpGet: { path: '/healthz', port: 8000 }
    periodSeconds: 15
    failureThreshold: 3
    timeoutSeconds: 5
  }
  {
    type: 'Readiness'
    httpGet: { path: '/readyz', port: 8000 }
    periodSeconds: 10
    failureThreshold: 3
    timeoutSeconds: 5
  }
]

// ---------------------------------------------------------------------------
// web
// ---------------------------------------------------------------------------

resource web 'Microsoft.App/containerApps@2025-07-01' = {
  name: webAppName
  location: location
  tags: union(tags, { 'reddysec-role': 'web' })
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: { '${webIdentityId}': {} }
  }
  properties: {
    environmentId: managedEnv.id
    workloadProfileName: lean ? null : appProfileName
    configuration: {
      activeRevisionsMode: 'Single'
      maxInactiveRevisions: 5
      ingress: {
        external: true
        targetPort: 8000
        transport: 'auto'
        allowInsecure: false
        // The Reading Room (v1) keeps its browser session in the replica that
        // started it. Front Door is configured with session affinity too.
        stickySessions: { affinity: 'sticky' }
        traffic: [{ latestRevision: true, weight: 100 }]
      }
      registries: [{ server: acrLoginServer, identity: webIdentityId }]
      secrets: webSecrets
    }
    template: {
      containers: [
        {
          name: 'web'
          image: appImage
          // The CLI binds 127.0.0.1 by default; ingress (Envoy) connects over the pod network.
          command: ['reddysec', 'web', '--host', '0.0.0.0', '--port', '8000']
          resources: { cpu: 1, memory: '2Gi' }
          env: concat(commonEnv, optionalEnv, [
            { name: 'AZURE_CLIENT_ID', value: webClientId }
            { name: 'RS_AZURE_IDENTITY_CLIENT_ID', value: webClientId }
            { name: 'RS_ANTHROPIC_FEDERATION_RULE_ID', value: anthropicWebFederationRuleId }
            { name: 'RS_SANDBOX_BACKEND', value: 'aci' }
            { name: 'RS_READING_ROOM_MAX_SESSIONS', value: '10' }
          ])
          probes: httpProbes
        }
      ]
      scale: {
        minReplicas: webMinReplicas
        maxReplicas: webMaxReplicas
        rules: [
          {
            name: 'http'
            http: { metadata: { concurrentRequests: '40' } }
          }
        ]
      }
    }
  }
}

// ---------------------------------------------------------------------------
// worker
// ---------------------------------------------------------------------------

resource worker 'Microsoft.App/containerApps@2025-07-01' = {
  name: '${namePrefix}-worker'
  location: location
  tags: union(tags, { 'reddysec-role': 'worker' })
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: { '${workerIdentityId}': {} }
  }
  properties: {
    environmentId: managedEnv.id
    workloadProfileName: lean ? null : appProfileName
    configuration: {
      activeRevisionsMode: 'Single'
      maxInactiveRevisions: 5
      registries: [{ server: acrLoginServer, identity: workerIdentityId }]
      secrets: workerSecrets
    }
    template: {
      containers: [
        {
          name: 'worker'
          image: appImage
          command: ['reddysec', 'worker']
          resources: { cpu: 1, memory: '2Gi' }
          env: concat(commonEnv, optionalEnv, [
            { name: 'AZURE_CLIENT_ID', value: workerClientId }
            { name: 'RS_AZURE_IDENTITY_CLIENT_ID', value: workerClientId }
            { name: 'RS_ANTHROPIC_FEDERATION_RULE_ID', value: anthropicWorkerFederationRuleId }
            { name: 'RS_SANDBOX_BACKEND', value: 'aci' }
            { name: 'RS_DETONATION_TIMEOUT_S', value: string(detonationTimeoutSeconds) }
            { name: 'RS_DETONATION_MAX_CONCURRENCY', value: string(detonationMaxConcurrency) }
            // chamber/backends/base.py + azure_aci.py read these
            { name: 'RS_ACI_SUBSCRIPTION_ID', value: subscription().subscriptionId }
            { name: 'RS_ACI_RESOURCE_GROUP', value: detonationResourceGroupName }
            { name: 'RS_ACI_LOCATION', value: location }
            { name: 'RS_ACI_SUBNET_ID', value: detonationSubnetId }
            { name: 'RS_CHAMBER_IMAGE', value: chamberImage }
            // pull credentials for the registry (repository-scoped token; ACR admin user in lean)
            { name: 'RS_ACI_REGISTRY_SERVER', value: acrLoginServer }
            { name: 'RS_ACI_REGISTRY_USERNAME', value: acrChamberPullUsername }
            { name: 'RS_ACI_REGISTRY_PASSWORD', secretRef: 'acr-chamber-pull-password' }
          ])
        }
      ]
      scale: {
        minReplicas: workerMinReplicas
        maxReplicas: workerMaxReplicas
        // No rules without Service Bus: the worker stays at workerMinReplicas.
        rules: useServiceBus
          ? [
              {
                name: 'detonations-queue'
                custom: {
                  type: 'azure-servicebus'
                  metadata: {
                    queueName: detonationsQueueName
                    namespace: serviceBusNamespaceName
                    messageCount: string(workerQueueLengthPerReplica)
                  }
                  identity: workerIdentityId
                }
              }
            ]
          : []
      }
    }
  }
}

// ---------------------------------------------------------------------------
// deadman: exactly one replica, always.
// ---------------------------------------------------------------------------

resource deadman 'Microsoft.App/containerApps@2025-07-01' = {
  name: '${namePrefix}-deadman'
  location: location
  tags: union(tags, { 'reddysec-role': 'deadman' })
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: { '${deadmanIdentityId}': {} }
  }
  properties: {
    environmentId: managedEnv.id
    workloadProfileName: lean ? null : appProfileName
    configuration: {
      activeRevisionsMode: 'Single'
      maxInactiveRevisions: 3
      registries: [{ server: acrLoginServer, identity: deadmanIdentityId }]
      secrets: deadmanSecrets
    }
    template: {
      containers: [
        {
          name: 'deadman'
          image: appImage
          command: ['reddysec', 'deadman']
          resources: { cpu: json('0.5'), memory: '1Gi' }
          env: concat(commonEnv, microsoftEnv, smtpEnv, kekPreviousEnv, [
            { name: 'AZURE_CLIENT_ID', value: deadmanClientId }
            { name: 'RS_LLM_PROVIDER', value: 'none' }
          ])
        }
      ]
      scale: {
        minReplicas: 1
        maxReplicas: 1
      }
    }
  }
}

output environmentId string = managedEnv.id
output environmentName string = managedEnv.name
output environmentDefaultDomain string = managedEnv.properties.defaultDomain
output environmentStaticIp string = managedEnv.properties.staticIp
output webFqdn string = web.properties.configuration.ingress.fqdn
output baseUrl string = effectiveBaseUrl
output webAppId string = web.id
output webAppName string = web.name
output workerAppId string = worker.id
output workerAppName string = worker.name
output deadmanAppId string = deadman.id
output deadmanAppName string = deadman.name

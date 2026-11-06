// Secureddy on Azure. Resource-group scope; run through bootstrap.sh
// (creates the two resource groups) or the deploy workflow.
//
// Two resource groups:
//   core        everything that is ours (this deployment's scope)
//   detonation  empty on purpose; the worker creates one ACI container group
//               per detonation here and deletes it afterwards
//
// Two-stage first run (bootstrap.sh does this for you):
//   1. deployApps=false  -> network, identities, Key Vault, data services, ACR
//      then: seed Key Vault secrets, build + push the images
//   2. deployApps=true   -> Container Apps, Front Door, alerts
// Later runs always use deployApps=true.

targetScope = 'resourceGroup'

// ---------------------------------------------------------------------------
// Parameters
// ---------------------------------------------------------------------------

@description('Azure region for everything regional.')
param location string = resourceGroup().location

@allowed(['dev', 'staging', 'prod'])
param envName string

@description('Short product prefix used in resource names.')
@minLength(2)
@maxLength(8)
param prefix string = 'rsec'

@description('Name of the (already existing) detonation resource group.')
param detonationResourceGroupName string

param tags object = {
  product: 'reddysec'
  owner: 'reddy'
}

@description('Deploy the application tier (Container Apps, Front Door, alerts). False for the first bootstrap pass.')
param deployApps bool = true

@description('Assign the detonation policies. Needs policy rights at subscription scope.')
param deployPolicy bool = true

@description('Public base URL of the product. With a custom domain: https://app.example.com')
param baseUrl string

@description('Custom domain for Front Door (app.example.com). Empty = *.azurefd.net only.')
param customDomain string = ''

// --- globally unique names (empty = derived from the resource group id) ----
param keyVaultName string = ''
param storageAccountName string = ''
param acrName string = ''
param postgresServerName string = ''
param serviceBusNamespaceName string = ''

// --- network ---------------------------------------------------------------
param vnetAddressPrefix string = '10.40.0.0/16'
param appsSubnetPrefix string = '10.40.0.0/23'
param dataSubnetPrefix string = '10.40.2.0/24'
param detonationSubnetPrefix string = '10.40.8.0/22'
param acrPrivateEndpointIps array = ['10.40.2.10', '10.40.2.11']
param deployAppsNatGateway bool = true

// --- operator access -------------------------------------------------------
@description('Public IPs allowed to reach Key Vault over its public endpoint (bootstrap operator). Empty = disabled.')
param adminIpAllowList array = []

@description('Object id of the operator (az ad signed-in-user show --query id).')
param operatorObjectId string = ''

@description('UPN of the operator, used as the Postgres Entra administrator.')
param operatorLogin string = ''

// --- data tier -------------------------------------------------------------
param postgresSkuName string = 'Standard_B1ms'
@allowed(['Burstable', 'GeneralPurpose', 'MemoryOptimized'])
param postgresSkuTier string = 'Burstable'
param postgresStorageGb int = 32
param postgresHighAvailability bool = false
param postgresBackupRetentionDays int = 7
param postgresGeoRedundantBackup bool = false
param postgresAdministratorLogin string = 'rsadmin'
@secure()
param postgresAdministratorPassword string = ''

@allowed(['Standard_LRS', 'Standard_ZRS', 'Standard_GRS', 'Standard_GZRS'])
param storageSku string = 'Standard_LRS'

@allowed(['Standard', 'Premium'])
param serviceBusSku string = 'Standard'

@allowed(['Enabled', 'Disabled'])
param acrPublicNetworkAccess string = 'Enabled'

// --- compute ---------------------------------------------------------------
param zoneRedundant bool = false
param dedicatedWorkloadProfileType string = ''
param imageTag string = 'latest'
param webMinReplicas int = 2
param webMaxReplicas int = 10
param workerMinReplicas int = 1
param workerMaxReplicas int = 3
param detonationTimeoutSeconds int = 45
param detonationMaxConcurrency int = 8
param holdDeadManMinutes int = 10
param logLevel string = 'INFO'

@description('KEK rotation window: Key Vault version id of the previous rs-token-kek (see docs/azure-deploy.md). Empty = single key.')
param tokenKekPreviousVersion string = ''

// --- integrations ----------------------------------------------------------
param googleClientId string = ''
param googlePubsubTopic string = ''
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

// --- edge ------------------------------------------------------------------
@allowed(['Prevention', 'Detection'])
param wafMode string = 'Prevention'
param rateLimitPerMinute int = 300

// --- observability ---------------------------------------------------------
param alertEmails array
param logRetentionDays int = 90
param logDailyQuotaGb int = 5
param monthlyBudgetUsd int = 1500
param budgetStartDate string = utcNow('yyyy-MM-01')

// --- CI/CD -----------------------------------------------------------------
@description('GitHub repository owner/name allowed to deploy via OIDC. Empty disables.')
param githubRepository string = ''

// ---------------------------------------------------------------------------
// Names
// ---------------------------------------------------------------------------

var namePrefix = '${prefix}-${envName}'
var suffix = take(uniqueString(resourceGroup().id), 8)
var kvName = empty(keyVaultName) ? 'kv-${prefix}-${envName}-${suffix}' : keyVaultName
var stName = empty(storageAccountName) ? toLower('st${prefix}${envName}${suffix}') : storageAccountName
var crName = empty(acrName) ? toLower('cr${prefix}${envName}${suffix}') : acrName
var pgName = empty(postgresServerName) ? 'pg-${prefix}-${envName}-${suffix}' : postgresServerName
var sbName = empty(serviceBusNamespaceName) ? 'sb-${prefix}-${envName}-${suffix}' : serviceBusNamespaceName

var allTags = union(tags, { env: envName })

// ---------------------------------------------------------------------------
// Foundation
// ---------------------------------------------------------------------------

module monitoring 'modules/monitoring.bicep' = {
  name: 'monitoring'
  params: {
    location: location
    namePrefix: namePrefix
    tags: allTags
    logRetentionDays: logRetentionDays
    dailyQuotaGb: logDailyQuotaGb
    alertEmails: alertEmails
  }
}

module identity 'modules/identity.bicep' = {
  name: 'identity'
  params: {
    location: location
    namePrefix: namePrefix
    tags: allTags
    githubRepository: githubRepository
  }
}

module network 'modules/network.bicep' = {
  name: 'network'
  params: {
    location: location
    namePrefix: namePrefix
    tags: allTags
    vnetAddressPrefix: vnetAddressPrefix
    appsSubnetPrefix: appsSubnetPrefix
    dataSubnetPrefix: dataSubnetPrefix
    detonationSubnetPrefix: detonationSubnetPrefix
    acrPrivateEndpointIps: acrPrivateEndpointIps
    deployAppsNatGateway: deployAppsNatGateway
    workerPrincipalId: identity.outputs.workerPrincipalId
    logAnalyticsWorkspaceId: monitoring.outputs.logAnalyticsWorkspaceId
  }
}

module keyVault 'modules/keyvault.bicep' = {
  name: 'keyvault'
  params: {
    location: location
    namePrefix: namePrefix
    tags: allTags
    keyVaultName: kvName
    adminIpAllowList: adminIpAllowList
    operatorObjectId: operatorObjectId
    webPrincipalId: identity.outputs.webPrincipalId
    workerPrincipalId: identity.outputs.workerPrincipalId
    deadmanPrincipalId: identity.outputs.deadmanPrincipalId
    deployPrincipalId: identity.outputs.deployPrincipalId
    dataSubnetId: network.outputs.dataSubnetId
    privateDnsZoneId: network.outputs.keyVaultDnsZoneId
    logAnalyticsWorkspaceId: monitoring.outputs.logAnalyticsWorkspaceId
  }
}

// ---------------------------------------------------------------------------
// Data tier
// ---------------------------------------------------------------------------

module postgres 'modules/postgres.bicep' = {
  name: 'postgres'
  params: {
    location: location
    namePrefix: namePrefix
    tags: allTags
    serverName: pgName
    skuName: postgresSkuName
    skuTier: postgresSkuTier
    storageSizeGb: postgresStorageGb
    highAvailability: postgresHighAvailability
    backupRetentionDays: postgresBackupRetentionDays
    geoRedundantBackup: postgresGeoRedundantBackup
    administratorLogin: postgresAdministratorLogin
    administratorLoginPassword: postgresAdministratorPassword
    entraAdminObjectId: operatorObjectId
    entraAdminLogin: operatorLogin
    dataSubnetId: network.outputs.dataSubnetId
    privateDnsZoneId: network.outputs.postgresDnsZoneId
    logAnalyticsWorkspaceId: monitoring.outputs.logAnalyticsWorkspaceId
  }
}

module storage 'modules/storage.bicep' = {
  name: 'storage'
  params: {
    location: location
    namePrefix: namePrefix
    tags: allTags
    storageAccountName: stName
    skuName: storageSku
    webPrincipalId: identity.outputs.webPrincipalId
    workerPrincipalId: identity.outputs.workerPrincipalId
    deadmanPrincipalId: identity.outputs.deadmanPrincipalId
    dataSubnetId: network.outputs.dataSubnetId
    privateDnsZoneId: network.outputs.blobDnsZoneId
    logAnalyticsWorkspaceId: monitoring.outputs.logAnalyticsWorkspaceId
  }
}

module serviceBus 'modules/servicebus.bicep' = {
  name: 'servicebus'
  params: {
    location: location
    namePrefix: namePrefix
    tags: allTags
    namespaceName: sbName
    sku: serviceBusSku
    webPrincipalId: identity.outputs.webPrincipalId
    workerPrincipalId: identity.outputs.workerPrincipalId
    deadmanPrincipalId: identity.outputs.deadmanPrincipalId
    dataSubnetId: network.outputs.dataSubnetId
    privateDnsZoneId: network.outputs.serviceBusDnsZoneId
    logAnalyticsWorkspaceId: monitoring.outputs.logAnalyticsWorkspaceId
  }
}

module acr 'modules/acr.bicep' = {
  name: 'acr'
  params: {
    location: location
    namePrefix: namePrefix
    tags: allTags
    registryName: crName
    publicNetworkAccess: acrPublicNetworkAccess
    zoneRedundant: zoneRedundant
    privateEndpointIps: acrPrivateEndpointIps
    webPrincipalId: identity.outputs.webPrincipalId
    workerPrincipalId: identity.outputs.workerPrincipalId
    deadmanPrincipalId: identity.outputs.deadmanPrincipalId
    deployPrincipalId: identity.outputs.deployPrincipalId
    dataSubnetId: network.outputs.dataSubnetId
    privateDnsZoneId: network.outputs.acrDnsZoneId
    logAnalyticsWorkspaceId: monitoring.outputs.logAnalyticsWorkspaceId
  }
}

// ---------------------------------------------------------------------------
// Detonation resource group + policy
// ---------------------------------------------------------------------------

module policyDefinitions 'modules/policy-definitions.bicep' = if (deployPolicy) {
  name: 'policy-definitions-${envName}'
  scope: subscription()
  params: {
    namePrefix: namePrefix
  }
}

module subscriptionRbac 'modules/sub-rbac.bicep' = if (deployPolicy) {
  name: 'sub-rbac-${envName}'
  scope: subscription()
  params: {
    deployPrincipalId: identity.outputs.deployPrincipalId
  }
}

module detonationRg 'modules/aci-detonation.bicep' = {
  name: 'aci-detonation'
  scope: resourceGroup(detonationResourceGroupName)
  params: {
    workerPrincipalId: identity.outputs.workerPrincipalId
    deployPrincipalId: identity.outputs.deployPrincipalId
    assignPolicies: deployPolicy
    denyPublicIpPolicyId: policyDefinitions.?outputs.?denyPublicIpId ?? ''
    denyRestartPolicyId: policyDefinitions.?outputs.?denyRestartId ?? ''
    requireSubnetPolicyId: policyDefinitions.?outputs.?requireSubnetId ?? ''
    denyIdentityPolicyId: policyDefinitions.?outputs.?denyIdentityId ?? ''
  }
}

// ---------------------------------------------------------------------------
// Application tier
// ---------------------------------------------------------------------------

var appImage = '${acr.outputs.loginServer}/reddysec-app:${imageTag}'
var chamberImage = '${acr.outputs.loginServer}/reddysec-chamber:${imageTag}'

module containerApps 'modules/containerapps.bicep' = if (deployApps) {
  name: 'containerapps'
  params: {
    location: location
    namePrefix: namePrefix
    tags: allTags
    envName: envName
    baseUrl: baseUrl
    zoneRedundant: zoneRedundant
    dedicatedWorkloadProfileType: dedicatedWorkloadProfileType
    appsSubnetId: network.outputs.appsSubnetId
    logAnalyticsWorkspaceId: monitoring.outputs.logAnalyticsWorkspaceId
    appInsightsConnectionString: monitoring.outputs.appInsightsConnectionString
    acrLoginServer: acr.outputs.loginServer
    appImage: appImage
    chamberImage: chamberImage
    keyVaultUri: keyVault.outputs.keyVaultUri
    webIdentityId: identity.outputs.webIdentityId
    webClientId: identity.outputs.webClientId
    workerIdentityId: identity.outputs.workerIdentityId
    workerClientId: identity.outputs.workerClientId
    deadmanIdentityId: identity.outputs.deadmanIdentityId
    deadmanClientId: identity.outputs.deadmanClientId
    storageBlobEndpoint: storage.outputs.blobEndpoint
    artifactsContainer: storage.outputs.artifactsContainer
    quarantineContainer: storage.outputs.quarantineContainer
    serviceBusNamespaceName: serviceBus.outputs.namespaceName
    serviceBusNamespaceFqdn: serviceBus.outputs.namespaceFqdn
    detonationsQueueName: serviceBus.outputs.detonationsQueueName
    notificationsQueueName: serviceBus.outputs.notificationsQueueName
    detonationResourceGroupName: detonationResourceGroupName
    detonationSubnetId: network.outputs.detonationSubnetId
    acrChamberPullTokenName: acr.outputs.chamberPullTokenName
    webMinReplicas: webMinReplicas
    webMaxReplicas: webMaxReplicas
    workerMinReplicas: workerMinReplicas
    workerMaxReplicas: workerMaxReplicas
    detonationTimeoutSeconds: detonationTimeoutSeconds
    detonationMaxConcurrency: detonationMaxConcurrency
    holdDeadManMinutes: holdDeadManMinutes
    logLevel: logLevel
    tokenKekPreviousVersion: tokenKekPreviousVersion
    googleClientId: googleClientId
    googlePubsubTopic: googlePubsubTopic
    safeBrowsingEnabled: safeBrowsingEnabled
    azureOpenAiEnabled: azureOpenAiEnabled
    azureOpenAiEndpoint: azureOpenAiEndpoint
    azureOpenAiDeployment: azureOpenAiDeployment
    smtpEnabled: smtpEnabled
    smtpHost: smtpHost
    smtpPort: smtpPort
    smtpUsername: smtpUsername
    notificationFrom: notificationFrom
    notifyWebhookUrl: notifyWebhookUrl
  }
  dependsOn: [detonationRg]
}

module edge 'modules/edge.bicep' = if (deployApps) {
  name: 'edge'
  params: {
    location: location
    namePrefix: namePrefix
    tags: allTags
    containerAppsEnvironmentId: containerApps.?outputs.?environmentId ?? ''
    webFqdn: containerApps.?outputs.?webFqdn ?? ''
    customDomain: customDomain
    wafMode: wafMode
    rateLimitPerMinute: rateLimitPerMinute
    logAnalyticsWorkspaceId: monitoring.outputs.logAnalyticsWorkspaceId
  }
}

module alerts 'modules/alerts.bicep' = if (deployApps) {
  name: 'alerts'
  params: {
    location: location
    namePrefix: namePrefix
    tags: allTags
    actionGroupId: monitoring.outputs.actionGroupId
    logAnalyticsWorkspaceId: monitoring.outputs.logAnalyticsWorkspaceId
    frontDoorProfileId: edge.?outputs.?profileId ?? ''
    webAppId: containerApps.?outputs.?webAppId ?? ''
    workerAppId: containerApps.?outputs.?workerAppId ?? ''
    deadmanAppId: containerApps.?outputs.?deadmanAppId ?? ''
    postgresServerId: postgres.outputs.serverId
    detonationResourceGroupId: detonationRg.outputs.resourceGroupId
    monthlyBudgetUsd: monthlyBudgetUsd
    budgetStartDate: budgetStartDate
    alertEmails: alertEmails
  }
}

// ---------------------------------------------------------------------------
// Outputs (bootstrap.sh and the deploy workflow read these)
// ---------------------------------------------------------------------------

output keyVaultName string = keyVault.outputs.keyVaultName
output keyVaultUri string = keyVault.outputs.keyVaultUri
output acrName string = acr.outputs.registryName
output acrLoginServer string = acr.outputs.loginServer
output acrChamberPullTokenName string = acr.outputs.chamberPullTokenName
output postgresServerName string = postgres.outputs.serverName
output postgresFqdn string = postgres.outputs.serverFqdn
output postgresDatabase string = postgres.outputs.databaseName
output postgresAdministratorLogin string = postgres.outputs.administratorLogin
output storageAccountName string = storage.outputs.storageAccountName
output serviceBusNamespace string = serviceBus.outputs.namespaceName
output detonationEgressIps array = network.outputs.detonationEgressIps
output appsEgressIp string = network.outputs.appsEgressIp
output detonationSubnetId string = network.outputs.detonationSubnetId
output logAnalyticsWorkspaceId string = monitoring.outputs.logAnalyticsWorkspaceId
output deployIdentityClientId string = identity.outputs.deployClientId
output workerIdentityClientId string = identity.outputs.workerClientId
output containerAppsEnvironmentId string = containerApps.?outputs.?environmentId ?? ''
output webFqdn string = containerApps.?outputs.?webFqdn ?? ''
output webAppName string = containerApps.?outputs.?webAppName ?? ''
output workerAppName string = containerApps.?outputs.?workerAppName ?? ''
output deadmanAppName string = containerApps.?outputs.?deadmanAppName ?? ''
output frontDoorEndpointHostName string = edge.?outputs.?endpointHostName ?? ''
output frontDoorId string = edge.?outputs.?frontDoorId ?? ''
output customDomainValidationToken string = edge.?outputs.?customDomainValidationToken ?? ''

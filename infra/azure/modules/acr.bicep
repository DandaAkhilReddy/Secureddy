// Azure Container Registry, Premium (needed for private endpoints, scope maps
// and zone redundancy). Admin user disabled; anonymous pull disabled.
//
// Two repositories: reddysec-app (web, worker, deadman) and reddysec-chamber.
//
// Pulls inside the VNet go through the private endpoint with STATIC IPs, so the
// detonation NSG can allow 443 to exactly those two addresses.
//
// Chamber containers hold no managed identity (nothing to steal if the browser
// is escaped), so they pull with a repository-scoped token limited to
// reddysec-chamber:read. bootstrap.sh generates the token password and stores
// it in Key Vault.
//
// Public endpoint: GitHub-hosted runners have no stable IPs, so `az acr build`
// needs the public endpoint (Entra ID auth only). Set publicNetworkAccess to
// Disabled once CI runs from a self-hosted runner in the VNet or an ACR agent pool.

param location string
param namePrefix string
param tags object = {}

@minLength(5)
@maxLength(50)
@description('Globally unique, alphanumerics only.')
param registryName string

@allowed(['Enabled', 'Disabled'])
param publicNetworkAccess string = 'Enabled'

param zoneRedundant bool = false

@description('Days to keep untagged manifests before the retention policy deletes them.')
param untaggedRetentionDays int = 7

@description('Two static IPs in the data subnet for the private endpoint (registry, registry_data).')
param privateEndpointIps array

param webPrincipalId string
param workerPrincipalId string
param deadmanPrincipalId string
param deployPrincipalId string

param dataSubnetId string
param privateDnsZoneId string
param logAnalyticsWorkspaceId string

var acrPullRoleId = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '7f951dda-4ed3-4680-a7ca-43fe172d538d')
var acrPushRoleId = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '8311e382-0749-4cb8-b61a-304f252e45ec')

resource registry 'Microsoft.ContainerRegistry/registries@2023-07-01' = {
  name: registryName
  location: location
  tags: tags
  sku: { name: 'Premium' }
  properties: {
    // Anonymous pull is off by default and only settable through the preview
    // API; we stay on the GA API and keep the default.
    adminUserEnabled: false
    dataEndpointEnabled: true
    zoneRedundancy: zoneRedundant ? 'Enabled' : 'Disabled'
    publicNetworkAccess: publicNetworkAccess
    networkRuleBypassOptions: 'AzureServices'
    networkRuleSet: {
      defaultAction: publicNetworkAccess == 'Enabled' ? 'Allow' : 'Deny'
    }
    policies: {
      retentionPolicy: { status: 'enabled', days: untaggedRetentionDays }
      quarantinePolicy: { status: 'disabled' }
      trustPolicy: { status: 'disabled', type: 'Notary' }
      exportPolicy: { status: 'enabled' }
    }
  }
}

resource chamberPullScope 'Microsoft.ContainerRegistry/registries/scopeMaps@2023-07-01' = {
  parent: registry
  name: 'chamber-pull'
  properties: {
    description: 'Pull-only access to the chamber image for detonation container groups'
    actions: [
      'repositories/reddysec-chamber/content/read'
    ]
  }
}

resource chamberPullToken 'Microsoft.ContainerRegistry/registries/tokens@2023-07-01' = {
  parent: registry
  name: 'chamber-pull'
  properties: {
    scopeMapId: chamberPullScope.id
    status: 'enabled'
    // Passwords are generated out of band: az acr token credential generate
  }
}

module privateEndpoint 'private-endpoint.bicep' = {
  name: '${registryName}-pe'
  params: {
    location: location
    tags: tags
    name: '${namePrefix}-pe-acr'
    subnetId: dataSubnetId
    privateLinkServiceId: registry.id
    groupId: 'registry'
    privateDnsZoneId: privateDnsZoneId
    ipConfigurations: [
      {
        name: 'registry'
        groupId: 'registry'
        memberName: 'registry'
        privateIPAddress: privateEndpointIps[0]
      }
      {
        name: 'registry-data'
        groupId: 'registry'
        memberName: 'registry_data_${location}'
        privateIPAddress: privateEndpointIps[1]
      }
    ]
  }
}

// --- RBAC ------------------------------------------------------------------

var pullers = [
  { id: webPrincipalId, label: 'web' }
  { id: workerPrincipalId, label: 'worker' }
  { id: deadmanPrincipalId, label: 'deadman' }
]

resource acrPull 'Microsoft.Authorization/roleAssignments@2022-04-01' = [
  for p in pullers: {
    name: guid(registry.id, p.id, acrPullRoleId)
    scope: registry
    properties: {
      roleDefinitionId: acrPullRoleId
      principalId: p.id
      principalType: 'ServicePrincipal'
      description: 'reddysec ${p.label}: pull images'
    }
  }
]

resource deployPush 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(registry.id, deployPrincipalId, acrPushRoleId)
  scope: registry
  properties: {
    roleDefinitionId: acrPushRoleId
    principalId: deployPrincipalId
    principalType: 'ServicePrincipal'
    description: 'GitHub deploy identity: push images'
  }
}

resource diag 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'to-law'
  scope: registry
  properties: {
    workspaceId: logAnalyticsWorkspaceId
    logs: [{ categoryGroup: 'allLogs', enabled: true }]
    metrics: [{ category: 'AllMetrics', enabled: true }]
  }
}

output registryId string = registry.id
output registryName string = registry.name
output loginServer string = registry.properties.loginServer
output chamberPullTokenName string = chamberPullToken.name

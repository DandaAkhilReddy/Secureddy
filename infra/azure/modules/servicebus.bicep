// Service Bus: the job queue between web/worker and the dead man's switch.
//
//   detonations    worker input; the Container Apps scale rule watches its length
//   notifications  outbound client notifications (email / webhook)
//
// Local (SAS) auth is disabled: every client authenticates with its managed
// identity. Dead-lettering is on for both queues.
//
// Tier trade-off: private endpoints and IP firewall rules exist only on the
// Premium tier (~USD 680/month for one messaging unit). Standard is enough for
// this volume, so Standard keeps a public endpoint protected by Entra ID auth
// and TLS 1.2. Set sku=Premium to get the private endpoint; the template then
// disables public access automatically.

param location string
param namePrefix string
param tags object = {}

@description('Globally unique namespace name.')
param namespaceName string

@allowed(['Standard', 'Premium'])
param sku string = 'Standard'

param webPrincipalId string
param workerPrincipalId string
param deadmanPrincipalId string

param dataSubnetId string
param privateDnsZoneId string
param logAnalyticsWorkspaceId string

var isPremium = sku == 'Premium'

var dataOwnerRoleId = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '090c5cfd-751d-490a-894a-3ce6f1109419')
var dataSenderRoleId = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '69a216fc-b8fb-44d8-bc22-1f3c2cd27a39')

resource namespace 'Microsoft.ServiceBus/namespaces@2024-01-01' = {
  name: namespaceName
  location: location
  tags: tags
  sku: {
    name: sku
    tier: sku
    capacity: isPremium ? 1 : null
  }
  properties: {
    disableLocalAuth: true
    minimumTlsVersion: '1.2'
    publicNetworkAccess: isPremium ? 'Disabled' : 'Enabled'
    premiumMessagingPartitions: isPremium ? 1 : null
  }
}

resource detonations 'Microsoft.ServiceBus/namespaces/queues@2024-01-01' = {
  parent: namespace
  name: 'detonations'
  properties: {
    // A detonation runs up to ~90 s plus ACI start-up; renew the lock in the worker.
    lockDuration: 'PT5M'
    maxDeliveryCount: 3
    deadLetteringOnMessageExpiration: true
    defaultMessageTimeToLive: 'P1D'
    requiresDuplicateDetection: true
    duplicateDetectionHistoryTimeWindow: 'PT10M'
    enablePartitioning: false
    enableBatchedOperations: true
  }
}

resource notifications 'Microsoft.ServiceBus/namespaces/queues@2024-01-01' = {
  parent: namespace
  name: 'notifications'
  properties: {
    lockDuration: 'PT1M'
    maxDeliveryCount: 5
    deadLetteringOnMessageExpiration: true
    defaultMessageTimeToLive: 'P7D'
    enablePartitioning: false
    enableBatchedOperations: true
  }
}

module privateEndpoint 'private-endpoint.bicep' = if (isPremium) {
  name: '${namespaceName}-pe'
  params: {
    location: location
    tags: tags
    name: '${namePrefix}-pe-servicebus'
    subnetId: dataSubnetId
    privateLinkServiceId: namespace.id
    groupId: 'namespace'
    privateDnsZoneId: privateDnsZoneId
  }
}

// --- RBAC ------------------------------------------------------------------

resource workerOwner 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(namespace.id, workerPrincipalId, dataOwnerRoleId)
  scope: namespace
  properties: {
    roleDefinitionId: dataOwnerRoleId
    principalId: workerPrincipalId
    principalType: 'ServicePrincipal'
    description: 'reddysec worker: receive, complete, dead-letter, read queue length for scaling'
  }
}

resource webSender 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(namespace.id, webPrincipalId, dataSenderRoleId)
  scope: namespace
  properties: {
    roleDefinitionId: dataSenderRoleId
    principalId: webPrincipalId
    principalType: 'ServicePrincipal'
  }
}

resource deadmanSender 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(namespace.id, deadmanPrincipalId, dataSenderRoleId)
  scope: namespace
  properties: {
    roleDefinitionId: dataSenderRoleId
    principalId: deadmanPrincipalId
    principalType: 'ServicePrincipal'
  }
}

resource diag 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'to-law'
  scope: namespace
  properties: {
    workspaceId: logAnalyticsWorkspaceId
    logs: [{ categoryGroup: 'allLogs', enabled: true }]
    metrics: [{ category: 'AllMetrics', enabled: true }]
  }
}

output namespaceId string = namespace.id
output namespaceName string = namespace.name
output namespaceFqdn string = replace(replace(namespace.properties.serviceBusEndpoint, 'https://', ''), ':443/', '')
output detonationsQueueName string = detonations.name
output notificationsQueueName string = notifications.name

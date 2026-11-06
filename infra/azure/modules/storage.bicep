// Artifact storage: screenshots, downloaded files, sanitized copies, and the
// original bytes of quarantined attachments.
//
//   artifacts             deleted 30 days after last modification
//   quarantine-originals  deleted 90 days after last modification
//
// Identity-only access (shared keys disabled), private endpoint only, TLS 1.2,
// no versioning. lean=true (dev cost profile): public endpoint instead of the
// private endpoint; still identity-only (no shared keys, no anonymous blobs),
// so a caller needs one of the three app identities' roles. Blob soft delete is OFF on purpose: the 30/90-day retention
// is a promise to the client, and a soft-deleted blob still exists.

param location string
param namePrefix string
param tags object = {}

@minLength(3)
@maxLength(24)
@description('Globally unique, lowercase letters and numbers only.')
param storageAccountName string

@description('Standard_ZRS in prod, Standard_LRS in dev.')
@allowed(['Standard_LRS', 'Standard_ZRS', 'Standard_GRS', 'Standard_GZRS'])
param skuName string = 'Standard_LRS'

param artifactsRetentionDays int = 30
param quarantineRetentionDays int = 90

param webPrincipalId string
param workerPrincipalId string
param deadmanPrincipalId string

param dataSubnetId string
param privateDnsZoneId string
param logAnalyticsWorkspaceId string

@description('Lean cost profile: public endpoint (identity-only auth), no private endpoint.')
param lean bool = false

var blobDataContributorRoleId = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'ba92f5b4-2d11-453d-a403-e96b0029c9fe')
var blobDataReaderRoleId = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '2a2b9908-6ea1-4ae2-8e65-a410df84e7d1')

resource account 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: storageAccountName
  location: location
  tags: tags
  kind: 'StorageV2'
  sku: { name: skuName }
  properties: {
    accessTier: 'Hot'
    minimumTlsVersion: 'TLS1_2'
    supportsHttpsTrafficOnly: true
    allowBlobPublicAccess: false
    allowSharedKeyAccess: false
    defaultToOAuthAuthentication: true
    allowCrossTenantReplication: false
    publicNetworkAccess: lean ? 'Enabled' : 'Disabled'
    networkAcls: {
      bypass: 'AzureServices'
      defaultAction: lean ? 'Allow' : 'Deny'
    }
    encryption: {
      keySource: 'Microsoft.Storage'
      requireInfrastructureEncryption: true
      services: {
        blob: { enabled: true, keyType: 'Account' }
      }
    }
  }
}

resource blobService 'Microsoft.Storage/storageAccounts/blobServices@2023-05-01' = {
  parent: account
  name: 'default'
  properties: {
    isVersioningEnabled: false
    deleteRetentionPolicy: { enabled: false }
    containerDeleteRetentionPolicy: { enabled: true, days: 7 }
  }
}

resource artifacts 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = {
  parent: blobService
  name: 'artifacts'
  properties: { publicAccess: 'None' }
}

resource quarantine 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = {
  parent: blobService
  name: 'quarantine-originals'
  properties: { publicAccess: 'None' }
}

resource lifecycle 'Microsoft.Storage/storageAccounts/managementPolicies@2023-05-01' = {
  parent: account
  name: 'default'
  properties: {
    policy: {
      rules: [
        {
          name: 'artifacts-${artifactsRetentionDays}d'
          enabled: true
          type: 'Lifecycle'
          definition: {
            filters: {
              blobTypes: ['blockBlob']
              prefixMatch: ['artifacts/']
            }
            actions: {
              baseBlob: {
                delete: { daysAfterModificationGreaterThan: artifactsRetentionDays }
              }
            }
          }
        }
        {
          name: 'quarantine-originals-${quarantineRetentionDays}d'
          enabled: true
          type: 'Lifecycle'
          definition: {
            filters: {
              blobTypes: ['blockBlob']
              prefixMatch: ['quarantine-originals/']
            }
            actions: {
              baseBlob: {
                delete: { daysAfterModificationGreaterThan: quarantineRetentionDays }
              }
            }
          }
        }
      ]
    }
  }
}

module privateEndpoint 'private-endpoint.bicep' = if (!lean) {
  name: '${storageAccountName}-pe'
  params: {
    location: location
    tags: tags
    name: '${namePrefix}-pe-blob'
    subnetId: dataSubnetId
    privateLinkServiceId: account.id
    groupId: 'blob'
    privateDnsZoneId: privateDnsZoneId
  }
}

// --- RBAC ------------------------------------------------------------------
// worker writes screenshots/downloads; web writes Reading Room downloads and
// serves screenshots; deadman only reads.

resource workerContributor 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(account.id, workerPrincipalId, blobDataContributorRoleId)
  scope: account
  properties: {
    roleDefinitionId: blobDataContributorRoleId
    principalId: workerPrincipalId
    principalType: 'ServicePrincipal'
  }
}

resource webContributor 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(account.id, webPrincipalId, blobDataContributorRoleId)
  scope: account
  properties: {
    roleDefinitionId: blobDataContributorRoleId
    principalId: webPrincipalId
    principalType: 'ServicePrincipal'
  }
}

resource deadmanReader 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(account.id, deadmanPrincipalId, blobDataReaderRoleId)
  scope: account
  properties: {
    roleDefinitionId: blobDataReaderRoleId
    principalId: deadmanPrincipalId
    principalType: 'ServicePrincipal'
  }
}

resource accountDiag 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'to-law'
  scope: account
  properties: {
    workspaceId: logAnalyticsWorkspaceId
    metrics: [{ category: 'Transaction', enabled: true }]
  }
}

resource blobDiag 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'to-law'
  scope: blobService
  properties: {
    workspaceId: logAnalyticsWorkspaceId
    logs: [{ categoryGroup: 'allLogs', enabled: true }]
    metrics: [{ category: 'Transaction', enabled: true }]
  }
}

output storageAccountId string = account.id
output storageAccountName string = account.name
output blobEndpoint string = account.properties.primaryEndpoints.blob
output artifactsContainer string = artifacts.name
output quarantineContainer string = quarantine.name

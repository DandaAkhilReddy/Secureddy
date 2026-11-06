// Azure Database for PostgreSQL Flexible Server 16.
//
//   prod: General Purpose, zone-redundant HA, 35-day geo-redundant backups
//   dev:  Burstable, no HA, 7-day local backups
//
// Private access only (private endpoint in the data subnet). Password auth for
// the application (URL stored in Key Vault as rs-database-url) plus an Entra ID
// administrator for humans. The admin password is only sent on first create;
// later deployments omit it so the server keeps whatever is in Key Vault.

param location string

@description('Region of the VNet; a private endpoint must live where its subnet lives, even when the server is elsewhere.')
param privateEndpointLocation string = location
param namePrefix string
param tags object = {}

@description('Globally unique server name (lowercase letters, numbers, hyphens).')
param serverName string

@description('SKU name, e.g. Standard_B1ms (dev) or Standard_D2ds_v5 (prod).')
param skuName string = 'Standard_B1ms'

@allowed(['Burstable', 'GeneralPurpose', 'MemoryOptimized'])
param skuTier string = 'Burstable'

@minValue(32)
param storageSizeGb int = 32

@description('Zone-redundant HA. Requires GeneralPurpose or MemoryOptimized.')
param highAvailability bool = false

@minValue(7)
@maxValue(35)
param backupRetentionDays int = 7

@description('Geo-redundant backups. Create-time only: changing it later needs a new server (restore into one).')
param geoRedundantBackup bool = false

param administratorLogin string = 'rsadmin'

@secure()
@description('Admin password. Required on first create. Leave empty on later deployments to keep the current password.')
param administratorLoginPassword string = ''

@description('Entra ID object id of the human administrator (az ad signed-in-user show --query id). Empty skips.')
param entraAdminObjectId string = ''

@description('Entra ID login name (UPN) matching entraAdminObjectId.')
param entraAdminLogin string = ''

@allowed(['User', 'Group', 'ServicePrincipal'])
param entraAdminPrincipalType string = 'User'

param dataSubnetId string
param privateDnsZoneId string
param logAnalyticsWorkspaceId string

resource server 'Microsoft.DBforPostgreSQL/flexibleServers@2024-08-01' = {
  name: serverName
  location: location
  tags: tags
  sku: {
    name: skuName
    tier: skuTier
  }
  properties: {
    version: '16'
    administratorLogin: administratorLogin
    administratorLoginPassword: empty(administratorLoginPassword) ? null : administratorLoginPassword
    authConfig: {
      activeDirectoryAuth: 'Enabled'
      passwordAuth: 'Enabled'
      tenantId: tenant().tenantId
    }
    storage: {
      storageSizeGB: storageSizeGb
      autoGrow: 'Enabled'
    }
    backup: {
      backupRetentionDays: backupRetentionDays
      geoRedundantBackup: geoRedundantBackup ? 'Enabled' : 'Disabled'
    }
    highAvailability: {
      mode: highAvailability ? 'ZoneRedundant' : 'Disabled'
    }
    network: {
      publicNetworkAccess: 'Disabled'
    }
    maintenanceWindow: {
      // Sunday 09:00 UTC = 01:00/02:00 Pacific
      customWindow: 'Enabled'
      dayOfWeek: 0
      startHour: 9
      startMinute: 0
    }
  }
}

resource database 'Microsoft.DBforPostgreSQL/flexibleServers/databases@2024-08-01' = {
  parent: server
  name: 'reddysec'
  properties: {
    charset: 'UTF8'
    collation: 'en_US.utf8'
  }
}

// Child operations on a flexible server must not overlap: admin after database.
resource entraAdmin 'Microsoft.DBforPostgreSQL/flexibleServers/administrators@2024-08-01' = if (!empty(entraAdminObjectId)) {
  parent: server
  name: entraAdminObjectId
  properties: {
    principalType: entraAdminPrincipalType
    principalName: entraAdminLogin
    tenantId: tenant().tenantId
  }
  dependsOn: [database]
}

module privateEndpoint 'private-endpoint.bicep' = {
  name: '${serverName}-pe'
  params: {
    location: privateEndpointLocation
    tags: tags
    name: '${namePrefix}-pe-postgres'
    subnetId: dataSubnetId
    privateLinkServiceId: server.id
    groupId: 'postgresqlServer'
    privateDnsZoneId: privateDnsZoneId
  }
}

resource diag 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'to-law'
  scope: server
  properties: {
    workspaceId: logAnalyticsWorkspaceId
    logs: [{ categoryGroup: 'allLogs', enabled: true }]
    metrics: [{ category: 'AllMetrics', enabled: true }]
  }
}

output serverId string = server.id
output serverName string = server.name
output serverFqdn string = server.properties.fullyQualifiedDomainName
output databaseName string = database.name
output administratorLogin string = administratorLogin

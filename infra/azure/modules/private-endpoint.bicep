// One private endpoint + its private DNS zone group. Used by every data service.

param location string
param name string
param tags object = {}

@description('Subnet the endpoint NIC lands in (the data subnet).')
param subnetId string

@description('Resource id of the service being exposed privately.')
param privateLinkServiceId string

@description('Sub-resource (group id), e.g. vault, blob, postgresqlServer, registry, namespace.')
param groupId string

@description('Private DNS zone that receives the A records.')
param privateDnsZoneId string

@description('Optional static IP configuration(s). Each item: { name, groupId, memberName, privateIPAddress }.')
param ipConfigurations array = []

resource pe 'Microsoft.Network/privateEndpoints@2024-05-01' = {
  name: name
  location: location
  tags: tags
  properties: {
    subnet: { id: subnetId }
    customNetworkInterfaceName: '${name}-nic'
    privateLinkServiceConnections: [
      {
        name: name
        properties: {
          privateLinkServiceId: privateLinkServiceId
          groupIds: [groupId]
        }
      }
    ]
    ipConfigurations: [
      for cfg in ipConfigurations: {
        name: cfg.name
        properties: {
          groupId: cfg.groupId
          memberName: cfg.memberName
          privateIPAddress: cfg.privateIPAddress
        }
      }
    ]
  }
}

resource dnsGroup 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups@2024-05-01' = {
  parent: pe
  name: 'default'
  properties: {
    privateDnsZoneConfigs: [
      {
        name: 'default'
        properties: { privateDnsZoneId: privateDnsZoneId }
      }
    ]
  }
}

output privateEndpointId string = pe.id

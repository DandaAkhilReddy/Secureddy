// Network: one VNet, three subnets, two NAT gateways, the detonation NSG and
// the private DNS zones every private endpoint needs.
//
//   apps        Container Apps environment (web, worker, deadman)
//   data        private endpoints (Key Vault, Storage, Postgres, ACR, Service Bus)
//   detonation  ACI container groups, one per detonation. "Dirty" subnet:
//               may only talk to the Internet on 80/443/53 and to the ACR
//               private endpoint to pull its image. Never to anything private.
//
// Egress from the detonation subnet goes through its own NAT gateway with two
// dedicated public IPs. Those two IPs are what a phishing site sees. The apps
// subnet has a separate NAT gateway so platform traffic (Google APIs, IMAP)
// never shares an IP with detonations.

@description('Azure region.')
param location string

@description('Name prefix, e.g. rsec-prod.')
param namePrefix string

param tags object = {}

param vnetAddressPrefix string = '10.40.0.0/16'
param appsSubnetPrefix string = '10.40.0.0/23'
param dataSubnetPrefix string = '10.40.2.0/24'
param detonationSubnetPrefix string = '10.40.8.0/22'

@description('Static private IPs reserved for the ACR private endpoint (registry, registry_data). The detonation NSG allows 443 to exactly these.')
param acrPrivateEndpointIps array

@description('Deploy a NAT gateway for the apps subnet (stable platform egress IP). Set false to save ~USD 35/month in dev.')
param deployAppsNatGateway bool = true

@description('Principal id of the worker identity. Gets Network Contributor on the detonation subnet so it can create VNet-injected container groups.')
param workerPrincipalId string

@description('Log Analytics workspace for diagnostic settings.')
param logAnalyticsWorkspaceId string

// Network Contributor
var networkContributorRoleId = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '4d97b98b-1d4f-4787-a291-c67834d212e7')

// Azure's recursive resolver / wire server. DNS only.
var azureDnsIp = '168.63.129.16/32'

// ---------------------------------------------------------------------------
// Public IPs and NAT gateways
// ---------------------------------------------------------------------------

resource detonationPip 'Microsoft.Network/publicIPAddresses@2024-05-01' = [
  for i in range(0, 2): {
    name: '${namePrefix}-pip-detonation-${i}'
    location: location
    tags: tags
    sku: { name: 'Standard', tier: 'Regional' }
    properties: {
      publicIPAllocationMethod: 'Static'
      publicIPAddressVersion: 'IPv4'
      idleTimeoutInMinutes: 4
    }
  }
]

resource detonationNat 'Microsoft.Network/natGateways@2024-05-01' = {
  name: '${namePrefix}-nat-detonation'
  location: location
  tags: tags
  sku: { name: 'Standard' }
  properties: {
    idleTimeoutInMinutes: 4
    publicIpAddresses: [
      for i in range(0, 2): {
        id: detonationPip[i].id
      }
    ]
  }
}

resource appsPip 'Microsoft.Network/publicIPAddresses@2024-05-01' = if (deployAppsNatGateway) {
  name: '${namePrefix}-pip-apps-0'
  location: location
  tags: tags
  sku: { name: 'Standard', tier: 'Regional' }
  properties: {
    publicIPAllocationMethod: 'Static'
    publicIPAddressVersion: 'IPv4'
    idleTimeoutInMinutes: 4
  }
}

resource appsNat 'Microsoft.Network/natGateways@2024-05-01' = if (deployAppsNatGateway) {
  name: '${namePrefix}-nat-apps'
  location: location
  tags: tags
  sku: { name: 'Standard' }
  properties: {
    idleTimeoutInMinutes: 10
    publicIpAddresses: [
      {
        id: appsPip.id
      }
    ]
  }
}

// ---------------------------------------------------------------------------
// Network security groups
// ---------------------------------------------------------------------------

// Detonation subnet: deny-by-default in both directions. Outbound allows only
// DNS to Azure DNS, 443 to the ACR private endpoint (image pull), and
// 80/443/53 to the public Internet. Everything private is denied explicitly
// before the Internet allow so the order is obvious to a reviewer.
resource detonationNsg 'Microsoft.Network/networkSecurityGroups@2024-05-01' = {
  name: '${namePrefix}-nsg-detonation'
  location: location
  tags: tags
  properties: {
    securityRules: [
      // ---- inbound: nothing. Overrides the default AllowVnetInBound. ----
      {
        name: 'DenyAllInbound'
        properties: {
          priority: 4000
          direction: 'Inbound'
          access: 'Deny'
          protocol: '*'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '*'
          description: 'Detonation containers accept no connections from anywhere.'
        }
      }
      // ---- outbound: allow list first, then explicit denies, then Internet ----
      {
        name: 'AllowAzureDnsOutbound'
        properties: {
          priority: 100
          direction: 'Outbound'
          access: 'Allow'
          protocol: '*'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: azureDnsIp
          destinationPortRange: '53'
          description: 'Name resolution through Azure DNS (also resolves the ACR private zone).'
        }
      }
      {
        name: 'AllowAcrPrivateEndpointOutbound'
        properties: {
          priority: 110
          direction: 'Outbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefixes: acrPrivateEndpointIps
          destinationPortRange: '443'
          description: 'Pull the chamber image from the ACR private endpoint. The only private destination allowed.'
        }
      }
      {
        name: 'DenyAppsSubnetOutbound'
        properties: {
          priority: 200
          direction: 'Outbound'
          access: 'Deny'
          protocol: '*'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: appsSubnetPrefix
          destinationPortRange: '*'
          description: 'Never reach web/worker/deadman.'
        }
      }
      {
        name: 'DenyDataSubnetOutbound'
        properties: {
          priority: 201
          direction: 'Outbound'
          access: 'Deny'
          protocol: '*'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: dataSubnetPrefix
          destinationPortRange: '*'
          description: 'Never reach Key Vault, Storage, Postgres or Service Bus private endpoints.'
        }
      }
      {
        name: 'DenyImdsOutbound'
        properties: {
          priority: 210
          direction: 'Outbound'
          access: 'Deny'
          protocol: '*'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: '169.254.169.254/32'
          destinationPortRange: '*'
          description: 'Instance metadata / managed identity endpoint. Chamber containers have no identity; make it explicit.'
        }
      }
      {
        name: 'DenyRfc1918Outbound10'
        properties: {
          priority: 220
          direction: 'Outbound'
          access: 'Deny'
          protocol: '*'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: '10.0.0.0/8'
          destinationPortRange: '*'
        }
      }
      {
        name: 'DenyRfc1918Outbound172'
        properties: {
          priority: 221
          direction: 'Outbound'
          access: 'Deny'
          protocol: '*'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: '172.16.0.0/12'
          destinationPortRange: '*'
        }
      }
      {
        name: 'DenyRfc1918Outbound192'
        properties: {
          priority: 222
          direction: 'Outbound'
          access: 'Deny'
          protocol: '*'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: '192.168.0.0/16'
          destinationPortRange: '*'
        }
      }
      {
        name: 'DenyCgnatOutbound'
        properties: {
          priority: 223
          direction: 'Outbound'
          access: 'Deny'
          protocol: '*'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: '100.64.0.0/10'
          destinationPortRange: '*'
          description: 'Carrier-grade NAT range, used by some Azure platform services.'
        }
      }
      {
        name: 'DenyVnetOutbound'
        properties: {
          priority: 230
          direction: 'Outbound'
          access: 'Deny'
          protocol: '*'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: 'VirtualNetwork'
          destinationPortRange: '*'
          description: 'Belt and braces: anything else in the VNet or peered networks.'
        }
      }
      {
        name: 'AllowInternetWebOutbound'
        properties: {
          priority: 300
          direction: 'Outbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: 'Internet'
          destinationPortRanges: ['80', '443']
          description: 'The job: fetch the page and whatever it loads.'
        }
      }
      {
        name: 'AllowInternetDnsOutbound'
        properties: {
          priority: 310
          direction: 'Outbound'
          access: 'Allow'
          protocol: '*'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: 'Internet'
          destinationPortRange: '53'
        }
      }
      {
        name: 'DenyAllOutbound'
        properties: {
          priority: 4000
          direction: 'Outbound'
          access: 'Deny'
          protocol: '*'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '*'
          description: 'No SMTP, no SSH, no raw TCP/UDP. Overrides AllowInternetOutBound.'
        }
      }
    ]
  }
}

// Apps subnet: nothing from the detonation subnet may ever come in.
resource appsNsg 'Microsoft.Network/networkSecurityGroups@2024-05-01' = {
  name: '${namePrefix}-nsg-apps'
  location: location
  tags: tags
  properties: {
    securityRules: [
      {
        name: 'DenyDetonationInbound'
        properties: {
          priority: 100
          direction: 'Inbound'
          access: 'Deny'
          protocol: '*'
          sourceAddressPrefix: detonationSubnetPrefix
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '*'
        }
      }
    ]
  }
}

// Data subnet: detonation may reach the ACR private endpoint on 443, nothing else.
resource dataNsg 'Microsoft.Network/networkSecurityGroups@2024-05-01' = {
  name: '${namePrefix}-nsg-data'
  location: location
  tags: tags
  properties: {
    securityRules: [
      {
        name: 'AllowDetonationToAcrInbound'
        properties: {
          priority: 100
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: detonationSubnetPrefix
          sourcePortRange: '*'
          destinationAddressPrefixes: acrPrivateEndpointIps
          destinationPortRange: '443'
        }
      }
      {
        name: 'DenyDetonationInbound'
        properties: {
          priority: 110
          direction: 'Inbound'
          access: 'Deny'
          protocol: '*'
          sourceAddressPrefix: detonationSubnetPrefix
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '*'
        }
      }
    ]
  }
}

// ---------------------------------------------------------------------------
// VNet
// ---------------------------------------------------------------------------

resource vnet 'Microsoft.Network/virtualNetworks@2024-05-01' = {
  name: '${namePrefix}-vnet'
  location: location
  tags: tags
  properties: {
    addressSpace: { addressPrefixes: [vnetAddressPrefix] }
    subnets: [
      {
        name: 'apps'
        properties: {
          addressPrefix: appsSubnetPrefix
          networkSecurityGroup: { id: appsNsg.id }
          natGateway: deployAppsNatGateway ? { id: appsNat.id } : null
          delegations: [
            {
              name: 'containerapps'
              properties: { serviceName: 'Microsoft.App/environments' }
            }
          ]
        }
      }
      {
        name: 'data'
        properties: {
          addressPrefix: dataSubnetPrefix
          networkSecurityGroup: { id: dataNsg.id }
          // Enabled so the NSG above actually applies to private endpoint traffic.
          privateEndpointNetworkPolicies: 'Enabled'
          privateLinkServiceNetworkPolicies: 'Enabled'
        }
      }
      {
        name: 'detonation'
        properties: {
          addressPrefix: detonationSubnetPrefix
          networkSecurityGroup: { id: detonationNsg.id }
          natGateway: { id: detonationNat.id }
          delegations: [
            {
              name: 'aci'
              properties: { serviceName: 'Microsoft.ContainerInstance/containerGroups' }
            }
          ]
        }
      }
    ]
  }
}

resource appsSubnet 'Microsoft.Network/virtualNetworks/subnets@2024-05-01' existing = {
  parent: vnet
  name: 'apps'
}

resource dataSubnet 'Microsoft.Network/virtualNetworks/subnets@2024-05-01' existing = {
  parent: vnet
  name: 'data'
}

resource detonationSubnet 'Microsoft.Network/virtualNetworks/subnets@2024-05-01' existing = {
  parent: vnet
  name: 'detonation'
}

// The worker creates container groups in this subnet. Network Contributor
// scoped to the subnet only, not the VNet.
resource workerSubnetJoin 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(detonationSubnet.id, workerPrincipalId, networkContributorRoleId)
  scope: detonationSubnet
  properties: {
    roleDefinitionId: networkContributorRoleId
    principalId: workerPrincipalId
    principalType: 'ServicePrincipal'
    description: 'reddysec worker: join VNet-injected container groups to the detonation subnet'
  }
}

// ---------------------------------------------------------------------------
// Private DNS zones (one per private-link service) linked to the VNet
// ---------------------------------------------------------------------------

var privateDnsZoneNames = [
  'privatelink.vaultcore.azure.net'
  'privatelink.blob.${environment().suffixes.storage}'
  'privatelink.postgres.database.azure.com'
  'privatelink.azurecr.io'
  'privatelink.servicebus.windows.net'
]

resource privateDnsZones 'Microsoft.Network/privateDnsZones@2024-06-01' = [
  for zoneName in privateDnsZoneNames: {
    name: zoneName
    location: 'global'
    tags: tags
  }
]

resource privateDnsZoneLinks 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2024-06-01' = [
  for (zoneName, i) in privateDnsZoneNames: {
    parent: privateDnsZones[i]
    name: '${namePrefix}-link'
    location: 'global'
    tags: tags
    properties: {
      registrationEnabled: false
      virtualNetwork: { id: vnet.id }
    }
  }
]

// ---------------------------------------------------------------------------
// Diagnostics
// ---------------------------------------------------------------------------

resource detonationNsgDiag 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'to-law'
  scope: detonationNsg
  properties: {
    workspaceId: logAnalyticsWorkspaceId
    logs: [{ categoryGroup: 'allLogs', enabled: true }]
  }
}

resource appsNsgDiag 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'to-law'
  scope: appsNsg
  properties: {
    workspaceId: logAnalyticsWorkspaceId
    logs: [{ categoryGroup: 'allLogs', enabled: true }]
  }
}

resource dataNsgDiag 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'to-law'
  scope: dataNsg
  properties: {
    workspaceId: logAnalyticsWorkspaceId
    logs: [{ categoryGroup: 'allLogs', enabled: true }]
  }
}

resource detonationNatDiag 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'to-law'
  scope: detonationNat
  properties: {
    workspaceId: logAnalyticsWorkspaceId
    metrics: [{ category: 'AllMetrics', enabled: true }]
  }
}

resource detonationPipDiag 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = [
  for i in range(0, 2): {
    name: 'to-law'
    scope: detonationPip[i]
    properties: {
      workspaceId: logAnalyticsWorkspaceId
      logs: [{ categoryGroup: 'allLogs', enabled: true }]
      metrics: [{ category: 'AllMetrics', enabled: true }]
    }
  }
]

// ---------------------------------------------------------------------------
// Outputs
// ---------------------------------------------------------------------------

output vnetId string = vnet.id
output vnetName string = vnet.name
output appsSubnetId string = appsSubnet.id
output dataSubnetId string = dataSubnet.id
output detonationSubnetId string = detonationSubnet.id
output detonationEgressIps array = [for i in range(0, 2): detonationPip[i].properties.ipAddress]
output appsEgressIp string = appsPip.?properties.?ipAddress ?? ''
output keyVaultDnsZoneId string = privateDnsZones[0].id
output blobDnsZoneId string = privateDnsZones[1].id
output postgresDnsZoneId string = privateDnsZones[2].id
output acrDnsZoneId string = privateDnsZones[3].id
output serviceBusDnsZoneId string = privateDnsZones[4].id

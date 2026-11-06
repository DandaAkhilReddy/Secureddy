// Custom Azure Policy definitions for the detonation resource group.
// Definitions can only live at subscription (or management group) scope, so
// this module is deployed there; the assignments are in aci-detonation.bicep.
//
// What they enforce on every container group the worker creates:
//   1. no public IP                   (ipAddress.type must not be Public)
//   2. restartPolicy == Never         (a detonation runs once and dies)
//   3. VNet-injected                  (must have a subnet)
//   4. no managed identity            (nothing to steal if the browser escapes)

targetScope = 'subscription'

@description('Prefix for the definition names, e.g. rsec-prod.')
param namePrefix string

resource denyPublicIp 'Microsoft.Authorization/policyDefinitions@2023-04-01' = {
  name: '${namePrefix}-aci-deny-public-ip'
  properties: {
    displayName: 'Secureddy: container groups must not have a public IP'
    policyType: 'Custom'
    mode: 'Indexed'
    description: 'Detonation containers egress through the NAT gateway and are never reachable from the Internet.'
    metadata: { category: 'Container Instance', product: 'reddysec' }
    policyRule: {
      if: {
        allOf: [
          { field: 'type', equals: 'Microsoft.ContainerInstance/containerGroups' }
          { field: 'Microsoft.ContainerInstance/containerGroups/ipAddress.type', equals: 'Public' }
        ]
      }
      then: { effect: 'deny' }
    }
  }
}

resource denyRestart 'Microsoft.Authorization/policyDefinitions@2023-04-01' = {
  name: '${namePrefix}-aci-deny-restart'
  properties: {
    displayName: 'Secureddy: container groups must use restartPolicy Never'
    policyType: 'Custom'
    mode: 'Indexed'
    description: 'A detonation runs exactly once. A restarting container would re-visit the target and keep billing.'
    metadata: { category: 'Container Instance', product: 'reddysec' }
    policyRule: {
      if: {
        allOf: [
          { field: 'type', equals: 'Microsoft.ContainerInstance/containerGroups' }
          { field: 'Microsoft.ContainerInstance/containerGroups/restartPolicy', notEquals: 'Never' }
        ]
      }
      then: { effect: 'deny' }
    }
  }
}

resource requireSubnet 'Microsoft.Authorization/policyDefinitions@2023-04-01' = {
  name: '${namePrefix}-aci-require-subnet'
  properties: {
    displayName: 'Secureddy: container groups must be VNet-injected'
    policyType: 'Custom'
    mode: 'Indexed'
    description: 'Only the detonation subnet carries the NSG and NAT gateway that make the sandbox safe.'
    metadata: { category: 'Container Instance', product: 'reddysec' }
    policyRule: {
      if: {
        allOf: [
          { field: 'type', equals: 'Microsoft.ContainerInstance/containerGroups' }
          {
            count: { field: 'Microsoft.ContainerInstance/containerGroups/subnetIds[*]' }
            less: 1
          }
        ]
      }
      then: { effect: 'deny' }
    }
  }
}

resource denyIdentity 'Microsoft.Authorization/policyDefinitions@2023-04-01' = {
  name: '${namePrefix}-aci-deny-identity'
  properties: {
    displayName: 'Secureddy: container groups must not have a managed identity'
    policyType: 'Custom'
    mode: 'Indexed'
    description: 'The chamber is the thing we expect to be attacked. It must hold no Azure credential.'
    metadata: { category: 'Container Instance', product: 'reddysec' }
    policyRule: {
      if: {
        allOf: [
          { field: 'type', equals: 'Microsoft.ContainerInstance/containerGroups' }
          { field: 'identity.type', exists: 'true' }
          { field: 'identity.type', notEquals: 'None' }
        ]
      }
      then: { effect: 'deny' }
    }
  }
}

output denyPublicIpId string = denyPublicIp.id
output denyRestartId string = denyRestart.id
output requireSubnetId string = requireSubnet.id
output denyIdentityId string = denyIdentity.id

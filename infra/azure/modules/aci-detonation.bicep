// Baseline of the detonation resource group. Deployed INTO that group.
//
// It holds nothing permanent. The worker creates one ACI container group per
// detonation here and deletes it afterwards. What this module adds:
//   * RBAC: the worker is Contributor here (and only here); the GitHub deploy
//     identity can manage the group
//   * Policy assignments (deny): no public IP, restartPolicy Never, VNet
//     injected, no managed identity, and only container groups + the handful
//     of ARM types a deployment needs may exist in this group
//
// The container group the worker instantiates is documented in
// docs/azure-deploy.md (section "Detonation container group") as the JSON the
// worker sends through the SDK.

targetScope = 'resourceGroup'

param workerPrincipalId string
param deployPrincipalId string

param denyPublicIpPolicyId string
param denyRestartPolicyId string
param requireSubnetPolicyId string
param denyIdentityPolicyId string

@description('Set false to skip policy assignments (e.g. the operator lacks policy rights at subscription scope).')
param assignPolicies bool = true

var contributorRoleId = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'b24988ac-6180-42a0-ab88-20f7382dd24c')
var rbacAdminRoleId = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'f58310d9-a9f6-439a-9e8d-f62e7b41a168')

// Built-in "Allowed resource types"
var allowedResourceTypesPolicyId = tenantResourceId('Microsoft.Authorization/policyDefinitions', 'a08ec900-254a-4555-9bf5-e42af04b5c5c')

resource workerContributor 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(resourceGroup().id, workerPrincipalId, contributorRoleId)
  properties: {
    roleDefinitionId: contributorRoleId
    principalId: workerPrincipalId
    principalType: 'ServicePrincipal'
    description: 'reddysec worker: create/read logs/delete detonation container groups'
  }
}

resource deployContributor 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(resourceGroup().id, deployPrincipalId, contributorRoleId)
  properties: {
    roleDefinitionId: contributorRoleId
    principalId: deployPrincipalId
    principalType: 'ServicePrincipal'
  }
}

// Lets the pipeline (re)create the worker's role assignment above, and nothing else.
resource deployRbacAdmin 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(resourceGroup().id, deployPrincipalId, rbacAdminRoleId)
  properties: {
    roleDefinitionId: rbacAdminRoleId
    principalId: deployPrincipalId
    principalType: 'ServicePrincipal'
    conditionVersion: '2.0'
    condition: '((!(ActionMatches{\'Microsoft.Authorization/roleAssignments/write\'})) OR (@Request[Microsoft.Authorization/roleAssignments:RoleDefinitionId] ForAnyOfAnyValues:GuidEquals {b24988ac-6180-42a0-ab88-20f7382dd24c})) AND ((!(ActionMatches{\'Microsoft.Authorization/roleAssignments/delete\'})) OR (@Resource[Microsoft.Authorization/roleAssignments:RoleDefinitionId] ForAnyOfAnyValues:GuidEquals {b24988ac-6180-42a0-ab88-20f7382dd24c}))'
  }
}

// --- Policy assignments ----------------------------------------------------

resource assignDenyPublicIp 'Microsoft.Authorization/policyAssignments@2024-04-01' = if (assignPolicies) {
  name: 'rsec-aci-no-public-ip'
  properties: {
    displayName: 'Detonation: no public IP'
    policyDefinitionId: denyPublicIpPolicyId
    enforcementMode: 'Default'
  }
}

resource assignDenyRestart 'Microsoft.Authorization/policyAssignments@2024-04-01' = if (assignPolicies) {
  name: 'rsec-aci-restart-never'
  properties: {
    displayName: 'Detonation: restartPolicy Never'
    policyDefinitionId: denyRestartPolicyId
    enforcementMode: 'Default'
  }
}

resource assignRequireSubnet 'Microsoft.Authorization/policyAssignments@2024-04-01' = if (assignPolicies) {
  name: 'rsec-aci-vnet-only'
  properties: {
    displayName: 'Detonation: VNet-injected only'
    policyDefinitionId: requireSubnetPolicyId
    enforcementMode: 'Default'
  }
}

resource assignDenyIdentity 'Microsoft.Authorization/policyAssignments@2024-04-01' = if (assignPolicies) {
  name: 'rsec-aci-no-identity'
  properties: {
    displayName: 'Detonation: no managed identity'
    policyDefinitionId: denyIdentityPolicyId
    enforcementMode: 'Default'
  }
}

resource assignAllowedTypes 'Microsoft.Authorization/policyAssignments@2024-04-01' = if (assignPolicies) {
  name: 'rsec-aci-allowed-types'
  properties: {
    displayName: 'Detonation: only container groups may exist here'
    policyDefinitionId: allowedResourceTypesPolicyId
    enforcementMode: 'Default'
    parameters: {
      listOfResourceTypesAllowed: {
        value: [
          'Microsoft.ContainerInstance/containerGroups'
          'Microsoft.Resources/deployments'
          'Microsoft.Authorization/roleAssignments'
          'Microsoft.Authorization/policyAssignments'
          'Microsoft.Authorization/locks'
        ]
      }
    }
  }
}

output resourceGroupId string = resourceGroup().id

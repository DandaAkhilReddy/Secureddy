// Subscription-scope role assignments for the GitHub deploy identity.
// The pipeline redeploys policy-definitions.bicep (subscription scope), so it
// needs Resource Policy Contributor. Nothing else at this scope.

targetScope = 'subscription'

param deployPrincipalId string

var resourcePolicyContributorRoleId = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '36243c78-bf99-498c-9df9-86d9f8d28608')

resource policyContributor 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(subscription().id, deployPrincipalId, resourcePolicyContributorRoleId)
  properties: {
    roleDefinitionId: resourcePolicyContributorRoleId
    principalId: deployPrincipalId
    principalType: 'ServicePrincipal'
    description: 'GitHub deploy identity: manage the reddysec custom policy definitions'
  }
}

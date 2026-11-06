// User-assigned managed identities. One per workload, plus one for GitHub
// Actions (OIDC federated, no stored credentials anywhere).
//
// Role assignments live next to the resource they grant access to (Key Vault,
// Storage, Service Bus, ACR modules) and in aci-detonation.bicep for the
// detonation resource group. This module only creates the principals.

param location string
param namePrefix string
param tags object = {}

@description('GitHub repository "owner/name" that may deploy through OIDC. Empty disables the federated credential.')
param githubRepository string = ''

@description('GitHub environment names that are allowed to log in with the deploy identity.')
param githubEnvironments array = ['dev', 'prod']

resource web 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: '${namePrefix}-id-web'
  location: location
  tags: tags
}

resource worker 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: '${namePrefix}-id-worker'
  location: location
  tags: tags
}

resource deadman 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: '${namePrefix}-id-deadman'
  location: location
  tags: tags
}

resource deploy 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: '${namePrefix}-id-github-deploy'
  location: location
  tags: tags
}

// Federated credentials on one identity must be created one at a time.
@batchSize(1)
resource githubFederation 'Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials@2023-01-31' = [
  for envName in githubEnvironments: if (!empty(githubRepository)) {
    parent: deploy
    name: 'github-${envName}'
    properties: {
      issuer: 'https://token.actions.githubusercontent.com'
      subject: 'repo:${githubRepository}:environment:${envName}'
      audiences: ['api://AzureADTokenExchange']
    }
  }
]

output webIdentityId string = web.id
output webPrincipalId string = web.properties.principalId
output webClientId string = web.properties.clientId

output workerIdentityId string = worker.id
output workerPrincipalId string = worker.properties.principalId
output workerClientId string = worker.properties.clientId

output deadmanIdentityId string = deadman.id
output deadmanPrincipalId string = deadman.properties.principalId
output deadmanClientId string = deadman.properties.clientId

output deployIdentityId string = deploy.id
output deployPrincipalId string = deploy.properties.principalId
output deployClientId string = deploy.properties.clientId

// Key Vault: RBAC mode, purge protection, soft delete, private endpoint.
//
// lean=true (dev cost profile): no private endpoint, public endpoint open
// (defaultAction Allow). Container Apps on a Consumption-only environment have
// no stable outbound IP and Key Vault references do not reliably ride the
// AzureServices bypass, so the firewall cannot be used. RBAC still gates every
// read (only the three app identities, the deploy identity and the operator
// have a role) and the vault only holds dev secrets. Prod keeps the private
// endpoint and the deny-by-default firewall.
//
// Secrets are NOT created here. Bicep would put their values in deployment
// history. infra/azure/bootstrap.sh creates them (random where possible,
// prompted otherwise). Names the apps expect (Key Vault names cannot contain
// underscores, so RS_TOKEN_KEK becomes rs-token-kek):
//
//   rs-token-kek               32 random bytes, base64 (RS_TOKEN_KEK)
//   rs-secret-key              session signing key (RS_SECRET_KEY)
//   rs-google-client-secret    Google OAuth client secret (RS_GOOGLE_CLIENT_SECRET)
//   rs-pubsub-token            shared token in the Gmail Pub/Sub push URL
//   rs-database-url            postgresql+asyncpg://... (RS_DATABASE_URL)
//   postgres-admin-password    server admin password (break glass)
//   acr-chamber-pull-password  repository-scoped pull token for the chamber image
//   rs-safe-browsing-api-key   optional, only when safeBrowsingEnabled
//   rs-smtp-password           optional, only when smtpEnabled
//   rs-azure-openai-api-key    optional, only when azureOpenAiEnabled

param location string
param namePrefix string
param tags object = {}

@description('Globally unique vault name (3-24 chars, alphanumerics and dashes).')
param keyVaultName string

@description('Public IPs allowed to use the public endpoint (the operator running bootstrap.sh). Empty = public network access disabled.')
param adminIpAllowList array = []

@description('Object id of the human operator. Gets Key Vault Secrets Officer so bootstrap.sh can write secrets.')
param operatorObjectId string = ''

param webPrincipalId string
param workerPrincipalId string
param deadmanPrincipalId string
param deployPrincipalId string

param dataSubnetId string
param privateDnsZoneId string
param logAnalyticsWorkspaceId string

@description('Lean cost profile: public endpoint with defaultAction Allow, no private endpoint. See the header comment for the trade-off.')
param lean bool = false

var secretsUserRoleId = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '4633458b-17de-408a-b874-0445c86b69e6')
var secretsOfficerRoleId = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'b86a8fe4-44ce-4948-aee5-eccb2c155cd7')

resource kv 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: keyVaultName
  location: location
  tags: tags
  properties: {
    tenantId: tenant().tenantId
    sku: { family: 'A', name: 'standard' }
    enableRbacAuthorization: true
    enableSoftDelete: true
    softDeleteRetentionInDays: 90
    enablePurgeProtection: true
    enabledForTemplateDeployment: true
    enabledForDeployment: false
    enabledForDiskEncryption: false
    publicNetworkAccess: (lean || !empty(adminIpAllowList)) ? 'Enabled' : 'Disabled'
    networkAcls: {
      bypass: 'AzureServices'
      // lean: Allow (RBAC-only protection, see header). standard: Deny + operator IPs.
      defaultAction: lean ? 'Allow' : 'Deny'
      ipRules: [for ip in adminIpAllowList: { value: ip }]
      virtualNetworkRules: []
    }
  }
}

module privateEndpoint 'private-endpoint.bicep' = if (!lean) {
  name: '${keyVaultName}-pe'
  params: {
    location: location
    tags: tags
    name: '${namePrefix}-pe-kv'
    subnetId: dataSubnetId
    privateLinkServiceId: kv.id
    groupId: 'vault'
    privateDnsZoneId: privateDnsZoneId
  }
}

// --- RBAC ------------------------------------------------------------------

var readers = [
  { id: webPrincipalId, label: 'web' }
  { id: workerPrincipalId, label: 'worker' }
  { id: deadmanPrincipalId, label: 'deadman' }
]

resource secretsUser 'Microsoft.Authorization/roleAssignments@2022-04-01' = [
  for r in readers: {
    name: guid(kv.id, r.id, secretsUserRoleId)
    scope: kv
    properties: {
      roleDefinitionId: secretsUserRoleId
      principalId: r.id
      principalType: 'ServicePrincipal'
      description: 'reddysec ${r.label}: read secrets'
    }
  }
]

resource deploySecretsOfficer 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(kv.id, deployPrincipalId, secretsOfficerRoleId)
  scope: kv
  properties: {
    roleDefinitionId: secretsOfficerRoleId
    principalId: deployPrincipalId
    principalType: 'ServicePrincipal'
    description: 'GitHub deploy identity: rotate secrets from pipelines'
  }
}

resource operatorSecretsOfficer 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (!empty(operatorObjectId)) {
  name: guid(kv.id, operatorObjectId, secretsOfficerRoleId)
  scope: kv
  properties: {
    roleDefinitionId: secretsOfficerRoleId
    principalId: operatorObjectId
    principalType: 'User'
    description: 'Operator running bootstrap.sh'
  }
}

resource diag 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'to-law'
  scope: kv
  properties: {
    workspaceId: logAnalyticsWorkspaceId
    logs: [{ categoryGroup: 'allLogs', enabled: true }]
    metrics: [{ category: 'AllMetrics', enabled: true }]
  }
}

output keyVaultId string = kv.id
output keyVaultName string = kv.name
output keyVaultUri string = kv.properties.vaultUri

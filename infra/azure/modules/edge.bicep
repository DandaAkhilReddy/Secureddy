// Edge: Azure Front Door Premium + WAF, private link to the Container Apps
// environment.
//
// Why Front Door Premium and not Application Gateway WAF_v2:
//   * The origin stays completely private. Front Door reaches the internal
//     Container Apps environment over Private Link; nothing in the apps subnet
//     has a public IP. App Gateway would need a public frontend in our VNet.
//   * Managed TLS certificates for the custom domain, no renewal work.
//   * Managed rule set DRS 2.1 + Bot Manager 1.1 + rate limiting at the edge,
//     i.e. before traffic enters our network. App Gateway has DRS/CRS but no
//     bot manager of the same quality and no edge DDoS absorption.
//   * Flat USD 330/month vs. App Gateway WAF_v2 at ~USD 263/month fixed plus
//     capacity units: comparable cost, more protection, less to operate.
//
// After the first deployment the private endpoint connection on the Container
// Apps environment must be approved once (bootstrap.sh does it).

param location string
param namePrefix string
param tags object = {}

@description('Resource id of the Container Apps managed environment (private link target).')
param containerAppsEnvironmentId string

@description('FQDN of the web app inside the environment, e.g. rsec-prod-web.<env>.westus2.azurecontainerapps.io')
param webFqdn string

@description('Custom domain, e.g. app.secureddy.com. Empty = only the *.azurefd.net endpoint.')
param customDomain string = ''

@allowed(['Prevention', 'Detection'])
param wafMode string = 'Prevention'

@description('Requests per minute per client IP before the WAF blocks. Pub/Sub webhooks are excluded from this rule.')
param rateLimitPerMinute int = 300

param logAnalyticsWorkspaceId string

var hasCustomDomain = !empty(customDomain)
var customDomainResourceName = replace(customDomain, '.', '-')

// ---------------------------------------------------------------------------
// WAF policy
// ---------------------------------------------------------------------------

resource waf 'Microsoft.Network/FrontDoorWebApplicationFirewallPolicies@2024-02-01' = {
  name: replace('${namePrefix}waf', '-', '')
  location: 'global'
  tags: tags
  sku: { name: 'Premium_AzureFrontDoor' }
  properties: {
    policySettings: {
      enabledState: 'Enabled'
      mode: wafMode
      requestBodyCheck: 'Enabled'
      customBlockResponseStatusCode: 403
    }
    managedRules: {
      managedRuleSets: [
        {
          ruleSetType: 'Microsoft_DefaultRuleSet'
          ruleSetVersion: '2.1'
          ruleSetAction: 'Block'
          exclusions: []
          ruleGroupOverrides: []
        }
        {
          ruleSetType: 'Microsoft_BotManagerRuleSet'
          ruleSetVersion: '1.1'
          exclusions: []
          ruleGroupOverrides: []
        }
      ]
    }
    customRules: {
      rules: [
        {
          name: 'RateLimitPerClientIp'
          priority: 100
          enabledState: 'Enabled'
          ruleType: 'RateLimitRule'
          rateLimitDurationInMinutes: 1
          rateLimitThreshold: rateLimitPerMinute
          action: 'Block'
          matchConditions: [
            {
              matchVariable: 'RequestUri'
              operator: 'Contains'
              negateCondition: true
              matchValue: ['/hooks/']
              transforms: ['Lowercase']
            }
          ]
        }
        {
          // Webhooks are machine traffic: allow a higher burst but still cap it.
          name: 'RateLimitWebhooks'
          priority: 110
          enabledState: 'Enabled'
          ruleType: 'RateLimitRule'
          rateLimitDurationInMinutes: 1
          rateLimitThreshold: 3000
          action: 'Block'
          matchConditions: [
            {
              matchVariable: 'RequestUri'
              operator: 'Contains'
              negateCondition: false
              matchValue: ['/hooks/']
              transforms: ['Lowercase']
            }
          ]
        }
      ]
    }
  }
}

// ---------------------------------------------------------------------------
// Front Door profile, endpoint, origin (private link), route
// ---------------------------------------------------------------------------

resource profile 'Microsoft.Cdn/profiles@2024-02-01' = {
  name: '${namePrefix}-afd'
  location: 'global'
  tags: tags
  sku: { name: 'Premium_AzureFrontDoor' }
  properties: {
    originResponseTimeoutSeconds: 120
  }
}

resource endpoint 'Microsoft.Cdn/profiles/afdEndpoints@2024-02-01' = {
  parent: profile
  name: '${namePrefix}-edge'
  location: 'global'
  tags: tags
  properties: {
    enabledState: 'Enabled'
  }
}

resource originGroup 'Microsoft.Cdn/profiles/originGroups@2024-02-01' = {
  parent: profile
  name: 'web'
  properties: {
    sessionAffinityState: 'Enabled'
    loadBalancingSettings: {
      sampleSize: 4
      successfulSamplesRequired: 3
      additionalLatencyInMilliseconds: 50
    }
    healthProbeSettings: {
      probePath: '/healthz'
      probeRequestType: 'GET'
      probeProtocol: 'Https'
      probeIntervalInSeconds: 30
    }
  }
}

resource origin 'Microsoft.Cdn/profiles/originGroups/origins@2024-02-01' = {
  parent: originGroup
  name: 'containerapps-web'
  properties: {
    hostName: webFqdn
    originHostHeader: webFqdn
    httpPort: 80
    httpsPort: 443
    priority: 1
    weight: 1000
    enabledState: 'Enabled'
    enforceCertificateNameCheck: true
    sharedPrivateLinkResource: {
      privateLink: { id: containerAppsEnvironmentId }
      groupId: 'managedEnvironments'
      privateLinkLocation: location
      requestMessage: 'Secureddy Front Door origin'
    }
  }
}

resource customDomainResource 'Microsoft.Cdn/profiles/customDomains@2024-02-01' = if (hasCustomDomain) {
  parent: profile
  name: customDomainResourceName
  properties: {
    hostName: customDomain
    tlsSettings: {
      certificateType: 'ManagedCertificate'
      minimumTlsVersion: 'TLS12'
    }
  }
}

resource route 'Microsoft.Cdn/profiles/afdEndpoints/routes@2024-02-01' = {
  parent: endpoint
  name: 'web'
  properties: {
    originGroup: { id: originGroup.id }
    customDomains: hasCustomDomain ? [{ id: customDomainResource.id }] : []
    supportedProtocols: ['Https']
    patternsToMatch: ['/*']
    forwardingProtocol: 'HttpsOnly'
    linkToDefaultDomain: 'Enabled'
    httpsRedirect: 'Enabled'
    enabledState: 'Enabled'
    // Dynamic app: no caching at the edge.
  }
  dependsOn: [origin]
}

resource securityPolicy 'Microsoft.Cdn/profiles/securityPolicies@2024-02-01' = {
  parent: profile
  name: 'waf'
  properties: {
    parameters: {
      type: 'WebApplicationFirewall'
      wafPolicy: { id: waf.id }
      associations: [
        {
          domains: hasCustomDomain ? [{ id: endpoint.id }, { id: customDomainResource.id }] : [{ id: endpoint.id }]
          patternsToMatch: ['/*']
        }
      ]
    }
  }
}

resource diag 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'to-law'
  scope: profile
  properties: {
    workspaceId: logAnalyticsWorkspaceId
    logs: [{ categoryGroup: 'allLogs', enabled: true }]
    metrics: [{ category: 'AllMetrics', enabled: true }]
  }
}

output profileId string = profile.id
output profileName string = profile.name
output endpointHostName string = endpoint.properties.hostName
output frontDoorId string = profile.properties.frontDoorId
output customDomainValidationToken string = customDomainResource.?properties.?validationProperties.?validationToken ?? ''
output customDomainValidationExpiry string = customDomainResource.?properties.?validationProperties.?expirationDate ?? ''
output wafPolicyId string = waf.id

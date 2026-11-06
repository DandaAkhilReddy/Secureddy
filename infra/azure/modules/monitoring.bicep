// Log Analytics + workspace-based Application Insights + the action group.
// Deployed first: every other module writes diagnostic settings here.
// Alert rules live in alerts.bicep because they reference resources created
// later (Front Door, Container Apps, Postgres).

param location string
param namePrefix string
param tags object = {}

@minValue(30)
@maxValue(730)
param logRetentionDays int = 90

@description('Daily ingestion cap in GB. -1 = unlimited. Keeps a log storm from becoming a bill.')
param dailyQuotaGb int = 5

@description('Email addresses that receive alerts.')
param alertEmails array

resource law 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: '${namePrefix}-law'
  location: location
  tags: tags
  properties: {
    sku: { name: 'PerGB2018' }
    retentionInDays: logRetentionDays
    features: {
      enableLogAccessUsingOnlyResourcePermissions: true
    }
    workspaceCapping: {
      dailyQuotaGb: dailyQuotaGb
    }
    publicNetworkAccessForIngestion: 'Enabled'
    publicNetworkAccessForQuery: 'Enabled'
  }
}

resource appInsights 'Microsoft.Insights/components@2020-02-02' = {
  name: '${namePrefix}-appi'
  location: location
  tags: tags
  kind: 'web'
  properties: {
    Application_Type: 'web'
    WorkspaceResourceId: law.id
    IngestionMode: 'LogAnalytics'
    RetentionInDays: logRetentionDays
    DisableLocalAuth: false
    publicNetworkAccessForIngestion: 'Enabled'
    publicNetworkAccessForQuery: 'Enabled'
  }
}

resource actionGroup 'Microsoft.Insights/actionGroups@2023-01-01' = {
  name: '${namePrefix}-ag-oncall'
  location: 'global'
  tags: tags
  properties: {
    groupShortName: 'rsec-oncall'
    enabled: true
    emailReceivers: [
      for (email, i) in alertEmails: {
        name: 'email-${i}'
        emailAddress: email
        useCommonAlertSchema: true
      }
    ]
  }
}

output logAnalyticsWorkspaceId string = law.id
output logAnalyticsWorkspaceName string = law.name
output logAnalyticsCustomerId string = law.properties.customerId
output appInsightsId string = appInsights.id
output appInsightsConnectionString string = appInsights.properties.ConnectionString
output actionGroupId string = actionGroup.id

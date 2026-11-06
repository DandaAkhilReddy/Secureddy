// Alert rules and the monthly budget. Deployed last; everything it watches
// already exists.
//
// Log contract with the application (structlog JSON, one object per line,
// worker/deadman.py and worker/engine.py):
//   deadman.released          a HOLD mailbox had a stale heartbeat; held mail was released
//   deadman.release_failed    it could NOT release (credentials dead); mail may be trapped
//   deadman.check_crashed     the watchdog loop itself threw
// The worker records its heartbeat in the database (hold_heartbeats.beat_at),
// not in a log line, so "worker missing" is detected from the platform metric
// Replicas < 1, which needs no cooperation from the code.
// Console logs arrive in the ContainerAppConsoleLogs table (azure-monitor destination).

param location string
param namePrefix string
param tags object = {}

param actionGroupId string
param logAnalyticsWorkspaceId string

param frontDoorProfileId string
param webAppId string
param workerAppId string
param deadmanAppId string
param postgresServerId string

@description('Resource id of the detonation resource group (scope for the ACI activity-log alert).')
param detonationResourceGroupId string

@description('Monthly budget in USD for the core resource group.')
param monthlyBudgetUsd int = 1500

@description('First day of the month the budget starts (yyyy-MM-01). Must not be more than three months in the past.')
param budgetStartDate string = utcNow('yyyy-MM-01')

param alertEmails array

// ---------------------------------------------------------------------------
// Log alerts
// ---------------------------------------------------------------------------

resource holdHeartbeatStale 'Microsoft.Insights/scheduledQueryRules@2023-03-15-preview' = {
  name: '${namePrefix}-alert-hold-heartbeat-stale'
  location: location
  tags: tags
  kind: 'LogAlert'
  properties: {
    displayName: 'Dead man\'s switch fired: a HOLD mailbox had a stale heartbeat'
    description: 'deadman.released: held mail was released because the worker stopped beating. deadman.release_failed: it could not release and mail may be trapped. Page immediately either way.'
    severity: 0
    enabled: true
    evaluationFrequency: 'PT5M'
    windowSize: 'PT5M'
    scopes: [logAnalyticsWorkspaceId]
    autoMitigate: false
    criteria: {
      allOf: [
        {
          query: 'ContainerAppConsoleLogs | where Log has "deadman.released" or Log has "deadman.release_failed" or Log has "deadman.check_crashed" | summarize n = count()'
          timeAggregation: 'Total'
          metricMeasureColumn: 'n'
          operator: 'GreaterThan'
          threshold: 0
          failingPeriods: { numberOfEvaluationPeriods: 1, minFailingPeriodsToAlert: 1 }
        }
      ]
    }
    actions: { actionGroups: [actionGroupId] }
  }
}

resource workerMissing 'Microsoft.Insights/metricAlerts@2018-03-01' = {
  name: '${namePrefix}-alert-worker-missing'
  location: 'global'
  tags: tags
  properties: {
    description: 'The worker has no running replica. Heartbeats stop now; the dead man\'s switch releases held mail in RS_HOLD_DEAD_MAN_MINUTES.'
    severity: 1
    enabled: true
    scopes: [workerAppId]
    evaluationFrequency: 'PT1M'
    windowSize: 'PT5M'
    targetResourceType: 'Microsoft.App/containerApps'
    criteria: {
      'odata.type': 'Microsoft.Azure.Monitor.SingleResourceMultipleMetricCriteria'
      allOf: [
        {
          name: 'Replicas'
          metricNamespace: 'Microsoft.App/containerApps'
          metricName: 'Replicas'
          operator: 'LessThan'
          threshold: 1
          timeAggregation: 'Average'
          criterionType: 'StaticThresholdCriterion'
        }
      ]
    }
    actions: [{ actionGroupId: actionGroupId }]
  }
}

resource deadmanMissing 'Microsoft.Insights/metricAlerts@2018-03-01' = {
  name: '${namePrefix}-alert-deadman-missing'
  location: 'global'
  tags: tags
  properties: {
    description: 'The dead man\'s switch has no running replica. Held mail would never be released if the worker also fails.'
    severity: 0
    enabled: true
    scopes: [deadmanAppId]
    evaluationFrequency: 'PT1M'
    windowSize: 'PT5M'
    targetResourceType: 'Microsoft.App/containerApps'
    criteria: {
      'odata.type': 'Microsoft.Azure.Monitor.SingleResourceMultipleMetricCriteria'
      allOf: [
        {
          name: 'Replicas'
          metricNamespace: 'Microsoft.App/containerApps'
          metricName: 'Replicas'
          operator: 'LessThan'
          threshold: 1
          timeAggregation: 'Average'
          criterionType: 'StaticThresholdCriterion'
        }
      ]
    }
    actions: [{ actionGroupId: actionGroupId }]
  }
}

resource workerRestarts 'Microsoft.Insights/metricAlerts@2018-03-01' = {
  name: '${namePrefix}-alert-worker-restarts'
  location: 'global'
  tags: tags
  properties: {
    description: 'Worker containers restarted more than 3 times in 15 minutes (crash loop).'
    severity: 1
    enabled: true
    scopes: [workerAppId]
    evaluationFrequency: 'PT5M'
    windowSize: 'PT15M'
    targetResourceType: 'Microsoft.App/containerApps'
    criteria: {
      'odata.type': 'Microsoft.Azure.Monitor.SingleResourceMultipleMetricCriteria'
      allOf: [
        {
          name: 'RestartCount'
          metricNamespace: 'Microsoft.App/containerApps'
          metricName: 'RestartCount'
          operator: 'GreaterThan'
          threshold: 3
          timeAggregation: 'Maximum'
          criterionType: 'StaticThresholdCriterion'
        }
      ]
    }
    actions: [{ actionGroupId: actionGroupId }]
  }
}

resource appErrors 'Microsoft.Insights/scheduledQueryRules@2023-03-15-preview' = {
  name: '${namePrefix}-alert-app-errors'
  location: location
  tags: tags
  kind: 'LogAlert'
  properties: {
    displayName: 'Application error burst'
    description: 'More than 20 error-level log lines in 15 minutes across web/worker/deadman.'
    severity: 2
    enabled: true
    evaluationFrequency: 'PT15M'
    windowSize: 'PT15M'
    scopes: [logAnalyticsWorkspaceId]
    autoMitigate: true
    criteria: {
      allOf: [
        {
          query: 'ContainerAppConsoleLogs | where Log has "\\"level\\": \\"error\\"" or Log has "\\"level\\":\\"error\\"" | summarize n = count()'
          timeAggregation: 'Total'
          metricMeasureColumn: 'n'
          operator: 'GreaterThan'
          threshold: 20
          failingPeriods: { numberOfEvaluationPeriods: 1, minFailingPeriodsToAlert: 1 }
        }
      ]
    }
    actions: { actionGroups: [actionGroupId] }
  }
}

// ---------------------------------------------------------------------------
// Activity log: ACI container group create failures in the detonation RG
// ---------------------------------------------------------------------------

resource aciCreateFailures 'Microsoft.Insights/activityLogAlerts@2020-10-01' = {
  name: '${namePrefix}-alert-aci-create-failed'
  location: 'global'
  tags: tags
  properties: {
    enabled: true
    description: 'A detonation container group failed to deploy (quota, image pull, subnet). Worker falls back to "still checking" verdicts; investigate.'
    scopes: [detonationResourceGroupId]
    condition: {
      allOf: [
        { field: 'category', equals: 'Administrative' }
        { field: 'operationName', equals: 'Microsoft.ContainerInstance/containerGroups/write' }
        { field: 'status', equals: 'Failed' }
      ]
    }
    actions: {
      actionGroups: [{ actionGroupId: actionGroupId }]
    }
  }
}

// ---------------------------------------------------------------------------
// Metric alerts
// ---------------------------------------------------------------------------

resource frontDoor5xx 'Microsoft.Insights/metricAlerts@2018-03-01' = {
  name: '${namePrefix}-alert-edge-5xx'
  location: 'global'
  tags: tags
  properties: {
    description: 'More than 5% of responses at the edge are 5xx over 5 minutes.'
    severity: 1
    enabled: true
    scopes: [frontDoorProfileId]
    evaluationFrequency: 'PT1M'
    windowSize: 'PT5M'
    targetResourceType: 'Microsoft.Cdn/profiles'
    criteria: {
      'odata.type': 'Microsoft.Azure.Monitor.SingleResourceMultipleMetricCriteria'
      allOf: [
        {
          name: 'Percentage5XX'
          metricNamespace: 'Microsoft.Cdn/profiles'
          metricName: 'Percentage5XX'
          operator: 'GreaterThan'
          threshold: 5
          timeAggregation: 'Average'
          criterionType: 'StaticThresholdCriterion'
        }
      ]
    }
    actions: [{ actionGroupId: actionGroupId }]
  }
}

resource frontDoorOriginHealth 'Microsoft.Insights/metricAlerts@2018-03-01' = {
  name: '${namePrefix}-alert-edge-origin-health'
  location: 'global'
  tags: tags
  properties: {
    description: 'Front Door health probes to the web origin are failing.'
    severity: 1
    enabled: true
    scopes: [frontDoorProfileId]
    evaluationFrequency: 'PT1M'
    windowSize: 'PT5M'
    targetResourceType: 'Microsoft.Cdn/profiles'
    criteria: {
      'odata.type': 'Microsoft.Azure.Monitor.SingleResourceMultipleMetricCriteria'
      allOf: [
        {
          name: 'OriginHealthPercentage'
          metricNamespace: 'Microsoft.Cdn/profiles'
          metricName: 'OriginHealthPercentage'
          operator: 'LessThan'
          threshold: 50
          timeAggregation: 'Average'
          criterionType: 'StaticThresholdCriterion'
        }
      ]
    }
    actions: [{ actionGroupId: actionGroupId }]
  }
}

resource web5xx 'Microsoft.Insights/metricAlerts@2018-03-01' = {
  name: '${namePrefix}-alert-web-5xx'
  location: 'global'
  tags: tags
  properties: {
    description: 'web returned more than 20 5xx responses in 5 minutes.'
    severity: 2
    enabled: true
    scopes: [webAppId]
    evaluationFrequency: 'PT1M'
    windowSize: 'PT5M'
    targetResourceType: 'Microsoft.App/containerApps'
    criteria: {
      'odata.type': 'Microsoft.Azure.Monitor.SingleResourceMultipleMetricCriteria'
      allOf: [
        {
          name: 'Requests5xx'
          metricNamespace: 'Microsoft.App/containerApps'
          metricName: 'Requests'
          operator: 'GreaterThan'
          threshold: 20
          timeAggregation: 'Total'
          criterionType: 'StaticThresholdCriterion'
          dimensions: [
            { name: 'statusCodeCategory', operator: 'Include', values: ['5xx'] }
          ]
        }
      ]
    }
    actions: [{ actionGroupId: actionGroupId }]
  }
}

resource postgresStorage 'Microsoft.Insights/metricAlerts@2018-03-01' = {
  name: '${namePrefix}-alert-postgres-storage'
  location: 'global'
  tags: tags
  properties: {
    description: 'Postgres storage above 85%. Autogrow is on, but check for a runaway table.'
    severity: 2
    enabled: true
    scopes: [postgresServerId]
    evaluationFrequency: 'PT15M'
    windowSize: 'PT30M'
    targetResourceType: 'Microsoft.DBforPostgreSQL/flexibleServers'
    criteria: {
      'odata.type': 'Microsoft.Azure.Monitor.SingleResourceMultipleMetricCriteria'
      allOf: [
        {
          name: 'storage_percent'
          metricNamespace: 'Microsoft.DBforPostgreSQL/flexibleServers'
          metricName: 'storage_percent'
          operator: 'GreaterThan'
          threshold: 85
          timeAggregation: 'Average'
          criterionType: 'StaticThresholdCriterion'
        }
      ]
    }
    actions: [{ actionGroupId: actionGroupId }]
  }
}

// ---------------------------------------------------------------------------
// Budget (scope: this resource group)
// ---------------------------------------------------------------------------

resource budget 'Microsoft.Consumption/budgets@2023-11-01' = {
  name: '${namePrefix}-budget-monthly'
  properties: {
    category: 'Cost'
    amount: monthlyBudgetUsd
    timeGrain: 'Monthly'
    timePeriod: {
      startDate: budgetStartDate
    }
    notifications: {
      actual80: {
        enabled: true
        operator: 'GreaterThan'
        threshold: 80
        thresholdType: 'Actual'
        contactEmails: alertEmails
        contactGroups: [actionGroupId]
      }
      actual100: {
        enabled: true
        operator: 'GreaterThan'
        threshold: 100
        thresholdType: 'Actual'
        contactEmails: alertEmails
        contactGroups: [actionGroupId]
      }
      forecast110: {
        enabled: true
        operator: 'GreaterThan'
        threshold: 110
        thresholdType: 'Forecasted'
        contactEmails: alertEmails
        contactGroups: [actionGroupId]
      }
    }
  }
}

output budgetId string = budget.id

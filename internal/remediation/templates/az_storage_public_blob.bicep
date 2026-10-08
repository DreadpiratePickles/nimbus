// Disables anonymous blob access and public network access on {{ .Name }}.
param location string = '{{ default "eastus" .Region }}'

resource storage 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: '{{ .Name }}'
  location: location
  kind: 'StorageV2'
  sku: { name: 'Standard_LRS' }
  properties: {
    allowBlobPublicAccess: false
    publicNetworkAccess: 'Disabled'
    minimumTlsVersion: 'TLS1_2'
    supportsHttpsTrafficOnly: true
  }
}

// Disables anonymous blob access on {{ .Name }}; network access is left as it is.
// ARM deployments PUT the account: set kind and SKU to the CURRENT values. Prefer the CLI:
// CLI: az storage account update --name={{ sh .Raw.Name }} --resource-group="$RESOURCE_GROUP" --allow-blob-public-access false
param location string = '{{ default "eastus" .Region }}'
param kind string = '{{ default "StorageV2" .Attr.kind }}'
param skuName string = '{{ default "Standard_LRS" .Attr.sku }}'

resource storage 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: '{{ .Name }}'
  location: location
  kind: kind
  sku: { name: skuName }
  properties: {
    allowBlobPublicAccess: false
    minimumTlsVersion: 'TLS1_2'
    supportsHttpsTrafficOnly: true
  }
}

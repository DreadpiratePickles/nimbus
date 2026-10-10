// ARM deployments PUT the account: set kind and SKU to the CURRENT values (a kind change is
// irreversible; a SKU change moves data). Prefer the in-place CLI:
// CLI: az storage account update --name={{ sh .Raw.Name }} --resource-group="$RESOURCE_GROUP" --https-only true --min-tls-version TLS1_2
param location string = '{{ default "eastus" .Region }}'
param kind string = '{{ default "StorageV2" .Attr.kind }}'
param skuName string = '{{ default "Standard_LRS" .Attr.sku }}'

resource storage 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: '{{ .Name }}'
  location: location
  kind: kind
  sku: { name: skuName }
  properties: {
    supportsHttpsTrafficOnly: true
    minimumTlsVersion: 'TLS1_2'
  }
}

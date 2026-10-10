// ARM deployments PUT the whole vault: any property not set here (access policies, network ACLs,
// RBAC mode, SKU) is reset. Prefer the in-place CLI, which changes only these two settings:
// CLI: az keyvault update --name={{ sh .Raw.Name }} --enable-purge-protection true --retention-days 90
// Purge protection cannot be turned off again once enabled.
param location string = '{{ default "eastus" .Region }}'
param tenantId string = subscription().tenantId
@description('Current SKU of the vault (standard or premium); a downgrade breaks HSM-backed keys.')
param skuName string = '{{ default "standard" .Attr.sku }}'

resource existingKv 'Microsoft.KeyVault/vaults@2023-07-01' existing = {
  name: '{{ .Name }}'
}

resource kv 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: '{{ .Name }}'
  location: location
  properties: {
    tenantId: tenantId
    sku: { family: 'A', name: skuName }
    // Carried over from the live vault so the PUT does not wipe them.
    accessPolicies: existingKv.properties.accessPolicies
    enableRbacAuthorization: existingKv.properties.enableRbacAuthorization
    networkAcls: existingKv.properties.networkAcls
    enableSoftDelete: true
    softDeleteRetentionInDays: 90
    enablePurgeProtection: true
  }
}

import {
  to = azurerm_key_vault.{{ .Slug }}
  id = "{{ .ID }}"
}

resource "azurerm_key_vault" "{{ .Slug }}" {
  name                       = "{{ .Name }}"
  location                   = "{{ default "eastus" .Region }}"
  resource_group_name        = {{ with .Attr.resource_group }}"{{ . }}"{{ else }}"TODO-rg"{{ end }}
  tenant_id                  = {{ with .Attr.tenant_id }}"{{ . }}"{{ else }}"TODO-tenant"{{ end }}
  sku_name                   = "standard"
  soft_delete_retention_days = 90
  purge_protection_enabled   = true
  lifecycle {
    ignore_changes = [access_policy, tags, sku_name, network_acls]
  }
}

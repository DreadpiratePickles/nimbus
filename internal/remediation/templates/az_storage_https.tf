import {
  to = azurerm_storage_account.{{ .Slug }}
  id = "{{ .ID }}"
}

resource "azurerm_storage_account" "{{ .Slug }}" {
  name                      = "{{ .Name }}"
  resource_group_name       = {{ with .Attr.resource_group }}"{{ . }}"{{ else }}"TODO-rg"{{ end }}
  location                  = "{{ default "eastus" .Region }}"
  account_tier              = "Standard"
  account_replication_type  = "LRS"
  https_traffic_only_enabled = true
  min_tls_version           = "TLS1_2"
  lifecycle {
    ignore_changes = [account_tier, account_replication_type, tags, location, resource_group_name]
  }
}

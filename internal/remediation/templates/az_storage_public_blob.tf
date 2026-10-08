import {
  to = azurerm_storage_account.{{ .Slug }}
  id = "{{ .ID }}"
}

resource "azurerm_storage_account" "{{ .Slug }}" {
  name                            = "{{ .Name }}"
  resource_group_name             = {{ with .Attr.resource_group }}"{{ . }}"{{ else }}"TODO-rg"{{ end }}
  location                        = "{{ default "eastus" .Region }}"
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  allow_nested_items_to_be_public = false
  public_network_access_enabled   = false
  min_tls_version                 = "TLS1_2"
  lifecycle {
    ignore_changes = [account_tier, account_replication_type, tags, location, resource_group_name]
  }
}
# CLI: az storage account update -n {{ .Name }} -g <rg> --allow-blob-public-access false

variable "{{ .Slug }}_allowed_source" {
  description = "Source address prefix allowed on the previously world-open port"
  type        = string
  default     = "10.0.0.0/8"
}
{{ range .Ports }}
resource "azurerm_network_security_rule" "{{ $.Slug }}_restrict_{{ . }}" {
  name                        = "cloud-posture-restrict-{{ . }}"
  priority                    = 100
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "{{ . }}"
  source_address_prefix       = var.{{ $.Slug }}_allowed_source
  destination_address_prefix  = "*"
  resource_group_name         = {{ with $.Attr.resource_group }}"{{ . }}"{{ else }}"TODO-rg"{{ end }}
  network_security_group_name = "{{ $.Name }}"
}
{{ end }}
# Then delete the Internet/Any rule:  az network nsg rule delete -g <rg> --nsg-name {{ .Name }} -n <open-rule>

# Least-change fix for NSG {{ .Name }}: two higher-precedence rules per port, nothing deleted.
# priority_base (allow) and priority_base+1 (deny Internet) must be lower numbers than the
# world-open rule and unused in this NSG (Azure rejects duplicates; nothing is overwritten).
variable "{{ .Slug }}_allowed_source" {
  description = "REQUIRED: source CIDR or service tag (e.g. VirtualNetwork, your VPN range) allowed on the previously Internet-open port(s)."
  type        = string
  validation {
    condition     = !contains(["*", "internet", "any"], lower(var.{{ .Slug }}_allowed_source)) && !endswith(var.{{ .Slug }}_allowed_source, "/0")
    error_message = "allowed_source must not be *, Internet, Any or a /0 range."
  }
}

variable "{{ .Slug }}_priority_base" {
  description = "Priority for the allow rule; the deny-Internet rule uses priority_base + 1 (per port, +10 between ports)."
  type        = number
  default     = 100
}
{{ range $i, $p := .Ports }}
resource "azurerm_network_security_rule" "{{ $.Slug }}_allow_{{ $p }}" {
  name                        = "nimbus-allow-{{ $p }}"
  priority                    = var.{{ $.Slug }}_priority_base + {{ $i }} * 10
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "{{ $p }}"
  source_address_prefix       = var.{{ $.Slug }}_allowed_source
  destination_address_prefix  = "*"
  resource_group_name         = {{ with $.Attr.resource_group }}"{{ . }}"{{ else }}"TODO-rg"{{ end }}
  network_security_group_name = "{{ $.Name }}"
}

resource "azurerm_network_security_rule" "{{ $.Slug }}_deny_internet_{{ $p }}" {
  name                        = "nimbus-deny-internet-{{ $p }}"
  priority                    = var.{{ $.Slug }}_priority_base + {{ $i }} * 10 + 1
  direction                   = "Inbound"
  access                      = "Deny"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "{{ $p }}"
  source_address_prefix       = "Internet"
  destination_address_prefix  = "*"
  resource_group_name         = {{ with $.Attr.resource_group }}"{{ . }}"{{ else }}"TODO-rg"{{ end }}
  network_security_group_name = "{{ $.Name }}"
}
{{ end }}
# Optional clean-up once traffic is verified: delete the old Internet/Any rule
# (set RESOURCE_GROUP and OPEN_RULE, the name of the world-open rule):
# CLI: az network nsg rule delete --resource-group="$RESOURCE_GROUP" --nsg-name={{ sh .Raw.Name }} --name="$OPEN_RULE"

// Least-change fix for NSG {{ .Name }}: an allow rule for your source plus a deny-Internet rule at
// higher precedence, per port. Nothing is deleted; priorities must be unused in this NSG.
@description('REQUIRED: source CIDR or service tag (e.g. VirtualNetwork) allowed on the previously Internet-open port(s).')
param allowedSource string
param priorityBase int = 100

resource nsg 'Microsoft.Network/networkSecurityGroups@2023-05-01' existing = {
  name: '{{ .Name }}'
}
{{ range $i, $p := .Ports }}
resource allow{{ $p }} 'Microsoft.Network/networkSecurityGroups/securityRules@2023-05-01' = {
  parent: nsg
  name: 'nimbus-allow-{{ $p }}'
  properties: {
    priority: priorityBase + {{ $i }} * 10
    direction: 'Inbound'
    access: 'Allow'
    protocol: 'Tcp'
    sourcePortRange: '*'
    destinationPortRange: '{{ $p }}'
    sourceAddressPrefix: allowedSource
    destinationAddressPrefix: '*'
  }
}

resource denyInternet{{ $p }} 'Microsoft.Network/networkSecurityGroups/securityRules@2023-05-01' = {
  parent: nsg
  name: 'nimbus-deny-internet-{{ $p }}'
  properties: {
    priority: priorityBase + {{ $i }} * 10 + 1
    direction: 'Inbound'
    access: 'Deny'
    protocol: 'Tcp'
    sourcePortRange: '*'
    destinationPortRange: '{{ $p }}'
    sourceAddressPrefix: 'Internet'
    destinationAddressPrefix: '*'
  }
}
{{ end }}
// Optional clean-up once traffic is verified (set RESOURCE_GROUP and OPEN_RULE, the world-open rule):
// CLI: az network nsg rule delete --resource-group="$RESOURCE_GROUP" --nsg-name={{ sh .Raw.Name }} --name="$OPEN_RULE"

param allowedSource string = '10.0.0.0/8'
param location string = '{{ default "eastus" .Region }}'

resource nsg 'Microsoft.Network/networkSecurityGroups@2023-05-01' existing = {
  name: '{{ .Name }}'
}
{{ range .Ports }}
resource restrict{{ . }} 'Microsoft.Network/networkSecurityGroups/securityRules@2023-05-01' = {
  parent: nsg
  name: 'cloud-posture-restrict-{{ . }}'
  properties: {
    priority: 100
    direction: 'Inbound'
    access: 'Allow'
    protocol: 'Tcp'
    sourcePortRange: '*'
    destinationPortRange: '{{ . }}'
    sourceAddressPrefix: allowedSource
    destinationAddressPrefix: '*'
  }
}
{{ end }}
// Then remove the Internet/Any rule: az network nsg rule delete -g <rg> --nsg-name {{ .Name }} -n <open-rule>

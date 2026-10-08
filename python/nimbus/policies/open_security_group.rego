# Deny security groups that open administrative ports (or everything) to the internet.
# Input: Terraform plan JSON.
package nimbus.aws.open_security_group

import rego.v1

admin_ports := {22, 3389, 5432, 3306, 1433, 6379, 9200, 27017}

open_cidr(c) if c == "0.0.0.0/0"

open_cidr(c) if c == "::/0"

deny contains msg if {
	rc := input.resource_changes[_]
	rc.type == "aws_security_group"
	rule := rc.change.after.ingress[_]
	some cidr in array.concat(object.get(rule, "cidr_blocks", []), object.get(rule, "ipv6_cidr_blocks", []))
	open_cidr(cidr)
	exposes_admin(rule.from_port, rule.to_port, rule.protocol)
	msg := sprintf("%s: ingress %v-%v open to %s (EC2_SG_OPEN_SSH/RDP/ALL)", [rc.address, rule.from_port, rule.to_port, cidr])
}

deny contains msg if {
	rc := input.resource_changes[_]
	rc.type in {"aws_vpc_security_group_ingress_rule", "aws_security_group_rule"}
	object.get(rc.change.after, "type", "ingress") == "ingress"
	some cidr in array.concat(object.get(rc.change.after, "cidr_blocks", []), [object.get(rc.change.after, "cidr_ipv4", "")])
	open_cidr(cidr)
	exposes_admin(rc.change.after.from_port, rc.change.after.to_port, object.get(rc.change.after, "ip_protocol", object.get(rc.change.after, "protocol", "tcp")))
	msg := sprintf("%s: rule opens %v-%v to %s", [rc.address, rc.change.after.from_port, rc.change.after.to_port, cidr])
}

exposes_admin(_, _, proto) if proto == "-1"

exposes_admin(from, to, _) if {
	some p in admin_ports
	from <= p
	p <= to
}

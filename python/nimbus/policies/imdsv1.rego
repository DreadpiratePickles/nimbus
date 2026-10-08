# Require IMDSv2 (http_tokens = "required") on EC2 instances and launch templates.
# Input: Terraform plan JSON.
package nimbus.aws.imdsv1

import rego.v1

deny contains msg if {
	rc := input.resource_changes[_]
	rc.type in {"aws_instance", "aws_launch_template"}
	not imdsv2_required(rc.change.after)
	msg := sprintf("%s: metadata_options.http_tokens must be \"required\" (EC2_IMDSV1)", [rc.address])
}

imdsv2_required(after) if {
	some opt in after.metadata_options
	opt.http_tokens == "required"
}

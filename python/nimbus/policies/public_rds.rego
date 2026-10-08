# Deny publicly accessible RDS instances.
# Input: Terraform plan JSON.
package nimbus.aws.public_rds

import rego.v1

deny contains msg if {
	rc := input.resource_changes[_]
	rc.type in {"aws_db_instance", "aws_rds_cluster_instance"}
	rc.change.after.publicly_accessible == true
	msg := sprintf("%s: publicly_accessible must be false (RDS_PUBLIC)", [rc.address])
}

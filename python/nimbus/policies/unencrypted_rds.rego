# Require storage encryption on RDS instances and Aurora clusters.
# Input: Terraform plan JSON.
package nimbus.aws.unencrypted_rds

import rego.v1

deny contains msg if {
	rc := input.resource_changes[_]
	rc.type in {"aws_db_instance", "aws_rds_cluster"}
	not rc.change.after.storage_encrypted == true
	msg := sprintf("%s: storage_encrypted must be true (RDS_UNENCRYPTED)", [rc.address])
}

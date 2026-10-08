# Deny S3 buckets that can become public.
# Input: `terraform show -json plan.out` (resource_changes).
package nimbus.aws.s3_public

import rego.v1

public_acls := {"public-read", "public-read-write", "authenticated-read"}

deny contains msg if {
	rc := input.resource_changes[_]
	rc.type == "aws_s3_bucket_acl"
	public_acls[rc.change.after.acl]
	msg := sprintf("%s: S3 bucket ACL %q makes the bucket public (S3_PUBLIC_BUCKET)", [rc.address, rc.change.after.acl])
}

deny contains msg if {
	rc := input.resource_changes[_]
	rc.type == "aws_s3_bucket_public_access_block"
	some flag in ["block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"]
	rc.change.after[flag] == false
	msg := sprintf("%s: %s must be true (S3_PUBLIC_BUCKET)", [rc.address, flag])
}

deny contains msg if {
	rc := input.resource_changes[_]
	rc.type == "aws_s3_bucket"
	not has_public_access_block(rc.change.after.bucket)
	msg := sprintf("%s: bucket has no aws_s3_bucket_public_access_block (S3_PUBLIC_BUCKET)", [rc.address])
}

has_public_access_block(bucket) if {
	rc := input.resource_changes[_]
	rc.type == "aws_s3_bucket_public_access_block"
	rc.change.after.bucket == bucket
}

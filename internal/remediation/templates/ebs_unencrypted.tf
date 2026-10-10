# Turn on account-wide default EBS encryption; existing volumes need a snapshot/copy cycle.
resource "aws_ebs_encryption_by_default" "{{ .Slug }}" {
  enabled = true
}
# Migrate {{ .Name }}:
# CLI: aws ec2 create-snapshot --volume-id={{ sh .Raw.Name }} --description "pre-encryption"
# then, with SNAPSHOT_ID set to the snapshot it printed:
# CLI: aws ec2 copy-snapshot --source-snapshot-id="$SNAPSHOT_ID" --encrypted --source-region={{ sh (default "us-east-1" .Raw.Region) }}

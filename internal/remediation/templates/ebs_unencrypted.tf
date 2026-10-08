# Turn on account-wide default EBS encryption; existing volumes need a snapshot/copy cycle.
resource "aws_ebs_encryption_by_default" "{{ .Slug }}" {
  enabled = true
}
# Migrate {{ .Name }}:
#   aws ec2 create-snapshot --volume-id {{ .Name }} --description "pre-encryption"
#   aws ec2 copy-snapshot --source-snapshot-id <snap> --encrypted --source-region {{ default "us-east-1" .Region }}

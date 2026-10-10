package iam

import (
	"encoding/json"
	"strings"
)

// Built-in copies of well-known AWS managed policies, used when a principal names an attached
// managed policy whose document was not collected (the lab estate, ingested inventories).
// AdministratorAccess is exact (its document is Allow * on *). The others are the documented
// shape of the policy's data-relevant statements, not the full current version: decisions that
// rest on them are never "verified" (callers read the exact flag).
var managedDocs = map[string]struct {
	exact bool
	doc   string
}{
	"AdministratorAccess": {true, `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`},
	"PowerUserAccess": {false, `{"Version":"2012-10-17","Statement":[
		{"Effect":"Allow","NotAction":["iam:*","organizations:*","account:*"],"Resource":"*"},
		{"Effect":"Allow","Action":["iam:CreateServiceLinkedRole","iam:DeleteServiceLinkedRole","iam:ListRoles","organizations:DescribeOrganization","account:ListRegions","account:GetAccountInformation"],"Resource":"*"}]}`},
	"ReadOnlyAccess": {false, `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":[
		"s3:Get*","s3:List*","dynamodb:BatchGet*","dynamodb:Describe*","dynamodb:Get*","dynamodb:List*","dynamodb:Query","dynamodb:Scan",
		"kms:Describe*","kms:Get*","kms:List*","secretsmanager:Describe*","secretsmanager:List*","secretsmanager:GetResourcePolicy",
		"iam:Get*","iam:List*","iam:Generate*","ec2:Describe*","ec2:Get*","lambda:Get*","lambda:List*","rds:Describe*","rds:List*",
		"sqs:Get*","sqs:List*","sns:Get*","sns:List*","sts:GetCallerIdentity","organizations:Describe*","organizations:List*",
		"logs:Describe*","logs:Get*","cloudtrail:Describe*","cloudtrail:Get*","cloudtrail:LookupEvents","eks:Describe*","eks:List*"],"Resource":"*"}]}`},
	"AmazonS3FullAccess":       {false, `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:*","s3-object-lambda:*"],"Resource":"*"}]}`},
	"AmazonS3ReadOnlyAccess":   {false, `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:Get*","s3:List*","s3:Describe*","s3-object-lambda:Get*","s3-object-lambda:List*"],"Resource":"*"}]}`},
	"IAMFullAccess":            {false, `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["iam:*","organizations:DescribeAccount","organizations:DescribeOrganization","organizations:DescribeOrganizationalUnit","organizations:DescribePolicy","organizations:ListChildren","organizations:ListParents","organizations:ListPoliciesForTarget","organizations:ListRoots","organizations:ListPolicies","organizations:ListTargetsForPolicy"],"Resource":"*"}]}`},
	"SecretsManagerReadWrite":  {false, `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["secretsmanager:*","kms:DescribeKey","kms:ListAliases","kms:ListKeys"],"Resource":"*"}]}`},
	"AmazonDynamoDBFullAccess": {false, `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["dynamodb:*"],"Resource":"*"}]}`},
	"AmazonEC2FullAccess":      {false, `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["ec2:*","elasticloadbalancing:*","cloudwatch:*","autoscaling:*"],"Resource":"*"}]}`},
	"FullAWSAccess":            {true, `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`},
}

// FullAWSAccessID is the policy id of the default SCP every OU level carries.
const FullAWSAccessID = "p-FullAWSAccess"

// ManagedPolicy returns the built-in copy of an AWS managed policy named by ARN
// (arn:aws:iam::aws:policy/<path/>Name) or bare name. exact reports that the copy is the
// complete document. A customer-managed policy ARN never matches.
func ManagedPolicy(ref string) (p Policy, exact, ok bool) {
	name := ref
	if strings.HasPrefix(ref, "arn:") {
		if !strings.HasPrefix(ref, "arn:aws:iam::aws:policy/") {
			return Policy{}, false, false
		}
		name = ref[strings.LastIndex(ref, "/")+1:]
	}
	m, found := managedDocs[name]
	if !found {
		return Policy{}, false, false
	}
	p, err := ParsePolicy([]byte(m.doc))
	if err != nil {
		return Policy{}, false, false
	}
	p.ID = ref
	if !strings.HasPrefix(ref, "arn:") && name != "FullAWSAccess" {
		p.ID = "arn:aws:iam::aws:policy/" + name
	}
	if name == "FullAWSAccess" {
		p.ID = FullAWSAccessID
	}
	return p, m.exact, true
}

// ParseAny parses a policy given as JSON text, raw JSON bytes, or a decoded JSON value (the
// map an ingested finding carries). A single statement object (no Statement key) is wrapped.
func ParseAny(v any) (Policy, error) {
	var b []byte
	switch x := v.(type) {
	case string:
		b = []byte(x)
	case []byte:
		b = x
	case json.RawMessage:
		b = x
	default:
		var err error
		if b, err = json.Marshal(v); err != nil {
			return Policy{}, err
		}
	}
	var probe map[string]json.RawMessage
	if json.Unmarshal(b, &probe) == nil {
		if _, ok := probe["Statement"]; !ok {
			if _, eff := probe["Effect"]; eff {
				b = append(append([]byte(`{"Version":"2012-10-17","Statement":[`), b...), ']', '}')
			}
		}
	}
	return ParsePolicy(b)
}

// Tier groups the curated actions probed per resource type.
type Tier string

const (
	TierRead     Tier = "read"     // reads the data (exfiltration)
	TierWrite    Tier = "write"    // changes or destroys the data
	TierAdmin    Tier = "admin"    // changes who can access it
	TierMetadata Tier = "metadata" // lists or describes without reading content
	TierInvoke   Tier = "invoke"   // runs existing code
	TierAssume   Tier = "assume"   // obtains the role's credentials
	TierPass     Tier = "pass"     // hands the role to a service
)

// Probe is one (action, resource) request evaluated for a resource.
type Probe struct {
	Tier     Tier
	Action   string
	Resource string
	// ImpliesRead: an admin action that by itself yields the data (RDS master-password reset).
	ImpliesRead bool
}

// ResourceProbes is the curated action set for a resource type (graph node type), resolved to
// concrete request resources (S3 object actions on <bucket>/*). Unsupported types return nil.
func ResourceProbes(resourceType, arn string) []Probe {
	p := func(t Tier, res string, acts ...string) []Probe {
		out := make([]Probe, 0, len(acts))
		for _, a := range acts {
			out = append(out, Probe{Tier: t, Action: a, Resource: res})
		}
		return out
	}
	var out []Probe
	switch resourceType {
	case "aws_s3_bucket":
		obj := arn + "/*"
		out = append(out, p(TierRead, obj, "s3:GetObject")...)
		out = append(out, p(TierWrite, obj, "s3:PutObject", "s3:DeleteObject")...)
		out = append(out, p(TierAdmin, arn, "s3:PutBucketPolicy", "s3:PutBucketAcl", "s3:DeleteBucket")...)
		out = append(out, p(TierMetadata, arn, "s3:ListBucket")...)
		// s3:GetObjectVersion is not probed (v1 models the current-object read; see evaluator.md).
	case "aws_dynamodb_table":
		out = append(out, p(TierRead, arn, "dynamodb:GetItem", "dynamodb:Query", "dynamodb:Scan", "dynamodb:BatchGetItem")...)
		out = append(out, p(TierWrite, arn, "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:DeleteItem", "dynamodb:BatchWriteItem")...)
		out = append(out, p(TierAdmin, arn, "dynamodb:DeleteTable", "dynamodb:UpdateTable", "dynamodb:PutResourcePolicy")...)
	case "aws_kms_key":
		out = append(out, p(TierRead, arn, "kms:Decrypt")...)
		out = append(out, p(TierWrite, arn, "kms:Encrypt", "kms:GenerateDataKey")...)
		out = append(out, p(TierAdmin, arn, "kms:PutKeyPolicy", "kms:CreateGrant", "kms:ScheduleKeyDeletion")...)
	case "aws_secretsmanager_secret":
		out = append(out, p(TierRead, arn, "secretsmanager:GetSecretValue")...)
		out = append(out, p(TierWrite, arn, "secretsmanager:PutSecretValue", "secretsmanager:UpdateSecret")...)
		out = append(out, p(TierAdmin, arn, "secretsmanager:PutResourcePolicy", "secretsmanager:DeleteSecret")...)
	case "aws_db_instance", "aws_rds_cluster":
		region, acct := arnRegion(arn), arnAccount(arn)
		out = append(out, p(TierRead, "arn:aws:rds-db:"+region+":"+acct+":dbuser:*/*", "rds-db:connect")...)
		out = append(out, Probe{Tier: TierAdmin, Action: "rds:ModifyDBInstance", Resource: arn, ImpliesRead: true})
		out = append(out, p(TierAdmin, arn, "rds:CreateDBSnapshot", "rds:DeleteDBInstance")...)
	case "aws_sqs_queue":
		out = append(out, p(TierRead, arn, "sqs:ReceiveMessage")...)
		out = append(out, p(TierWrite, arn, "sqs:SendMessage", "sqs:PurgeQueue")...)
		out = append(out, p(TierAdmin, arn, "sqs:SetQueueAttributes", "sqs:AddPermission")...)
	case "aws_sns_topic":
		out = append(out, p(TierRead, arn, "sns:Subscribe")...)
		out = append(out, p(TierWrite, arn, "sns:Publish")...)
		out = append(out, p(TierAdmin, arn, "sns:SetTopicAttributes", "sns:AddPermission")...)
	case "aws_ssm_parameter":
		out = append(out, p(TierRead, arn, "ssm:GetParameter", "ssm:GetParameters")...)
		out = append(out, p(TierWrite, arn, "ssm:PutParameter")...)
	case "aws_lambda_function":
		out = append(out, p(TierInvoke, arn, "lambda:InvokeFunction")...)
		out = append(out, p(TierRead, arn, "lambda:GetFunction")...)
		out = append(out, p(TierWrite, arn, "lambda:UpdateFunctionCode")...)
		out = append(out, p(TierAdmin, arn, "lambda:AddPermission")...)
	case "aws_iam_role":
		out = append(out, p(TierAssume, arn, "sts:AssumeRole")...)
		out = append(out, p(TierPass, arn, "iam:PassRole")...)
		out = append(out, p(TierAdmin, arn, "iam:UpdateAssumeRolePolicy", "iam:PutRolePolicy", "iam:AttachRolePolicy")...)
	}
	return out
}

func arnRegion(arn string) string {
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) < 4 {
		return ""
	}
	return parts[3]
}

// AdminDecision adapts EvaluateSet for IsAdmin: the sampled resources are moved into the
// principal's own account so a same-account admin is not mistaken for a cross-account denial.
func AdminDecision(principal, account string, ps PolicySet) DecisionFunc {
	return func(action, resource string) Decision {
		if a := arnAccount(resource); a != "" && account != "" {
			resource = strings.Replace(resource, ":"+a+":", ":"+account+":", 1)
		}
		return EvaluateSet(Request{Principal: principal, Action: action, Resource: resource, ResourceAccount: account}, ps)
	}
}

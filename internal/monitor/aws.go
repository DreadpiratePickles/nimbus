package monitor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cttypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"

	"github.com/DreadpiratePickles/nimbus/internal/collector/core"
	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// CloudTrailEvents are the management events the AWS source watches.
var CloudTrailEvents = []string{
	"PutBucketAcl", "PutBucketPolicy", "DeleteBucketPolicy", "PutPublicAccessBlock", "DeletePublicAccessBlock",
	"AuthorizeSecurityGroupIngress", "AttachRolePolicy", "AttachUserPolicy", "PutRolePolicy", "PutUserPolicy",
	"CreateAccessKey", "ConsoleLogin", "StopLogging", "DeleteTrail", "UpdateTrail", "ModifyDBInstance",
	"DeactivateMFADevice", "CreateUser", "UpdateAssumeRolePolicy", "ModifyInstanceMetadataOptions",
}

// CloudTrailAPI is the subset of *cloudtrail.Client the monitor uses.
type CloudTrailAPI interface {
	LookupEvents(ctx context.Context, in *cloudtrail.LookupEventsInput, optFns ...func(*cloudtrail.Options)) (*cloudtrail.LookupEventsOutput, error)
}

// CloudTrailSource polls LookupEvents for one account and region.
type CloudTrailSource struct {
	API     CloudTrailAPI
	Account string // fallback account when events lack recipientAccountId
	Region  string
	Events  []string
	Now     func() time.Time
}

func (s *CloudTrailSource) Name() string { return "cloudtrail:" + s.Region }

// Poll issues one paginated LookupEvents query per watched event name (the API
// accepts a single lookup attribute per call).
func (s *CloudTrailSource) Poll(ctx context.Context, since time.Time) ([]Event, error) {
	names := s.Events
	if len(names) == 0 {
		names = CloudTrailEvents
	}
	end := time.Now()
	if s.Now != nil {
		end = s.Now()
	}
	var out []Event
	var errs []error
	for _, name := range names {
		p := cloudtrail.NewLookupEventsPaginator(s.API, &cloudtrail.LookupEventsInput{
			StartTime:        aws.Time(since),
			EndTime:          aws.Time(end),
			LookupAttributes: []cttypes.LookupAttribute{{AttributeKey: cttypes.LookupAttributeKeyEventName, AttributeValue: aws.String(name)}},
			MaxResults:       aws.Int32(50),
		})
		for p.HasMorePages() {
			page, err := p.NextPage(ctx)
			if err != nil {
				errs = append(errs, fmt.Errorf("LookupEvents %s: %w", name, err))
				break
			}
			for _, ev := range page.Events {
				if ev.CloudTrailEvent == nil {
					continue
				}
				if e, ok := MapCloudTrail(*ev.CloudTrailEvent, s.Account, s.Region); ok {
					if e.Time.IsZero() && ev.EventTime != nil {
						e.Time = *ev.EventTime
					}
					out = append(out, e)
				}
			}
		}
		if ctx.Err() != nil {
			errs = append(errs, ctx.Err())
			break
		}
	}
	return out, errors.Join(errs...)
}

func newCloudTrailSources(ctx context.Context, spec core.AccountSpec) ([]Source, error) {
	regions := spec.Regions
	if len(regions) == 0 {
		regions = []string{core.DefaultAWSRegion}
	}
	var out []Source
	var errs []error
	for _, r := range regions {
		cfg, err := core.AWSConfig(ctx, spec, r)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		out = append(out, &CloudTrailSource{API: cloudtrail.NewFromConfig(cfg), Account: spec.Label(), Region: r})
	}
	return out, errors.Join(errs...)
}

// MapCloudTrail maps one CloudTrailEvent JSON document onto a monitor Event. It
// returns false for unwatched or failed calls.
func MapCloudTrail(raw string, account, region string) (Event, bool) {
	var ev map[string]any
	if err := json.Unmarshal([]byte(raw), &ev); err != nil {
		return Event{}, false
	}
	if gets(ev, "errorCode") != "" {
		return Event{}, false
	}
	name := gets(ev, "eventName")
	if acct := gets(ev, "recipientAccountId"); acct != "" {
		account = acct
	}
	if r := gets(ev, "awsRegion"); r != "" {
		region = r
	}
	e := Event{
		Provider:  model.ProviderAWS,
		Account:   account,
		Region:    region,
		Source:    gets(ev, "eventSource"),
		EventName: name,
		Actor:     ctActor(ev),
		Raw:       ev,
	}
	if e.Source == "" {
		e.Source = "cloudtrail"
	}
	if t, err := time.Parse(time.RFC3339, gets(ev, "eventTime")); err == nil {
		e.Time = t
	}
	ev["event_id"] = gets(ev, "eventID")
	req := get(ev, "requestParameters")
	bucket := gets(req, "bucketName")
	bucketARN := "arn:aws:s3:::" + bucket
	set := func(canon string, sev model.Severity, resID, resType, title string) {
		e.CanonicalID, e.Severity, e.ResourceID, e.ResourceType, e.Title = canon, sev, resID, resType, title
	}

	switch name {
	case "PutBucketAcl":
		if s3ACLPublic(req) {
			set("S3_PUBLIC_BUCKET", model.High, bucketARN, "aws_s3_bucket", "S3 bucket ACL grants public access")
		} else {
			set("", model.Low, bucketARN, "aws_s3_bucket", "S3 bucket ACL changed")
		}
	case "PutBucketPolicy":
		if policyPublic(jsonish(get(req, "bucketPolicy"))) {
			set("S3_PUBLIC_BUCKET", model.High, bucketARN, "aws_s3_bucket", "S3 bucket policy allows public (Principal *) access")
		} else {
			set("", model.Low, bucketARN, "aws_s3_bucket", "S3 bucket policy changed")
		}
	case "DeleteBucketPolicy":
		set("", model.Low, bucketARN, "aws_s3_bucket", "S3 bucket policy deleted")
	case "DeletePublicAccessBlock":
		set("S3_PUBLIC_BUCKET", model.High, bucketARN, "aws_s3_bucket", "S3 Block Public Access removed")
	case "PutPublicAccessBlock":
		cfg := get(req, "PublicAccessBlockConfiguration")
		weakened := false
		for _, k := range []string{"BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"} {
			if isFalse(get(cfg, k)) {
				weakened = true
			}
		}
		if weakened {
			set("S3_PUBLIC_BUCKET", model.High, bucketARN, "aws_s3_bucket", "S3 Block Public Access weakened")
		} else {
			set("", model.Info, bucketARN, "aws_s3_bucket", "S3 Block Public Access enabled")
		}
	case "AuthorizeSecurityGroupIngress":
		gid := gets(req, "groupId")
		id := fmt.Sprintf("arn:aws:ec2:%s:%s:security-group/%s", region, account, gid)
		switch sgExposure(req) {
		case "all":
			set("EC2_SG_OPEN_ALL", model.Critical, id, "aws_security_group", "Security group opened all ports to the internet")
		case "ssh":
			set("EC2_SG_OPEN_SSH", model.High, id, "aws_security_group", "Security group opened SSH (22) to the internet")
		case "rdp":
			set("EC2_SG_OPEN_RDP", model.High, id, "aws_security_group", "Security group opened RDP (3389) to the internet")
		case "other":
			set("", model.Medium, id, "aws_security_group", "Security group opened a port to the internet")
		default:
			set("", model.Low, id, "aws_security_group", "Security group ingress rule added")
		}
	case "AttachRolePolicy", "AttachUserPolicy":
		resID, resType := iamPrincipal(req, account)
		arn := gets(req, "policyArn")
		if strings.HasSuffix(arn, "/AdministratorAccess") {
			set("IAM_ADMIN_POLICY", model.Critical, resID, resType, "AdministratorAccess attached to "+lastSeg(resID))
		} else {
			set("", model.Low, resID, resType, "Managed policy "+lastSeg(arn)+" attached to "+lastSeg(resID))
		}
	case "PutRolePolicy", "PutUserPolicy":
		resID, resType := iamPrincipal(req, account)
		if policyAdmin(decodePolicy(get(req, "policyDocument"))) {
			set("IAM_ADMIN_POLICY", model.Critical, resID, resType, "Inline policy grants *:* to "+lastSeg(resID))
		} else {
			set("", model.Low, resID, resType, "Inline policy changed on "+lastSeg(resID))
		}
	case "CreateAccessKey":
		user := gets(get(ev, "responseElements"), "accessKey", "userName")
		if user == "" {
			user = gets(req, "userName")
		}
		set("", model.Low, fmt.Sprintf("arn:aws:iam::%s:user/%s", account, user), "aws_iam_user", "New access key created for "+user)
	case "ConsoleLogin":
		if gets(ev, "userIdentity", "type") != "Root" || gets(ev, "responseElements", "ConsoleLogin") == "Failure" {
			return Event{}, false
		}
		id := fmt.Sprintf("arn:aws:iam::%s:root", account)
		if strings.EqualFold(gets(ev, "additionalEventData", "MFAUsed"), "No") {
			set("IAM_ROOT_NO_MFA", model.Critical, id, "aws_iam_root", "Root user console login without MFA")
		} else {
			set("", model.Medium, id, "aws_iam_root", "Root user console login")
		}
	case "StopLogging", "DeleteTrail":
		set("CLOUDTRAIL_DISABLED", model.Critical, trailARN(gets(req, "name"), region, account), "aws_cloudtrail", "CloudTrail logging stopped ("+name+")")
	case "UpdateTrail":
		id := trailARN(gets(req, "name"), region, account)
		if isFalse(get(req, "isMultiRegionTrail")) {
			set("CLOUDTRAIL_DISABLED", model.High, id, "aws_cloudtrail", "CloudTrail changed to single-region")
		} else {
			set("", model.Low, id, "aws_cloudtrail", "CloudTrail trail updated")
		}
	case "ModifyDBInstance":
		db := gets(req, "dBInstanceIdentifier")
		id := fmt.Sprintf("arn:aws:rds:%s:%s:db:%s", region, account, db)
		if isTrue(get(req, "publiclyAccessible")) {
			set("RDS_PUBLIC", model.Critical, id, "aws_db_instance", "RDS instance made publicly accessible")
		} else {
			set("", model.Low, id, "aws_db_instance", "RDS instance modified")
		}
	case "DeactivateMFADevice":
		user := gets(req, "userName")
		set("IAM_USER_NO_MFA", model.High, fmt.Sprintf("arn:aws:iam::%s:user/%s", account, user), "aws_iam_user", "MFA device deactivated for "+user)
	case "CreateUser":
		user := gets(req, "userName")
		set("", model.Low, fmt.Sprintf("arn:aws:iam::%s:user/%s", account, user), "aws_iam_user", "IAM user created: "+user)
	case "UpdateAssumeRolePolicy":
		role := gets(req, "roleName")
		id := fmt.Sprintf("arn:aws:iam::%s:role/%s", account, role)
		if trustExternal(decodePolicy(get(req, "policyDocument")), account) {
			set("IAM_CROSS_ACCOUNT_TRUST", model.High, id, "aws_iam_role", "Role trust policy allows external or wildcard principals")
		} else {
			set("", model.Low, id, "aws_iam_role", "Role trust policy updated")
		}
	case "ModifyInstanceMetadataOptions":
		inst, tokens := "", ""
		walk(req, func(k string, v any) {
			switch strings.ToLower(k) {
			case "instanceid":
				inst = str(v)
			case "httptokens":
				tokens = str(v)
			}
		})
		id := fmt.Sprintf("arn:aws:ec2:%s:%s:instance/%s", region, account, inst)
		if strings.EqualFold(tokens, "optional") {
			set("EC2_IMDSV1", model.High, id, "aws_instance", "Instance metadata changed to allow IMDSv1")
		} else {
			set("", model.Low, id, "aws_instance", "Instance metadata options modified")
		}
	default:
		return Event{}, false
	}
	return e, true
}

func ctActor(ev map[string]any) string {
	for _, p := range [][]string{{"userIdentity", "arn"}, {"userIdentity", "userName"}, {"userIdentity", "principalId"}, {"userIdentity", "invokedBy"}} {
		if v := gets(ev, p...); v != "" {
			return v
		}
	}
	return ""
}

func iamPrincipal(req any, account string) (string, string) {
	if r := gets(req, "roleName"); r != "" {
		return fmt.Sprintf("arn:aws:iam::%s:role/%s", account, r), "aws_iam_role"
	}
	return fmt.Sprintf("arn:aws:iam::%s:user/%s", account, gets(req, "userName")), "aws_iam_user"
}

func trailARN(name, region, account string) string {
	if strings.HasPrefix(name, "arn:") {
		return name
	}
	return fmt.Sprintf("arn:aws:cloudtrail:%s:%s:trail/%s", region, account, name)
}

func s3ACLPublic(req any) bool {
	for _, acl := range strs(get(req, "x-amz-acl")) {
		if strings.HasPrefix(acl, "public-read") || acl == "authenticated-read" {
			return true
		}
	}
	return containsString(get(req, "AccessControlPolicy"), "acs.amazonaws.com/groups/global/AllUsers", "acs.amazonaws.com/groups/global/AuthenticatedUsers") ||
		containsString(req, "uri=http://acs.amazonaws.com/groups/global/AllUsers")
}

// decodePolicy accepts a policy document as object, JSON string or URL-encoded JSON string.
func decodePolicy(v any) any {
	if s, ok := v.(string); ok {
		if u, err := url.QueryUnescape(s); err == nil && strings.HasPrefix(strings.TrimSpace(u), "{") {
			s = u
		}
		return jsonish(s)
	}
	return v
}

func statements(doc any) []any { return list(get(doc, "Statement")) }

func principalWildcard(p any) bool {
	if str(p) == "*" {
		return true
	}
	for _, k := range []string{"AWS", "CanonicalUser"} {
		for _, s := range strs(get(p, k)) {
			if s == "*" {
				return true
			}
		}
	}
	return false
}

func policyPublic(doc any) bool {
	for _, st := range statements(doc) {
		if gets(st, "Effect") == "Allow" && principalWildcard(get(st, "Principal")) && get(st, "Condition") == nil {
			return true
		}
	}
	return false
}

func policyAdmin(doc any) bool {
	for _, st := range statements(doc) {
		if gets(st, "Effect") != "Allow" {
			continue
		}
		act, res := false, false
		for _, a := range strs(get(st, "Action")) {
			if a == "*" || a == "*:*" {
				act = true
			}
		}
		for _, r := range strs(get(st, "Resource")) {
			if r == "*" {
				res = true
			}
		}
		if act && res {
			return true
		}
	}
	return false
}

func trustExternal(doc any, account string) bool {
	for _, st := range statements(doc) {
		if gets(st, "Effect") != "Allow" {
			continue
		}
		p := get(st, "Principal")
		if principalWildcard(p) {
			return true
		}
		for _, a := range strs(get(p, "AWS")) {
			acct := a
			if strings.HasPrefix(a, "arn:") {
				parts := strings.Split(a, ":")
				if len(parts) > 4 {
					acct = parts[4]
				}
			}
			if acct != "" && acct != account {
				return true
			}
		}
	}
	return false
}

// sgExposure classifies an AuthorizeSecurityGroupIngress request: all | ssh | rdp | other | "".
func sgExposure(req any) string {
	best := ""
	rank := map[string]int{"": 0, "other": 1, "rdp": 2, "ssh": 3, "all": 4}
	for _, perm := range list(get(req, "ipPermissions")) {
		open := false
		for _, r := range list(get(perm, "ipRanges")) {
			if openSource(gets(r, "cidrIp")) {
				open = true
			}
		}
		for _, r := range list(get(perm, "ipv6Ranges")) {
			if openSource(gets(r, "cidrIpv6")) {
				open = true
			}
		}
		if !open {
			continue
		}
		proto := gets(perm, "ipProtocol")
		from, okF := num(get(perm, "fromPort"))
		to, okT := num(get(perm, "toPort"))
		cls := "other"
		switch {
		case proto == "-1" || proto == "all" || (!okF && !okT) || (from <= 0 && to >= 65535) || from == -1:
			cls = "all"
		case from <= 22 && to >= 22:
			cls = "ssh"
		case from <= 3389 && to >= 3389:
			cls = "rdp"
		}
		if rank[cls] > rank[best] {
			best = cls
		}
	}
	return best
}

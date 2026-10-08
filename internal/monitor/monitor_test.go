package monitor

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"cloud.google.com/go/logging"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/monitor/armmonitor"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cttypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"

	"github.com/DreadpiratePickles/nimbus/internal/model"
)

func ct(name string, extra map[string]any) string {
	ev := map[string]any{
		"eventID": "id-" + name, "eventName": name, "eventSource": "test.amazonaws.com", "awsRegion": "eu-west-1",
		"eventTime": "2026-10-08T10:00:00Z", "recipientAccountId": "111122223333",
		"userIdentity": map[string]any{"type": "IAMUser", "arn": "arn:aws:iam::111122223333:user/alice"},
	}
	for k, v := range extra {
		ev[k] = v
	}
	b, _ := json.Marshal(ev)
	return string(b)
}

func rp(m map[string]any) map[string]any { return map[string]any{"requestParameters": m} }

func TestMapCloudTrail(t *testing.T) {
	adminDoc := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`
	tests := []struct {
		name     string
		event    string
		extra    map[string]any
		want     bool
		canon    string
		sev      model.Severity
		resource string
	}{
		{"acl public", "PutBucketAcl", rp(map[string]any{"bucketName": "b1", "x-amz-acl": []any{"public-read"}}), true, "S3_PUBLIC_BUCKET", model.High, "arn:aws:s3:::b1"},
		{"acl grant allusers", "PutBucketAcl", rp(map[string]any{"bucketName": "b1", "AccessControlPolicy": map[string]any{"AccessControlList": map[string]any{"Grant": []any{map[string]any{"Grantee": map[string]any{"URI": "http://acs.amazonaws.com/groups/global/AllUsers"}}}}}}), true, "S3_PUBLIC_BUCKET", model.High, ""},
		{"acl private", "PutBucketAcl", rp(map[string]any{"bucketName": "b1", "x-amz-acl": "private"}), true, "", model.Low, ""},
		{"policy public", "PutBucketPolicy", rp(map[string]any{"bucketName": "b1", "bucketPolicy": map[string]any{"Statement": []any{map[string]any{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject"}}}}), true, "S3_PUBLIC_BUCKET", model.High, ""},
		{"policy public string", "PutBucketPolicy", rp(map[string]any{"bucketName": "b1", "bucketPolicy": `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"*"}}]}`}), true, "S3_PUBLIC_BUCKET", model.High, ""},
		{"policy private", "PutBucketPolicy", rp(map[string]any{"bucketName": "b1", "bucketPolicy": map[string]any{"Statement": []any{map[string]any{"Effect": "Allow", "Principal": map[string]any{"AWS": "arn:aws:iam::111122223333:root"}}}}}), true, "", model.Low, ""},
		{"delete policy", "DeleteBucketPolicy", rp(map[string]any{"bucketName": "b1"}), true, "", model.Low, ""},
		{"delete pab", "DeletePublicAccessBlock", rp(map[string]any{"bucketName": "b1"}), true, "S3_PUBLIC_BUCKET", model.High, ""},
		{"put pab weak", "PutPublicAccessBlock", rp(map[string]any{"bucketName": "b1", "PublicAccessBlockConfiguration": map[string]any{"BlockPublicAcls": true, "BlockPublicPolicy": false}}), true, "S3_PUBLIC_BUCKET", model.High, ""},
		{"put pab strong", "PutPublicAccessBlock", rp(map[string]any{"bucketName": "b1", "PublicAccessBlockConfiguration": map[string]any{"BlockPublicAcls": true, "BlockPublicPolicy": true, "IgnorePublicAcls": true, "RestrictPublicBuckets": true}}), true, "", model.Info, ""},
		{"sg ssh", "AuthorizeSecurityGroupIngress", rp(map[string]any{"groupId": "sg-1", "ipPermissions": map[string]any{"items": []any{map[string]any{"ipProtocol": "tcp", "fromPort": 22, "toPort": 22, "ipRanges": map[string]any{"items": []any{map[string]any{"cidrIp": "0.0.0.0/0"}}}}}}}), true, "EC2_SG_OPEN_SSH", model.High, "arn:aws:ec2:eu-west-1:111122223333:security-group/sg-1"},
		{"sg rdp v6", "AuthorizeSecurityGroupIngress", rp(map[string]any{"groupId": "sg-1", "ipPermissions": map[string]any{"items": []any{map[string]any{"ipProtocol": "tcp", "fromPort": 3389, "toPort": 3389, "ipv6Ranges": map[string]any{"items": []any{map[string]any{"cidrIpv6": "::/0"}}}}}}}), true, "EC2_SG_OPEN_RDP", model.High, ""},
		{"sg all", "AuthorizeSecurityGroupIngress", rp(map[string]any{"groupId": "sg-1", "ipPermissions": map[string]any{"items": []any{map[string]any{"ipProtocol": "-1", "ipRanges": map[string]any{"items": []any{map[string]any{"cidrIp": "0.0.0.0/0"}}}}}}}), true, "EC2_SG_OPEN_ALL", model.Critical, ""},
		{"sg other port", "AuthorizeSecurityGroupIngress", rp(map[string]any{"groupId": "sg-1", "ipPermissions": map[string]any{"items": []any{map[string]any{"ipProtocol": "tcp", "fromPort": 443, "toPort": 443, "ipRanges": map[string]any{"items": []any{map[string]any{"cidrIp": "0.0.0.0/0"}}}}}}}), true, "", model.Medium, ""},
		{"sg private", "AuthorizeSecurityGroupIngress", rp(map[string]any{"groupId": "sg-1", "ipPermissions": map[string]any{"items": []any{map[string]any{"ipProtocol": "tcp", "fromPort": 22, "toPort": 22, "ipRanges": map[string]any{"items": []any{map[string]any{"cidrIp": "10.0.0.0/8"}}}}}}}), true, "", model.Low, ""},
		{"attach admin role", "AttachRolePolicy", rp(map[string]any{"roleName": "app", "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}), true, "IAM_ADMIN_POLICY", model.Critical, "arn:aws:iam::111122223333:role/app"},
		{"attach admin user", "AttachUserPolicy", rp(map[string]any{"userName": "bob", "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}), true, "IAM_ADMIN_POLICY", model.Critical, "arn:aws:iam::111122223333:user/bob"},
		{"attach readonly", "AttachRolePolicy", rp(map[string]any{"roleName": "app", "policyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess"}), true, "", model.Low, ""},
		{"inline admin role", "PutRolePolicy", rp(map[string]any{"roleName": "app", "policyDocument": adminDoc}), true, "IAM_ADMIN_POLICY", model.Critical, ""},
		{"inline admin user urlenc", "PutUserPolicy", rp(map[string]any{"userName": "bob", "policyDocument": "%7B%22Statement%22%3A%5B%7B%22Effect%22%3A%22Allow%22%2C%22Action%22%3A%5B%22*%22%5D%2C%22Resource%22%3A%22*%22%7D%5D%7D"}), true, "IAM_ADMIN_POLICY", model.Critical, ""},
		{"inline scoped", "PutUserPolicy", rp(map[string]any{"userName": "bob", "policyDocument": `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`}), true, "", model.Low, ""},
		{"create key", "CreateAccessKey", map[string]any{"responseElements": map[string]any{"accessKey": map[string]any{"userName": "bob"}}}, true, "", model.Low, "arn:aws:iam::111122223333:user/bob"},
		{"root login no mfa", "ConsoleLogin", map[string]any{"userIdentity": map[string]any{"type": "Root", "arn": "arn:aws:iam::111122223333:root"}, "additionalEventData": map[string]any{"MFAUsed": "No"}, "responseElements": map[string]any{"ConsoleLogin": "Success"}}, true, "IAM_ROOT_NO_MFA", model.Critical, "arn:aws:iam::111122223333:root"},
		{"root login mfa", "ConsoleLogin", map[string]any{"userIdentity": map[string]any{"type": "Root"}, "additionalEventData": map[string]any{"MFAUsed": "Yes"}}, true, "", model.Medium, ""},
		{"user login ignored", "ConsoleLogin", map[string]any{"additionalEventData": map[string]any{"MFAUsed": "No"}}, false, "", "", ""},
		{"root login failed ignored", "ConsoleLogin", map[string]any{"userIdentity": map[string]any{"type": "Root"}, "responseElements": map[string]any{"ConsoleLogin": "Failure"}}, false, "", "", ""},
		{"stop logging", "StopLogging", rp(map[string]any{"name": "main"}), true, "CLOUDTRAIL_DISABLED", model.Critical, "arn:aws:cloudtrail:eu-west-1:111122223333:trail/main"},
		{"delete trail arn", "DeleteTrail", rp(map[string]any{"name": "arn:aws:cloudtrail:us-east-1:111122223333:trail/x"}), true, "CLOUDTRAIL_DISABLED", model.Critical, "arn:aws:cloudtrail:us-east-1:111122223333:trail/x"},
		{"update trail single", "UpdateTrail", rp(map[string]any{"name": "main", "isMultiRegionTrail": false}), true, "CLOUDTRAIL_DISABLED", model.High, ""},
		{"update trail other", "UpdateTrail", rp(map[string]any{"name": "main", "s3BucketName": "logs"}), true, "", model.Low, ""},
		{"rds public", "ModifyDBInstance", rp(map[string]any{"dBInstanceIdentifier": "db1", "publiclyAccessible": true}), true, "RDS_PUBLIC", model.Critical, "arn:aws:rds:eu-west-1:111122223333:db:db1"},
		{"rds other", "ModifyDBInstance", rp(map[string]any{"dBInstanceIdentifier": "db1", "allocatedStorage": 100}), true, "", model.Low, ""},
		{"deactivate mfa", "DeactivateMFADevice", rp(map[string]any{"userName": "bob"}), true, "IAM_USER_NO_MFA", model.High, "arn:aws:iam::111122223333:user/bob"},
		{"create user", "CreateUser", rp(map[string]any{"userName": "eve"}), true, "", model.Low, "arn:aws:iam::111122223333:user/eve"},
		{"trust wildcard", "UpdateAssumeRolePolicy", rp(map[string]any{"roleName": "r", "policyDocument": `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}`}), true, "IAM_CROSS_ACCOUNT_TRUST", model.High, "arn:aws:iam::111122223333:role/r"},
		{"trust external", "UpdateAssumeRolePolicy", rp(map[string]any{"roleName": "r", "policyDocument": `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::999988887777:root"},"Action":"sts:AssumeRole"}]}`}), true, "IAM_CROSS_ACCOUNT_TRUST", model.High, ""},
		{"trust same account", "UpdateAssumeRolePolicy", rp(map[string]any{"roleName": "r", "policyDocument": `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111122223333:root"}}]}`}), true, "", model.Low, ""},
		{"trust service", "UpdateAssumeRolePolicy", rp(map[string]any{"roleName": "r", "policyDocument": `{"Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"}}]}`}), true, "", model.Low, ""},
		{"imds optional", "ModifyInstanceMetadataOptions", rp(map[string]any{"ModifyInstanceMetadataOptionsRequest": map[string]any{"InstanceId": "i-1", "HttpTokens": "optional"}}), true, "EC2_IMDSV1", model.High, "arn:aws:ec2:eu-west-1:111122223333:instance/i-1"},
		{"imds required", "ModifyInstanceMetadataOptions", rp(map[string]any{"instanceId": "i-1", "httpTokens": "required"}), true, "", model.Low, ""},
		{"failed call ignored", "StopLogging", map[string]any{"errorCode": "AccessDenied"}, false, "", "", ""},
		{"unwatched ignored", "DescribeInstances", nil, false, "", "", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e, ok := MapCloudTrail(ct(tc.event, tc.extra), "fallback", "us-east-1")
			if ok != tc.want {
				t.Fatalf("ok=%v want %v", ok, tc.want)
			}
			if !ok {
				return
			}
			if e.CanonicalID != tc.canon || e.Severity != tc.sev {
				t.Errorf("got canon=%q sev=%q, want %q %q", e.CanonicalID, e.Severity, tc.canon, tc.sev)
			}
			if tc.resource != "" && e.ResourceID != tc.resource {
				t.Errorf("resource %q want %q", e.ResourceID, tc.resource)
			}
			if e.Account != "111122223333" || e.Region != "eu-west-1" || e.Provider != "aws" || e.Title == "" || e.ResourceType == "" {
				t.Errorf("bad event fields %+v", e)
			}
			if e.Time.IsZero() || e.ID() != "id-"+tc.event {
				t.Errorf("time/id not parsed: %v %q", e.Time, e.ID())
			}
		})
	}
}

func TestCloudTrailEventListCoversSpec(t *testing.T) {
	if len(CloudTrailEvents) != 20 {
		t.Fatalf("expected 20 watched events, got %d", len(CloudTrailEvents))
	}
}

type fakeCT struct {
	mu    sync.Mutex
	pages map[string][][]string // event name -> pages of raw events
	calls []string
	fail  map[string]error
}

func (f *fakeCT) LookupEvents(_ context.Context, in *cloudtrail.LookupEventsInput, _ ...func(*cloudtrail.Options)) (*cloudtrail.LookupEventsOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	name := aws.ToString(in.LookupAttributes[0].AttributeValue)
	if in.LookupAttributes[0].AttributeKey != cttypes.LookupAttributeKeyEventName || in.StartTime == nil {
		return nil, errors.New("bad input")
	}
	f.calls = append(f.calls, name+"#"+aws.ToString(in.NextToken))
	if err := f.fail[name]; err != nil {
		return nil, err
	}
	pages := f.pages[name]
	idx := 0
	if in.NextToken != nil {
		idx = len(aws.ToString(in.NextToken))
	}
	out := &cloudtrail.LookupEventsOutput{}
	if idx < len(pages) {
		for _, raw := range pages[idx] {
			out.Events = append(out.Events, cttypes.Event{CloudTrailEvent: aws.String(raw)})
		}
	}
	if idx+1 < len(pages) {
		out.NextToken = aws.String(strings.Repeat("x", idx+1))
	}
	return out, nil
}

func TestCloudTrailSourcePaginates(t *testing.T) {
	sg := ct("AuthorizeSecurityGroupIngress", rp(map[string]any{"groupId": "sg-1", "ipPermissions": map[string]any{"items": []any{map[string]any{"ipProtocol": "-1", "ipRanges": map[string]any{"items": []any{map[string]any{"cidrIp": "0.0.0.0/0"}}}}}}}))
	stop := ct("StopLogging", rp(map[string]any{"name": "t"}))
	api := &fakeCT{pages: map[string][][]string{
		"StopLogging":                   {{stop}, {strings.Replace(stop, "id-StopLogging", "id-2", 1)}},
		"AuthorizeSecurityGroupIngress": {{sg}},
	}, fail: map[string]error{"CreateUser": errors.New("throttled")}}
	src := &CloudTrailSource{API: api, Account: "acct", Region: "eu-west-1"}
	evs, err := src.Poll(context.Background(), time.Now().Add(-time.Hour))
	if err == nil || !strings.Contains(err.Error(), "CreateUser") {
		t.Fatalf("expected partial error for CreateUser, got %v", err)
	}
	if len(evs) != 3 {
		t.Fatalf("want 3 events (2 pages + 1), got %d", len(evs))
	}
	var sawSecondPage bool
	for _, c := range api.calls {
		if c == "StopLogging#x" {
			sawSecondPage = true
		}
	}
	if !sawSecondPage {
		t.Errorf("paginator did not request page 2: %v", api.calls)
	}
	if len(api.calls) < len(CloudTrailEvents) {
		t.Errorf("expected one query per event name, got %d calls", len(api.calls))
	}
}

func azEvent(op, status string, props map[string]string, resID string) *armmonitor.EventData {
	p := map[string]*string{}
	for k, v := range props {
		p[k] = to.Ptr(v)
	}
	ts := time.Date(2026, 10, 8, 9, 0, 0, 0, time.UTC)
	return &armmonitor.EventData{
		OperationName:  &armmonitor.LocalizableString{Value: to.Ptr(op)},
		Status:         &armmonitor.LocalizableString{Value: to.Ptr(status)},
		Properties:     p,
		ResourceID:     to.Ptr(resID),
		Caller:         to.Ptr("admin@contoso.com"),
		EventDataID:    to.Ptr("az-" + op + status),
		SubscriptionID: to.Ptr("sub-1"),
		EventTimestamp: &ts,
	}
}

type ptrHelper struct{}

func (ptrHelper) Ptr(s string) *string { return &s }

var to ptrHelper

const nsgRule = "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/nsg1/securityRules/r1"

func TestMapActivityLog(t *testing.T) {
	ruleBody := func(port, src string) map[string]string {
		return map[string]string{"responseBody": `{"properties":{"access":"Allow","direction":"Inbound","sourceAddressPrefix":"` + src + `","destinationPortRange":"` + port + `"}}`}
	}
	tests := []struct {
		name  string
		ev    *armmonitor.EventData
		want  bool
		canon string
		sev   model.Severity
		res   string
	}{
		{"nsg ssh", azEvent(AzureOperations[0], "Succeeded", ruleBody("22", "*"), nsgRule), true, "AZ_NSG_OPEN_SSH", model.High, "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/nsg1"},
		{"nsg rdp range", azEvent(AzureOperations[0], "Succeeded", ruleBody("3380-3390", "Internet"), nsgRule), true, "AZ_NSG_OPEN_RDP", model.High, ""},
		{"nsg all", azEvent(AzureOperations[0], "Succeeded", ruleBody("*", "0.0.0.0/0"), nsgRule), true, "AZ_NSG_OPEN_SSH", model.Critical, ""},
		{"nsg private", azEvent(AzureOperations[0], "Succeeded", ruleBody("22", "10.0.0.0/8"), nsgRule), true, "", model.Low, ""},
		{"nsg no body", azEvent(AzureOperations[0], "Succeeded", nil, nsgRule), true, "", model.Medium, ""},
		{"nsg started skipped", azEvent(AzureOperations[0], "Started", ruleBody("22", "*"), nsgRule), false, "", "", ""},
		{"storage public", azEvent(AzureOperations[1], "Succeeded", map[string]string{"requestbody": `{"properties":{"allowBlobPublicAccess":true}}`}, "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/sa"), true, "AZ_STORAGE_PUBLIC_BLOB", model.High, ""},
		{"storage http", azEvent(AzureOperations[1], "Succeeded", map[string]string{"responseBody": `{"properties":{"supportsHttpsTrafficOnly":false}}`}, "/x/storageAccounts/sa"), true, "AZ_STORAGE_HTTP_ALLOWED", model.Medium, ""},
		{"storage other", azEvent(AzureOperations[1], "Succeeded", nil, "/x/storageAccounts/sa"), true, "", model.Medium, ""},
		{"owner assignment", azEvent(AzureOperations[2], "Succeeded", map[string]string{"responseBody": `{"properties":{"roleDefinitionId":"/subscriptions/sub-1/providers/Microsoft.Authorization/roleDefinitions/` + OwnerRoleID + `"}}`}, "/x/roleAssignments/a"), true, "", model.Critical, ""},
		{"reader assignment", azEvent(AzureOperations[2], "Succeeded", map[string]string{"responseBody": `{"properties":{"roleDefinitionId":"/x/acdd72a7-3385-48ef-bd42-f606fba81ae7"}}`}, "/x/roleAssignments/a"), true, "", model.High, ""},
		{"vault softdelete off", azEvent(AzureOperations[3], "Succeeded", map[string]string{"responseBody": `{"properties":{"enableSoftDelete":false}}`}, "/x/vaults/kv"), true, "AZ_KEYVAULT_NO_SOFTDELETE", model.Medium, ""},
		{"vault change", azEvent(AzureOperations[3], "Succeeded", nil, "/x/vaults/kv"), true, "", model.Medium, ""},
		{"sql open", azEvent(AzureOperations[4], "Succeeded", map[string]string{"responseBody": `{"properties":{"startIpAddress":"0.0.0.0","endIpAddress":"255.255.255.255"}}`}, "/x/servers/sql1/firewallRules/all"), true, "AZ_SQL_PUBLIC", model.Critical, "/x/servers/sql1"},
		{"sql azure services", azEvent(AzureOperations[4], "Succeeded", map[string]string{"responseBody": `{"properties":{"startIpAddress":"0.0.0.0","endIpAddress":"0.0.0.0"}}`}, "/x/servers/sql1/firewallRules/a"), true, "", model.Medium, ""},
		{"unwatched", azEvent("Microsoft.Compute/virtualMachines/write", "Succeeded", nil, "/x"), false, "", "", ""},
		{"failed", azEvent(AzureOperations[4], "Failed", nil, "/x"), false, "", "", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e, ok := MapActivityLog(tc.ev, "fallback")
			if ok != tc.want {
				t.Fatalf("ok=%v want %v", ok, tc.want)
			}
			if !ok {
				return
			}
			if e.CanonicalID != tc.canon || e.Severity != tc.sev {
				t.Errorf("got %q/%q want %q/%q", e.CanonicalID, e.Severity, tc.canon, tc.sev)
			}
			if tc.res != "" && e.ResourceID != tc.res {
				t.Errorf("resource %q want %q", e.ResourceID, tc.res)
			}
			if e.Account != "sub-1" || e.Actor != "admin@contoso.com" || e.Provider != "azure" {
				t.Errorf("bad fields %+v", e)
			}
		})
	}
}

type fakeActivity struct {
	pages  [][]*armmonitor.EventData
	filter string
}

func (f *fakeActivity) NewListPager(filter string, _ *armmonitor.ActivityLogsClientListOptions) *runtime.Pager[armmonitor.ActivityLogsClientListResponse] {
	f.filter = filter
	i := 0
	return runtime.NewPager(runtime.PagingHandler[armmonitor.ActivityLogsClientListResponse]{
		More: func(armmonitor.ActivityLogsClientListResponse) bool { return i < len(f.pages) },
		Fetcher: func(context.Context, *armmonitor.ActivityLogsClientListResponse) (armmonitor.ActivityLogsClientListResponse, error) {
			p := f.pages[i]
			i++
			return armmonitor.ActivityLogsClientListResponse{EventDataCollection: armmonitor.EventDataCollection{Value: p}}, nil
		},
	})
}

func TestActivityLogSourcePoll(t *testing.T) {
	open := azEvent(AzureOperations[4], "Succeeded", map[string]string{"responseBody": `{"properties":{"startIpAddress":"0.0.0.0","endIpAddress":"255.255.255.255"}}`}, "/x/servers/s/firewallRules/r")
	api := &fakeActivity{pages: [][]*armmonitor.EventData{
		{open, azEvent("Microsoft.Compute/virtualMachines/write", "Succeeded", nil, "/vm")},
		{azEvent(AzureOperations[3], "Succeeded", nil, "/x/vaults/kv")},
	}}
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	src := &ActivityLogSource{API: api, Subscription: "sub-1", Now: func() time.Time { return now }}
	evs, err := src.Poll(context.Background(), now.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 2 {
		t.Fatalf("want 2 watched events across pages, got %d", len(evs))
	}
	if want := "eventTimestamp ge '2026-10-08T11:00:00Z' and eventTimestamp le '2026-10-08T12:00:00Z'"; api.filter != want {
		t.Errorf("filter %q", api.filter)
	}
}

func TestMapAuditLog(t *testing.T) {
	ts := time.Date(2026, 10, 8, 8, 0, 0, 0, time.UTC)
	fw := func(method string, ranges []any, allowed []any) map[string]any {
		return map[string]any{"methodName": method, "serviceName": "compute.googleapis.com", "resourceName": "projects/p1/global/firewalls/fw1",
			"authenticationInfo": map[string]any{"principalEmail": "dev@example.com"},
			"request":            map[string]any{"direction": "INGRESS", "sourceRanges": ranges, "alloweds": allowed}}
	}
	tcp := func(ports ...any) []any { return []any{map[string]any{"IPProtocol": "tcp", "ports": ports}} }
	tests := []struct {
		name  string
		p     map[string]any
		want  bool
		canon string
		sev   model.Severity
	}{
		{"bucket allUsers", map[string]any{"methodName": "storage.setIamPermissions", "resourceName": "projects/_/buckets/b1", "serviceData": map[string]any{"policyDelta": map[string]any{"bindingDeltas": []any{map[string]any{"action": "ADD", "role": "roles/storage.objectViewer", "member": "allUsers"}}}}}, true, "GCP_BUCKET_PUBLIC", model.High},
		{"bucket private", map[string]any{"methodName": "storage.setIamPermissions", "resourceName": "projects/_/buckets/b1", "serviceData": map[string]any{"policyDelta": map[string]any{"bindingDeltas": []any{map[string]any{"action": "ADD", "member": "user:a@x.com"}}}}}, true, "", model.Low},
		{"fw ssh insert", fw("v1.compute.firewalls.insert", []any{"0.0.0.0/0"}, tcp("22")), true, "GCP_FIREWALL_OPEN_SSH", model.High},
		{"fw rdp patch", fw("v1.compute.firewalls.patch", []any{"0.0.0.0/0"}, tcp("3389")), true, "GCP_FIREWALL_OPEN_RDP", model.High},
		{"fw all", fw("v1.compute.firewalls.insert", []any{"0.0.0.0/0"}, []any{map[string]any{"IPProtocol": "all"}}), true, "GCP_FIREWALL_OPEN_SSH", model.Critical},
		{"fw https", fw("v1.compute.firewalls.insert", []any{"0.0.0.0/0"}, tcp("443")), true, "", model.Medium},
		{"fw private", fw("v1.compute.firewalls.insert", []any{"10.0.0.0/8"}, tcp("22")), true, "", model.Low},
		{"owner granted", map[string]any{"methodName": "SetIamPolicy", "resourceName": "projects/p1", "serviceData": map[string]any{"policyDelta": map[string]any{"bindingDeltas": []any{map[string]any{"action": "ADD", "role": "roles/owner", "member": "user:x@y.com"}}}}}, true, "GCP_IAM_PRIMITIVE_ROLE", model.High},
		{"viewer granted", map[string]any{"methodName": "google.iam.admin.v1.SetIamPolicy", "resourceName": "projects/p1", "request": map[string]any{"policy": map[string]any{"bindings": []any{map[string]any{"role": "roles/viewer", "members": []any{"user:x@y.com"}}}}}}, true, "", model.Low},
		{"sql open", map[string]any{"methodName": "cloudsql.instances.update", "resourceName": "projects/p1/instances/db", "request": map[string]any{"body": map[string]any{"settings": map[string]any{"ipConfiguration": map[string]any{"authorizedNetworks": []any{map[string]any{"value": "0.0.0.0/0"}}}}}}}, true, "GCP_SQL_PUBLIC", model.Critical},
		{"sql private", map[string]any{"methodName": "cloudsql.instances.update", "resourceName": "projects/p1/instances/db", "request": map[string]any{}}, true, "", model.Low},
		{"failed status", map[string]any{"methodName": "cloudsql.instances.update", "status": map[string]any{"code": float64(7)}}, false, "", ""},
		{"unwatched", map[string]any{"methodName": "v1.compute.instances.insert"}, false, "", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e, ok := MapAuditLog(tc.p, ts, "ins-1", "p1")
			if ok != tc.want {
				t.Fatalf("ok=%v want %v", ok, tc.want)
			}
			if !ok {
				return
			}
			if e.CanonicalID != tc.canon || e.Severity != tc.sev {
				t.Errorf("got %q/%q want %q/%q", e.CanonicalID, e.Severity, tc.canon, tc.sev)
			}
			if e.Account != "p1" || e.ID() != "ins-1" || e.ResourceID == "" {
				t.Errorf("bad fields %+v", e)
			}
		})
	}
}

type fakeAudit struct {
	entries []*logging.Entry
	filter  string
}

func (f *fakeAudit) Entries(_ context.Context, filter string) ([]*logging.Entry, error) {
	f.filter = filter
	return f.entries, nil
}

func TestAuditLogSourcePoll(t *testing.T) {
	api := &fakeAudit{entries: []*logging.Entry{
		{Timestamp: time.Now(), InsertID: "a", Payload: map[string]any{"methodName": "v1.compute.firewalls.insert", "resourceName": "projects/p/global/firewalls/f", "request": map[string]any{"sourceRanges": []any{"0.0.0.0/0"}, "alloweds": []any{map[string]any{"IPProtocol": "tcp", "ports": []any{"22"}}}}}},
		{Timestamp: time.Now(), InsertID: "b", Payload: "not json"},
	}}
	src := &AuditLogSource{API: api, Project: "p"}
	evs, err := src.Poll(context.Background(), time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	if err != nil || len(evs) != 1 || evs[0].CanonicalID != "GCP_FIREWALL_OPEN_SSH" {
		t.Fatalf("got %v %+v", err, evs)
	}
	for _, want := range []string{`logName:"cloudaudit.googleapis.com"`, `timestamp>="2026-01-01T00:00:00Z"`, `"storage.setIamPermissions" OR`, `"cloudsql.instances.update")`} {
		if !strings.Contains(api.filter, want) {
			t.Errorf("filter %q missing %q", api.filter, want)
		}
	}
}

type fakeSource struct {
	name   string
	mu     sync.Mutex
	events []Event
	err    error
	sinces []time.Time
}

func (f *fakeSource) Name() string { return f.name }
func (f *fakeSource) Poll(_ context.Context, since time.Time) ([]Event, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sinces = append(f.sinces, since)
	var out []Event
	for _, e := range f.events {
		if !e.Time.Before(since) {
			out = append(out, e)
		}
	}
	return out, f.err
}

func TestPollCheckpointsAndDedup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "checkpoint.json")
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	t1 := now.Add(-30 * time.Minute)
	t2 := now.Add(-10 * time.Minute)
	ok := &fakeSource{name: "good", events: []Event{
		{Time: t1, EventName: "StopLogging", Raw: map[string]any{"event_id": "e1"}},
		{Time: t2, EventName: "StopLogging", Raw: map[string]any{"event_id": "e2"}},
		{Time: t2, EventName: "StopLogging", Raw: map[string]any{"event_id": "e2"}}, // duplicate
	}}
	bad := &fakeSource{name: "bad", events: []Event{{Time: t1, EventName: "X", Raw: map[string]any{"event_id": "e3"}}}, err: errors.New("boom")}

	m := New(nil, path)
	m.Now = func() time.Time { return now }
	m.AddSource("acct", ok)
	m.AddSource("acct", bad)
	evs, err := m.Poll(context.Background())
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("expected partial error, got %v", err)
	}
	if len(evs) != 3 { // e1, e2 deduped, e3 from failing source kept
		t.Fatalf("want 3 events, got %d", len(evs))
	}
	if !ok.sinces[0].Equal(now.Add(-time.Hour)) {
		t.Errorf("initial since %v", ok.sinces[0])
	}
	cp, found := m.Checkpoint("acct", "good")
	if !found || !cp.Equal(t2.Add(time.Nanosecond)) {
		t.Errorf("checkpoint %v %v", cp, found)
	}
	if _, found := m.Checkpoint("acct", "bad"); found {
		t.Errorf("failed source must not advance checkpoint")
	}
	data, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(data), "acct|good") {
		t.Fatalf("checkpoint file: %v %s", err, data)
	}

	// A fresh monitor resumes from the persisted checkpoint and sees nothing new.
	m2 := New(nil, path)
	m2.Now = func() time.Time { return now }
	ok2 := &fakeSource{name: "good", events: ok.events}
	m2.AddSource("acct", ok2)
	evs, err = m2.Poll(context.Background())
	if err != nil || len(evs) != 0 {
		t.Fatalf("resume: %v %d", err, len(evs))
	}
	if !ok2.sinces[0].Equal(t2.Add(time.Nanosecond)) {
		t.Errorf("resume since %v", ok2.sinces[0])
	}
}

func TestRunEmitsAndStops(t *testing.T) {
	src := &fakeSource{name: "s", events: []Event{{Time: time.Now(), EventName: "DeleteTrail", Raw: map[string]any{"event_id": "x"}}}}
	m := New(nil, filepath.Join(t.TempDir(), "cp.json"))
	m.InitialLookback = 24 * time.Hour
	m.AddSource("a", src)
	ctx, cancel := context.WithCancel(context.Background())
	out := make(chan Event, 10)
	done := make(chan error, 1)
	go func() { done <- m.Run(ctx, 5*time.Millisecond, out) }()
	select {
	case e := <-out:
		if e.EventName != "DeleteTrail" {
			t.Errorf("unexpected %+v", e)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no event")
	}
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("Run returned %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not stop")
	}
	src.mu.Lock()
	defer src.mu.Unlock()
	if len(src.sinces) < 2 {
		t.Errorf("expected repeated polls, got %d", len(src.sinces))
	}
}

func TestToFinding(t *testing.T) {
	ts := time.Date(2026, 10, 8, 10, 0, 0, 0, time.UTC)
	e := Event{Time: ts, Provider: "aws", Account: "111", Region: "us-east-1", Source: "s3.amazonaws.com", EventName: "PutBucketPolicy",
		Actor: "arn:aws:iam::111:user/alice", ResourceID: "arn:aws:s3:::b1", ResourceType: "aws_s3_bucket", Title: "public", Severity: model.High,
		CanonicalID: "S3_PUBLIC_BUCKET", Raw: map[string]any{"event_id": "1"}}
	f := e.ToFinding()
	if f.Source != "monitor" || f.CheckID != "PutBucketPolicy" || f.Status != model.Fail || f.CanonicalID != "S3_PUBLIC_BUCKET" {
		t.Fatalf("bad finding %+v", f)
	}
	if f.ID == "" || f.Resource.Name != "b1" || f.Tags["actor"] != e.Actor || f.Tags["event_source"] != e.Source || !f.FirstSeen.Equal(ts) {
		t.Errorf("bad fields %+v", f)
	}
	if !f.HasWeakness("PUBLIC_DATA_STORE") || len(f.Compliance) == 0 || len(f.Raw) == 0 || !strings.Contains(f.Description, "alice") {
		t.Errorf("not enriched %+v", f)
	}
	g := Event{Time: ts, Provider: "azure", EventName: "Microsoft.KeyVault/vaults/write", Severity: model.Medium}.ToFinding()
	if g.CanonicalID != "MONITOR:Microsoft.KeyVault/vaults/write" || g.Title == "" {
		t.Errorf("generic finding %+v", g)
	}
}

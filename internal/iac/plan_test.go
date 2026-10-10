package iac

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/model"
)

const fixturePlans = "../../testdata/action-fixture/plans"

func loadPlan(t *testing.T, name string) *Plan {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(fixturePlans, name))
	if err != nil {
		t.Fatal(err)
	}
	p, err := ParsePlanJSON(data, PlanLimits{})
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return p
}

func byAddr(rs []PlanResource) map[string]PlanResource {
	m := map[string]PlanResource{}
	for _, r := range rs {
		m[r.Address] = r
	}
	return m
}

func hasRel(r PlanResource, kind, to string) bool {
	for _, rel := range r.Relations {
		if rel.Kind == kind && rel.ID == to {
			return true
		}
	}
	return false
}

const (
	sgAddr   = "module.web.aws_security_group.ssh"
	instAddr = "module.web.aws_instance.host"
	roleAddr = "module.web.aws_iam_role.host"
	sgARN    = "arn:aws:ec2:us-east-1:123456789012:security-group/sg-0fixture000000001"
	roleARN  = "arn:aws:iam::123456789012:role/fixture-host-role"
	instARN  = "arn:aws:ec2:us-east-1:123456789012:instance/i-0fixture000000001"
)

func TestParsePlanFixtureBad(t *testing.T) {
	p := loadPlan(t, "bad.plan.json")
	if len(p.Changes) != 5 {
		t.Fatalf("changes = %d, want 5", len(p.Changes))
	}
	acts := map[string]PlanAction{}
	for _, c := range p.Changes {
		acts[c.Address] = c.Action
	}
	if acts[sgAddr] != PlanUpdate || acts[instAddr] != PlanNoOp {
		t.Fatalf("actions = %v", acts)
	}
	before, after := byAddr(p.Resources(SideBefore)), byAddr(p.Resources(SideAfter))
	sgB, sgA := before[sgAddr], after[sgAddr]
	if sgA.ID != sgARN || sgB.ID != sgARN {
		t.Fatalf("sg ids before %q after %q", sgB.ID, sgA.ID)
	}
	if OpenIngress(sgB.Ingress) != nil || len(OpenIngress(sgA.Ingress)) != 1 || sgA.Ingress[0].FromPort != 22 {
		t.Fatalf("ingress before %+v after %+v", sgB.Ingress, sgA.Ingress)
	}
	if len(sgA.Checks) == 0 || sgA.Checks[0].CanonicalID != "EC2_SG_OPEN_SSH" {
		t.Errorf("open SG check missing: %+v", sgA.Checks)
	}
	inst := after[instAddr]
	if inst.ID != instARN || len(inst.SecurityGroups) != 1 || inst.SecurityGroups[0] != sgARN {
		t.Fatalf("instance %q SGs %v", inst.ID, inst.SecurityGroups)
	}
	if !hasRel(inst, "runs_as", roleARN) {
		t.Errorf("instance → role (via instance profile) missing: %+v", inst.Relations)
	}
	if inst.PublicReachable != ReachYes {
		t.Errorf("public reachability = %v", inst.PublicReachable)
	}
	if contains(inst.Weaknesses, "IMDSV1_ENABLED") {
		t.Errorf("http_tokens=required read as IMDSv1")
	}
	role := after[roleAddr]
	if role.ID != roleARN || !contains(role.Weaknesses, "OVERPRIVILEGED_IDENTITY") {
		t.Errorf("role %q weaknesses %v", role.ID, role.Weaknesses)
	}
}

func TestParsePlanCreateResolvesReferences(t *testing.T) {
	p := loadPlan(t, "create.plan.json")
	after := byAddr(p.Resources(SideAfter))
	inst := after[instAddr]
	if inst.ID != "tf:"+instAddr {
		t.Fatalf("unknown arn → address id, got %q", inst.ID)
	}
	if len(inst.SecurityGroups) != 1 || inst.SecurityGroups[0] != "tf:"+sgAddr {
		t.Fatalf("SGs from configuration references: %v", inst.SecurityGroups)
	}
	if !hasRel(inst, "runs_as", "tf:"+roleAddr) {
		t.Errorf("runs_as role by name: %+v", inst.Relations)
	}
	if inst.PublicReachable != ReachUnknown {
		t.Errorf("unknown public ip should be ReachUnknown, got %v", inst.PublicReachable)
	}
	if len(p.Resources(SideBefore)) != 0 {
		t.Errorf("create plan has no before side")
	}
}

func TestPlanActionsAndModes(t *testing.T) {
	src := `{"format_version":"1.2","resource_changes":[
	 {"address":"aws_s3_bucket.a","mode":"managed","type":"aws_s3_bucket","name":"a","change":{"actions":["delete","create"],"before":{"bucket":"a","arn":"arn:aws:s3:::a"},"after":{"bucket":"a"},"after_unknown":{"arn":true}}},
	 {"address":"aws_s3_bucket.b","mode":"managed","type":"aws_s3_bucket","name":"b","change":{"actions":["create","delete"],"before":{"bucket":"b"},"after":{"bucket":"b"}}},
	 {"address":"aws_s3_bucket.c","mode":"managed","type":"aws_s3_bucket","name":"c","change":{"actions":["delete"],"before":{"bucket":"c"},"after":null}},
	 {"address":"data.aws_iam_policy_document.d","mode":"data","type":"aws_iam_policy_document","name":"d","change":{"actions":["read"],"before":null,"after":{}}}]}`
	p, err := ParsePlanJSON([]byte(src), PlanLimits{})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]PlanAction{"aws_s3_bucket.a": PlanReplace, "aws_s3_bucket.b": PlanReplace, "aws_s3_bucket.c": PlanDelete}
	if len(p.Changes) != 3 {
		t.Fatalf("data sources must be dropped: %d changes", len(p.Changes))
	}
	for _, c := range p.Changes {
		if want[c.Address] != c.Action {
			t.Errorf("%s: %s, want %s", c.Address, c.Action, want[c.Address])
		}
	}
	// A replaced bucket keeps its id on both sides (before arn wins over an unknown after arn).
	a := byAddr(p.Resources(SideAfter))["aws_s3_bucket.a"]
	if a.ID != "arn:aws:s3:::a" {
		t.Errorf("replace id = %q", a.ID)
	}
	if _, ok := byAddr(p.Resources(SideAfter))["aws_s3_bucket.c"]; ok {
		t.Errorf("deleted resource present after")
	}
}

// One plan exercising every mapping rule.
const mappingPlan = `{"format_version":"1.2","resource_changes":[
 {"address":"aws_iam_role.gha","mode":"managed","type":"aws_iam_role","name":"gha","change":{"actions":["create"],"before":null,"after":{"name":"gha-deploy",
   "assume_role_policy":"{\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"sts:AssumeRoleWithWebIdentity\",\"Principal\":{\"Federated\":\"arn:aws:iam::111111111111:oidc-provider/token.actions.githubusercontent.com\"},\"Condition\":{\"StringLike\":{\"token.actions.githubusercontent.com:sub\":\"repo:acme/infra:*\"}}}]}",
   "managed_policy_arns":["arn:aws:iam::aws:policy/AdministratorAccess"]},"after_unknown":{"arn":true}}},
 {"address":"aws_iam_role.xacct","mode":"managed","type":"aws_iam_role","name":"xacct","change":{"actions":["update"],"before":{"name":"x","arn":"arn:aws:iam::111111111111:role/x","assume_role_policy":"{}"},
   "after":{"name":"x","arn":"arn:aws:iam::111111111111:role/x","assume_role_policy":"{\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"sts:AssumeRole\",\"Principal\":{\"AWS\":\"arn:aws:iam::999999999999:root\"}}]}"}}},
 {"address":"aws_iam_role_policy.inline","mode":"managed","type":"aws_iam_role_policy","name":"inline","change":{"actions":["create"],"before":null,"after":{"role":"x","policy":"{\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\"}]}"}}},
 {"address":"aws_s3_bucket_policy.p","mode":"managed","type":"aws_s3_bucket_policy","name":"p","change":{"actions":["create"],"before":null,"after":{"bucket":"pii-exports","policy":"{\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"s3:GetObject\",\"Resource\":\"arn:aws:s3:::pii-exports/*\"}]}"}}},
 {"address":"aws_s3_bucket.org","mode":"managed","type":"aws_s3_bucket","name":"org","change":{"actions":["create"],"before":null,"after":{"bucket":"org-only","acl":"private"}}},
 {"address":"aws_s3_bucket_policy.org","mode":"managed","type":"aws_s3_bucket_policy","name":"org","change":{"actions":["create"],"before":null,"after":{"bucket":"org-only","policy":"{\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"s3:GetObject\",\"Resource\":\"*\",\"Condition\":{\"StringEquals\":{\"aws:PrincipalOrgID\":\"o-1\"}}}]}"}}},
 {"address":"aws_lambda_function.fn","mode":"managed","type":"aws_lambda_function","name":"fn","change":{"actions":["no-op"],"before":{"function_name":"fn","arn":"arn:aws:lambda:us-east-1:111111111111:function:fn","role":"arn:aws:iam::111111111111:role/x"},"after":{"function_name":"fn","arn":"arn:aws:lambda:us-east-1:111111111111:function:fn","role":"arn:aws:iam::111111111111:role/x"}}},
 {"address":"aws_lambda_function_url.u","mode":"managed","type":"aws_lambda_function_url","name":"u","change":{"actions":["create"],"before":null,"after":{"function_name":"fn","authorization_type":"NONE"}}},
 {"address":"aws_eks_cluster.k","mode":"managed","type":"aws_eks_cluster","name":"k","change":{"actions":["create"],"before":null,"after":{"name":"k","vpc_config":[{"endpoint_public_access":true,"public_access_cidrs":["198.51.100.0/24"]}]}}},
 {"address":"aws_vpc_security_group_ingress_rule.r","mode":"managed","type":"aws_vpc_security_group_ingress_rule","name":"r","change":{"actions":["create"],"before":null,"after":{"security_group_id":"sg-live1","cidr_ipv4":"0.0.0.0/0","from_port":3389,"to_port":3389,"ip_protocol":"tcp"}}},
 {"address":"aws_db_instance.db","mode":"managed","type":"aws_db_instance","name":"db","change":{"actions":["create"],"before":null,"after":{"identifier":"ledger","publicly_accessible":true,"storage_encrypted":false,"vpc_security_group_ids":["sg-live1"]}}},
 {"address":"aws_instance.v1","mode":"managed","type":"aws_instance","name":"v1","change":{"actions":["create"],"before":null,"after":{"ami":"ami-1","associate_public_ip_address":false,"iam_instance_profile":"live-profile"}}}]}`

func TestPlanMappingRules(t *testing.T) {
	p, err := ParsePlanJSON([]byte(mappingPlan), PlanLimits{})
	if err != nil {
		t.Fatal(err)
	}
	all := p.Resources(SideAfter)
	a := byAddr(all)
	gha := a["aws_iam_role.gha"]
	if !contains(gha.Weaknesses, "OVERPRIVILEGED_IDENTITY") || len(gha.OIDCSubjects) != 1 || gha.OIDCSubjects[0] != "repo:acme/infra:*" {
		t.Errorf("gha role: %+v", gha)
	}
	if gha.Attributes["oidc_subject_class"] != "unpinned" {
		t.Errorf("gha subject class: %v", gha.Attributes["oidc_subject_class"])
	}
	x := a["aws_iam_role.xacct"]
	if !contains(x.Weaknesses, "CROSS_ACCOUNT_TRUST") || !contains(x.Weaknesses, "OVERPRIVILEGED_IDENTITY") {
		t.Errorf("cross-account role with inline admin policy: %v", x.Weaknesses)
	}
	var bucket, org, fn, sg, db PlanResource
	for _, r := range all {
		switch r.ID {
		case "arn:aws:s3:::pii-exports":
			bucket = r
		case "arn:aws:s3:::org-only":
			org = r
		case "arn:aws:lambda:us-east-1:111111111111:function:fn":
			fn = r
		case "sg-live1":
			sg = r
		}
		if r.Address == "aws_db_instance.db" {
			db = r
		}
	}
	if !contains(bucket.Weaknesses, "PUBLIC_DATA_STORE") {
		t.Errorf("Principal * bucket policy: %+v", bucket)
	}
	if contains(org.Weaknesses, "PUBLIC_DATA_STORE") {
		t.Errorf("org-conditioned bucket policy read as public: %+v", org)
	}
	if !contains(fn.Weaknesses, "PUBLIC_NETWORK_EXPOSURE") || fn.Attributes["function_url_auth_type"] != "NONE" || !hasRel(fn, "runs_as", "arn:aws:iam::111111111111:role/x") {
		t.Errorf("function url NONE: %+v", fn)
	}
	eks := a["aws_eks_cluster.k"]
	if !contains(eks.Weaknesses, "PUBLIC_NETWORK_EXPOSURE") || len(toStringList(eks.Attributes["exposure_cidrs"])) != 1 {
		t.Errorf("eks public endpoint: %+v", eks)
	}
	if !sg.Partial || len(OpenIngress(sg.Ingress)) != 1 || sg.Ingress[0].FromPort != 3389 {
		t.Errorf("ingress rule resource on a live SG: %+v", sg)
	}
	if db.PublicReachable != ReachYes || len(db.SecurityGroups) != 1 || db.SecurityGroups[0] != "sg-live1" || !contains(db.Weaknesses, "UNENCRYPTED_AT_REST") {
		t.Errorf("rds: %+v", db)
	}
	v1 := a["aws_instance.v1"]
	if v1.PublicReachable != ReachNo || !contains(v1.Weaknesses, "IMDSV1_ENABLED") || !hasRel(v1, "runs_as", "name:aws_iam_instance_profile/live-profile") {
		t.Errorf("instance without metadata_options / private / live profile: %+v", v1)
	}
	// Findings: one FAIL per check, weaknesses set, typed relations carried.
	var fails int
	for _, r := range all {
		for _, f := range r.Findings() {
			if f.Status == model.Fail {
				fails++
				if len(f.Weaknesses) == 0 || f.Resource.ID != r.ID {
					t.Errorf("finding %+v", f)
				}
			}
		}
	}
	if fails < 6 {
		t.Errorf("FAIL findings = %d", fails)
	}
}

func TestPlanLimits(t *testing.T) {
	big := append([]byte(`{"resource_changes":[],"x":"`), bytes.Repeat([]byte("a"), 2048)...)
	big = append(big, `"}`...)
	_, err := ParsePlanJSON(big, PlanLimits{MaxBytes: 1024})
	var le *PlanLimitError
	if !errors.As(err, &le) || !strings.Contains(le.Error(), "size") {
		t.Fatalf("size cap: %v", err)
	}
	deep := []byte(`{"resource_changes":` + strings.Repeat("[", 70000) + strings.Repeat("]", 70000) + `}`)
	if _, err := ParsePlanJSON(deep, PlanLimits{}); !errors.As(err, &le) || !strings.Contains(le.Error(), "depth") {
		t.Fatalf("70k nesting: %v", err)
	}
	// Brackets inside strings do not count.
	ok := []byte(`{"format_version":"1.2","resource_changes":[],"x":"` + strings.Repeat("[", 5000) + `"}`)
	if _, err := ParsePlanJSON(ok, PlanLimits{}); err != nil {
		t.Fatalf("brackets in a string: %v", err)
	}
	var many strings.Builder
	many.WriteString(`{"resource_changes":[`)
	for i := 0; i < 30; i++ {
		if i > 0 {
			many.WriteString(",")
		}
		many.WriteString(`{"address":"a.b","mode":"managed","type":"a","name":"b","change":{"actions":["no-op"]}}`)
	}
	many.WriteString(`]}`)
	if _, err := ParsePlanJSON([]byte(many.String()), PlanLimits{MaxResources: 10}); !errors.As(err, &le) {
		t.Fatalf("resource cap: %v", err)
	}
	if _, err := ParsePlanJSON([]byte(`{"resource_changes":{}}`), PlanLimits{}); err == nil {
		t.Fatal("wrong shape accepted")
	}
	if _, err := ParsePlanJSON([]byte(`not json`), PlanLimits{}); err == nil {
		t.Fatal("garbage accepted")
	}
	// ReadPlanJSON never buffers more than the cap.
	if _, err := ReadPlanJSON(bytes.NewReader(big), PlanLimits{MaxBytes: 1024}); !errors.As(err, &le) {
		t.Fatalf("reader size cap: %v", err)
	}
}

// The plan is untrusted: paths inside it (module sources, file attributes, local-exec
// commands) are data. plan.go must not read files or run commands.
func TestPlanIngestReadsNoFilesAndRunsNothing(t *testing.T) {
	src, err := os.ReadFile("plan.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"os.Open", "os.ReadFile", "os/exec", "exec.Command", "ioutil.ReadFile", "os.Stat", "filepath.Walk"} {
		if bytes.Contains(src, []byte(bad)) {
			t.Errorf("plan.go uses %s", bad)
		}
	}
	hostile := `{"resource_changes":[{"address":"aws_s3_bucket.x","mode":"managed","type":"aws_s3_bucket","name":"x","change":{"actions":["create"],"before":null,
	 "after":{"bucket":"x","acl":"public-read","source":"/etc/passwd","file":"../../../../etc/shadow"}}}],
	 "configuration":{"root_module":{"module_calls":{"m":{"source":"/etc","module":{"resources":[]}}},"resources":[{"address":"null_resource.p","provisioners":[{"type":"local-exec","expressions":{"command":{"constant_value":"touch PWNED"}}}]}]}}}`
	p, err := ParsePlanJSON([]byte(hostile), PlanLimits{})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range p.Resources(SideAfter) {
		for k := range r.Attributes {
			if k == "source" || k == "file" {
				t.Errorf("unrelated attribute %q copied", k)
			}
		}
	}
	if _, err := os.Stat("PWNED"); err == nil {
		t.Fatal("command ran")
	}
}

func FuzzPlanJSON(f *testing.F) {
	for _, n := range []string{"bad.plan.json", "revert.plan.json", "create.plan.json"} {
		if b, err := os.ReadFile(filepath.Join(fixturePlans, n)); err == nil {
			f.Add(b)
		}
	}
	f.Add([]byte(mappingPlan))
	f.Add([]byte(`{"resource_changes":[{"change":{"actions":["update"],"before":{"ingress":[{"cidr_blocks":[null,1,"0.0.0.0/0"]}]},"after":{"ingress":"x"}}}]}`))
	f.Add([]byte(`{"resource_changes":[{"type":"aws_instance","change":{"actions":["create"],"after":{"vpc_security_group_ids":{"a":1},"metadata_options":[1]},"after_unknown":[]}}]}`))
	f.Add([]byte(`{"configuration":{"root_module":{"module_calls":{"a":{"module":{"module_calls":{"a":{}}}}}}}}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := ParsePlanJSON(data, PlanLimits{MaxBytes: 1 << 20})
		if err != nil {
			return
		}
		for _, side := range []Side{SideBefore, SideAfter} {
			for _, r := range p.Resources(side) {
				_ = r.Findings()
			}
		}
	})
}

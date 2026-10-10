package governance

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/config"
	"github.com/DreadpiratePickles/nimbus/internal/model"
)

const testCodeowners = `# GitHub syntax, last match wins
*                 @org/default-team
*.tf              @org/terraform
/infra/           @org/infra
/infra/payments/  @org/payments payments@example.com
infra/legacy/
apps/             @org/apps
docs/*            docs@example.com   # inline comment
**/logs           @org/logging
/build/logs/      @org/build
\#hash.tf         @org/hash
bad-owner.tf      not-an-owner
`

func testGovernance(t *testing.T) config.Governance {
	t.Helper()
	two := 2
	c := &config.Config{Governance: config.Governance{
		Rules: []config.GovernanceRule{
			{ID: "payments", Match: config.GovernanceMatch{Provider: "aws", Account: "aws-prod*", Tag: map[string]string{"team": "payments"}},
				Owner: "payments@example.com", SLADays: config.SLADays{Critical: 3}, GraceDays: &two},
			{ID: "iac", Match: config.GovernanceMatch{IaCPathGlob: "infra/**"}, Owner: "codeowners"},
			{ID: "ci", Match: config.GovernanceMatch{NameRegex: "^ci-"}, Owner: "tag:Owner"},
			{ID: "gcp", Match: config.GovernanceMatch{Provider: "gcp"}, Owner: "gcp-team@example.com", SLADays: config.SLADays{High: 21}},
			{ID: "k8s", Match: config.GovernanceMatch{Provider: "kubernetes", Tag: map[string]string{"env": "*"}}, Owner: "platform@example.com"},
		},
		Defaults: config.GovernanceDefaults{Owner: "secops@example.com", SLADays: config.SLADays{Medium: 45}, GraceDays: 1},
	}}
	if err := c.Validate(); err != nil {
		t.Fatalf("test governance invalid: %v", err)
	}
	return c.Governance
}

func testCO(t *testing.T) *Codeowners {
	t.Helper()
	co, err := ParseCodeowners(strings.NewReader(testCodeowners))
	if err != nil {
		t.Fatal(err)
	}
	return co
}

var t0 = time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)

func day(n int) time.Time { return t0.Add(time.Duration(n) * 24 * time.Hour) }

func TestResolveTable(t *testing.T) {
	g := testGovernance(t)
	co := testCO(t)
	r := NewResolver(g, co)
	type want struct {
		owner, source, rule string
		sla, grace          int
		due, graceUntil     time.Time
	}
	crit, high, med, low := model.Critical, model.High, model.Medium, model.Low
	cases := []struct {
		name string
		s    Subject
		w    want
	}{
		{"rule literal owner with rule SLA and grace", Subject{Provider: "aws", Account: "aws-prod", Severity: crit, Tags: map[string]string{"team": "payments"}, OpenedAt: t0},
			want{"payments@example.com", SourceRule, "payments", 3, 2, day(3), day(5)}},
		{"rule without severity SLA falls back to defaults", Subject{Provider: "aws", Account: "aws-prod", Severity: high, Tags: map[string]string{"team": "payments"}, OpenedAt: t0},
			want{"payments@example.com", SourceRule, "payments", 14, 2, day(14), day(16)}},
		{"account glob", Subject{Provider: "aws", Account: "aws-prod-eu", Severity: crit, Tags: map[string]string{"team": "payments"}, OpenedAt: t0},
			want{"payments@example.com", SourceRule, "payments", 3, 2, day(3), day(5)}},
		{"no rule: default owner tag team", Subject{Provider: "aws", Account: "aws-dev", Severity: crit, Tags: map[string]string{"team": "payments"}, OpenedAt: t0},
			want{"payments", SourceTag, "", 7, 1, day(7), day(8)}},
		{"tag key and value match case-insensitively", Subject{Provider: "aws", Account: "aws-prod", Severity: crit, Tags: map[string]string{"TEAM": "Payments"}, OpenedAt: t0},
			want{"payments@example.com", SourceRule, "payments", 3, 2, day(3), day(5)}},
		{"provider matches case-insensitively", Subject{Provider: "AWS", Account: "aws-prod", Severity: crit, Tags: map[string]string{"team": "payments"}, OpenedAt: t0},
			want{"payments@example.com", SourceRule, "payments", 3, 2, day(3), day(5)}},
		{"codeowners rule: nested anchored dir", Subject{Provider: "iac", Severity: high, IaCPath: "infra/payments/main.tf", OpenedAt: t0},
			want{"@org/payments", SourceCodeowners, "iac", 14, 1, day(14), day(15)}},
		{"codeowners rule: last match wins over *.tf", Subject{Provider: "iac", Severity: high, IaCPath: "infra/network/vpc.tf", OpenedAt: t0},
			want{"@org/infra", SourceCodeowners, "iac", 14, 1, day(14), day(15)}},
		{"codeowners unowned pattern falls back to default", Subject{Provider: "iac", Severity: high, IaCPath: "infra/legacy/old.tf", OpenedAt: t0},
			want{"secops@example.com", SourceDefault, "iac", 14, 1, day(14), day(15)}},
		{"iac path ./ prefix normalised", Subject{Provider: "iac", Severity: low, IaCPath: "./infra/x.tf", OpenedAt: t0},
			want{"@org/infra", SourceCodeowners, "iac", 90, 1, day(90), day(91)}},
		{"iac path backslashes normalised", Subject{Provider: "iac", Severity: low, IaCPath: `infra\x.tf`, OpenedAt: t0},
			want{"@org/infra", SourceCodeowners, "iac", 90, 1, day(90), day(91)}},
		{"tag:Owner rule", Subject{Provider: "aws", Name: "ci-runner", Severity: med, Tags: map[string]string{"Owner": "alice@example.com"}, OpenedAt: t0},
			want{"alice@example.com", SourceTag, "ci", 45, 1, day(45), day(46)}},
		{"tag:Owner rule, tag key case-insensitive", Subject{Provider: "aws", Name: "ci-runner", Severity: med, Tags: map[string]string{"owner": "alice@example.com"}, OpenedAt: t0},
			want{"alice@example.com", SourceTag, "ci", 45, 1, day(45), day(46)}},
		{"tag:Owner rule, tag missing: default owner", Subject{Provider: "aws", Name: "ci-runner", Severity: med, OpenedAt: t0},
			want{"secops@example.com", SourceDefault, "ci", 45, 1, day(45), day(46)}},
		{"tag:Owner rule, tag missing: owner_tags fallback", Subject{Provider: "aws", Name: "ci-runner", Severity: med, Tags: map[string]string{"team": "build"}, OpenedAt: t0},
			want{"build", SourceTag, "ci", 45, 1, day(45), day(46)}},
		{"tag:Owner rule, empty tag value is missing", Subject{Provider: "aws", Name: "ci-runner", Severity: med, Tags: map[string]string{"Owner": "  "}, OpenedAt: t0},
			want{"secops@example.com", SourceDefault, "ci", 45, 1, day(45), day(46)}},
		{"rule SLA override", Subject{Provider: "gcp", Severity: high, OpenedAt: t0},
			want{"gcp-team@example.com", SourceRule, "gcp", 21, 1, day(21), day(22)}},
		{"rule SLA unset severity uses built-in", Subject{Provider: "gcp", Severity: crit, OpenedAt: t0},
			want{"gcp-team@example.com", SourceRule, "gcp", 7, 1, day(7), day(8)}},
		{"rule SLA unset severity uses defaults block", Subject{Provider: "gcp", Severity: med, OpenedAt: t0},
			want{"gcp-team@example.com", SourceRule, "gcp", 45, 1, day(45), day(46)}},
		{"tag presence selector", Subject{Provider: "kubernetes", Severity: low, Tags: map[string]string{"env": "dev"}, OpenedAt: t0},
			want{"platform@example.com", SourceRule, "k8s", 90, 1, day(90), day(91)}},
		{"tag presence selector, tag absent: no rule", Subject{Provider: "kubernetes", Severity: low, OpenedAt: t0},
			want{"secops@example.com", SourceDefault, "", 90, 1, day(90), day(91)}},
		{"INFO has no SLA", Subject{Provider: "gcp", Severity: model.Info, OpenedAt: t0},
			want{"gcp-team@example.com", SourceRule, "gcp", 0, 1, time.Time{}, time.Time{}}},
		{"no opened-at: no due date", Subject{Provider: "gcp", Severity: high},
			want{"gcp-team@example.com", SourceRule, "gcp", 21, 1, time.Time{}, time.Time{}}},
		{"account owner fallback", Subject{Provider: "azure", Severity: high, AccountOwner: "acct@example.com", OpenedAt: t0},
			want{"acct@example.com", SourceAccount, "", 14, 1, day(14), day(15)}},
		{"tag beats account owner", Subject{Provider: "azure", Severity: high, AccountOwner: "acct@example.com", Tags: map[string]string{"owner": "o@example.com"}, OpenedAt: t0},
			want{"o@example.com", SourceTag, "", 14, 1, day(14), day(15)}},
		{"codeowners fallback without a rule: *.tf", Subject{Provider: "iac", Severity: high, IaCPath: "app/main.tf", OpenedAt: t0},
			want{"@org/terraform", SourceCodeowners, "", 14, 1, day(14), day(15)}},
		{"docs/* matches direct children", Subject{Provider: "iac", Severity: high, IaCPath: "docs/readme.md", OpenedAt: t0},
			want{"docs@example.com", SourceCodeowners, "", 14, 1, day(14), day(15)}},
		{"docs/* does not match nested files", Subject{Provider: "iac", Severity: high, IaCPath: "docs/a/b.md", OpenedAt: t0},
			want{"@org/default-team", SourceCodeowners, "", 14, 1, day(14), day(15)}},
		{"**/logs at any depth", Subject{Provider: "iac", Severity: high, IaCPath: "svc/logs/x.tf", OpenedAt: t0},
			want{"@org/logging", SourceCodeowners, "", 14, 1, day(14), day(15)}},
		{"/build/logs/ anchored beats **/logs (later line)", Subject{Provider: "iac", Severity: high, IaCPath: "build/logs/a.tf", OpenedAt: t0},
			want{"@org/build", SourceCodeowners, "", 14, 1, day(14), day(15)}},
		{"apps/ unanchored dir at any depth", Subject{Provider: "iac", Severity: high, IaCPath: "x/apps/y.tf", OpenedAt: t0},
			want{"@org/apps", SourceCodeowners, "", 14, 1, day(14), day(15)}},
		{"escaped # is unsupported by GitHub: line skipped", Subject{Provider: "iac", Severity: high, IaCPath: "#hash.tf", OpenedAt: t0},
			want{"@org/terraform", SourceCodeowners, "", 14, 1, day(14), day(15)}},
		{"invalid owner line skipped", Subject{Provider: "iac", Severity: high, IaCPath: "bad-owner.tf", OpenedAt: t0},
			want{"@org/terraform", SourceCodeowners, "", 14, 1, day(14), day(15)}},
		{"first match wins over a later rule", Subject{Provider: "gcp", Name: "ci-x", Severity: high, OpenedAt: t0},
			want{"secops@example.com", SourceDefault, "ci", 14, 1, day(14), day(15)}},
		{"no iac path: iac_path_glob never matches", Subject{Provider: "aws", Severity: low, OpenedAt: t0},
			want{"secops@example.com", SourceDefault, "", 90, 1, day(90), day(91)}},
		{"low severity default", Subject{Provider: "oci", Severity: low, OpenedAt: t0},
			want{"secops@example.com", SourceDefault, "", 90, 1, day(90), day(91)}},
		{"severity spelled lower-case", Subject{Provider: "oci", Severity: "critical", OpenedAt: t0},
			want{"secops@example.com", SourceDefault, "", 7, 1, day(7), day(8)}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := r.Resolve(c.s)
			got := want{a.Owner, a.Source, a.RuleID, a.SLADays, a.GraceDays, a.DueAt, a.GraceUntil}
			if !reflect.DeepEqual(got, c.w) {
				t.Errorf("Resolve(%+v)\n got %+v\nwant %+v\n why %s", c.s, got, c.w, a.Why)
			}
			if a.Why == "" {
				t.Error("Why must explain the assignment")
			}
			if again := r.Resolve(c.s); !reflect.DeepEqual(again, a) {
				t.Error("Resolve is not deterministic")
			}
		})
	}
}

func TestResolveNoGovernanceAndNilCodeowners(t *testing.T) {
	a := Resolve(config.Governance{}, nil, Subject{Provider: "aws", Severity: model.Critical, IaCPath: "infra/a.tf", OpenedAt: t0})
	if a.Owner != "" || a.Source != SourceUnassigned || a.SLADays != 7 || !a.DueAt.Equal(day(7)) || !a.GraceUntil.Equal(day(7)) {
		t.Errorf("zero governance = %+v", a)
	}
	g := testGovernance(t)
	a = Resolve(g, nil, Subject{Provider: "iac", Severity: model.High, IaCPath: "infra/a.tf", OpenedAt: t0})
	if a.Owner != "secops@example.com" || a.Source != SourceDefault || a.RuleID != "iac" {
		t.Errorf("codeowners rule with no CODEOWNERS file = %+v", a)
	}
}

func TestResolveCodeownersMultipleOwners(t *testing.T) {
	a := NewResolver(testGovernance(t), testCO(t)).Resolve(Subject{Provider: "iac", Severity: model.High, IaCPath: "infra/payments/db.tf", OpenedAt: t0})
	if !reflect.DeepEqual(a.Owners, []string{"@org/payments", "payments@example.com"}) || a.Owner != "@org/payments" {
		t.Errorf("owners = %v / %q", a.Owners, a.Owner)
	}
}

func TestAssignmentOverdue(t *testing.T) {
	a := Assignment{SLADays: 7, DueAt: day(7), GraceUntil: day(9)}
	if a.Overdue(day(7)) || !a.Overdue(day(7).Add(time.Second)) {
		t.Error("overdue strictly after due")
	}
	if a.PastGrace(day(8)) || !a.PastGrace(day(10)) {
		t.Error("past grace strictly after grace_until")
	}
	if (Assignment{}).Overdue(day(1000)) {
		t.Error("no due date is never overdue")
	}
}

func TestSubjectFromFinding(t *testing.T) {
	f := model.Finding{Provider: "iac", Account: "repo", Severity: model.High, File: "./infra/main.tf", FirstSeen: t0,
		Resource: model.Resource{ID: "aws_s3_bucket.logs", Name: "logs", Attributes: map[string]any{"tags": map[string]any{"Owner": "a@example.com"}}},
		Tags:     map[string]string{"team": "t", "Owner": "ignored"}}
	s := SubjectFromFinding(f)
	if s.IaCPath != "infra/main.tf" || s.Name != "logs" || s.ResourceID != "aws_s3_bucket.logs" || s.Tags["Owner"] != "a@example.com" || s.Tags["team"] != "t" || !s.OpenedAt.Equal(t0) || s.Severity != model.High {
		t.Errorf("subject = %+v", s)
	}
}

func TestSubjectFromIssue(t *testing.T) {
	is := model.Issue{ID: "i1", Provider: "aws", Account: "aws-prod", Severity: model.Critical, ResourceID: "arn:x", FirstSeen: t0}
	ev := []model.Finding{
		{ID: "b", Resource: model.Resource{Name: "second"}},
		{ID: "a", Resource: model.Resource{Name: "first", Attributes: map[string]any{"tags": map[string]string{"team": "payments"}}}},
	}
	s := SubjectFromIssue(is, ev)
	if s.Provider != "aws" || s.Account != "aws-prod" || s.Severity != model.Critical || s.Name != "first" || s.Tags["team"] != "payments" || s.ResourceID != "arn:x" || !s.OpenedAt.Equal(t0) {
		t.Errorf("subject = %+v", s)
	}
	if s2 := SubjectFromIssue(is, nil); s2.Name != "arn:x" {
		t.Errorf("no evidence: name falls back to resource id, got %q", s2.Name)
	}
}

package config

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestLoadGovernanceBlock(t *testing.T) {
	p := writeCfg(t, `
integrations:
  slack: {url_env: SLACK_WEBHOOK_URL}
governance:
  codeowners_file: .github/CODEOWNERS
  rules:
    - id: payments
      match: {provider: aws, account: "aws-prod*", tag: {team: payments}}
      owner: payments-oncall@example.com
      sla_days: {critical: 3, high: 10}
      grace_days: 2
    - match: {iac_path_glob: "infra/**/*.tf"}
      owner: codeowners
    - match: {name_regex: "^ci-"}
      owner: "tag:Owner"
  defaults:
    owner: secops@example.com
    sla_days: {critical: 7, high: 14, medium: 30, low: 90}
    grace_days: 1
  digest: {schedule: weekly, sink: slack, group_by: owner, dedup_window: 72h}
`)
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	g := cfg.Governance
	if !g.Enabled() || len(g.Rules) != 3 {
		t.Fatalf("governance not loaded: %+v", g)
	}
	r0 := g.Rules[0]
	if r0.ID != "payments" || r0.Match.Provider != "aws" || r0.Match.Tag["team"] != "payments" || r0.SLADays.Critical != 3 || r0.GraceDays == nil || *r0.GraceDays != 2 {
		t.Errorf("rule 0 = %+v", r0)
	}
	if g.Rules[1].ID != "rule-2" || g.Rules[2].ID != "rule-3" {
		t.Errorf("unnamed rules get positional ids, got %q %q", g.Rules[1].ID, g.Rules[2].ID)
	}
	if g.Rules[1].OwnerKind() != OwnerCodeowners || g.Rules[2].OwnerKind() != OwnerTag || g.Rules[2].OwnerTag() != "Owner" || r0.OwnerKind() != OwnerLiteral {
		t.Errorf("owner kinds wrong")
	}
	if g.Digest.Schedule != "weekly" || g.Digest.Sink != "slack" || g.Digest.GroupBy != "owner" || g.Digest.DedupWindow() != 72*time.Hour {
		t.Errorf("digest = %+v (window %v)", g.Digest, g.Digest.DedupWindow())
	}
	if len(cfg.Warnings()) != 0 {
		t.Errorf("unexpected warnings %v", cfg.Warnings())
	}
}

func TestGovernanceDefaults(t *testing.T) {
	var g Governance
	if g.Enabled() {
		t.Error("empty block must not be enabled")
	}
	sla := g.Defaults.SLADays.WithFallback(DefaultSLADays)
	if sla != (SLADays{Critical: 7, High: 14, Medium: 30, Low: 90}) {
		t.Errorf("built-in SLA = %+v", sla)
	}
	if got := (SLADays{High: 5}).WithFallback(DefaultSLADays); got.High != 5 || got.Critical != 7 || got.Low != 90 {
		t.Errorf("partial override = %+v", got)
	}
	if (DigestConfig{}).DedupWindow() != 7*24*time.Hour || (DigestConfig{Schedule: "daily"}).DedupWindow() != 24*time.Hour {
		t.Error("dedup window must default to the schedule period")
	}
	if (DigestConfig{}).ScheduleOrDefault() != "weekly" || (DigestConfig{}).GroupByOrDefault() != "owner" {
		t.Error("digest defaults")
	}
	if got := (SLADays{Critical: 1, High: 2, Medium: 3, Low: 4}).For("HIGH"); got != 2 {
		t.Errorf("For(HIGH) = %d", got)
	}
	if got := DefaultSLADays.For("INFO"); got != 0 {
		t.Errorf("INFO has no SLA, got %d", got)
	}
}

func TestGovernanceValidationErrors(t *testing.T) {
	neg := -1
	c := &Config{Governance: Governance{
		Rules: []GovernanceRule{
			{Match: GovernanceMatch{Provider: "aws"}},                                        // 0: no owner
			{Owner: "team@x"},                                                                // 1: no selector
			{Match: GovernanceMatch{NameRegex: "(bad"}, Owner: "a@x"},                        // 2: regex
			{Match: GovernanceMatch{IaCPathGlob: "infra/[x"}, Owner: "a@x"},                  // 3: glob
			{Match: GovernanceMatch{Account: "p"}, Owner: "tag:"},                            // 4: empty tag key
			{Match: GovernanceMatch{Account: "p"}, Owner: "a@x", SLADays: SLADays{High: -3}}, // 5: negative SLA
			{Match: GovernanceMatch{Account: "p"}, Owner: "a@x", GraceDays: &neg},            // 6: negative grace
			{ID: "dup", Match: GovernanceMatch{Account: "p"}, Owner: "a@x"},                  // 7
			{ID: "dup", Match: GovernanceMatch{Account: "q"}, Owner: "a@x"},                  // 8: duplicate id
			{Match: GovernanceMatch{Provider: "[bad"}, Owner: "a@x"},                         // 9: bad provider glob
		},
		Defaults: GovernanceDefaults{SLADays: SLADays{Low: 99999}},
		Digest:   DigestConfig{Schedule: "hourly", Sink: "carrier-pigeon", GroupBy: "colour", Window: "soon"},
	}}
	err := c.Validate()
	var ve ValidationErrors
	if !errors.As(err, &ve) {
		t.Fatalf("want ValidationErrors, got %v", err)
	}
	want := map[string]error{
		"governance.rules[0].owner":               ErrInvalidOwner,
		"governance.rules[1].match":               ErrEmptySelector,
		"governance.rules[2].match.name_regex":    ErrInvalidRegex,
		"governance.rules[3].match.iac_path_glob": ErrInvalidGlob,
		"governance.rules[4].owner":               ErrInvalidOwner,
		"governance.rules[5].sla_days.high":       ErrInvalidSLA,
		"governance.rules[6].grace_days":          ErrInvalidSLA,
		"governance.rules[8].id":                  ErrDuplicateRuleID,
		"governance.rules[9].match.provider":      ErrInvalidGlob,
		"governance.defaults.sla_days.low":        ErrInvalidSLA,
		"governance.digest.schedule":              ErrInvalidDigest,
		"governance.digest.sink":                  ErrInvalidDigest,
		"governance.digest.group_by":              ErrInvalidDigest,
		"governance.digest.dedup_window":          ErrInvalidDuration,
	}
	got := map[string]error{}
	for _, e := range ve {
		got[e.Field] = e.Err
	}
	for f, sentinel := range want {
		if got[f] == nil {
			t.Errorf("missing error for %s (got %v)", f, ve)
			continue
		}
		if !errors.Is(got[f], sentinel) {
			t.Errorf("%s: err %v, want %v", f, got[f], sentinel)
		}
	}
	if len(ve) != len(want) {
		t.Errorf("got %d errors, want %d: %v", len(ve), len(want), ve)
	}
}

func TestGovernanceDigestSinkNotConfiguredWarns(t *testing.T) {
	c := &Config{Governance: Governance{Digest: DigestConfig{Sink: "teams"}}}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	w := strings.Join(c.Warnings(), "\n")
	if !strings.Contains(w, "governance.digest.sink") {
		t.Errorf("want a warning that the teams integration is not configured, got %q", w)
	}
}

func TestGovernanceRuleCap(t *testing.T) {
	c := &Config{}
	for i := 0; i < MaxGovernanceRules+5; i++ {
		c.Governance.Rules = append(c.Governance.Rules, GovernanceRule{Match: GovernanceMatch{Provider: "aws"}, Owner: "a@x"})
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if len(c.Governance.Rules) != MaxGovernanceRules || len(c.Warnings()) == 0 {
		t.Errorf("cap not enforced: %d rules, warnings %v", len(c.Governance.Rules), c.Warnings())
	}
}

func TestCompileGlob(t *testing.T) {
	cases := []struct {
		glob, path string
		want       bool
	}{
		{"infra/**/*.tf", "infra/main.tf", true},
		{"infra/**/*.tf", "infra/a/b/main.tf", true},
		{"infra/**/*.tf", "app/infra/main.tf", false},
		{"infra/*.tf", "infra/a/main.tf", false},
		{"**/*.tf", "main.tf", true},
		{"**", "anything/at/all", true},
		{"modules/?pc/*", "modules/vpc/main.tf", true},
		{"aws-prod*", "aws-prod-eu", true},
		{"a.b", "axb", false},
		{"[ab]*.tf", "b1.tf", true},
	}
	for _, c := range cases {
		re, err := CompileGlob(c.glob)
		if err != nil {
			t.Fatalf("%s: %v", c.glob, err)
		}
		if got := re.MatchString(c.path); got != c.want {
			t.Errorf("glob %q vs %q = %v, want %v", c.glob, c.path, got, c.want)
		}
	}
	if _, err := CompileGlob("[unclosed"); err == nil {
		t.Error("unclosed class must fail")
	}
}

func TestExampleConfigGovernance(t *testing.T) {
	cfg, err := Load("../../cloud-posture.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	g := cfg.Governance
	if len(g.Rules) != 3 || g.Rules[1].OwnerKind() != OwnerCodeowners || g.Defaults.Owner == "" || g.Digest.Sink != "slack" {
		t.Errorf("example governance block not loaded: %+v", g)
	}
}

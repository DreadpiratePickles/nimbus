package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeCfg(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "cloud-posture.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadParsesTrustedCIDRsAndCrownJewels(t *testing.T) {
	p := writeCfg(t, `
accounts:
  aws-prod: {provider: aws, profile: prod}
trusted_cidrs: [203.0.113.0/24, "198.51.100.7", "2001:db8::/32"]
crown_jewels:
  - {level: very_high, types: [aws_s3_bucket], tags: {classification: pii}}
  - {level: high, name_regex: "^payments-", accounts: [aws-prod]}
scan:
  account_timeout: 5m
neo4j:
  uri_env: NEO4J_URI
  password_env: NEO4J_PASSWORD
`)
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.TrustedCIDRs) != 3 || len(cfg.CrownJewels) != 2 || cfg.CrownJewels[0].Level != LevelVeryHigh {
		t.Fatalf("cfg = %+v", cfg)
	}
	if cfg.AccountTimeout() != 5*time.Minute {
		t.Errorf("AccountTimeout = %v", cfg.AccountTimeout())
	}
	if cfg.Neo4j.URIEnv != "NEO4J_URI" || cfg.Neo4j.PasswordEnv != "NEO4J_PASSWORD" {
		t.Errorf("neo4j *_env keys from the example file not loaded: %+v", cfg.Neo4j)
	}
}

func TestAccountTimeoutDefault(t *testing.T) {
	if got := (&Config{}).AccountTimeout(); got != 10*time.Minute {
		t.Errorf("default = %v", got)
	}
	c := &Config{}
	c.Scan.AccountTimeout = "none"
	if got := c.AccountTimeout(); got >= 0 {
		t.Errorf("none should disable (negative), got %v", got)
	}
}

func TestValidateCollectsAllTypedErrors(t *testing.T) {
	c := &Config{
		TrustedCIDRs: []string{"203.0.113.0/24", "not-a-cidr", "0.0.0.0/0"},
		CrownJewels: []CrownJewelRule{
			{Level: "critical", Types: []string{"aws_s3_bucket"}},
			{Level: LevelHigh, NameRegex: "(unclosed"},
			{Level: LevelLow},
		},
		Integrations: map[string]*SinkConfig{"jira": {Token: "abc123"}},
	}
	c.Neo4j.Password = "hunter2"
	c.Scan.AccountTimeout = "ten minutes"
	err := c.Validate()
	var ve ValidationErrors
	if !errors.As(err, &ve) {
		t.Fatalf("Validate() = %v, want ValidationErrors", err)
	}
	for _, want := range []error{ErrInvalidCIDR, ErrTrustedCIDRTooBroad, ErrInvalidLevel, ErrInvalidRegex, ErrEmptySelector, ErrPlaintextSecret, ErrInvalidDuration} {
		if !errors.Is(err, want) {
			t.Errorf("missing %v in %v", want, err)
		}
	}
	if len(ve) != 8 { // cidr, /0, level, regex, empty selector, 2 secrets, duration
		t.Errorf("got %d errors: %v", len(ve), err)
	}
	msg := err.Error()
	for _, s := range []string{"trusted_cidrs[1]", "crown_jewels[1].name_regex", "integrations.jira.token", "token_env", "neo4j.password", "password_env"} {
		if !strings.Contains(msg, s) {
			t.Errorf("error text lacks %q: %s", s, msg)
		}
	}
	if strings.Contains(msg, "abc123") || strings.Contains(msg, "hunter2") {
		t.Errorf("secret value leaked into the error: %s", msg)
	}
}

func TestValidateOK(t *testing.T) {
	c := &Config{TrustedCIDRs: []string{"203.0.113.0/24"}, CrownJewels: []CrownJewelRule{{Level: LevelMedium, Tags: map[string]string{"env": "prod"}}}}
	c.Neo4j.PasswordEnv = "NEO4J_PASSWORD"
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestLoadRejectsPlaintextSecrets(t *testing.T) {
	for _, body := range []string{
		"integrations:\n  pagerduty: {token: R0UT1NGKEY}\n",
		"neo4j:\n  password: hunter2\n",
		"accounts:\n  m365:\n    provider: m365\n    secret: s3cr3t\n",
		"plugins:\n  - name: x\n    command: [x]\n    client_secret: abc\n",
	} {
		_, err := Load(writeCfg(t, body))
		if !errors.Is(err, ErrPlaintextSecret) {
			t.Errorf("Load(%q) = %v, want ErrPlaintextSecret", body, err)
			continue
		}
		if !strings.Contains(err.Error(), "_env") {
			t.Errorf("no *_env guidance: %v", err)
		}
		for _, v := range []string{"R0UT1NGKEY", "hunter2", "s3cr3t", "abc"} {
			if strings.Contains(err.Error(), ": "+v) || strings.Contains(err.Error(), "\""+v+"\"") {
				t.Errorf("secret value leaked: %v", err)
			}
		}
	}
	// *_env keys and empty values are fine.
	if _, err := Load(writeCfg(t, "integrations:\n  pagerduty: {token_env: PD_KEY}\nneo4j:\n  password: \"\"\n")); err != nil {
		t.Errorf("env reference rejected: %v", err)
	}
}

func TestCrownJewelCapWarns(t *testing.T) {
	c := &Config{}
	for i := 0; i < MaxCrownJewelRules+5; i++ {
		c.CrownJewels = append(c.CrownJewels, CrownJewelRule{Level: LevelLow, Types: []string{"aws_s3_bucket"}})
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("over-cap is a warning, not an error: %v", err)
	}
	if len(c.CrownJewels) != MaxCrownJewelRules {
		t.Errorf("rules kept = %d", len(c.CrownJewels))
	}
	if w := c.Warnings(); len(w) != 1 || !strings.Contains(w[0], "200") {
		t.Errorf("warnings = %v", w)
	}
}

func TestMatchCrownJewel(t *testing.T) {
	rules := []CrownJewelRule{
		{Level: LevelMedium, Types: []string{"aws_s3_*"}},
		{Level: LevelVeryHigh, Types: []string{"aws_s3_bucket"}, Tags: map[string]string{"classification": "pii"}},
		{Level: LevelHigh, NameRegex: "^payments-", Accounts: []string{"111111111111", "aws-prod"}},
		{Level: LevelLow, Tags: map[string]string{"backup": "*"}},
	}
	if err := (&Config{CrownJewels: rules}).Validate(); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		node  JewelSubject
		level string
		ok    bool
	}{
		{"highest wins", JewelSubject{Type: "aws_s3_bucket", Name: "cust", Tags: map[string]string{"Classification": "PII"}}, LevelVeryHigh, true},
		{"glob type", JewelSubject{Type: "aws_s3_bucket", Name: "logs"}, LevelMedium, true},
		{"all selectors must match (account)", JewelSubject{Type: "aws_db_instance", Name: "payments-db", Account: "222"}, "", false},
		{"name + account", JewelSubject{Type: "aws_db_instance", Name: "payments-db", Account: "aws-prod"}, LevelHigh, true},
		{"tag wildcard", JewelSubject{Type: "gcp_disk", Tags: map[string]string{"backup": "daily"}}, LevelLow, true},
		{"no match", JewelSubject{Type: "aws_instance", Name: "web"}, "", false},
	}
	for _, tc := range cases {
		level, ok := MatchCrownJewel(rules, tc.node)
		if level != tc.level || ok != tc.ok {
			t.Errorf("%s: got (%q,%v), want (%q,%v)", tc.name, level, ok, tc.level, tc.ok)
		}
	}
	// Attribute-map helper (graph.Node.Attributes["tags"] is map[string]any).
	s := JewelSubjectFromAttrs("aws_s3_bucket", "cust", "1", map[string]any{"tags": map[string]any{"classification": "pii"}})
	if level, _ := MatchCrownJewel(rules, s); level != LevelVeryHigh {
		t.Errorf("from attrs = %q", level)
	}
	// Works on rules that were never validated (regex compiled lazily).
	if level, ok := MatchCrownJewel([]CrownJewelRule{{Level: LevelHigh, NameRegex: "^db"}}, JewelSubject{Name: "db1"}); !ok || level != LevelHigh {
		t.Errorf("lazy regex = %q %v", level, ok)
	}
}

func TestExampleConfigLoads(t *testing.T) {
	cfg, err := Load(filepath.Join("..", "..", "cloud-posture.example.yaml"))
	if err != nil {
		t.Fatalf("example config does not validate: %v", err)
	}
	if len(cfg.TrustedCIDRs) == 0 || len(cfg.CrownJewels) == 0 || cfg.Neo4j.PasswordEnv != "NEO4J_PASSWORD" {
		t.Errorf("example keys not loaded: %+v", cfg)
	}
}

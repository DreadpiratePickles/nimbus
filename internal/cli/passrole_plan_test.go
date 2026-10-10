package cli

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/attackpath"
)

const (
	labDevSam   = "arn:aws:iam::111111111111:user/nimbus-lab-dev-sam"
	labEC2Admin = "arn:aws:iam::111111111111:role/nimbus-lab-ec2-admin-role"
)

// Item 12 (V4-ENGINE handoff): the PassRole escalation step of `plan` renders the PassRole
// scoping fix (remediation.PassRoleFix via attackpath.PassRoleFixOf) with its own sidecar
// phases and a runnable command, not the phases of an unrelated finding on the principal;
// the plan headline states the min-fix coverage to one decimal (95.5% on the lab).
func TestPlanPassRoleStepUsesPassRoleFix(t *testing.T) {
	labDB(t)
	out := run(t, "plan", "--top", "100", "--json")
	var d planDoc
	if err := json.Unmarshal([]byte(out[strings.Index(out, "{"):]), &d); err != nil {
		t.Fatalf("plan --json: %v", err)
	}
	var step *planStep
	for i := range d.Steps {
		if d.Steps[i].Fix.Weakness == attackpath.WeaknessPassRoleEscalation {
			step = &d.Steps[i]
		}
	}
	if step == nil {
		t.Fatalf("no PassRole step in the lab plan (%d steps)", len(d.Steps))
	}
	if step.Template != "iam_passrole_scope.tf" {
		t.Errorf("PassRole step template %q, want iam_passrole_scope.tf", step.Template)
	}
	if !strings.Contains(step.Fix.Command, "cloud-posture fix --passrole "+labDevSam+" --role "+labEC2Admin) {
		t.Errorf("PassRole step command not runnable: %q", step.Fix.Command)
	}
	phases, _ := json.Marshal(step.Phases)
	if strings.Contains(string(phases), "IAM_USER_NO_MFA") || !strings.Contains(string(phases), "iam_passrole_scope") {
		t.Errorf("PassRole step phases come from another finding: %s", phases)
	}
	// The coverage moves with the engine (95.5% at the V4-ENGINE handoff); the headline must
	// print the same number as the JSON to one decimal, not a rounded 96%.
	if want := fmt.Sprintf("removes %.1f%% of traversal path score", d.MinFixCoverage); !strings.Contains(run(t, "plan", "--top", "3"), want) {
		txt := run(t, "plan", "--top", "3")
		t.Errorf("plan headline must show the coverage to one decimal:\n%s", txt[:min(len(txt), 600)])
	}
}

// `fix --passrole <principal> --role <role>` prints the PassRole scoping fix and its steps.
func TestFixPassRolePrintsScopedPolicy(t *testing.T) {
	labDB(t)
	out := run(t, "fix", "--passrole", labDevSam, "--role", labEC2Admin, "--print")
	for _, want := range []string{"iam:PassRole", "iam:PassedToService", "nimbus-lab-ec2-admin-role", "terraform plan"} {
		if !strings.Contains(out, want) {
			t.Errorf("fix --passrole output lacks %q:\n%s", want, out)
		}
	}
	if _, err := runErr(t, "fix", "--passrole", labDevSam, "--role", "arn:aws:iam::111111111111:role/not-escalated", "--print"); err == nil {
		t.Error("fix --passrole for a role with no escalation edge must fail")
	}
}

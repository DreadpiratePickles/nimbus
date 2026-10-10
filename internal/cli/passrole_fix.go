package cli

// PassRole scoping fix wiring (V4-ENGINE handoff, item 12): an iam:PassRole escalation edge in
// the minimum fix set is fixed by narrowing the principal's PassRole statement, rendered by
// remediation.PassRoleFix from attackpath.PassRoleFixOf. `plan` prints it with its sidecar
// phases; `fix --passrole <principal> --role <role>` renders it.

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/DreadpiratePickles/nimbus/internal/attackpath"
	"github.com/DreadpiratePickles/nimbus/internal/graph"
	"github.com/DreadpiratePickles/nimbus/internal/remediation"
)

func passRoleRemediation(pr attackpath.PassRoleEdgeFix) (*remediation.Fix, error) {
	return remediation.PassRoleFix(remediation.PassRoleInput{Principal: pr.Principal, Role: pr.Role, Technique: pr.Technique,
		Statement: pr.Statement, PolicyARN: pr.PolicyARN})
}

func passRoleFixCommand(pr attackpath.PassRoleEdgeFix) string {
	where := "its policies"
	if pr.Statement != "" {
		where = "statement " + pr.Statement
	}
	return fmt.Sprintf("cloud-posture fix --passrole %s --role %s   # scope iam:PassRole (%s): drop the role, add iam:PassedToService", pr.Principal, pr.Role, where)
}

// passRoleEdge finds the PassRole escalation edge principal → role in g.
func passRoleEdge(g *graph.Graph, principal, role string) (attackpath.PassRoleEdgeFix, error) {
	fx := attackpath.Fix{Weakness: attackpath.WeaknessPassRoleEscalation, Edge: &attackpath.EdgeRef{From: principal, To: role, Kind: graph.EdgeCanAssume}}
	pr, _ := attackpath.PassRoleFixOf(g, fx)
	if pr.Technique == "" {
		return pr, fmt.Errorf("no iam:PassRole escalation edge %s → %s in the graph (see `cloud-posture plan`)", principal, role)
	}
	return pr, nil
}

func runPassRoleFix(principal, role string) error {
	if role == "" {
		return fmt.Errorf("--passrole needs --role <role ARN> (the role the principal must no longer pass)")
	}
	st, err := openStore()
	if err != nil {
		return err
	}
	defer st.Close()
	g, err := graphFromStore(st)
	if err != nil {
		return err
	}
	pr, err := passRoleEdge(g, principal, role)
	if err != nil {
		return err
	}
	fix, err := passRoleRemediation(pr)
	if err != nil {
		return err
	}
	if fixFlags.print {
		fmt.Println(fix.Content)
	} else {
		if err := os.MkdirAll(fixFlags.outDir, 0o755); err != nil {
			return err
		}
		p := filepath.Join(fixFlags.outDir, fix.FileName)
		if err := os.WriteFile(p, []byte(fix.Content), 0o644); err != nil {
			return err
		}
		fmt.Printf("✓ wrote %s\n", p)
	}
	fmt.Printf("PassRole scoping fix for %s → %s (%s)\n", pr.Principal, pr.Role, pr.Technique)
	for i, s := range fix.Steps {
		fmt.Printf("  %d. %s\n", i+1, s)
	}
	return nil
}

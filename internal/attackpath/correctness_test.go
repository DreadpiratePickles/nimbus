package attackpath

import (
	"strings"
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/graph"
	"github.com/DreadpiratePickles/nimbus/internal/model"
)

func entryOf(p model.AttackPath) string {
	if len(p.Steps) > 0 && p.Steps[0].Relation == "entry" {
		return p.Steps[0].Resource
	}
	return graph.InternetNodeID
}

func seqKey(entry string, steps []model.Step) string {
	ids := make([]string, 0, len(steps))
	for _, s := range steps {
		ids = append(ids, s.Resource)
	}
	return entry + "|" + strings.Join(ids, ">")
}

// Defect 18(a): the CLUSTER_ADMIN weakness lives on the ClusterRoleBinding; deleting that
// binding must show up as a fix that breaks the pod → SA → cluster-admin path.
func TestBindingWeaknessBreaksK8sPath(t *testing.T) {
	an := Traverse(k8sSAGraph(), DefaultTraversalOptions())
	var fix *Fix
	for i := range an.BreakFixes {
		if an.BreakFixes[i].NodeID == "k8s/clusterrolebinding/api-admin" && an.BreakFixes[i].Weakness == "CLUSTER_ADMIN" {
			fix = &an.BreakFixes[i]
		}
	}
	if fix == nil {
		t.Fatalf("binding CLUSTER_ADMIN is not a break fix; break=%+v reduce=%+v", an.BreakFixes, an.ReduceFixes)
	}
	for _, p := range an.Paths {
		if p.Steps[len(p.Steps)-1].Resource != "k8s/clusterrole/cluster-admin" {
			continue
		}
		found := false
		for _, id := range fix.Breaks {
			found = found || id == p.ID
		}
		if !found {
			t.Errorf("binding fix does not break path %s", p.Name)
		}
	}
}

// Defect 18(b): a path that is a strict prefix of a longer path from the same entry is not
// a separate path, and totals are computed over complete paths only.
func TestPrefixPathsAreNotCounted(t *testing.T) {
	an := Traverse(demoGraph(), DefaultTraversalOptions())
	keys := map[string]bool{}
	for _, p := range an.Paths {
		keys[seqKey(entryOf(p), p.Steps)] = true
	}
	total := 0.0
	for _, p := range an.Paths {
		total += p.Score
		for k := 1; k < len(p.Steps); k++ {
			if pk := seqKey(entryOf(p), p.Steps[:k]); keys[pk] {
				t.Errorf("prefix path counted: %s (prefix of %s)", pk, p.Name)
			}
		}
	}
	if d := total - an.TotalScore; d > 0.001 || d < -0.001 {
		t.Errorf("TotalScore %.2f != sum of complete paths %.2f", an.TotalScore, total)
	}
}

// Defect 18(c): `requires` is an AND precondition on the stage's resource — it is satisfied
// by any failing finding on the same resource, not only by the matched finding itself.
func TestRuleRequiresIsResourceLevelAND(t *testing.T) {
	rules, err := LoadRules(nil)
	if err != nil {
		t.Fatal(err)
	}
	open := f("o1", "RDS_SG_OPEN", "arn:aws:rds:us-east-1:1:db:pay", "PUBLIC_NETWORK_EXPOSURE")
	enc := f("o2", "RDS_UNENCRYPTED", "arn:aws:rds:us-east-1:1:db:pay", "UNENCRYPTED_AT_REST", "DATABASE")
	vm := f("o3", "EC2_SG_OPEN_SSH", "i-9", "PUBLIC_NETWORK_EXPOSURE")
	vmEnc := f("o4", "EBS_UNENCRYPTED", "i-9", "UNENCRYPTED_AT_REST")
	paths := Evaluate([]model.Finding{open, enc, vm, vmEnc}, rules)
	var hits []model.AttackPath
	for _, p := range paths {
		if p.RuleID == "PUBLIC_DATABASE_BREACH" {
			hits = append(hits, p)
		}
	}
	if len(hits) != 1 || hits[0].Steps[0].Resource != "arn:aws:rds:us-east-1:1:db:pay" {
		t.Fatalf("PUBLIC_DATABASE_BREACH should fire once, on the database only (both preconditions hold there): %+v", hits)
	}
}

// Defect 18(b) follow-up: dropping a prefix must not lower the reported risk. A complete path
// that passes through a crown jewel scores at least what the path to that jewel scored.
func TestCompletePathKeepsBestJewelScore(t *testing.T) {
	g := graph.New()
	g.AddNode(&graph.Node{ID: "ci/pod/runner", Type: "k8s_pod", Name: "runner", Weaknesses: []string{"PUBLIC_NETWORK_EXPOSURE", "UNPATCHED", "SERVICE_ACCOUNT_TOKEN"}})
	g.AddNode(&graph.Node{ID: "ci/serviceaccount/deployer", Type: "k8s_service_account", Name: "deployer"})
	g.AddNode(&graph.Node{ID: "cluster/clusterrolebinding/deployer-admin", Type: "k8s_cluster_role_binding", Name: "deployer-admin", Weaknesses: []string{"CLUSTER_ADMIN"}})
	g.AddNode(&graph.Node{ID: "cluster/clusterrole/cluster-admin", Type: "k8s_cluster_role", Name: "cluster-admin"})
	g.AddEdge(graph.InternetNodeID, "ci/pod/runner", graph.EdgeExposes, nil)
	g.AddEdge("ci/pod/runner", "ci/serviceaccount/deployer", graph.EdgeAttachedTo, map[string]any{"hint": true})
	g.AddEdge("ci/serviceaccount/deployer", "cluster/clusterrolebinding/deployer-admin", graph.EdgeAttachedTo, map[string]any{"hint": true})
	g.AddEdge("cluster/clusterrolebinding/deployer-admin", "cluster/clusterrole/cluster-admin", graph.EdgeAttachedTo, map[string]any{"hint": true})
	an := Traverse(g, DefaultTraversalOptions())
	if len(an.Paths) != 1 || len(an.Incomplete) == 0 {
		t.Fatalf("want 1 complete path and its prefixes as incomplete: paths=%+v incomplete=%d", an.Paths, len(an.Incomplete))
	}
	best := 0.0
	for _, p := range an.Incomplete {
		if p.Score > best {
			best = p.Score
		}
	}
	if an.Paths[0].Score < best {
		t.Errorf("complete path scores %.2f, below its prefix's %.2f", an.Paths[0].Score, best)
	}
	// The fix view agrees with the traversal on the max-over-jewels score.
	if v := newFixView(g, nil); !v.survives(an.Paths[0], an.opts) {
		t.Error("unfixed path does not survive re-evaluation")
	}
}

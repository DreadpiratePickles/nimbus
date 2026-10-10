package attackpath

import (
	"strings"
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/graph"
)

// Graph queries (delta r3 #8, matrix IG6): `paths --from --to --through --max-hops` on the
// stored graph, with the engine's per-hop because.

func TestQueryInternetToBucketThroughRole(t *testing.T) {
	g, _ := labGraph(t, false)
	res, err := Query(g, labOptions(), PathQuery{From: "internet", To: "type:aws_s3_bucket", Through: "type:aws_iam_role", MaxHops: 6})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Paths) == 0 {
		t.Fatal("no internet → role → bucket path on the lab")
	}
	for _, p := range res.Paths {
		last := p.Steps[len(p.Steps)-1]
		n, _ := g.Node(last.Resource)
		if n == nil || n.Type != "aws_s3_bucket" {
			t.Fatalf("%s ends at %v, not a bucket", p.Name, last.Resource)
		}
		role := false
		for _, s := range p.Steps {
			if s.Because == "" {
				t.Fatalf("%s: hop %d has no because", p.Name, s.Stage)
			}
			if m, _ := g.Node(s.Resource); m != nil && m.Type == "aws_iam_role" {
				role = true
			}
		}
		if !role {
			t.Fatalf("%s does not pass through a role", p.Name)
		}
		if len(p.Steps) > 6 {
			t.Fatalf("%s: %d hops > max 6", p.Name, len(p.Steps))
		}
		if p.RuleID != "GRAPH_QUERY" {
			t.Fatalf("rule id %q", p.RuleID)
		}
	}
	// The lab's #1 path: Internet → export lambda → its role → customer-pii.
	found := false
	for _, p := range res.Paths {
		if strings.Contains(p.Name, "customer-pii") {
			found = true
		}
	}
	if !found {
		t.Fatal("customer-pii not reached through a role from the internet")
	}
}

// The because text of a query hop is the engine's: a query path with the same hops as an
// engine path carries the same per-hop because.
func TestQueryBecauseMatchesEngine(t *testing.T) {
	g, _ := labGraph(t, false)
	an := Traverse(g, labOptions())
	eng := map[string][]string{}
	for _, p := range an.Paths {
		var b []string
		for _, s := range p.Steps {
			b = append(b, s.Because)
		}
		eng[p.ID] = b
	}
	res, err := Query(g, labOptions(), PathQuery{From: "internet", To: "type:aws_s3_bucket", MaxHops: DefaultQueryMaxHops})
	if err != nil {
		t.Fatal(err)
	}
	same := 0
	for _, p := range res.Paths {
		want, ok := eng[p.ID]
		if !ok {
			continue
		}
		same++
		for i, s := range p.Steps {
			// The engine may tag the last hop with a toxic-combination suffix; the hop's own
			// because must be the same prefix.
			if !strings.HasPrefix(want[i], s.Because) && !strings.HasPrefix(s.Because, want[i]) {
				t.Fatalf("%s hop %d:\nquery  %q\nengine %q", p.Name, i+1, s.Because, want[i])
			}
		}
	}
	if same == 0 {
		t.Fatal("no query path coincides with an engine path")
	}
}

func TestQueryMaxHopsAndThroughNode(t *testing.T) {
	g, _ := labGraph(t, false)
	res, err := Query(g, labOptions(), PathQuery{From: "internet", To: "type:aws_s3_bucket", Through: "type:aws_iam_role", MaxHops: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Paths) != 0 {
		t.Fatalf("max-hops 1 cannot pass through a role, got %d", len(res.Paths))
	}
	// Through a concrete node (by name) narrows to paths that visit it.
	all, _ := Query(g, labOptions(), PathQuery{From: "internet", To: "type:aws_s3_bucket", Through: "type:aws_iam_role", MaxHops: DefaultQueryMaxHops})
	var role string
	for _, s := range all.Paths[0].Steps {
		if n, _ := g.Node(s.Resource); n != nil && n.Type == "aws_iam_role" {
			role = n.Name
		}
	}
	one, err := Query(g, labOptions(), PathQuery{From: "internet", To: "type:aws_s3_bucket", Through: role, MaxHops: DefaultQueryMaxHops})
	if err != nil {
		t.Fatal(err)
	}
	if len(one.Paths) == 0 || len(one.Paths) > len(all.Paths) {
		t.Fatalf("through %s: %d paths (all roles %d)", role, len(one.Paths), len(all.Paths))
	}
	for _, p := range one.Paths {
		ok := false
		for _, s := range p.Steps {
			if n, _ := g.Node(s.Resource); n != nil && n.Name == role {
				ok = true
			}
		}
		if !ok {
			t.Fatalf("%s does not visit %s", p.Name, role)
		}
	}
}

func TestQueryFromIdentityStartsWithFoothold(t *testing.T) {
	g, _ := labGraph(t, false)
	res, err := Query(g, labOptions(), PathQuery{From: "type:aws_iam_user", To: "type:aws_iam_role", MaxHops: DefaultQueryMaxHops})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Paths) == 0 {
		t.Fatal("no user → role path on the lab (P13 PassRole developer)")
	}
	for _, p := range res.Paths {
		if p.Steps[0].Relation != "entry" || p.Steps[0].Because == "" {
			t.Fatalf("%s: first step %+v is not a foothold", p.Name, p.Steps[0])
		}
	}
}

func TestQuerySelectorErrors(t *testing.T) {
	g := graph.New()
	if _, err := Query(g, DefaultTraversalOptions(), PathQuery{From: "", To: "type:aws_s3_bucket", MaxHops: DefaultQueryMaxHops}); err == nil {
		t.Fatal("empty --from accepted")
	}
	if _, err := Query(g, DefaultTraversalOptions(), PathQuery{From: "internet", To: "no-such-node", MaxHops: DefaultQueryMaxHops}); err == nil || !strings.Contains(err.Error(), "no-such-node") {
		t.Fatalf("unknown --to: %v", err)
	}
	if _, err := Query(g, DefaultTraversalOptions(), PathQuery{From: "internet", To: "type:x", MaxHops: 99}); err == nil {
		t.Fatal("max-hops 99 accepted")
	}
}

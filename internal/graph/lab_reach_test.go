package graph

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// Competitive delta r3 #14: the seeded lab must carry the network facts (subnet, route table,
// NACL, internet gateway) the live AWS collector emits, so every AWS instance and RDS instance
// gets a definite reachability verdict (reachable | blocked), never "unknown".

func labEstateGraph(t *testing.T) *Graph {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "lab", "local", "out", "estate.findings.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fs []model.Finding
	if err := json.Unmarshal(b, &fs); err != nil {
		t.Fatal(err)
	}
	g := New()
	g.AttachFindings(fs)
	return g
}

// labReachKind buckets the node types the reachability model covers on AWS.
func labReachKind(n *Node) string {
	t := strings.ToLower(n.Type)
	switch {
	case t == "aws_instance":
		return "aws_instance"
	case strings.Contains(t, "db_instance") || t == "aws_rds_cluster":
		return "aws_rds"
	case t == "aws_lb" || t == "aws_alb" || t == "aws_elb":
		return "aws_lb"
	}
	return ""
}

func TestLabReachabilityCounts(t *testing.T) {
	g := labEstateGraph(t)
	per := map[string]map[string]int{}
	overall := map[string]int{}
	nodes := g.Nodes()
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].ID < nodes[j].ID })
	for _, n := range nodes {
		if n.ID == InternetNodeID {
			continue
		}
		v := g.Verdict(n.ID)
		st := v.Status
		if st == "" {
			st = "(none)"
		}
		overall[st]++
		k := labReachKind(n)
		if k == "" {
			continue
		}
		if per[k] == nil {
			per[k] = map[string]int{}
		}
		per[k][st]++
		t.Logf("%-12s %-10s %s  %s", k, st, n.Name, v.Label)
		if v.Status != VerdictReachable && v.Status != VerdictBlocked {
			t.Errorf("%s (%s): reachability %q, want reachable or blocked (lab must carry subnet/route/NACL facts): %s", n.Name, k, v.Status, v.Reason)
		}
	}
	t.Logf("overall: %s", fmtCounts(overall))
	for _, k := range []string{"aws_instance", "aws_rds", "aws_lb"} {
		t.Logf("%s: %s", k, fmtCounts(per[k]))
	}
}

func fmtCounts(m map[string]int) string {
	var ks []string
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	var out []string
	for _, k := range ks {
		out = append(out, fmt.Sprintf("%s=%d", k, m[k]))
	}
	return strings.Join(out, " ")
}

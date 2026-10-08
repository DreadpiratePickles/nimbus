package attackpath

import (
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/graph"
)

func demoGraph() *graph.Graph {
	g := graph.New()
	g.AddNode(&graph.Node{ID: "sg-1", Type: "aws_security_group", Name: "web-sg", Provider: "aws", Account: "1", Weaknesses: []string{"PUBLIC_NETWORK_EXPOSURE"}, FindingIDs: []string{"f-sg"}})
	g.AddNode(&graph.Node{ID: "i-1", Type: "aws_instance", Name: "web-1", Provider: "aws", Account: "1", Criticality: "production", Weaknesses: []string{"PUBLIC_NETWORK_EXPOSURE", "IMDSV1_ENABLED"}, FindingIDs: []string{"f-pub", "f-imds"}})
	g.AddNode(&graph.Node{ID: "role", Type: "aws_iam_role", Name: "web-admin-role", Provider: "aws", Account: "1"})
	g.AddNode(&graph.Node{ID: "pol", Type: "aws_iam_policy", Name: "AdministratorAccess", Provider: "aws", Account: "1", Weaknesses: []string{"OVERPRIVILEGED_IDENTITY"}, FindingIDs: []string{"f-admin"}})
	g.AddNode(&graph.Node{ID: "db", Type: "aws_db_instance", Name: "payments-prod", Provider: "aws", Account: "1", Sensitive: true, Criticality: "production", Weaknesses: []string{"UNENCRYPTED_AT_REST"}, FindingIDs: []string{"f-enc"}})
	g.AddNode(&graph.Node{ID: "bucket", Type: "aws_s3_bucket", Name: "customer-pii-exports", Provider: "aws", Account: "1", Sensitive: true, Weaknesses: []string{"PUBLIC_DATA_STORE", "NO_LOGGING"}, FindingIDs: []string{"f-bpub", "f-blog"}})
	g.AddNode(&graph.Node{ID: "user", Type: "aws_iam_user", Name: "ci-deployer", Provider: "aws", Account: "1", Weaknesses: []string{"NO_MFA"}, FindingIDs: []string{"f-mfa"}})
	g.AddEdge(graph.InternetNodeID, "sg-1", graph.EdgeExposes, nil)
	g.AddEdge("sg-1", "i-1", graph.EdgeAllowsTrafficTo, map[string]any{"ports": "22"})
	g.AddEdge(graph.InternetNodeID, "i-1", graph.EdgeExposes, nil)
	g.AddEdge("i-1", "role", graph.EdgeRunsAs, nil)
	g.AddEdge("role", "pol", graph.EdgeHasPolicy, nil)
	g.AddEdge("pol", "db", graph.EdgeGrantsAccessTo, nil)
	g.AddEdge(graph.InternetNodeID, "bucket", graph.EdgeExposes, nil)
	g.AddEdge("user", "pol", graph.EdgeHasPolicy, nil)
	return g
}

func TestTraverseFindsMultiHopPaths(t *testing.T) {
	an := Traverse(demoGraph(), DefaultTraversalOptions())
	if len(an.Paths) == 0 {
		t.Fatal("no paths")
	}
	var toDB, toBucket, viaUser bool
	bestDB := 0.0
	for _, p := range an.Paths {
		last := p.Steps[len(p.Steps)-1]
		if last.Resource == "db" && len(p.Steps) >= 4 && p.Score >= 2 {
			toDB = true
			if p.Score > bestDB {
				bestDB = p.Score
			}
			if len(p.Mitre) == 0 || len(p.FindingIDs) < 3 {
				t.Errorf("path metadata: %+v", p)
			}
		}
		if last.Resource == "bucket" && len(p.Steps) == 1 && p.Score >= 4 {
			toBucket = true
		}
		if p.Steps[0].Resource == "user" && last.Resource == "db" {
			viaUser = true
		}
	}
	if bestDB < 4 {
		t.Errorf("best internet→db path should be HIGH or above, got %.2f", bestDB)
	}
	if !toDB || !toBucket || !viaUser {
		t.Errorf("paths missing: db=%v bucket=%v viaUser=%v\n%+v", toDB, toBucket, viaUser, an.Paths)
	}
	if an.Paths[0].Score < an.Paths[len(an.Paths)-1].Score {
		t.Errorf("not sorted")
	}
	if len(an.ChokePoints) == 0 || an.ChokePoints[0].NodeID != "i-1" {
		t.Errorf("choke point should be the exposed instance every internet path crosses: %+v", an.ChokePoints)
	}
	// The admin policy sits on every path to the database (internet and phished-user entries), so it is the top fix.
	if len(an.BreakFixes) == 0 || an.BreakFixes[0].Weakness != "OVERPRIVILEGED_IDENTITY" || len(an.BreakFixes[0].Breaks) < 6 || an.BreakFixes[0].Command == "" {
		t.Errorf("top break fix: %+v (paths %d)", an.BreakFixes[0], len(an.Paths))
	}
	hasExposureFix := false
	for _, f := range an.BreakFixes {
		if f.NodeID == "i-1" && f.Weakness == "PUBLIC_NETWORK_EXPOSURE" && len(f.Breaks) >= 4 {
			hasExposureFix = true
		}
	}
	if !hasExposureFix {
		t.Errorf("instance exposure fix missing: %+v", an.BreakFixes)
	}
	// Admin policy + public bucket + exposed instance (role is itself a crown jewel) cut everything.
	if len(an.MinFixSet) > 3 {
		t.Errorf("min fix set too large: %+v", an.MinFixSet)
	}
	foundReduce := false
	for _, f := range an.ReduceFixes {
		if f.Weakness == "NO_LOGGING" || f.Weakness == "UNENCRYPTED_AT_REST" {
			foundReduce = true
		}
	}
	if !foundReduce {
		t.Errorf("reduce-only fixes missing: %+v", an.ReduceFixes)
	}
	if len(an.MinFixSet) == 0 || an.MinFixCoverage < 99 {
		t.Errorf("min fix set should cut all paths: %+v cov=%.1f", an.MinFixSet, an.MinFixCoverage)
	}
	reach, sens := BlastRadius(demoGraph(), "role", 4, nil)
	if len(reach) < 2 || len(sens) == 0 {
		t.Errorf("blast radius: %v %v", reach, sens)
	}
	g := demoGraph()
	n, _ := g.Node("db")
	if Criticality(n, nil) != 4 {
		t.Errorf("prod sensitive db should be tier 4")
	}
	if Criticality(n, []JewelRule{{Pattern: "payments*", Criticality: 2}}) != 2 {
		t.Errorf("user rules should override")
	}
}

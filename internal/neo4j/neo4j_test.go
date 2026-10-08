package neo4j

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/graph"
)

func TestLabelFor(t *testing.T) {
	cases := []struct {
		typ, class, want string
	}{
		{"aws_account", "", "AWSAccount"},
		{"azure_subscription", "", "AzureSubscription"},
		{"gcp_project", "", "GCPProject"},
		{"aws_instance", "", "EC2Instance"},
		{"aws_s3_bucket", "", "S3Bucket"},
		{"aws_iam_role", "", "IAMRole"},
		{"aws_iam_user", "", "IAMUser"},
		{"aws_iam_policy", "", "IAMPolicy"},
		{"aws_security_group", "", "SecurityGroup"},
		{"aws_db_instance", "", "RDSInstance"},
		{"aws_lambda_function", "", "LambdaFunction"},
		{"aws_eks_cluster", "", "EKSCluster"},
		{"aws_ebs_volume", "", "EBSVolume"},
		{"azure_virtual_machine", "", "AzureVM"},
		{"azure_storage_account", "", "AzureStorageAccount"},
		{"azure_network_security_group", "", "AzureNSG"},
		{"azure_sql_server", "", "AzureSQLServer"},
		{"azure_key_vault", "", "KeyVault"},
		{"gcp_compute_instance", "", "GCEInstance"},
		{"gcp_storage_bucket", "", "GCSBucket"},
		{"gcp_compute_firewall", "", "GCPFirewall"},
		{"gcp_sql_database_instance", "", "CloudSQLInstance"},
		{"k8s_pod", "", "KubernetesPod"},
		{"k8s_namespace", "", "KubernetesNamespace"},
		{"k8s_service_account", "", "KubernetesServiceAccount"},
		{"k8s_cluster_role_binding", "", "ClusterRoleBinding"},
		{"github_repository", "", "GitHubRepository"},
		{"github_organization", "", "GitHubOrganization"},
		{"okta_user", "", "OktaUser"},
		{"internet", "", "Internet"},
		{"AWS_S3_BUCKET", "", "S3Bucket"},
		{"aws_secretsmanager_secret", graph.ClassDataStore, "Datastore"},
		{"m365_user", graph.ClassIdentity, "Identity"},
		{"container_image", graph.ClassImage, "Image"},
		{"weird_thing", "", "Compute"},
	}
	for _, c := range cases {
		t.Run(c.typ, func(t *testing.T) {
			got := LabelFor(&graph.Node{ID: "x", Type: c.typ, Class: c.class})
			if got != c.want {
				t.Fatalf("LabelFor(%q) = %q, want %q", c.typ, got, c.want)
			}
		})
	}
	if got := LabelFor(&graph.Node{ID: graph.InternetNodeID}); got != "Internet" {
		t.Fatalf("internet id: %q", got)
	}
	if got := Labels(&graph.Node{ID: "b", Type: "aws_s3_bucket"}); len(got) != 2 || got[0] != "S3Bucket" || got[1] != "Resource" {
		t.Fatalf("Labels = %v", got)
	}
}

func testGraph() *graph.Graph {
	g := graph.New()
	g.AddNode(&graph.Node{ID: "aws:account:1", Type: "aws_account", Class: graph.ClassAccount, Account: "1", Provider: "aws"})
	g.AddNode(&graph.Node{ID: "i-1", Type: "aws_instance", Account: "1", Provider: "aws",
		Attributes: map[string]any{"public_ip": "1.2.3.4", "tags": map[string]any{"env": "prod"}, "security_groups": []string{"sg-1"},
			"mixed": []any{"a", 1}, "strs": []any{"a", "b"}, "count": 3, "bad key": true}})
	g.AddNode(&graph.Node{ID: "sg-1", Type: "aws_security_group", Account: "1"})
	g.AddNode(&graph.Node{ID: "arn:aws:iam::1:role/r", Type: "aws_iam_role", Account: "1"})
	g.AddNode(&graph.Node{ID: "arn:aws:s3:::b", Type: "aws_s3_bucket", Account: "1", Sensitive: true})
	g.AddNode(&graph.Node{ID: "nsg", Type: "azure_network_security_group"})
	g.AddNode(&graph.Node{ID: "fw", Type: "gcp_compute_firewall"})
	g.AddEdge("aws:account:1", "i-1", graph.EdgeContains, nil)
	g.AddEdge("i-1", "sg-1", graph.EdgeAttachedTo, nil)
	g.AddEdge("i-1", "arn:aws:iam::1:role/r", graph.EdgeRunsAs, nil)
	g.AddEdge(graph.InternetNodeID, "i-1", graph.EdgeExposes, map[string]any{"ports": "22", "nested": map[string]any{"a": 1}})
	return g
}

func TestRelFor(t *testing.T) {
	g := testGraph()
	cases := []struct {
		from, to, kind, want string
	}{
		{"i-1", "sg-1", graph.EdgeAttachedTo, "MEMBER_OF_SECURITY_GROUP"},
		{"vm", "nsg", graph.EdgeAttachedTo, "MEMBER_OF_SECURITY_GROUP"},
		{"gce", "fw", graph.EdgeAttachedTo, "MEMBER_OF_SECURITY_GROUP"},
		{"i-1", "arn:aws:iam::1:role/r", graph.EdgeAttachedTo, "ATTACHED_TO"},
		{"a", "b", graph.EdgeContains, "RESOURCE"},
		{"a", "b", graph.EdgeCanAssume, "STS_ASSUME_ROLE_ALLOWS"},
		{"a", "b", graph.EdgeHasPolicy, "POLICY"},
		{"a", "b", graph.EdgeGrantsAccessTo, "GRANTS_ACCESS_TO"},
		{"a", "b", graph.EdgeAllowsTrafficTo, "ALLOWS_TRAFFIC_TO"},
		{"a", "b", graph.EdgeExposes, "EXPOSED_TO_INTERNET"},
		{"a", "b", graph.EdgeRunsAs, "RUNS_AS"},
		{"a", "b", graph.EdgeBoundTo, "BOUND_TO"},
		{"a", "b", graph.EdgeMemberOf, "MEMBER_OF"},
		{"a", "b", graph.EdgeTrusts, "TRUSTS"},
		{"a", "b", graph.EdgeRunsOn, "RUNS_ON"},
		{"a", "b", graph.EdgeStoresDataIn, "STORES_DATA_IN"},
		{"a", "b", "reads-from", "READS_FROM"},
		{"a", "b", "---", "RELATED_TO"},
		{"a", "b", "2hop", "R_2HOP"},
	}
	for _, c := range cases {
		t.Run(c.kind+"_"+c.to, func(t *testing.T) {
			if got := RelFor(&graph.Edge{From: c.from, To: c.to, Kind: c.kind}, g); got != c.want {
				t.Fatalf("RelFor(%s) = %q, want %q", c.kind, got, c.want)
			}
		})
	}
}

func TestStatements(t *testing.T) {
	g := testGraph()
	stmts := Statements(g, 2)
	if !strings.HasPrefix(stmts[0].Cypher, "CREATE CONSTRAINT") || !strings.Contains(stmts[0].Cypher, "(n:Resource) REQUIRE n.id IS UNIQUE") {
		t.Fatalf("first statement must be the Resource constraint: %s", stmts[0].Cypher)
	}
	nodeRows, relRows := 0, 0
	seenNodeMerge := false
	for _, s := range stmts {
		rows, _ := s.Params["rows"].([]map[string]any)
		if len(rows) > 2 {
			t.Fatalf("batch too large: %d", len(rows))
		}
		switch {
		case strings.HasPrefix(s.Cypher, "CREATE"):
			if seenNodeMerge {
				t.Fatal("schema statements must come before data")
			}
		case strings.Contains(s.Cypher, "MERGE (n:Resource"):
			seenNodeMerge = true
			nodeRows += len(rows)
			l := s.Params["label"].(string)
			if l != "Resource" && !strings.Contains(s.Cypher, "SET n:"+l+",") {
				t.Fatalf("label not set: %s", s.Cypher)
			}
			if !strings.Contains(s.Cypher, "$update_tag") {
				t.Fatal("missing update tag")
			}
		case strings.Contains(s.Cypher, "MERGE (a)-[r:"):
			relRows += len(rows)
			for _, r := range rows {
				if r["from"] == "" || r["to"] == "" {
					t.Fatalf("bad rel row %v", r)
				}
			}
		}
	}
	if nodeRows != g.Len() {
		t.Fatalf("node rows %d, want %d", nodeRows, g.Len())
	}
	if relRows != len(g.Edges()) {
		t.Fatalf("rel rows %d, want %d", relRows, len(g.Edges()))
	}
	// SecurityGroup MEMBER_OF_SECURITY_GROUP statement present.
	found := false
	for _, s := range stmts {
		if strings.Contains(s.Cypher, "[r:MEMBER_OF_SECURITY_GROUP]") {
			found = true
		}
	}
	if !found {
		t.Fatal("expected MEMBER_OF_SECURITY_GROUP statement")
	}
}

func TestNodePropsFlatten(t *testing.T) {
	g := testGraph()
	n, _ := g.Node("i-1")
	p := NodeProps(n)
	cases := []struct {
		key  string
		want any
	}{
		{"public_ip", "1.2.3.4"},
		{"tags", `{"env":"prod"}`},
		{"mixed", `["a",1]`},
		{"count", int64(3)},
		{"bad_key", true},
		{"id", "i-1"},
		{"type", "aws_instance"},
		{"sensitive", false},
		{"cve_count", int64(0)},
	}
	for _, c := range cases {
		if got := p[c.key]; got != c.want {
			t.Errorf("prop %s = %#v, want %#v", c.key, got, c.want)
		}
	}
	if sg, ok := p["security_groups"].([]string); !ok || sg[0] != "sg-1" {
		t.Errorf("security_groups = %#v", p["security_groups"])
	}
	if s, ok := p["strs"].([]string); !ok || len(s) != 2 {
		t.Errorf("strs = %#v", p["strs"])
	}
	if w, ok := p["weaknesses"].([]string); !ok || w == nil {
		t.Errorf("weaknesses must be a non-nil list: %#v", p["weaknesses"])
	}
	e := edgeProps(&graph.Edge{Kind: "exposes", Attr: map[string]any{"nested": map[string]any{"a": 1}, "ports": "22"}})
	if e["nested"] != `{"a":1}` || e["ports"] != "22" || e["kind"] != "exposes" {
		t.Errorf("edge props %#v", e)
	}
}

type fakeRunner struct {
	calls  []string
	params []map[string]any
	failAt int
}

func (f *fakeRunner) Run(_ context.Context, cypher string, params map[string]any) error {
	f.calls = append(f.calls, cypher)
	f.params = append(f.params, params)
	if f.failAt > 0 && len(f.calls) == f.failAt {
		return errors.New("boom")
	}
	return nil
}

func TestPushWith(t *testing.T) {
	g := testGraph()
	cases := []struct {
		name    string
		cfg     Config
		failAt  int
		wantErr bool
	}{
		{"ok", Config{BatchSize: 2}, 0, false},
		{"cleanup", Config{BatchSize: 100, Cleanup: true}, 0, false},
		{"error", Config{}, 3, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := &fakeRunner{failAt: c.failAt}
			st, err := pushWith(context.Background(), r, g, c.cfg, 42)
			if c.wantErr {
				if err == nil || !strings.Contains(err.Error(), "boom") {
					t.Fatalf("want boom error, got %v", err)
				}
				if len(r.calls) != c.failAt {
					t.Fatalf("push should stop at first failure, calls=%d", len(r.calls))
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if st.Nodes != g.Len() || st.Relationships != len(g.Edges()) {
				t.Fatalf("stats %+v", st)
			}
			if st.Labels["EC2Instance"] != 1 || st.RelTypes["EXPOSED_TO_INTERNET"] != 1 || st.RelTypes["MEMBER_OF_SECURITY_GROUP"] != 1 {
				t.Fatalf("stats breakdown %+v", st)
			}
			for i, p := range r.params {
				if p["update_tag"] != int64(42) {
					t.Fatalf("call %d missing update_tag", i)
				}
				if _, bad := p["label"]; bad {
					t.Fatal("internal label param leaked")
				}
				if rows, ok := p["rows"]; ok {
					if _, isAny := rows.([]any); !isAny {
						t.Fatalf("rows must be []any for the driver, got %T", rows)
					}
				}
			}
			last := r.calls[len(r.calls)-1]
			if c.cfg.Cleanup != strings.Contains(last, "DETACH DELETE") {
				t.Fatalf("cleanup=%v but last statement %q", c.cfg.Cleanup, last)
			}
		})
	}
	if _, err := PushWith(context.Background(), &fakeRunner{}, nil, Config{}); err == nil {
		t.Fatal("nil graph should error")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := PushWith(ctx, &fakeRunner{}, g, Config{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("want context canceled, got %v", err)
	}
	if _, err := Push(context.Background(), Config{}, g); err == nil {
		t.Fatal("Push without URI should error")
	}
}

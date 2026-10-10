package graph

import "testing"

// Defect 9: service accounts are identities, storage accounts are data stores; only the
// provider's top-level scope is an account.
func TestClassForServiceAccountsAreIdentities(t *testing.T) {
	cases := map[string]string{
		"k8s_service_account":      ClassIdentity,
		"gcp_service_account":      ClassIdentity,
		"ServiceAccount":           ClassIdentity,
		"azure_storage_account":    ClassDataStore,
		"aws_account":              ClassAccount,
		"gcp_project":              ClassAccount,
		"azure_subscription":       ClassAccount,
		"k8s_cluster_account":      ClassAccount,
		"m365_tenant":              ClassAccount,
		"k8s_cluster_role":         ClassIdentity,
		"k8s_cluster_role_binding": ClassIdentity,
		"aws_iam_role":             ClassIdentity,
		"aws_s3_bucket":            ClassDataStore,
		"aws_instance":             ClassCompute,
		"k8s_pod":                  ClassCompute,
	}
	for typ, want := range cases {
		if got := ClassFor(typ); got != want {
			t.Errorf("ClassFor(%q) = %q, want %q", typ, got, want)
		}
	}
}

// A node first seen as an edge placeholder (unknown type, guessed class) takes the real type
// and class when the resource itself arrives later.
func TestPlaceholderTakesRealClass(t *testing.T) {
	g := New()
	g.AddEdge("ci/serviceaccount/deployer", "cluster/clusterrolebinding/ci-deployer-admin", EdgeAttachedTo, nil)
	g.AddNode(&Node{ID: "cluster/clusterrolebinding/ci-deployer-admin", Type: "k8s_cluster_role_binding"})
	n, _ := g.Node("cluster/clusterrolebinding/ci-deployer-admin")
	if n.Type != "k8s_cluster_role_binding" || n.Class != ClassIdentity {
		t.Fatalf("placeholder kept type=%q class=%q", n.Type, n.Class)
	}
	// An explicitly classed node is not overridden by a later typed merge.
	g.AddNode(&Node{ID: "x", Type: "aws_instance", Class: ClassCompute})
	g.AddNode(&Node{ID: "x", Type: "aws_iam_role"})
	if n, _ := g.Node("x"); n.Class != ClassCompute {
		t.Fatalf("typed node reclassified: %q", n.Class)
	}
}

// A guessed placeholder type (GuessType on the edge ID) yields to the resource's real type.
func TestGuessedTypeYieldsToRealType(t *testing.T) {
	g := New()
	sa := "//iam.googleapis.com/projects/acme/serviceAccounts/123-compute@developer.gserviceaccount.com"
	g.AddEdge("vm", sa, EdgeAttachedTo, nil)
	g.AddNode(&Node{ID: sa, Type: "gcp_service_account"})
	n, _ := g.Node(sa)
	if n.Type != "gcp_service_account" || n.Class != ClassIdentity {
		t.Fatalf("placeholder kept type=%q class=%q", n.Type, n.Class)
	}
	if got := GuessType(sa); got != "gcp_service_account" {
		t.Errorf("GuessType(gcp SA) = %q", got)
	}
}

package adapters

// Tests for the P1-INTEROP inbound adapters: trivy-operator CRD reports, Kubescape v3 JSON,
// kube-bench --json and Cartography Neo4j exports.
//
// Every fixture under testdata/adapters/** is SYNTHETIC: it is hand-written in the shape of the
// upstream format (doc URLs are in each fixture's "_fixture_note" where JSON allows a field;
// for the JSON-array and JSON-lines fixtures they are listed here):
//   - trivy-operator/rbacassessmentreports.array.json: https://aquasecurity.github.io/trivy-operator/latest/docs/crds/rbacassessment-report/
//   - kube-bench/kube-bench.legacy-array.json: https://github.com/aquasecurity/kube-bench (pre-Totals bare []Controls form)
//   - cartography/apoc-export.json: https://neo4j.com/labs/apoc/5/export/json/ (apoc.export.json.all, JSON lines)
// Account ids (123456789012), IPs (192.0.2.0/24, 203.0.113.0/24) and AWS keys (AWS documentation
// example values) are placeholders.
//
// Regenerate goldens: go test ./internal/adapters -run Golden -update

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/graph"
	"github.com/DreadpiratePickles/nimbus/internal/model"
)

var update = flag.Bool("update", false, "rewrite testdata/golden/adapters/*.golden.json")

var goldenNow = time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)

func interopPath(rel string) string { return filepath.Join("..", "..", "testdata", "adapters", rel) }

// parseInterop parses a fixture with content/filename detection and checks the adapter chosen.
func parseInterop(t *testing.T, rel, wantAdapter string, opts Options) []model.Finding {
	t.Helper()
	if opts.Now.IsZero() {
		opts.Now = goldenNow
	}
	fs, name, err := ParseFile(interopPath(rel), "", opts)
	if err != nil {
		t.Fatalf("%s: %v", rel, err)
	}
	if name != wantAdapter {
		t.Fatalf("%s detected as %q, want %q", rel, name, wantAdapter)
	}
	return fs
}

type goldenFixture struct {
	Fixture  string          `json:"fixture"`
	Count    int             `json:"count"`
	Findings []model.Finding `json:"findings"`
}

func runGolden(t *testing.T, tool, adapter string, fixtures ...string) {
	t.Helper()
	var doc []goldenFixture
	for _, rel := range fixtures {
		fs := parseInterop(t, rel, adapter, Options{})
		if len(fs) == 0 {
			t.Fatalf("%s: no findings", rel)
		}
		for i := range fs {
			fs[i].Raw = nil
		}
		doc = append(doc, goldenFixture{Fixture: rel, Count: len(fs), Findings: fs})
	}
	got, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	path := filepath.Join("..", "..", "testdata", "golden", "adapters", tool+".golden.json")
	if *update {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden (run with -update to create): %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("%s differs from golden %s (run `go test ./internal/adapters -run Golden -update` and review the diff)", tool, path)
	}
}

func TestGoldenTrivyOperator(t *testing.T) {
	runGolden(t, "trivy-operator", "trivy-operator",
		"trivy-operator/vulnerabilityreports.list.json",
		"trivy-operator/configauditreport.json",
		"trivy-operator/rbacassessmentreports.array.json")
}

func TestGoldenKubescape(t *testing.T) {
	runGolden(t, "kubescape", "kubescape", "kubescape/kubescape-v3.json")
}

func TestGoldenKubeBench(t *testing.T) {
	runGolden(t, "kube-bench", "kube-bench", "kube-bench/kube-bench.json", "kube-bench/kube-bench.legacy-array.json")
}

func TestGoldenCartography(t *testing.T) {
	runGolden(t, "cartography", "cartography", "cartography/apoc-export.json", "cartography/graph.json")
}

func findCheck(fs []model.Finding, checkID, resourceID string) *model.Finding {
	for i := range fs {
		if fs[i].CheckID == checkID && (resourceID == "" || fs[i].Resource.ID == resourceID) {
			return &fs[i]
		}
	}
	return nil
}

func hasRelation(r model.Resource, id, kind string) bool {
	for _, rel := range r.Relations {
		if rel.ID == id && rel.Kind == kind {
			return true
		}
	}
	return false
}

func TestTrivyOperatorVulnerabilityReport(t *testing.T) {
	fs := parseInterop(t, "trivy-operator/vulnerabilityreports.list.json", "trivy-operator", Options{})
	if len(fs) != 5 {
		t.Fatalf("want 3 vulns + 2 secrets, got %d", len(fs))
	}
	f := findCheck(fs, "CVE-2022-37434", "")
	if f == nil {
		t.Fatal("CVE-2022-37434 missing")
	}
	if f.CanonicalID != "CVE_VULNERABILITY" || f.Severity != model.Critical || f.Status != model.Fail || f.Provider != model.ProviderKubernetes {
		t.Errorf("core fields: %+v", f)
	}
	if f.Account != "" {
		t.Errorf("account should be empty without Options.Account, got %q", f.Account)
	}
	if f.Resource.ID != "shop/replicaset/storefront-6d4cf56db6" || f.Resource.Type != "k8s_replica_set" || f.Resource.Name != "storefront-6d4cf56db6" {
		t.Errorf("workload resource: %+v", f.Resource)
	}
	a := f.Resource.Attributes
	if a["cvss"] != 9.8 || a["primary_url"] != "https://avd.aquasec.com/nvd/cve-2022-37434" || a["container"] != "web" ||
		a["image_repository"] != "library/nginx" || a["image_tag"] != "1.21.0" || a["package"] != "zlib1g" {
		t.Errorf("attributes: %v", a)
	}
	if f.Tags["cvss"] != "9.8" || f.Tags["primary_url"] != "https://avd.aquasec.com/nvd/cve-2022-37434" {
		t.Errorf("tags: %v", f.Tags)
	}
	if !hasRelation(f.Resource, "namespace/shop", "member_of") {
		t.Errorf("workload -> namespace relation missing: %+v", f.Resource.Relations)
	}
	// Same workload, two CVEs: distinct IDs.
	if g := findCheck(fs, "CVE-2022-1292", ""); g == nil || g.ID == f.ID {
		t.Errorf("distinct CVEs must have distinct ids")
	}
	// Account label is applied when given.
	fs2 := parseInterop(t, "trivy-operator/vulnerabilityreports.list.json", "trivy-operator", Options{Account: "prod-eks"})
	if fs2[0].Account != "prod-eks" {
		t.Errorf("Options.Account not applied: %q", fs2[0].Account)
	}
}

func TestTrivyOperatorSecretsRedacted(t *testing.T) {
	fs := parseInterop(t, "trivy-operator/vulnerabilityreports.list.json", "trivy-operator", Options{})
	all, err := json.Marshal(fs) // includes Raw
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"} {
		if bytes.Contains(all, []byte(secret)) {
			t.Errorf("secret %q leaked into findings (incl. raw)", secret)
		}
	}
	f := findCheck(fs, "aws-access-key-id", "")
	if f == nil {
		t.Fatal("secret finding missing")
	}
	if f.Status != model.Fail || f.Severity != model.Critical || f.CanonicalID != "SECRET_HARDCODED" || f.File != "/app/config/.env" {
		t.Errorf("secret finding: %+v", f)
	}
	if f.Resource.ID != "shop/replicaset/storefront-6d4cf56db6" {
		t.Errorf("secret resource should be the workload: %s", f.Resource.ID)
	}
}

func TestTrivyOperatorConfigAndRBAC(t *testing.T) {
	fs := parseInterop(t, "trivy-operator/configauditreport.json", "trivy-operator", Options{})
	if len(fs) != 4 {
		t.Fatalf("want 4 checks, got %d", len(fs))
	}
	esc := findCheck(fs, "KSV001", "")
	if esc == nil || esc.Status != model.Fail || esc.CanonicalID != "K8S_PRIVILEGE_ESCALATION" || esc.Resource.ID != "data/statefulset/orders-db" {
		t.Errorf("KSV001: %+v", esc)
	}
	if !strings.Contains(esc.Description, "allowPrivilegeEscalation") {
		t.Errorf("messages should be in the description: %q", esc.Description)
	}
	if priv := findCheck(fs, "KSV017", ""); priv == nil || priv.Status != model.Pass {
		t.Errorf("success=true must be PASS: %+v", priv)
	}

	rb := parseInterop(t, "trivy-operator/rbacassessmentreports.array.json", "trivy-operator", Options{})
	if len(rb) != 3 {
		t.Fatalf("want 3 rbac checks, got %d", len(rb))
	}
	role := findCheck(rb, "KSV041", "")
	if role == nil || role.Resource.ID != "ci/role/pod-manager" || role.Resource.Type != "k8s_role" || role.Status != model.Fail {
		t.Errorf("role check: %+v", role)
	}
	cr := findCheck(rb, "KSV046", "")
	if cr == nil || cr.Resource.ID != "cluster/clusterrole/ops-admin" || cr.Resource.Type != "k8s_cluster_role" || cr.CanonicalID != "K8S_CLUSTER_ADMIN_BINDING" {
		t.Errorf("cluster role check: %+v", cr)
	}
	if len(cr.Resource.Relations) != 0 {
		t.Errorf("cluster-scoped resource has no namespace relation: %+v", cr.Resource.Relations)
	}
}

func TestTrivyOperatorSingleObjectAndListShapes(t *testing.T) {
	data, err := os.ReadFile(interopPath("trivy-operator/configauditreport.json"))
	if err != nil {
		t.Fatal(err)
	}
	a := &TrivyOperator{}
	single, err := a.Parse(data, Options{})
	if err != nil {
		t.Fatal(err)
	}
	asArray, err := a.Parse(append(append([]byte("["), data...), ']'), Options{})
	if err != nil {
		t.Fatal(err)
	}
	asList, err := a.Parse([]byte(`{"apiVersion":"v1","kind":"List","items":[`+string(data)+`]}`), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(single) != 4 || len(asArray) != 4 || len(asList) != 4 {
		t.Errorf("shapes: single=%d array=%d list=%d", len(single), len(asArray), len(asList))
	}
}

func TestKubescapeV3(t *testing.T) {
	fs := parseInterop(t, "kubescape/kubescape-v3.json", "kubescape", Options{})
	if len(fs) != 6 {
		t.Fatalf("want 6 (resource, control) findings, got %d", len(fs))
	}
	priv := findCheck(fs, "C-0057", "shop/deployment/storefront")
	if priv == nil || priv.Status != model.Fail || priv.Severity != model.High || priv.Provider != model.ProviderKubernetes || priv.Resource.Type != "k8s_deployment" {
		t.Fatalf("C-0057: %+v", priv)
	}
	if priv.Account != "synthetic-kind" {
		t.Errorf("account from clusterName: %q", priv.Account)
	}
	if !hasRelation(priv.Resource, "namespace/shop", "member_of") {
		t.Errorf("namespace relation: %+v", priv.Resource.Relations)
	}
	if f := findCheck(fs, "C-0017", ""); f == nil || f.Severity != model.Low {
		t.Errorf("scoreFactor 3 -> LOW: %+v", f)
	}
	if f := findCheck(fs, "C-0016", ""); f == nil || f.Status != model.Pass || f.Severity != model.Medium {
		t.Errorf("passed / scoreFactor 6 -> PASS MEDIUM: %+v", f)
	}
	if f := findCheck(fs, "C-0270", ""); f == nil || f.Status != model.Skip {
		t.Errorf("skipped -> SKIP: %+v", f)
	}
	if f := findCheck(fs, "C-0035", "cluster/clusterrole/ops-admin"); f == nil || f.Severity != model.Critical {
		t.Errorf("cluster role / scoreFactor 9 -> CRITICAL: %+v", f)
	}
	if f := findCheck(fs, "C-0034", "shop/serviceaccount/default"); f == nil || f.Resource.Type != "k8s_service_account" {
		t.Errorf("service account resource: %+v", f)
	}
}

func TestKubescapeSeverityFromScoreFactor(t *testing.T) {
	for _, c := range []struct {
		score float64
		want  model.Severity
	}{{10, model.Critical}, {9, model.Critical}, {8.9, model.High}, {7, model.High}, {6.9, model.Medium}, {4, model.Medium}, {3.9, model.Low}, {1, model.Low}, {0, model.Low}} {
		if got := kubescapeSeverity(c.score); got != c.want {
			t.Errorf("scoreFactor %v: got %s want %s", c.score, got, c.want)
		}
	}
}

func TestKubeBench(t *testing.T) {
	fs := parseInterop(t, "kube-bench/kube-bench.json", "kube-bench", Options{})
	if len(fs) != 6 {
		t.Fatalf("want 6 results, got %d", len(fs))
	}
	f := findCheck(fs, "1.2.16", "")
	if f == nil || f.Status != model.Fail || f.Provider != model.ProviderKubernetes || f.Resource.ID != "cluster/nodetype/master" || f.Resource.Name != "master" {
		t.Fatalf("1.2.16: %+v", f)
	}
	if got := f.Compliance["cis_k8s"]; len(got) == 0 || got[0] != "1.2.16" {
		t.Errorf("cis_k8s compliance: %v", f.Compliance)
	}
	if f.Severity != model.Medium {
		t.Errorf("scored FAIL -> MEDIUM, got %s", f.Severity)
	}
	if w := findCheck(fs, "1.2.1", ""); w == nil || w.Status != model.Skip || w.Tags["kube_bench_status"] != "WARN" {
		t.Errorf("WARN -> SKIP with tag: %+v", w)
	}
	if p := findCheck(fs, "4.2.2", "cluster/nodetype/node"); p == nil || p.Status != model.Pass {
		t.Errorf("PASS on node: %+v", p)
	}
	if m := findCheck(fs, "5.1.1", "cluster/nodetype/policies"); m == nil || m.Status != model.Skip {
		t.Errorf("manual policies check: %+v", m)
	}

	legacy := parseInterop(t, "kube-bench/kube-bench.legacy-array.json", "kube-bench", Options{})
	if len(legacy) != 3 {
		t.Fatalf("legacy array: want 3, got %d", len(legacy))
	}
	if f := findCheck(legacy, "2.2", "cluster/nodetype/etcd"); f == nil || f.Status != model.Fail {
		t.Errorf("legacy etcd FAIL: %+v", f)
	}
	if f := findCheck(legacy, "2.7", ""); f == nil || f.Status != model.Skip || f.Tags["kube_bench_status"] != "INFO" {
		t.Errorf("INFO -> SKIP: %+v", f)
	}
}

func TestCartography(t *testing.T) {
	fs := parseInterop(t, "cartography/apoc-export.json", "cartography", Options{})
	// 16 nodes -> 16 inventory records, plus one EC2_PUBLIC_IP failure for the exposed instance.
	if len(fs) != 17 {
		t.Fatalf("want 17, got %d", len(fs))
	}
	obj := parseInterop(t, "cartography/graph.json", "cartography", Options{})
	a, _ := json.Marshal(fs)
	b, _ := json.Marshal(obj)
	if !bytes.Equal(a, b) {
		t.Errorf("JSON-lines and {nodes,relationships} forms must parse identically")
	}

	const (
		acct     = "aws:account:123456789012"
		instance = "arn:aws:ec2:us-east-1:123456789012:instance/i-0a1b2c3d4e5f60001"
		sg       = "arn:aws:ec2:us-east-1:123456789012:security-group/sg-0123456789abcdef0"
		role     = "arn:aws:iam::123456789012:role/web-app-role"
		user     = "arn:aws:iam::123456789012:user/alice"
		group    = "arn:aws:iam::123456789012:group/developers"
		policy   = "arn:aws:iam::123456789012:policy/web-app-s3-read"
		lambda   = "arn:aws:lambda:us-east-1:123456789012:function:thumbnailer"
		external = "arn:aws:iam::210987654321:root"
	)
	inv := func(label, id string) *model.Finding {
		t.Helper()
		f := findCheck(fs, "inventory:"+label, id)
		if f == nil {
			t.Fatalf("inventory:%s %s missing", label, id)
		}
		if f.Status != model.Pass || f.Severity != model.Info || f.Source != "cartography" {
			t.Errorf("inventory record fields: %+v", f)
		}
		return f
	}
	ac := inv("AWSAccount", acct)
	if ac.Resource.Type != "aws_account" || ac.Account != "123456789012" || ac.Provider != model.ProviderAWS {
		t.Errorf("account: %+v", ac)
	}
	if !hasRelation(ac.Resource, instance, "contains") || !hasRelation(ac.Resource, role, "contains") {
		t.Errorf("account contains: %+v", ac.Resource.Relations)
	}
	in := inv("EC2Instance", instance)
	if in.Resource.Type != "aws_instance" || in.Account != "123456789012" || in.Region != "us-east-1" || in.Resource.Attributes["publicipaddress"] != "203.0.113.10" {
		t.Errorf("instance: %+v", in)
	}
	if !hasRelation(in.Resource, sg, "attached_to") || !hasRelation(in.Resource, role, "runs_as") || !hasRelation(in.Resource, "internet", "exposed_to_internet") {
		t.Errorf("instance relations: %+v", in.Resource.Relations)
	}
	if got := in.Resource.Attributes["cartography_unmapped_relationships"]; got == nil {
		t.Errorf("unmapped TAGGED relationship should be counted on the instance: %v", in.Resource.Attributes)
	}
	r := inv("AWSRole", role)
	if r.Resource.Type != "aws_iam_role" || !hasRelation(r.Resource, external, "trusts") || !hasRelation(r.Resource, policy, "has_policy") {
		t.Errorf("role: %+v", r.Resource)
	}
	u := inv("AWSUser", user)
	if u.Resource.Type != "aws_iam_user" || !hasRelation(u.Resource, group, "member_of") || !hasRelation(u.Resource, role, "can_assume") {
		t.Errorf("user: %+v", u.Resource)
	}
	if l := inv("AWSLambda", lambda); l.Resource.Type != "aws_lambda_function" || !hasRelation(l.Resource, role, "runs_as") {
		t.Errorf("lambda: %+v", l.Resource)
	}
	inv("S3Bucket", "arn:aws:s3:::synthetic-assets-bucket")
	inv("RDSInstance", "arn:aws:rds:us-east-1:123456789012:db:orders-db")
	inv("AWSPolicy", policy)
	if tag := inv("AWSTag", "Environment:prod"); tag.Resource.Type != "cartography:AWSTag" {
		t.Errorf("unmapped label type: %s", tag.Resource.Type)
	}
	lb := findCheck(fs, "inventory:LoadBalancerV2", "")
	if lb == nil || !hasRelation(lb.Resource, instance, "allows_traffic_to") || lb.Resource.Attributes["exposed_internet"] != true {
		t.Errorf("load balancer: %+v", lb)
	}
	ns := inv("KubernetesNamespace", "namespace/shop")
	if ns.Provider != model.ProviderKubernetes || ns.Resource.Type != "k8s_namespace" || !hasRelation(ns.Resource, "shop/pod/storefront-6d4cf56db6-x7k2p", "contains") {
		t.Errorf("k8s namespace: %+v", ns)
	}
	inv("KubernetesPod", "shop/pod/storefront-6d4cf56db6-x7k2p")

	pub := findCheck(fs, "ec2_instance_public_ip", instance)
	if pub == nil || pub.Status != model.Fail || pub.CanonicalID != "EC2_PUBLIC_IP" || !pub.HasWeakness("PUBLIC_NETWORK_EXPOSURE") {
		t.Errorf("exposed_internet instance should yield EC2_PUBLIC_IP FAIL: %+v", pub)
	}
	for _, f := range fs {
		if f.CheckID == "ec2_instance_public_ip" && f.Resource.ID != instance {
			t.Errorf("only EC2 instances get a public-exposure finding, got %s", f.Resource.ID)
		}
	}
}

func TestInteropDetectDoesNotStealExistingFormats(t *testing.T) {
	for file, want := range map[string]string{
		"prowler.ocsf.json": "prowler", "checkov.json": "checkov", "trivy.json": "trivy",
		"steampipe.json": "steampipe", "scoutsuite_results_azure.js": "scoutsuite", "native.findings.json": "native",
	} {
		data, err := os.ReadFile(filepath.Join("..", "..", "testdata", file))
		if err != nil {
			t.Fatal(err)
		}
		a, ok := Detect(file, data)
		if !ok || a.Name() != want {
			got := ""
			if ok {
				got = a.Name()
			}
			t.Errorf("%s detected as %q, want %q", file, got, want)
		}
		// Content sniffing alone (neutral file name) must not claim existing formats either.
		for _, n := range []Adapter{&TrivyOperator{}, &Kubescape{}, &KubeBench{}, &Cartography{}} {
			if n.Detect("input.json", data) {
				t.Errorf("%s claims %s", n.Name(), file)
			}
		}
	}
}

func TestInteropVersions(t *testing.T) {
	v := Versions()
	for _, name := range []string{"trivy-operator", "kubescape", "kube-bench", "cartography"} {
		if v[name] == "" {
			t.Errorf("Versions()[%q] empty", name)
		}
		if _, ok := ByName(name); !ok {
			t.Errorf("%s not registered", name)
		}
	}
}

// Every relation kind the new adapters declare must be a kind the graph understands, or it
// would degrade to an untyped attached_to hint.
func TestInteropRelationKindsResolveInGraph(t *testing.T) {
	for _, c := range []struct{ rel, adapter string }{
		{"trivy-operator/vulnerabilityreports.list.json", "trivy-operator"},
		{"kubescape/kubescape-v3.json", "kubescape"},
		{"cartography/apoc-export.json", "cartography"},
	} {
		for _, f := range parseInterop(t, c.rel, c.adapter, Options{}) {
			for _, rel := range f.Resource.Relations {
				if _, _, ok := graph.RelationEdge(rel.Kind); !ok {
					t.Errorf("%s: relation kind %q on %s is not a graph edge kind", c.rel, rel.Kind, f.Resource.ID)
				}
			}
		}
	}
}

package graph

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/model"
	"github.com/DreadpiratePickles/nimbus/lab/local/estate"
)

const repoRoot = "../.."

// collectorDirs are the packages whose emitted resource types must all be registered.
var collectorDirs = []string{"aws", "azure", "gcp", "k8s", "saas", "core"}

// notNodeTypes are provider-prefixed string literals in collector code that are not node
// types (attribute keys, check ids, cost-only buckets). Each needs a reason; keep it short.
var notNodeTypes = map[string]string{
	"aws_managed":                     "attribute key on aws_iam_policy (AWS-managed policy flag)",
	"aws_service":                     "core.CostSignal.ResourceType for Cost Explorer per-service spend; never a graph node",
	"okta_admin_user_mfa_enrolled":    "check id",
	"okta_sign_on_policy_require_mfa": "check id",
}

var (
	prefixedLit = regexp.MustCompile(`"((?:aws|azure|gcp|k8s|kubernetes|m365|okta|github|oci)_[a-z0-9_]+)"`)
	typeField   = regexp.MustCompile(`(?:\bType|ResourceType):\s*"([A-Za-z0-9_]+)"`)
)

// collectorTypes greps every non-test Go file of the collector packages for the type strings
// they emit: provider-prefixed literals and Type:/ResourceType: field literals.
func collectorTypes(t *testing.T) map[string][]string {
	t.Helper()
	out := map[string][]string{}
	for _, d := range collectorDirs {
		files, err := filepath.Glob(filepath.Join(repoRoot, "internal", "collector", d, "*.go"))
		if err != nil || len(files) == 0 {
			t.Fatalf("no Go files under internal/collector/%s (err=%v)", d, err)
		}
		for _, f := range files {
			if strings.HasSuffix(f, "_test.go") {
				continue
			}
			src, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			rel, _ := filepath.Rel(repoRoot, f)
			for _, re := range []*regexp.Regexp{prefixedLit, typeField} {
				for _, m := range re.FindAllStringSubmatch(string(src), -1) {
					out[m[1]] = appendUnique(out[m[1]], rel)
				}
			}
		}
	}
	return out
}

// funcReturnLiterals parses a Go file and returns the string literals returned by fn.
func funcReturnLiterals(t *testing.T, file, fn string) []string {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, file, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Name.Name != fn {
			continue
		}
		ast.Inspect(fd, func(n ast.Node) bool {
			r, ok := n.(*ast.ReturnStmt)
			if !ok {
				return true
			}
			for _, res := range r.Results {
				if bl, ok := res.(*ast.BasicLit); ok && bl.Kind == token.STRING {
					if s, _ := strconv.Unquote(bl.Value); s != "" {
						out = append(out, s)
					}
				}
			}
			return true
		})
	}
	if len(out) == 0 {
		t.Fatalf("%s: found no string returns in %s", file, fn)
	}
	return out
}

// labEstateTypes reads every lab estate (lab/local/estate.yaml plus any estate-shaped YAML
// under lab/local/noise) and returns resource types and provider account types.
func labEstateTypes(t *testing.T) map[string][]string {
	t.Helper()
	files := []string{filepath.Join(repoRoot, "lab", "local", "estate.yaml")}
	more, _ := filepath.Glob(filepath.Join(repoRoot, "lab", "local", "noise", "*.yaml"))
	files = append(files, more...)
	out := map[string][]string{}
	for i, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		e, err := estate.Parse(data)
		if err != nil || len(e.Resources) == 0 {
			if i == 0 {
				t.Fatalf("lab estate %s: %v", f, err)
			}
			continue // not an estate file
		}
		rel, _ := filepath.Rel(repoRoot, f)
		for _, r := range e.Resources {
			out[r.Type] = appendUnique(out[r.Type], rel)
		}
		for _, a := range e.Accounts {
			// graph.AttachFindings creates <provider>_account nodes for every finding account.
			out[a.Provider+"_account"] = appendUnique(out[a.Provider+"_account"], rel+" (account)")
		}
	}
	return out
}

// TestRegistryCoversCollectorTypes fails when a collector, GuessType, core.AccountType,
// AttachFindings' account nodes or the lab estate emits a type absent from the registry.
func TestRegistryCoversCollectorTypes(t *testing.T) {
	emitted := collectorTypes(t)
	for _, typ := range funcReturnLiterals(t, "graph.go", "GuessType") {
		emitted[typ] = appendUnique(emitted[typ], "internal/graph/graph.go GuessType")
	}
	for _, typ := range funcReturnLiterals(t, filepath.Join(repoRoot, "internal", "collector", "core", "graphutil.go"), "AccountType") {
		emitted[typ] = appendUnique(emitted[typ], "internal/collector/core AccountType")
	}
	for _, p := range []string{model.ProviderAWS, model.ProviderAzure, model.ProviderGCP, model.ProviderOCI, model.ProviderKubernetes, model.ProviderGitHub, model.ProviderM365, model.ProviderOkta} {
		emitted[p+"_account"] = appendUnique(emitted[p+"_account"], "internal/graph AttachFindings account node")
	}
	for typ, srcs := range labEstateTypes(t) {
		emitted[typ] = appendUnique(emitted[typ], srcs...)
	}
	var missing []string
	for typ, srcs := range emitted {
		if _, skip := notNodeTypes[typ]; skip {
			continue
		}
		if _, ok := Lookup(typ); !ok {
			missing = append(missing, typ+" (from "+strings.Join(srcs, ", ")+")")
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("%d emitted type(s) missing from the registry (internal/graph/registry.go):\n  %s", len(missing), strings.Join(missing, "\n  "))
	}
	// The exclusion list must not hide a registered type or go stale.
	for typ := range notNodeTypes {
		if _, ok := Lookup(typ); ok {
			t.Errorf("notNodeTypes lists %q, which is a registered type", typ)
		}
		if _, ok := emitted[typ]; !ok {
			t.Errorf("notNodeTypes lists %q, which no collector emits any more; drop it", typ)
		}
	}
}

// Every registered type and alias resolves to the class the old substring heuristic gave it,
// except the reviewed overrides below: the registry must not move groundtruth numbers.
func TestRegistryClassMatchesLegacy(t *testing.T) {
	overrides := map[string]string{
		// legacy fell through to compute ("managed_identity" hits no rule).
		"azure_managed_identity":                           ClassIdentity,
		"azurerm_user_assigned_identity":                   ClassIdentity,
		"microsoft.managedidentity/userassignedidentities": ClassIdentity,
		// legacy compute ("public_ip" hits no rule); only a cost-signal ResourceType today, never a node.
		"azure_public_ip":   ClassNetwork,
		"azurerm_public_ip": ClassNetwork,
	}
	for _, s := range Registry() {
		for _, name := range append([]string{s.Type}, s.Aliases...) {
			want := legacyClassFor(name)
			if o, ok := overrides[strings.ToLower(name)]; ok {
				want = o
			}
			if s.Class != want {
				t.Errorf("%s (alias of %s): registry class %q, legacy heuristic %q", name, s.Type, s.Class, want)
			}
		}
	}
}

func TestRegistryWellFormed(t *testing.T) {
	seen := map[string]string{}
	classes := map[string]bool{ClassInternet: true, ClassCompute: true, ClassNetwork: true, ClassIdentity: true, ClassDataStore: true, ClassCluster: true, ClassSaaS: true, ClassAccount: true, ClassImage: true}
	for _, s := range Registry() {
		if s.Type == "" || s.Class == "" || s.Provider == "" || s.Display == "" {
			t.Errorf("incomplete spec %+v", s)
		}
		if !classes[s.Class] {
			t.Errorf("%s: unknown class %q", s.Type, s.Class)
		}
		if s.IsIdentity != (s.Class == ClassIdentity) {
			t.Errorf("%s: IsIdentity=%v disagrees with class %s", s.Type, s.IsIdentity, s.Class)
		}
		if s.IsDataStore != (s.Class == ClassDataStore) {
			t.Errorf("%s: IsDataStore=%v disagrees with class %s", s.Type, s.IsDataStore, s.Class)
		}
		for _, n := range append([]string{s.Type}, s.Aliases...) {
			k := strings.ToLower(n)
			if prev, ok := seen[k]; ok {
				t.Errorf("%q registered twice (%s and %s)", n, prev, s.Type)
			}
			seen[k] = s.Type
		}
		if got, ok := Lookup(strings.ToUpper(s.Type)); !ok || got.Type != s.Type {
			t.Errorf("Lookup is not case-insensitive for %s", s.Type)
		}
	}
	if n := len(Registry()); n < 60 {
		t.Errorf("registry has %d types; expected the collector + lab + alias set (>= 60)", n)
	}
}

// Unknown types keep the heuristic class but are marked guessed and listed.
func TestUnregisteredTypesGuessedAndReported(t *testing.T) {
	ResetUnregisteredTypes()
	g := New()
	g.AddNode(&Node{ID: "x1", Type: "acme_widget_bucket"})
	g.AddNode(&Node{ID: "r1", Type: "aws_iam_role"})
	g.AddNode(&Node{ID: "n0"})
	x, _ := g.Node("x1")
	if !x.Guessed || x.Class != legacyClassFor("acme_widget_bucket") || x.Class != ClassDataStore {
		t.Fatalf("unknown type: guessed=%v class=%q", x.Guessed, x.Class)
	}
	r, _ := g.Node("r1")
	if r.Guessed || r.Class != ClassIdentity {
		t.Fatalf("registered type: guessed=%v class=%q", r.Guessed, r.Class)
	}
	if n0, _ := g.Node("n0"); !n0.Guessed {
		t.Fatalf("typeless node not guessed")
	}
	if got := UnregisteredTypes(); len(got) != 1 || got[0] != "acme_widget_bucket" {
		t.Fatalf("UnregisteredTypes() = %v", got)
	}
	if got := g.UnregisteredTypes(); got["acme_widget_bucket"] != 1 || len(got) != 1 {
		t.Fatalf("g.UnregisteredTypes() = %v", got)
	}
	// An edge placeholder is guessed until the real resource arrives with a registered type.
	g.AddEdge("r1", "arn:aws:s3:::later", EdgeGrantsAccessTo, nil)
	p, _ := g.Node("arn:aws:s3:::later")
	if !p.Guessed {
		t.Fatalf("placeholder not guessed")
	}
	g.AddNode(&Node{ID: "arn:aws:s3:::later", Type: "aws_s3_bucket"})
	if p, _ = g.Node("arn:aws:s3:::later"); p.Guessed || p.Class != ClassDataStore {
		t.Fatalf("resolved placeholder: guessed=%v class=%q", p.Guessed, p.Class)
	}
	// Guessed survives JSON (the stored node doc) and Clone.
	b, _ := json.Marshal(x)
	if !strings.Contains(string(b), `"guessed":true`) {
		t.Fatalf("node JSON lacks guessed: %s", b)
	}
	if c, _ := g.Clone().Node("x1"); !c.Guessed {
		t.Fatalf("clone lost guessed")
	}
}

// Every node the lab estate's findings put in the graph has a registered type, except edge
// placeholders (ids referenced but never declared), which stay guessed.
func TestLabGraphNodesRegistered(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(repoRoot, "lab", "local", "out", "estate.findings.json"))
	if err != nil {
		t.Fatalf("lab findings: %v (run `make lab-local`)", err)
	}
	var fs []model.Finding
	if err := json.Unmarshal(data, &fs); err != nil {
		t.Fatal(err)
	}
	g := New()
	g.AttachFindings(fs)
	declared := map[string]bool{InternetNodeID: true}
	for _, f := range fs {
		declared[f.Resource.ID] = true
		if f.Account != "" {
			declared[accountNodeID(f.Provider, f.Account)] = true
		}
	}
	placeholders := 0
	for _, n := range g.Nodes() {
		if !declared[n.ID] {
			placeholders++
			continue
		}
		if n.Guessed {
			t.Errorf("lab node %s has unregistered type %q", n.ID, n.Type)
		}
	}
	t.Logf("lab graph: %d nodes, %d edge placeholders (guessed)", g.Len(), placeholders)
}

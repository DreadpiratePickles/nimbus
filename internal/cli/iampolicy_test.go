package cli

// TestReadOnlyPolicies derives least-privilege read-only permission documents
// (docs/iam/*) from the cloud API calls the native collectors actually make, and
// fails when a collector starts calling an API that docs/iam/api-permissions.json
// does not map. Regenerate with:
//
//	go test ./internal/cli -run TestReadOnlyPolicies -update

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
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
)

var updateIAM = flag.Bool("update", false, "rewrite docs/iam read-only policy documents from collector source")

var iamRepoRoot = filepath.Join("..", "..")

// sdkCalls maps an extracted call key to the source position that produced it.
type sdkCalls map[string]string

func (s sdkCalls) add(key string, fset *token.FileSet, pos token.Pos) {
	if _, ok := s[key]; !ok {
		s[key] = fset.Position(pos).String()
	}
}

// parsedFile is one parsed non-test Go file plus its import table (local name -> path).
type parsedFile struct {
	f       *ast.File
	imports map[string]string
}

func parseGoDir(t *testing.T, dir string) (*token.FileSet, []parsedFile) {
	t.Helper()
	fset := token.NewFileSet()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	var out []parsedFile
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, n), nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", n, err)
		}
		imps := map[string]string{}
		for _, im := range f.Imports {
			p, _ := strconv.Unquote(im.Path.Value)
			name := ""
			if im.Name != nil {
				name = im.Name.Name
			} else {
				parts := strings.Split(p, "/")
				name = parts[len(parts)-1]
				if regexp.MustCompile(`^v\d+$`).MatchString(name) && len(parts) > 1 {
					name = parts[len(parts)-2]
				}
			}
			imps[name] = p
		}
		out = append(out, parsedFile{f: f, imports: imps})
	}
	if len(out) == 0 {
		t.Fatalf("no Go sources in %s", dir)
	}
	return fset, out
}

// namedInterfaces calls fn for every top-level `type X interface{...}`.
func namedInterfaces(pf parsedFile, fn func(name string, it *ast.InterfaceType)) {
	for _, d := range pf.f.Decls {
		gd, ok := d.(*ast.GenDecl)
		if !ok || gd.Tok != token.TYPE {
			continue
		}
		for _, s := range gd.Specs {
			ts := s.(*ast.TypeSpec)
			if it, ok := ts.Type.(*ast.InterfaceType); ok {
				fn(ts.Name.Name, it)
			}
		}
	}
}

// qualifiedTypes calls fn(importPath, typeName) for every pkg.Type selector inside n.
func qualifiedTypes(pf parsedFile, n ast.Node, fn func(path, name string)) {
	ast.Inspect(n, func(x ast.Node) bool {
		if se, ok := x.(*ast.SelectorExpr); ok {
			if id, ok := se.X.(*ast.Ident); ok {
				if p, ok := pf.imports[id.Name]; ok {
					fn(p, se.Sel.Name)
				}
			}
			return false
		}
		return true
	})
}

// constructedPkgs reports import paths whose package-level constructor (a func name
// matching ctor) is called, e.g. ec2.NewFromConfig(...).
func constructedPkgs(pf parsedFile, ctor *regexp.Regexp, fn func(path string, pos token.Pos)) {
	ast.Inspect(pf.f, func(x ast.Node) bool {
		ce, ok := x.(*ast.CallExpr)
		if !ok {
			return true
		}
		if se, ok := ce.Fun.(*ast.SelectorExpr); ok && ctor.MatchString(se.Sel.Name) {
			if id, ok := se.X.(*ast.Ident); ok {
				if p, ok := pf.imports[id.Name]; ok {
					fn(p, ce.Pos())
				}
			}
		}
		return true
	})
}

// ---- AWS -------------------------------------------------------------------

const awsServicePrefix = "github.com/aws/aws-sdk-go-v2/service/"

func awsService(path string) string {
	if !strings.HasPrefix(path, awsServicePrefix) {
		return ""
	}
	return strings.SplitN(strings.TrimPrefix(path, awsServicePrefix), "/", 2)[0]
}

// extractAWS returns "<service>.<Operation>" for every method of every named
// interface in dir (explicit methods and embedded SDK <Op>APIClient paginator
// interfaces). The service comes from SDK types in the method signature; an
// interface named *API whose methods use no SDK types (a hand-rolled client such
// as S3ControlAPI) is keyed by its lower-cased name minus "API". It also reports
// every SDK service constructed with NewFromConfig so callers can check coverage.
func extractAWS(t *testing.T, dir string) (calls sdkCalls, constructed map[string]string) {
	fset, files := parseGoDir(t, dir)
	calls, constructed = sdkCalls{}, map[string]string{}
	for _, pf := range files {
		namedInterfaces(pf, func(iname string, it *ast.InterfaceType) {
			for _, m := range it.Methods.List {
				switch typ := m.Type.(type) {
				case *ast.FuncType:
					svc := ""
					qualifiedTypes(pf, typ, func(p, _ string) {
						if s := awsService(p); s != "" && svc == "" {
							svc = s
						}
					})
					if svc == "" {
						if !strings.HasSuffix(iname, "API") {
							continue // not a cloud client interface
						}
						svc = strings.ToLower(strings.TrimSuffix(iname, "API"))
					}
					for _, n := range m.Names {
						calls.add(svc+"."+n.Name, fset, n.Pos())
					}
				case *ast.SelectorExpr:
					id, ok := typ.X.(*ast.Ident)
					if !ok {
						continue
					}
					svc := awsService(pf.imports[id.Name])
					if svc == "" {
						continue
					}
					calls.add(svc+"."+strings.TrimSuffix(typ.Sel.Name, "APIClient"), fset, typ.Pos())
				}
			}
		})
		constructedPkgs(pf, regexp.MustCompile(`^NewFromConfig$`), func(p string, pos token.Pos) {
			if s := awsService(p); s != "" {
				constructed[s] = fset.Position(pos).String()
			}
		})
	}
	return calls, constructed
}

// ---- Azure -----------------------------------------------------------------

const azureARMMarker = "/azure-sdk-for-go/sdk/resourcemanager/"

func armPkg(path string) string {
	if !strings.Contains(path, azureARMMarker) {
		return ""
	}
	parts := strings.Split(path, "/")
	n := parts[len(parts)-1]
	if regexp.MustCompile(`^v\d+$`).MatchString(n) {
		n = parts[len(parts)-2]
	}
	return n
}

// extractAzure returns "<armpkg>.<ClientType>.<Method>" for every interface method in
// dir whose signature uses an ARM SDK type named <ClientType><Op>{Options,Response}
// (e.g. armcompute.VirtualMachinesClientListAllResponse -> VirtualMachinesClient).
func extractAzure(t *testing.T, dir string) (calls sdkCalls, constructed map[string]string) {
	fset, files := parseGoDir(t, dir)
	calls, constructed = sdkCalls{}, map[string]string{}
	for _, pf := range files {
		namedInterfaces(pf, func(_ string, it *ast.InterfaceType) {
			for _, m := range it.Methods.List {
				ft, ok := m.Type.(*ast.FuncType)
				if !ok {
					continue
				}
				pkg, client := "", ""
				qualifiedTypes(pf, ft, func(p, name string) {
					if client != "" {
						return
					}
					if ap := armPkg(p); ap != "" {
						if i := strings.Index(name, "Client"); i >= 0 {
							pkg, client = ap, name[:i+len("Client")]
						}
					}
				})
				if client == "" {
					continue
				}
				for _, n := range m.Names {
					calls.add(pkg+"."+client+"."+n.Name, fset, n.Pos())
				}
			}
		})
		constructedPkgs(pf, regexp.MustCompile(`^New\w*Client(Factory)?$`), func(p string, pos token.Pos) {
			if ap := armPkg(p); ap != "" {
				constructed[ap] = fset.Position(pos).String()
			}
		})
	}
	return calls, constructed
}

// ---- GCP -------------------------------------------------------------------

func gcpAPI(path string) string {
	for _, pre := range []string{"google.golang.org/api/", "cloud.google.com/go/"} {
		if strings.HasPrefix(path, pre) {
			api := strings.SplitN(strings.TrimPrefix(path, pre), "/", 2)[0]
			switch api {
			case "option", "iterator", "googleapi", "transport", "internal", "civil":
				return ""
			}
			return api
		}
	}
	return ""
}

// gcpBuilderMethods are request-builder / execution methods stripped from the end of
// a call chain: c.svc.Firewalls.List(p).Context(ctx).Pages(...) -> Firewalls.List.
var gcpBuilderMethods = map[string]bool{
	"Context": true, "Pages": true, "Do": true, "Fields": true, "Header": true,
	"Filter": true, "MaxResults": true, "PageToken": true, "OrderBy": true,
	"ReturnPartialSuccess": true, "IncludeAllScopes": true, "PageSize": true,
}

// extractGCP finds SDK calls made through a receiver's SDK-typed struct field:
// for `func (c *computeClient) ...` with `computeClient{svc *compute.Service}`, the
// outermost call chain rooted at c.svc becomes "compute.<Resource...>.<Method>"
// (builder methods trimmed). Chains through call results are kept, so
// s.c.Bucket(n).IAM().Policy(ctx) -> "storage.Bucket.IAM.Policy".
func extractGCP(t *testing.T, dir string) (calls sdkCalls, constructed map[string]string) {
	fset, files := parseGoDir(t, dir)
	calls, constructed = sdkCalls{}, map[string]string{}
	// struct name -> field name -> api
	fields := map[string]map[string]string{}
	for _, pf := range files {
		for _, d := range pf.f.Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok || gd.Tok != token.TYPE {
				continue
			}
			for _, s := range gd.Specs {
				ts := s.(*ast.TypeSpec)
				st, ok := ts.Type.(*ast.StructType)
				if !ok {
					continue
				}
				for _, fl := range st.Fields.List {
					ft := fl.Type
					if se, ok := ft.(*ast.StarExpr); ok {
						ft = se.X
					}
					sel, ok := ft.(*ast.SelectorExpr)
					if !ok {
						continue
					}
					id, ok := sel.X.(*ast.Ident)
					if !ok {
						continue
					}
					api := gcpAPI(pf.imports[id.Name])
					if api == "" {
						continue
					}
					for _, n := range fl.Names {
						if fields[ts.Name.Name] == nil {
							fields[ts.Name.Name] = map[string]string{}
						}
						fields[ts.Name.Name][n.Name] = api
					}
				}
			}
		}
	}
	for _, pf := range files {
		for _, d := range pf.f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Recv == nil || len(fd.Recv.List) != 1 || len(fd.Recv.List[0].Names) != 1 || fd.Body == nil {
				continue
			}
			rt := fd.Recv.List[0].Type
			if se, ok := rt.(*ast.StarExpr); ok {
				rt = se.X
			}
			rid, ok := rt.(*ast.Ident)
			if !ok || fields[rid.Name] == nil {
				continue
			}
			recv, ff := fd.Recv.List[0].Names[0].Name, fields[rid.Name]
			inner := map[*ast.CallExpr]bool{}
			ast.Inspect(fd.Body, func(x ast.Node) bool {
				ce, ok := x.(*ast.CallExpr)
				if !ok {
					return true
				}
				if se, ok := ce.Fun.(*ast.SelectorExpr); ok {
					if innerCall, ok := se.X.(*ast.CallExpr); ok {
						inner[innerCall] = true
					}
				}
				if inner[ce] {
					return true
				}
				var names []string
				var e ast.Expr = ce
				root := ""
			walk:
				for {
					switch v := e.(type) {
					case *ast.CallExpr:
						e = v.Fun
					case *ast.SelectorExpr:
						names = append([]string{v.Sel.Name}, names...)
						e = v.X
					case *ast.Ident:
						root = v.Name
						break walk
					default:
						break walk
					}
				}
				if root != recv || len(names) < 2 {
					return true
				}
				api, ok := ff[names[0]]
				if !ok {
					return true
				}
				chain := names[1:]
				for len(chain) > 1 && gcpBuilderMethods[chain[len(chain)-1]] {
					chain = chain[:len(chain)-1]
				}
				calls.add(api+"."+strings.Join(chain, "."), fset, ce.Pos())
				return true
			})
		}
		constructedPkgs(pf, regexp.MustCompile(`^New(Service|Client)$`), func(p string, pos token.Pos) {
			if api := gcpAPI(p); api != "" {
				constructed[api] = fset.Position(pos).String()
			}
		})
	}
	return calls, constructed
}

// ---- mapping + documents ---------------------------------------------------

type apiPermissions struct {
	AWS   map[string][]string `json:"aws"`
	Azure map[string][]string `json:"azure"`
	GCP   map[string][]string `json:"gcp"`
}

func loadAPIPermissions(t *testing.T) apiPermissions {
	t.Helper()
	path := filepath.Join(iamRepoRoot, "docs", "iam", "api-permissions.json")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v (create the mapping file: {\"aws\":{...},\"azure\":{...},\"gcp\":{...}})", path, err)
	}
	var m apiPermissions
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return m
}

// unmapped returns "cloud key (pos)" for each extracted call with no mapping entry.
func unmapped(cloud string, calls sdkCalls, mapping map[string][]string) []string {
	var out []string
	for k, pos := range calls {
		if len(mapping[k]) == 0 {
			out = append(out, fmt.Sprintf("unmapped collector call %s %q (%s): add it to docs/iam/api-permissions.json", cloud, k, pos))
		}
	}
	sort.Strings(out)
	return out
}

func mappedActions(calls sdkCalls, mapping map[string][]string) []string {
	set := map[string]bool{}
	for k := range calls {
		for _, a := range mapping[k] {
			set[a] = true
		}
	}
	out := make([]string, 0, len(set))
	for a := range set {
		out = append(out, a)
	}
	sort.Strings(out)
	return out
}

var awsReadOnlyAllowlist = map[string]bool{
	// Generating the credential report is a prerequisite for reading it and changes
	// no customer resource; it is part of AWS's own SecurityAudit policy.
	"iam:GenerateCredentialReport": true,
}

func awsActionReadOnly(a string) bool {
	if awsReadOnlyAllowlist[a] {
		return true
	}
	i := strings.Index(a, ":")
	if i <= 0 {
		return false
	}
	verb := a[i+1:]
	for _, p := range []string{"Get", "List", "Describe", "Lookup", "BatchGet"} {
		if strings.HasPrefix(verb, p) {
			return true
		}
	}
	return false
}

func azureActionReadOnly(a string) bool {
	return strings.HasPrefix(a, "Microsoft.") && strings.HasSuffix(a, "/read")
}

func gcpPermissionReadOnly(p string) bool {
	for _, s := range []string{".get", ".list", ".getIamPolicy"} {
		if strings.HasSuffix(p, s) {
			return true
		}
	}
	return false
}

func marshalDoc(t *testing.T, v any) []byte {
	t.Helper()
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

type awsPolicy struct {
	Version   string               `json:"Version"`
	Statement []awsPolicyStatement `json:"Statement"`
}

type awsPolicyStatement struct {
	Sid      string   `json:"Sid"`
	Effect   string   `json:"Effect"`
	Action   []string `json:"Action"`
	Resource string   `json:"Resource"`
}

type azureRole struct {
	Name             string   `json:"Name"`
	IsCustom         bool     `json:"IsCustom"`
	Description      string   `json:"Description"`
	Actions          []string `json:"Actions"`
	NotActions       []string `json:"NotActions"`
	DataActions      []string `json:"DataActions"`
	NotDataActions   []string `json:"NotDataActions"`
	AssignableScopes []string `json:"AssignableScopes"`
}

type gcpRole struct {
	Title               string   `json:"title"`
	Description         string   `json:"description"`
	Stage               string   `json:"stage"`
	IncludedPermissions []string `json:"includedPermissions"`
}

func TestReadOnlyPolicies(t *testing.T) {
	collector := filepath.Join(iamRepoRoot, "internal", "collector")
	awsCalls, awsCtors := extractAWS(t, filepath.Join(collector, "aws"))
	azCalls, azCtors := extractAzure(t, filepath.Join(collector, "azure"))
	gcpCalls, gcpCtors := extractGCP(t, filepath.Join(collector, "gcp"))
	t.Logf("extracted calls: aws=%d azure=%d gcp=%d", len(awsCalls), len(azCalls), len(gcpCalls))

	// Every constructed SDK client must surface at least one extracted call, otherwise
	// it is used outside the narrow interfaces and the extractor cannot see it.
	coverage := func(cloud string, calls sdkCalls, ctors map[string]string) {
		for pkg, pos := range ctors {
			found := false
			for k := range calls {
				if strings.HasPrefix(k, pkg+".") {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("%s SDK package %q is constructed at %s but no call through it was extracted; expose it via a narrow interface so its permissions are generated", cloud, pkg, pos)
			}
		}
	}
	coverage("aws", awsCalls, awsCtors)
	coverage("azure", azCalls, azCtors)
	coverage("gcp", gcpCalls, gcpCtors)
	for _, c := range []sdkCalls{awsCalls, azCalls, gcpCalls} {
		if len(c) == 0 {
			t.Fatal("extractor found no calls; the collector layout changed and this test must be updated")
		}
	}

	m := loadAPIPermissions(t)
	var missing []string
	missing = append(missing, unmapped("aws", awsCalls, m.AWS)...)
	missing = append(missing, unmapped("azure", azCalls, m.Azure)...)
	missing = append(missing, unmapped("gcp", gcpCalls, m.GCP)...)
	if len(missing) > 0 {
		t.Fatalf("%d collector call(s) have no permission mapping:\n%s", len(missing), strings.Join(missing, "\n"))
	}

	awsActs := mappedActions(awsCalls, m.AWS)
	azActs := mappedActions(azCalls, m.Azure)
	gcpPerms := mappedActions(gcpCalls, m.GCP)
	for _, a := range awsActs {
		if !awsActionReadOnly(a) {
			t.Errorf("AWS action %q is not read-only (verb must start Get/List/Describe/Lookup/BatchGet or be allowlisted)", a)
		}
	}
	for _, a := range azActs {
		if !azureActionReadOnly(a) {
			t.Errorf("Azure action %q is not a /read action", a)
		}
	}
	for _, p := range gcpPerms {
		if !gcpPermissionReadOnly(p) {
			t.Errorf("GCP permission %q is not .get/.list/.getIamPolicy", p)
		}
	}

	docs := map[string][]byte{
		"readonly-policy-aws.json": marshalDoc(t, awsPolicy{Version: "2012-10-17", Statement: []awsPolicyStatement{{
			Sid: "CloudPostureReadOnly", Effect: "Allow", Action: awsActs, Resource: "*",
		}}}),
		"readonly-role-azure.json": marshalDoc(t, azureRole{
			Name: "Cloud Posture Reader", IsCustom: true,
			Description:      "Least-privilege read-only access for nimbus native Azure collection (generated from collector source).",
			Actions:          azActs,
			NotActions:       []string{},
			DataActions:      []string{},
			NotDataActions:   []string{},
			AssignableScopes: []string{"/subscriptions/00000000-0000-0000-0000-000000000000"},
		}),
		"readonly-role-gcp.json": marshalDoc(t, gcpRole{
			Title:               "Cloud Posture Reader",
			Description:         "Least-privilege read-only access for nimbus native GCP collection (generated from collector source).",
			Stage:               "GA",
			IncludedPermissions: gcpPerms,
		}),
	}
	names := make([]string, 0, len(docs))
	for n := range docs {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		path := filepath.Join(iamRepoRoot, "docs", "iam", n)
		if *updateIAM {
			if err := os.WriteFile(path, docs[n], 0o644); err != nil {
				t.Fatalf("write %s: %v", path, err)
			}
			continue
		}
		got, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(got, docs[n]) {
			t.Errorf("docs/iam/%s is missing or stale; regenerate with: go test ./internal/cli -run TestReadOnlyPolicies -update", n)
		}
	}

	// `onboard --deploy-role` go:embeds the AWS policy, and go:embed cannot reach
	// docs/, so keep an identical copy under internal/cli/iam.
	embedPath := filepath.Join("iam", "readonly-policy-aws.json")
	if *updateIAM {
		if err := os.MkdirAll(filepath.Dir(embedPath), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(embedPath, docs["readonly-policy-aws.json"], 0o644); err != nil {
			t.Fatalf("write %s: %v", embedPath, err)
		}
	} else {
		canonical, _ := os.ReadFile(filepath.Join(iamRepoRoot, "docs", "iam", "readonly-policy-aws.json"))
		got, err := os.ReadFile(embedPath)
		if err != nil || !bytes.Equal(got, canonical) || !bytes.Equal(got, docs["readonly-policy-aws.json"]) {
			t.Errorf("internal/cli/iam/readonly-policy-aws.json (embedded by onboard --deploy-role) is missing or differs from docs/iam/readonly-policy-aws.json; regenerate with: go test ./internal/cli -run TestReadOnlyPolicies -update")
		}
	}
}

// TestReadOnlyPoliciesGuardFires proves the extractor reports a write call that is
// not in the mapping, and that the read-only check rejects a write action.
func TestReadOnlyPoliciesGuardFires(t *testing.T) {
	dir := t.TempDir()
	src := `package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/s3"
)

type S3API interface {
	s3.ListBucketsAPIClient
	PutBucketPolicy(context.Context, *s3.PutBucketPolicyInput, ...func(*s3.Options)) (*s3.PutBucketPolicyOutput, error)
}

func build() { _ = s3.NewFromConfig }
`
	if err := os.WriteFile(filepath.Join(dir, "clients.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	calls, _ := extractAWS(t, dir)
	if _, ok := calls["s3.PutBucketPolicy"]; !ok {
		t.Fatalf("extractor missed s3.PutBucketPolicy; got %v", calls)
	}
	if _, ok := calls["s3.ListBuckets"]; !ok {
		t.Fatalf("extractor missed embedded s3.ListBucketsAPIClient; got %v", calls)
	}
	m := loadAPIPermissions(t)
	miss := unmapped("aws", calls, m.AWS)
	if len(miss) != 1 || !strings.Contains(miss[0], `"s3.PutBucketPolicy"`) {
		t.Fatalf("want exactly s3.PutBucketPolicy reported unmapped, got %v", miss)
	}
	if awsActionReadOnly("s3:PutBucketPolicy") {
		t.Fatal("s3:PutBucketPolicy must not pass the read-only check")
	}
	if azureActionReadOnly("Microsoft.Compute/virtualMachines/write") || gcpPermissionReadOnly("compute.instances.setIamPolicy") {
		t.Fatal("write actions must not pass the Azure/GCP read-only checks")
	}
}

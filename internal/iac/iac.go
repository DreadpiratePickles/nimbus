// Package iac provides native Infrastructure-as-Code scanning and patching:
//   - file-type detection (Terraform, CloudFormation, Bicep, Kubernetes, Helm, Pulumi, CDK, Ansible)
//   - a built-in Terraform (HCL) scanner for the highest-impact checks (no Python needed)
//   - an HCL patcher that rewrites the offending block in place (hclwrite, comments preserved)
//   - cloud-to-code mapping: Terraform state (and Yor `yor_trace` tags) link a live resource to file:line
package iac

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/DreadpiratePickles/nimbus/internal/model"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

type Kind string

const (
	Terraform      Kind = "terraform"
	CloudFormation Kind = "cloudformation"
	Bicep          Kind = "bicep"
	Kubernetes     Kind = "kubernetes"
	Helm           Kind = "helm"
	Pulumi         Kind = "pulumi"
	CDK            Kind = "cdk"
	Ansible        Kind = "ansible"
	Dockerfile     Kind = "dockerfile"
	Unknown        Kind = ""
)

// DetectKind classifies a file by extension and content sniffing.
func DetectKind(path string, head []byte) Kind {
	base := strings.ToLower(filepath.Base(path))
	ext := strings.ToLower(filepath.Ext(path))
	h := string(head)
	switch {
	case ext == ".tf" || ext == ".tfvars" || ext == ".hcl":
		return Terraform
	case ext == ".bicep":
		return Bicep
	case base == "dockerfile" || strings.HasSuffix(base, ".dockerfile"):
		return Dockerfile
	case base == "chart.yaml" || base == "values.yaml" || strings.Contains(path, "/templates/") && (ext == ".yaml" || ext == ".yml" || ext == ".tpl"):
		return Helm
	case base == "pulumi.yaml" || strings.Contains(h, "pulumi."):
		return Pulumi
	case base == "cdk.json" || strings.Contains(h, "aws-cdk-lib") || strings.Contains(h, "@aws-cdk/"):
		return CDK
	case ext == ".yaml" || ext == ".yml" || ext == ".json":
		switch {
		case strings.Contains(h, "AWSTemplateFormatVersion") || strings.Contains(h, "\"Resources\"") && strings.Contains(h, "\"Type\": \"AWS::") || strings.Contains(h, "Type: AWS::"):
			return CloudFormation
		case strings.Contains(h, "apiVersion:") && strings.Contains(h, "kind:"):
			return Kubernetes
		case strings.Contains(h, "hosts:") && (strings.Contains(h, "tasks:") || strings.Contains(h, "roles:")):
			return Ansible
		case base == "playbook.yml" || base == "playbook.yaml" || base == "site.yml":
			return Ansible
		}
	case ext == ".ts" || ext == ".py" || ext == ".go" || ext == ".cs" || ext == ".java":
		if strings.Contains(h, "aws-cdk") || strings.Contains(h, "aws_cdk") {
			return CDK
		}
		if strings.Contains(h, "@pulumi/") || strings.Contains(h, "import pulumi") {
			return Pulumi
		}
	}
	return Unknown
}

// Inventory walks a directory and groups files by IaC kind (used to decide which external scanners to run).
func Inventory(root string) (map[Kind][]string, error) {
	out := map[Kind][]string{}
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			name := d.Name()
			if name == ".git" || name == "node_modules" || name == ".terraform" || name == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		f, err := os.Open(p)
		if err != nil {
			return nil
		}
		head := make([]byte, 4096)
		n, _ := f.Read(head)
		f.Close()
		if k := DetectKind(p, head[:n]); k != Unknown {
			out[k] = append(out[k], p)
		}
		return nil
	})
	return out, err
}

// ---------------------------------------------------------------- native Terraform scanner

type Block struct {
	File    string
	Type    string // resource type e.g. aws_s3_bucket
	Name    string
	Address string // aws_s3_bucket.exports
	Range   hcl.Range
	Attrs   map[string]cty.Value
	Body    *hclsyntax.Body
}

func providerOfType(t string) string {
	switch {
	case strings.HasPrefix(t, "aws_"):
		return model.ProviderAWS
	case strings.HasPrefix(t, "azurerm_"), strings.HasPrefix(t, "azuread_"):
		return model.ProviderAzure
	case strings.HasPrefix(t, "google_"):
		return model.ProviderGCP
	case strings.HasPrefix(t, "oci_"):
		return model.ProviderOCI
	case strings.HasPrefix(t, "kubernetes_"), strings.HasPrefix(t, "helm_"):
		return model.ProviderKubernetes
	case strings.HasPrefix(t, "github_"):
		return model.ProviderGitHub
	case strings.HasPrefix(t, "okta_"):
		return model.ProviderOkta
	}
	return model.ProviderIaC
}

func containsStr(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// maxLCSCells bounds the LCS table UnifiedDiff builds for the changed middle of a file (16 MB of
// int32). Beyond it the middle is emitted as a plain remove/add block: still a correct diff.
const maxLCSCells = 4 << 20

// UnifiedDiff produces a line-based unified diff for PR bodies. The common prefix and suffix are
// trimmed first and only the changed middle goes through an LCS, so memory and time are linear in
// the file size for a patch (Verification 2 defect 9: the full n×m table used 1.33 GB for a
// 12k-line file and ran out of memory at 10 MB).
func UnifiedDiff(name, a, b string) string {
	al := strings.Split(a, "\n")
	bl := strings.Split(b, "\n")
	n, m := len(al), len(bl)
	pre := 0
	for pre < n && pre < m && al[pre] == bl[pre] {
		pre++
	}
	suf := 0
	for suf < n-pre && suf < m-pre && al[n-1-suf] == bl[m-1-suf] {
		suf++
	}

	var out strings.Builder
	out.WriteString("--- a/" + name + "\n+++ b/" + name)
	run := 0 // collapse long unchanged runs: keep 3 context lines, then one marker
	emit := func(prefix byte, line string) {
		if prefix == ' ' {
			run++
			if run > 3 {
				return
			}
		} else {
			if run > 3 {
				out.WriteString("\n@@ ... @@")
			}
			run = 0
		}
		out.WriteByte('\n')
		out.WriteByte(prefix)
		out.WriteString(line)
	}
	for i := 0; i < pre; i++ {
		emit(' ', al[i])
	}
	ma, mb := al[pre:n-suf], bl[pre:m-suf]
	if len(ma) > 0 && len(mb) > 0 && (len(ma)+1)*(len(mb)+1) <= maxLCSCells {
		lcsDiff(ma, mb, emit)
	} else {
		for _, l := range ma {
			emit('-', l)
		}
		for _, l := range mb {
			emit('+', l)
		}
	}
	for i := n - suf; i < n; i++ {
		emit(' ', al[i])
	}
	return out.String()
}

func lcsDiff(al, bl []string, emit func(byte, string)) {
	n, m := len(al), len(bl)
	w := m + 1
	lcs := make([]int32, (n+1)*w)
	at := func(i, j int) int32 { return lcs[i*w+j] }
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			switch {
			case al[i] == bl[j]:
				lcs[i*w+j] = at(i+1, j+1) + 1
			case at(i+1, j) >= at(i, j+1):
				lcs[i*w+j] = at(i+1, j)
			default:
				lcs[i*w+j] = at(i, j+1)
			}
		}
	}
	i, j := 0, 0
	for i < n || j < m {
		switch {
		case i < n && j < m && al[i] == bl[j]:
			emit(' ', al[i])
			i++
			j++
		case i < n && (j >= m || at(i+1, j) >= at(i, j+1)):
			emit('-', al[i])
			i++
		default:
			emit('+', bl[j])
			j++
		}
	}
}

// ---------------------------------------------------------------- cloud-to-code mapping

// CodeLocation links a live cloud resource to its IaC definition. Address is the full Terraform
// address from the state (module.a.aws_instance.web[0]). When Unresolved is set the location must
// not be used: either no single block declares the address (Candidates lists what did), or one
// cloud ID / trace maps to several resources.
type CodeLocation struct {
	Address    string   `json:"address"`
	File       string   `json:"file"`
	Line       int      `json:"line"`
	Module     string   `json:"module,omitempty"`
	Trace      string   `json:"yor_trace,omitempty"`
	Unresolved string   `json:"unresolved,omitempty"`
	Candidates []string `json:"candidates,omitempty"`
	ambiguous  bool
}

type stateResource struct {
	Address string         `json:"address"`
	Mode    string         `json:"mode"`
	Type    string         `json:"type"`
	Name    string         `json:"name"`
	Values  map[string]any `json:"values"`
}

type stateModule struct {
	Address      string          `json:"address"`
	Resources    []stateResource `json:"resources"`
	ChildModules []stateModule   `json:"child_modules"`
}

// MapCloudToCode reads terraform.tfstate (or a `terraform show -json` dump) and the HCL
// sources to map cloud IDs/ARNs and yor_trace tags onto file:line.
//
// Resources are resolved by their full module address (Verification 2 defect 1): module.a.x.y is
// looked up only in the directory module "a" is sourced from (local sources, followed from root),
// never by bare type.name anywhere in the tree. An address that no single block declares, and a
// cloud ID or trace shared by several resources, map to an Unresolved location that Locate refuses.
func MapCloudToCode(statePath, root string) (map[string]CodeLocation, error) {
	data, err := os.ReadFile(statePath)
	if err != nil {
		return nil, err
	}
	var state struct {
		Resources []struct {
			Module    string `json:"module"`
			Mode      string `json:"mode"`
			Type      string `json:"type"`
			Name      string `json:"name"`
			Instances []struct {
				IndexKey   any            `json:"index_key"`
				Attributes map[string]any `json:"attributes"`
			} `json:"instances"`
		} `json:"resources"`
		Values struct {
			RootModule stateModule `json:"root_module"`
		} `json:"values"`
	}
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, err
	}
	ix := newModuleIndex(root)
	out := map[string]CodeLocation{}
	put := func(key string, loc CodeLocation) {
		prev, exists := out[key]
		if !exists {
			out[key] = loc
			return
		}
		if prev.Unresolved == "" && loc.Unresolved == "" && prev.File == loc.File && prev.Line == loc.Line && baseAddress(prev.Address) == baseAddress(loc.Address) {
			return // instances of one resource block (count/for_each)
		}
		if !prev.ambiguous {
			prev.Candidates = []string{prev.Address}
		}
		if !containsStr(prev.Candidates, loc.Address) {
			prev.Candidates = append(prev.Candidates, loc.Address)
		}
		sort.Strings(prev.Candidates)
		prev.ambiguous = true
		prev.Unresolved = fmt.Sprintf("%q identifies %d resources in the state", key, len(prev.Candidates))
		prev.File, prev.Line = "", 0
		out[key] = prev
	}
	add := func(module, typ, name, addr string, attrs map[string]any) {
		loc := CodeLocation{Address: addr, Module: module}
		loc.File, loc.Line, loc.Candidates, loc.Unresolved = ix.locate(module, typ, name)
		if tags, ok := attrs["tags"].(map[string]any); ok {
			if t, ok := tags["yor_trace"].(string); ok && t != "" {
				loc.Trace = t
				put("yor_trace:"+t, loc)
			}
		}
		seen := map[string]bool{}
		for _, k := range []string{"arn", "id", "self_link", "name", "bucket"} {
			if v, ok := attrs[k].(string); ok && v != "" && !seen[v] {
				seen[v] = true
				put(v, loc)
			}
		}
	}
	for _, r := range state.Resources {
		if r.Mode == "data" {
			continue
		}
		base := r.Type + "." + r.Name
		if r.Module != "" {
			base = r.Module + "." + base
		}
		for _, inst := range r.Instances {
			add(r.Module, r.Type, r.Name, base+indexKey(inst.IndexKey), inst.Attributes)
		}
	}
	var walk func(m stateModule)
	walk = func(m stateModule) {
		for _, r := range m.Resources {
			if r.Mode == "data" || strings.HasPrefix(r.Address, "data.") || strings.Contains(r.Address, ".data.") {
				continue
			}
			add(m.Address, r.Type, r.Name, r.Address, r.Values)
		}
		for _, c := range m.ChildModules {
			walk(c)
		}
	}
	walk(state.Values.RootModule)
	return out, nil
}

// indexKey renders a tfstate instance index_key as an address suffix: 0 → [0], "k" → ["k"].
func indexKey(k any) string {
	switch v := k.(type) {
	case nil:
		return ""
	case float64:
		return fmt.Sprintf("[%d]", int64(v))
	case string:
		b, _ := json.Marshal(v)
		return "[" + string(b) + "]"
	}
	return ""
}

// baseAddress drops a trailing instance key: module.a.aws_instance.web[0] → module.a.aws_instance.web.
func baseAddress(addr string) string { return indexSuffix.ReplaceAllString(addr, "") }

// Locate finds the code location for a cloud finding using the mapping. It reports false for
// unmapped findings and for locations LocateStrict would refuse.
func Locate(f model.Finding, mapping map[string]CodeLocation) (CodeLocation, bool) {
	loc, err := LocateStrict(f, mapping)
	return loc, err == nil
}

// LocateStrict is Locate with the reason: an error matching ErrAmbiguousTarget when the first
// identifier of the finding found in the mapping (ID, then name, then yor_trace) does not lead to
// exactly one resource block. Later identifiers are not tried after an ambiguous one.
func LocateStrict(f model.Finding, mapping map[string]CodeLocation) (CodeLocation, error) {
	keys := []string{f.Resource.ID, f.Resource.Name}
	if attrs := f.Resource.Attributes; attrs != nil {
		if tags, ok := attrs["tags"].(map[string]any); ok {
			if t, ok := tags["yor_trace"].(string); ok && t != "" {
				keys = append(keys, "yor_trace:"+t)
			}
		}
	}
	if t := f.Tags["yor_trace"]; t != "" {
		keys = append(keys, "yor_trace:"+t)
	}
	for _, k := range keys {
		if k == "" {
			continue
		}
		loc, ok := mapping[k]
		if !ok {
			continue
		}
		if loc.Unresolved != "" || loc.File == "" {
			reason := loc.Unresolved
			if reason == "" {
				reason = "no source file for the address"
			}
			return CodeLocation{}, &TargetError{File: loc.File, Want: loc.Address, Reason: reason, Candidates: loc.Candidates, CanonicalID: f.CanonicalID}
		}
		return loc, nil
	}
	return CodeLocation{}, fmt.Errorf("no tfstate resource matches %s", f.Resource.ID)
}

// ---------------------------------------------------------------- module resolution

var moduleCall = regexp.MustCompile(`^module\.([A-Za-z0-9_-]+)(\[(?:"(?:[^"\\]|\\.)*"|[^\]"]*)\])?(?:\.|$)`)

// modulePath splits "module.a[0].module.b" into ["a", "b"]. ok is false for anything else.
func modulePath(p string) ([]string, bool) {
	var names []string
	for p != "" {
		m := moduleCall.FindStringSubmatchIndex(p)
		if m == nil {
			return nil, false
		}
		names = append(names, p[m[2]:m[3]])
		p = p[m[1]:]
	}
	return names, true
}

// splitModuleAddress splits a full resource address into its module path and type.name:
// module.a["x"].aws_instance.web[0] → ("module.a[\"x\"]", "aws_instance.web").
func splitModuleAddress(addr string) (module, local string) {
	a := baseAddress(strings.TrimSpace(addr))
	for {
		m := moduleCall.FindStringIndex(a)
		if m == nil {
			break
		}
		module += a[:m[1]]
		a = a[m[1]:]
	}
	return strings.TrimSuffix(module, "."), a
}

type moduleDir struct {
	blocks  map[string][]Block  // type.name → resource blocks declared directly in the dir
	modules map[string][]string // module name → resolved source dirs ("" = not a local source)
}

// moduleIndex resolves module addresses to directories under root, parsing each directory once.
type moduleIndex struct {
	root string
	dirs map[string]*moduleDir
}

func newModuleIndex(root string) *moduleIndex {
	return &moduleIndex{root: filepath.Clean(root), dirs: map[string]*moduleDir{}}
}

func (ix *moduleIndex) dir(d string) *moduleDir {
	d = filepath.Clean(d)
	if md, ok := ix.dirs[d]; ok {
		return md
	}
	md := &moduleDir{blocks: map[string][]Block{}, modules: map[string][]string{}}
	ix.dirs[d] = md
	ents, _ := os.ReadDir(d)
	for _, e := range ents {
		p := filepath.Join(d, e.Name())
		if e.IsDir() || filepath.Ext(p) != ".tf" {
			continue
		}
		if info, err := e.Info(); err != nil || info.Size() > int64(currentLimits().MaxFileBytes) {
			continue
		}
		src, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		bs, _ := parseHCL(src, p)
		for _, b := range bs {
			md.blocks[b.Address] = append(md.blocks[b.Address], b)
		}
		f, _ := parseConfig(src, p)
		if f == nil {
			continue
		}
		body, ok := f.Body.(*hclsyntax.Body)
		if !ok {
			continue
		}
		for _, b := range body.Blocks {
			if b.Type != "module" || len(b.Labels) != 1 {
				continue
			}
			src := ""
			if v, st := attrStringBody(b.Body, "source"); st == stKnown && (strings.HasPrefix(v, "./") || strings.HasPrefix(v, "../")) {
				src = filepath.Join(d, filepath.FromSlash(v))
			}
			md.modules[b.Labels[0]] = append(md.modules[b.Labels[0]], src)
		}
	}
	return md
}

// resolve returns the directory a module path is sourced from.
func (ix *moduleIndex) resolve(module string) (string, error) {
	names, ok := modulePath(module)
	if !ok {
		return "", fmt.Errorf("unrecognised module address %q", module)
	}
	cur := ix.root
	for i, n := range names {
		srcs := ix.dir(cur).modules[n]
		switch {
		case len(srcs) == 0:
			return "", fmt.Errorf("no module %q is declared in %s", n, ix.rel(cur))
		case len(srcs) > 1:
			return "", fmt.Errorf("module %q is declared %d times in %s", n, len(srcs), ix.rel(cur))
		case srcs[0] == "":
			return "", fmt.Errorf("module %s is not a local source; its code is not under the IaC root", strings.Join(names[:i+1], "."))
		}
		next := filepath.Clean(srcs[0])
		if r, err := filepath.Rel(ix.root, next); err != nil || r == ".." || strings.HasPrefix(r, ".."+string(filepath.Separator)) {
			return "", fmt.Errorf("module %q is sourced from outside the IaC root", n)
		}
		cur = next
	}
	return cur, nil
}

// callersOf returns every module call (module.a, module.a.module.inner; instance keys omitted:
// the instances of one count/for_each call share code by design) reachable from root through
// local sources whose source directory is dir.
func (ix *moduleIndex) callersOf(dir string) []string {
	dir = filepath.Clean(dir)
	seen := map[string]bool{}
	var out []string
	var walk func(d, prefix string, depth int)
	walk = func(d, prefix string, depth int) {
		if depth > 32 { // a module cycle; Terraform rejects those
			return
		}
		md := ix.dir(d)
		names := make([]string, 0, len(md.modules))
		for n := range md.modules {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			for _, src := range md.modules[n] {
				if src == "" {
					continue
				}
				next := filepath.Clean(src)
				if r, err := filepath.Rel(ix.root, next); err != nil || r == ".." || strings.HasPrefix(r, ".."+string(filepath.Separator)) {
					continue
				}
				call := prefix + "module." + n
				if next == dir && !seen[call] {
					seen[call] = true
					out = append(out, call)
				}
				walk(next, call+".", depth+1)
			}
		}
	}
	walk(ix.root, "", 0)
	return out
}

func (ix *moduleIndex) rel(p string) string {
	if r, err := filepath.Rel(ix.root, p); err == nil {
		return filepath.ToSlash(r)
	}
	return p
}

// locate finds the single block declaring type.name in the module's directory.
func (ix *moduleIndex) locate(module, typ, name string) (file string, line int, candidates []string, unresolved string) {
	dir, err := ix.resolve(module)
	if err != nil {
		return "", 0, nil, err.Error()
	}
	bs := ix.dir(dir).blocks[typ+"."+name]
	switch len(bs) {
	case 0:
		return "", 0, nil, fmt.Sprintf("no block declares %s.%s in %s", typ, name, ix.rel(dir))
	case 1:
		return ix.rel(bs[0].File), bs[0].Range.Start.Line, nil, ""
	}
	for _, b := range bs {
		candidates = append(candidates, fmt.Sprintf("%s:%d", ix.rel(b.File), b.Range.Start.Line))
	}
	sort.Strings(candidates)
	return "", 0, candidates, fmt.Sprintf("%d blocks declare %s.%s in %s", len(bs), typ, name, ix.rel(dir))
}

// Rules exposes the native rule catalog (for docs / --list).
func Rules() []string {
	var out []string
	for _, r := range rules {
		out = append(out, r.CheckID+" -> "+r.ID+" ("+strings.Join(r.Types, ", ")+")")
	}
	sort.Strings(out)
	return out
}

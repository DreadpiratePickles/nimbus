package iac

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/DreadpiratePickles/nimbus/internal/model"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"
)

// Patch is a proposed in-place change to an IaC file.
type Patch struct {
	File         string  `json:"file"`
	Address      string  `json:"address"`
	CanonicalID  string  `json:"canonical_id"`
	Before       string  `json:"before"`
	After        string  `json:"after"`
	Diff         string  `json:"diff"`
	Explanation  string  `json:"explanation"`
	Confidence   float64 `json:"confidence"`    // 1.0 deterministic rewrite; <1 when assumptions were made
	WidensAccess bool    `json:"widens_access"` // guardrail: must be false before auto-commit
	// DeclaredVariables lists variable blocks the patch appended because the fix references them
	// and the module did not declare them. Variables without a default must be set before plan.
	DeclaredVariables []string `json:"declared_variables,omitempty"`
	LocalAddress      string   `json:"local_address,omitempty"`
	Callers           []string `json:"callers,omitempty"`
}

// ErrAmbiguousTarget is matched (errors.Is) whenever the patcher cannot identify exactly one block
// of a type the fix applies to. The patcher never guesses (inventory defect 7).
var ErrAmbiguousTarget = errors.New("ambiguous patch target")

// TargetError explains a refusal and lists the blocks that could have been meant.
type TargetError struct {
	File        string   `json:"file"`
	Want        string   `json:"want"`   // what the finding identified (address, trace, type/name)
	Reason      string   `json:"reason"` // why no single block was chosen
	Candidates  []string `json:"candidates"`
	CanonicalID string   `json:"canonical_id"`
}

func (e *TargetError) Error() string {
	c := "none"
	if len(e.Candidates) > 0 {
		c = strings.Join(e.Candidates, ", ")
	}
	return fmt.Sprintf("refusing to patch %s for %s in %s: %s (candidates: %s)", e.Want, e.CanonicalID, e.File, e.Reason, c)
}

func (e *TargetError) Is(target error) bool { return target == ErrAmbiguousTarget }

// fixTypes is the set of resource types each deterministic fix knows how to rewrite. A finding
// is only ever patched into a block of one of these types.
var fixTypes = map[string][]string{
	"S3_PUBLIC_BUCKET":             {"aws_s3_bucket", "aws_s3_bucket_acl", "aws_s3_bucket_public_access_block"},
	"EC2_SG_OPEN_SSH":              {"aws_security_group", "aws_security_group_rule", "aws_vpc_security_group_ingress_rule"},
	"EC2_SG_OPEN_RDP":              {"aws_security_group", "aws_security_group_rule", "aws_vpc_security_group_ingress_rule"},
	"EC2_SG_OPEN_ALL":              {"aws_security_group", "aws_security_group_rule", "aws_vpc_security_group_ingress_rule"},
	"EC2_IMDSV1":                   {"aws_instance", "aws_launch_template"},
	"EC2_PUBLIC_IP":                {"aws_instance"},
	"EBS_UNENCRYPTED":              {"aws_ebs_volume"},
	"RDS_PUBLIC":                   {"aws_db_instance", "aws_rds_cluster_instance"},
	"RDS_UNENCRYPTED":              {"aws_db_instance"},
	"CLOUDTRAIL_NO_LOG_VALIDATION": {"aws_cloudtrail"},
	"CLOUDTRAIL_DISABLED":          {"aws_cloudtrail"},
	"KMS_ROTATION_DISABLED":        {"aws_kms_key"},
	"EKS_PUBLIC_ENDPOINT":          {"aws_eks_cluster"},
	"AZ_STORAGE_PUBLIC_BLOB":       {"azurerm_storage_account"},
	"AZ_STORAGE_HTTP_ALLOWED":      {"azurerm_storage_account"},
	"AZ_NSG_OPEN_SSH":              {"azurerm_network_security_rule"},
	"AZ_NSG_OPEN_RDP":              {"azurerm_network_security_rule"},
	"GCP_BUCKET_PUBLIC":            {"google_storage_bucket_iam_member", "google_storage_bucket_iam_binding"},
	"GCP_FIREWALL_OPEN_SSH":        {"google_compute_firewall"},
	"GCP_FIREWALL_OPEN_RDP":        {"google_compute_firewall"},
	"GCP_SQL_PUBLIC":               {"google_sql_database_instance"},
}

// PatchOptions tunes PatchTerraformWith.
type PatchOptions struct {
	// AllCallers allows patching a module source directory that several module calls share
	// (the patch changes every caller; Patch.Callers names them). Without it such a patch is
	// refused (`fix --patch --all-callers`).
	AllCallers bool
}

// PatchTerraform rewrites the block that a finding points at. It returns (nil, nil) when no
// deterministic fix exists for the canonical ID (callers then fall back to the generated
// template), and an error matching ErrAmbiguousTarget when the block cannot be identified.
func PatchTerraform(f model.Finding, root string) (*Patch, error) {
	return PatchTerraformWith(f, root, PatchOptions{})
}

// PatchTerraformWith is PatchTerraform with options.
//
// A module address (module.b[0].aws_instance.web, from tfstate mapping) is patched only in the
// directory that module is sourced from, and only when that directory resolves under root: a
// registry, git, escaping, slash-less or undeclared module is refused, never matched against a
// same-named block elsewhere (Verification 3 defect 7). A source directory shared by several
// module calls is refused unless opts.AllCallers (defect 9). The patch keeps the full module
// address in Address; LocalAddress is the block's type.name in its file.
func PatchTerraformWith(f model.Finding, root string, opts PatchOptions) (*Patch, error) {
	if _, ok := fixTypes[f.CanonicalID]; !ok {
		return nil, nil
	}
	file := f.File
	if !filepath.IsAbs(file) {
		file = filepath.Join(root, file)
	}
	mod, local := splitModuleAddress(f.Resource.ID)
	var callers []string
	if mod != "" {
		ix := newModuleIndex(root)
		dir, err := ix.resolve(mod)
		if err != nil {
			return nil, &TargetError{File: f.File, Want: f.Resource.ID, CanonicalID: f.CanonicalID,
				Reason: fmt.Sprintf("cannot resolve %s to a directory under the IaC root (%v); refusing rather than patching a same-named block elsewhere", mod, err)}
		}
		absDir, _ := filepath.Abs(dir)
		absFileDir, _ := filepath.Abs(filepath.Dir(file))
		if absDir != absFileDir {
			return nil, &TargetError{File: f.File, Want: f.Resource.ID, CanonicalID: f.CanonicalID,
				Reason:     fmt.Sprintf("module %s is sourced from %s, not from the finding's file", mod, filepath.ToSlash(ix.rel(dir))),
				Candidates: []string{local}}
		}
		callers = ix.callersOf(dir)
		if len(callers) > 1 && !opts.AllCallers {
			return nil, &TargetError{File: f.File, Want: f.Resource.ID, CanonicalID: f.CanonicalID,
				Reason:     fmt.Sprintf("%s is the source of %d module calls (%s): a patch there changes every caller; pass --all-callers to patch them all", filepath.ToSlash(ix.rel(dir)), len(callers), strings.Join(callers, ", ")),
				Candidates: callers}
		}
	}
	if info, err := os.Stat(file); err == nil && info.Size() > int64(currentLimits().MaxFileBytes) {
		return nil, &LimitError{File: f.File, Reason: fmt.Sprintf("file size %d bytes exceeds the %d-byte limit (%s)", info.Size(), currentLimits().MaxFileBytes, EnvMaxFileBytes)}
	}
	src, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	p, err := patchSource(f, file, src, moduleVariables(filepath.Dir(file), file))
	if p == nil || err != nil || mod == "" {
		return p, err
	}
	p.Address = mod + "." + p.LocalAddress
	p.Callers = callers
	if len(callers) > 1 {
		p.Explanation += fmt.Sprintf(" The module source is shared: this also changes %s.", strings.Join(callers, ", "))
	}
	return p, nil
}

// moduleVariables returns the variable names declared by the other .tf files of a module dir.
func moduleVariables(dir, except string) map[string]bool {
	out := map[string]bool{}
	ents, err := os.ReadDir(dir)
	if err != nil {
		return out
	}
	for _, e := range ents {
		p := filepath.Join(dir, e.Name())
		if e.IsDir() || filepath.Ext(p) != ".tf" || filepath.Clean(p) == filepath.Clean(except) {
			continue
		}
		src, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		for name := range declaredVariables(src, p) {
			out[name] = true
		}
	}
	return out
}

func declaredVariables(src []byte, name string) map[string]bool {
	f, _ := parseConfig(src, name)
	return declaredIn(f)
}

func declaredIn(f *hcl.File) map[string]bool {
	out := map[string]bool{}
	if f == nil {
		return out
	}
	if body, ok := f.Body.(*hclsyntax.Body); ok {
		for _, b := range body.Blocks {
			if b.Type == "variable" && len(b.Labels) == 1 {
				out[b.Labels[0]] = true
			}
		}
	}
	return out
}

// patchSource is PatchTerraform on in-memory source. moduleVars are variables declared elsewhere
// in the module (nil = none).
func patchSource(f model.Finding, file string, src []byte, moduleVars map[string]bool) (p *Patch, err error) {
	allowed, ok := fixTypes[f.CanonicalID]
	if !ok {
		return nil, nil
	}
	defer func() {
		// hclwrite on pathological input must never take the CLI down.
		if r := recover(); r != nil {
			p, err = nil, fmt.Errorf("patch %s: internal error: %v", file, r)
		}
	}()
	// The hclsyntax tree of the file identifies the target block; hclwrite then rewrites and
	// formats only that block's bytes, which are spliced back. Memory and time stay linear in the
	// file size and nothing outside the target is reformatted (Verification 2 defect 9).
	sf, sdiags := parseConfig(src, file)
	if sdiags.HasErrors() {
		return nil, fmt.Errorf("parse %s: %s", file, sdiags.Error())
	}
	cands, err := syntaxCandidates(sf)
	if err != nil {
		return nil, err
	}
	target, err := resolveTarget(f, file, cands, allowed, sf.Body.(*hclsyntax.Body), src)
	if err != nil {
		return nil, err
	}
	declared := declaredIn(sf)
	addr, typ, labels := target.addr, target.s.Type, target.s.Labels
	rng := target.s.Range()
	start, end := rng.Start.Byte, rng.End.Byte
	if start < 0 || end > len(src) || start >= end {
		return nil, fmt.Errorf("patch %s: block range %d-%d outside the file", file, start, end)
	}
	block := append([]byte{}, src[start:end]...)
	// hclwrite cannot add an attribute to a single-line block (`b { x = 1 }`) without producing
	// invalid HCL (found by FuzzScanHCL), so expand those inside the target first.
	if expanded, ok := expandSingleLineBlocks(block, start, target.s); ok {
		block = expanded
	}
	sf, cands, target = nil, nil, candidate{}

	wf, diags := hclwrite.ParseConfig(block, file, hcl.Pos{Line: 1, Column: 1})
	if diags.HasErrors() {
		return nil, fmt.Errorf("parse %s (block %s): %s", file, addr, diags.Error())
	}
	wbs := wf.Body().Blocks()
	if len(wbs) != 1 || blockSig(wbs[0].Type(), wbs[0].Labels()) != blockSig(typ, labels) {
		return nil, fmt.Errorf("patch %s: block %s did not re-parse as one block", file, addr)
	}
	res := applyFix(wbs[0], f.CanonicalID)
	if !res.applied {
		return nil, nil
	}
	patched := hclwrite.Format(wf.Bytes())
	if !bytes.HasSuffix(block, []byte("\n")) {
		patched = bytes.TrimSuffix(patched, []byte("\n"))
	}
	after := make([]byte, 0, len(src)+len(patched)-(end-start)+256)
	after = append(append(append(after, src[:start]...), patched...), src[end:]...)

	for k := range moduleVars {
		declared[k] = true
	}
	var added []string
	var extra strings.Builder
	for _, v := range res.vars {
		if declared[v.name] {
			continue
		}
		declared[v.name] = true
		added = append(added, v.name)
		extra.WriteString("\n" + v.hcl())
	}
	if extra.Len() > 0 {
		if !bytes.HasSuffix(after, []byte("\n")) {
			after = append(after, '\n')
		}
		after = append(after, hclwrite.Format([]byte(extra.String()))...)
	}
	// Only the patched block (and any appended variables) changed, and the rest of the file parsed
	// with it before, so validating those parts validates the file without a third full parse.
	if _, d := hclsyntax.ParseConfig(patched, file, hcl.Pos{Line: 1, Column: 1}); d.HasErrors() {
		return nil, fmt.Errorf("patch for %s in %s would not parse; refusing: %s", addr, file, d.Error())
	}
	if extra.Len() > 0 {
		if _, d := hclsyntax.ParseConfig([]byte(extra.String()), file, hcl.Pos{Line: 1, Column: 1}); d.HasErrors() {
			return nil, fmt.Errorf("variables added for %s in %s would not parse; refusing: %s", addr, file, d.Error())
		}
	}
	explanation := res.explanation
	if len(added) > 0 {
		explanation += fmt.Sprintf(" Declared variable(s) %s in %s; set them (tfvars or the calling module) before `terraform plan`.", strings.Join(added, ", "), filepath.Base(file))
	}
	p = &Patch{File: f.File, Address: addr, LocalAddress: addr, CanonicalID: f.CanonicalID, Before: string(src), After: string(after), Explanation: explanation, Confidence: res.confidence, DeclaredVariables: added}
	if p.File == "" {
		p.File = filepath.Base(file)
	}
	p.Diff = UnifiedDiff(p.File, string(src), string(after))
	p.WidensAccess = widens(string(src), string(after))
	return p, nil
}

// expandSingleLineBlocks inserts newlines after `{` and before `}` of every block (the target
// and its nested blocks) whose braces sit on one line. ok is false when nothing changed.
// src holds the bytes from file offset base onward (the target block alone).
func expandSingleLineBlocks(src []byte, base int, target *hclsyntax.Block) ([]byte, bool) {
	var offs []int
	var visit func(b *hclsyntax.Block)
	visit = func(b *hclsyntax.Block) {
		if b.OpenBraceRange.Start.Line == b.CloseBraceRange.Start.Line {
			offs = append(offs, b.OpenBraceRange.End.Byte-base, b.CloseBraceRange.Start.Byte-base)
		}
		if b.Body != nil {
			for _, nb := range b.Body.Blocks {
				visit(nb)
			}
		}
	}
	visit(target)
	if len(offs) == 0 {
		return src, false
	}
	sort.Sort(sort.Reverse(sort.IntSlice(offs)))
	out := append([]byte{}, src...)
	for _, o := range offs {
		if o < 0 || o > len(out) {
			return src, false
		}
		out = append(out[:o], append([]byte("\n"), out[o:]...)...)
	}
	return out, true
}

// ---------------------------------------------------------------- target resolution

type candidate struct {
	s    *hclsyntax.Block
	typ  string
	name string
	addr string
}

func blockSig(typ string, labels []string) string { return typ + "\x00" + strings.Join(labels, "\x00") }

// syntaxCandidates returns the top-level resource blocks of a parsed file.
func syntaxCandidates(sf *hcl.File) ([]candidate, error) {
	sbody, ok := sf.Body.(*hclsyntax.Body)
	if !ok {
		return nil, fmt.Errorf("unexpected HCL body")
	}
	var out []candidate
	for _, sb := range sbody.Blocks {
		if sb.Type != "resource" || len(sb.Labels) != 2 {
			continue
		}
		out = append(out, candidate{s: sb, typ: sb.Labels[0], name: sb.Labels[1], addr: sb.Labels[0] + "." + sb.Labels[1]})
	}
	return out, nil
}

var (
	moduleSegment = regexp.MustCompile(`^module\.[A-Za-z0-9_-]+(\[[^\]]*\])?\.`)
	indexSuffix   = regexp.MustCompile(`\[[^\]]*\]$`)
	addressShape  = regexp.MustCompile(`^[a-z][a-z0-9]*_[a-z0-9_]+\.[A-Za-z_][A-Za-z0-9_-]*$`)
)

// normalizeAddress strips module prefixes and an instance key: module.app.aws_instance.web["a"]
// → aws_instance.web. It returns "" when id is not a Terraform resource address (ARN, cloud ID).
func normalizeAddress(id string) string {
	a := strings.TrimSpace(id)
	for moduleSegment.MatchString(a) {
		a = moduleSegment.ReplaceAllString(a, "")
	}
	a = indexSuffix.ReplaceAllString(a, "")
	if addressShape.MatchString(a) {
		return a
	}
	return ""
}

func yorTrace(f model.Finding) string {
	if t := f.Tags["yor_trace"]; t != "" {
		return t
	}
	if f.Resource.Attributes == nil {
		return ""
	}
	switch tags := f.Resource.Attributes["tags"].(type) {
	case map[string]any:
		if s, ok := tags["yor_trace"].(string); ok {
			return s
		}
	case map[string]string:
		return tags["yor_trace"]
	}
	return ""
}

// blockTraces returns every literal `yor_trace = "..."` value inside a block's tags expression,
// however deeply nested (merge(), conditionals, locals-built objects; Verification 2 defect 5).
func blockTraces(c candidate) []string {
	a, ok := c.s.Body.Attributes["tags"]
	if !ok {
		return nil
	}
	var out []string
	hclsyntax.VisitAll(a.Expr, func(n hclsyntax.Node) hcl.Diagnostics {
		obj, ok := n.(*hclsyntax.ObjectConsExpr)
		if !ok {
			return nil
		}
		for _, item := range obj.Items {
			k, kok := safeValue(item.KeyExpr)
			if !kok || k.Type() != cty.String || k.AsString() != "yor_trace" {
				continue
			}
			if v, ok := safeValue(item.ValueExpr); ok && v.Type() == cty.String && !containsStr(out, v.AsString()) {
				out = append(out, v.AsString())
			}
		}
		return nil
	})
	return out
}

// traceState reports the yor_trace values a tags expression sets and whether it may set one
// that is not statically known. merge() is resolved last-argument-wins when its last argument
// sets a literal trace.
func traceState(e hclsyntax.Expression) (traces []string, unknown bool) {
	if v, ok := safeValue(e); ok {
		if v.IsNull() || !(v.Type().IsObjectType() || v.Type().IsMapType()) {
			return nil, false
		}
		var t cty.Value
		switch {
		case v.Type().IsObjectType() && !v.Type().HasAttribute("yor_trace"):
			return nil, false
		case v.Type().IsObjectType():
			t = v.GetAttr("yor_trace")
		case !v.HasIndex(cty.StringVal("yor_trace")).True():
			return nil, false
		default:
			t = v.Index(cty.StringVal("yor_trace"))
		}
		if t.IsNull() || t.Type() != cty.String {
			return nil, true
		}
		return []string{t.AsString()}, false
	}
	switch x := e.(type) {
	case *hclsyntax.ObjectConsExpr:
		for _, item := range x.Items {
			k, ok := safeValue(item.KeyExpr)
			if !ok || k.Type() != cty.String {
				return traces, true // a computed key may be yor_trace
			}
			if k.AsString() != "yor_trace" {
				continue
			}
			v, ok := safeValue(item.ValueExpr)
			if !ok || v.Type() != cty.String {
				return traces, true
			}
			traces = append(traces, v.AsString())
		}
		return traces, false
	case *hclsyntax.FunctionCallExpr:
		if x.Name != "merge" || len(x.Args) == 0 || x.ExpandFinal {
			return nil, true
		}
		if last, unk := traceState(x.Args[len(x.Args)-1]); !unk && len(last) > 0 {
			return last, false
		}
		for _, a := range x.Args {
			ts, unk := traceState(a)
			if unk {
				return nil, true
			}
			traces = append(traces, ts...)
		}
		return traces, false
	}
	return nil, true
}

// traceUnknown reports whether a resource body's tags or tags_all may set a yor_trace that is not
// a literal.
func traceUnknown(body *hclsyntax.Body) bool {
	for _, name := range []string{"tags", "tags_all"} {
		if a, ok := body.Attributes[name]; ok {
			if _, unk := traceState(a.Expr); unk {
				return true
			}
		}
	}
	return false
}

// moduleMayCarryTrace reports whether a module call passes the trace (any literal mention) or a
// tags-like input whose yor_trace is not statically known.
func moduleMayCarryTrace(b *hclsyntax.Block, tr string) bool {
	if mentionsLiteral(candidate{s: b}, tr) {
		return true
	}
	for name, a := range b.Body.Attributes {
		if strings.Contains(name, "tags") {
			if _, unk := traceState(a.Expr); unk {
				return true
			}
		}
	}
	return false
}

// tagsRange is the byte range of the block's tags attribute.
func tagsRange(c candidate) (hcl.Range, bool) {
	a, ok := c.s.Body.Attributes["tags"]
	if !ok {
		return hcl.Range{}, false
	}
	return a.SrcRange, true
}

// onlyWithin reports whether every occurrence of s in src lies inside rng.
func onlyWithin(src []byte, s string, rng hcl.Range) bool {
	for off := 0; ; {
		i := bytes.Index(src[off:], []byte(s))
		if i < 0 {
			return true
		}
		i += off
		if i < rng.Start.Byte || i+len(s) > rng.End.Byte {
			return false
		}
		off = i + len(s)
	}
}

// mentionsLiteral reports whether s appears as a string literal anywhere in the block.
func mentionsLiteral(c candidate, s string) bool {
	found := false
	hclsyntax.VisitAll(c.s.Body, func(n hclsyntax.Node) hcl.Diagnostics {
		if lit, ok := n.(*hclsyntax.LiteralValueExpr); ok && !found {
			if v := lit.Val; v.IsKnown() && !v.IsNull() && v.Type() == cty.String && v.AsString() == s {
				found = true
			}
		}
		return nil
	})
	return found
}

func resolveTarget(f model.Finding, file string, cands []candidate, allowed []string, body *hclsyntax.Body, src []byte) (candidate, error) {
	refuse := func(want, reason string, pool []candidate) error {
		var names []string
		for _, c := range pool {
			names = append(names, c.addr)
		}
		sort.Strings(names)
		return &TargetError{File: file, Want: want, Reason: reason, Candidates: names, CanonicalID: f.CanonicalID}
	}
	ofAllowed := func() []candidate {
		var out []candidate
		for _, c := range cands {
			if containsStr(allowed, c.typ) {
				out = append(out, c)
			}
		}
		return out
	}
	pick := func(want string, matches []candidate) (candidate, error) {
		switch len(matches) {
		case 0:
			return candidate{}, refuse(want, "no block matches", ofAllowed())
		case 1:
			c := matches[0]
			if !containsStr(allowed, c.typ) {
				return candidate{}, refuse(want, fmt.Sprintf("matched %s, but the %s fix only applies to %s", c.addr, f.CanonicalID, strings.Join(allowed, ", ")), ofAllowed())
			}
			return c, nil
		default:
			return candidate{}, refuse(want, fmt.Sprintf("%d blocks match", len(matches)), matches)
		}
	}
	filter := func(keep func(candidate) bool) []candidate {
		var out []candidate
		for _, c := range cands {
			if keep(c) {
				out = append(out, c)
			}
		}
		return out
	}

	// 1. Terraform address (native findings, and cloud findings mapped through tfstate).
	if addr := normalizeAddress(f.Resource.ID); addr != "" {
		return pick(addr, filter(func(c candidate) bool { return c.addr == addr }))
	}
	// 2. Yor trace tag: the strongest link from a live resource to code.
	// Every block carrying the trace literal anywhere is a candidate, so a duplicate hidden in a
	// merge() or a nested block makes the target ambiguous instead of silently picking the other.
	// A block whose trace is not statically known (tags from a local, var, function or built
	// string), and every module call that passes it or an unknown tags value, could be the one
	// carrying it, so they are candidates too; and the trace may not appear anywhere else in the
	// file (a locals/variable default/provider default_tags/comment), Verification 3 defect 8.
	if tr := yorTrace(f); tr != "" {
		want := "yor_trace=" + tr
		matches := filter(func(c candidate) bool {
			return containsStr(blockTraces(c), tr) || mentionsLiteral(c, tr) || traceUnknown(c.s.Body)
		})
		for _, b := range body.Blocks {
			if b.Type == "module" && len(b.Labels) == 1 && (moduleMayCarryTrace(b, tr)) {
				matches = append(matches, candidate{s: b, typ: "module", name: b.Labels[0], addr: "module." + b.Labels[0]})
			}
		}
		if len(matches) == 1 && matches[0].typ != "module" && !traceUnknown(matches[0].s.Body) {
			if rng, ok := tagsRange(matches[0]); !ok || !onlyWithin(src, tr, rng) {
				return candidate{}, refuse(want, fmt.Sprintf("the trace also appears outside %s's tags (a local, variable, provider default_tags or comment), so another resource may carry it", matches[0].addr), matches)
			}
		}
		if len(matches) == 1 && traceUnknown(matches[0].s.Body) {
			return candidate{}, refuse(want, fmt.Sprintf("%s's yor_trace is not a literal (it comes from a local, variable or function)", matches[0].addr), matches)
		}
		if len(matches) > 1 {
			return candidate{}, refuse(want, fmt.Sprintf("%d blocks may carry the trace (literal, or tags that are not statically known)", len(matches)), matches)
		}
		c, err := pick(want, matches)
		if err != nil {
			return c, err
		}
		switch ts := blockTraces(c); {
		case !containsStr(ts, tr):
			return candidate{}, refuse(want, fmt.Sprintf("%s mentions the trace but its tags do not set yor_trace to it", c.addr), []candidate{c})
		case len(ts) > 1:
			return candidate{}, refuse(want, fmt.Sprintf("%s sets conflicting yor_trace values (%s)", c.addr, strings.Join(ts, ", ")), []candidate{c})
		}
		return c, nil
	}
	// 3. Resource type + block name.
	if f.Resource.Type != "" && f.Resource.Name != "" {
		want := f.Resource.Type + "." + f.Resource.Name
		if m := filter(func(c candidate) bool { return c.typ == f.Resource.Type && c.name == f.Resource.Name }); len(m) > 0 {
			return pick(want, m)
		}
	}
	// 4. Source line (scanner findings carry file:line), constrained by type when known.
	if f.LineStart > 0 {
		m := filter(func(c candidate) bool {
			r := c.s.Range()
			return r.Start.Line <= f.LineStart && f.LineStart <= r.End.Line && (f.Resource.Type == "" || c.typ == f.Resource.Type)
		})
		if len(m) > 0 {
			return pick(fmt.Sprintf("%s:%d", filepath.Base(file), f.LineStart), m)
		}
	}
	want := f.Resource.ID
	if want == "" {
		want = f.Resource.Name
	}
	return candidate{}, refuse(want, "no block matches the finding's address, yor_trace, type+name or line", ofAllowed())
}

// ---------------------------------------------------------------- fixes

// varSpec is a variable a fix references; it is declared in the patched file when the module
// does not declare it already.
type varSpec struct {
	name, typ, description, defaultHCL, condition, errMsg string
}

func (v varSpec) hcl() string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Added by nimbus fix: referenced by the patch above.\nvariable %q {\n  description = %q\n  type        = %s\n", v.name, v.description, v.typ)
	if v.defaultHCL != "" {
		fmt.Fprintf(&b, "  default     = %s\n", v.defaultHCL)
	}
	if v.condition != "" {
		fmt.Fprintf(&b, "  validation {\n    condition     = %s\n    error_message = %q\n  }\n", v.condition, v.errMsg)
	}
	b.WriteString("}\n")
	return b.String()
}

// The conditions avoid world-open literals so the never-widen guardrail (a substring count)
// does not trip on the validation text itself.
var (
	varAllowedCIDRs = varSpec{name: "allowed_cidrs", typ: "list(string)",
		description: "REQUIRED: CIDR ranges that may reach the port that was open to the world (e.g. VPN or bastion ranges). No default: nimbus cannot know your ranges.",
		condition:   `length(var.allowed_cidrs) > 0 && alltrue([for c in var.allowed_cidrs : !endswith(c, "/0")])`,
		errMsg:      "allowed_cidrs must list at least one CIDR and must not contain a /0 (world-open) range."}
	varAllowedCIDR = varSpec{name: "allowed_cidr", typ: "string",
		description: "REQUIRED: the IPv4 CIDR that may reach the port that was open to the world. No default: nimbus cannot know your ranges.",
		condition:   `!endswith(var.allowed_cidr, "/0")`,
		errMsg:      "allowed_cidr must not be a /0 (world-open) range."}
	varAllowedSource = varSpec{name: "allowed_source", typ: "string",
		description: "REQUIRED: source address prefix (CIDR or service tag such as VirtualNetwork) allowed on the port that was open to the Internet.",
		condition:   `!contains(["*", "internet", "any"], lower(var.allowed_source)) && !endswith(var.allowed_source, "/0")`,
		errMsg:      "allowed_source must not be *, Internet, Any or a /0 range."}
	varAllowedRanges = varSpec{name: "allowed_ranges", typ: "list(string)",
		description: "REQUIRED: source ranges allowed by the firewall rule. For SSH/RDP via Identity-Aware Proxy use 35.235.240.0/20.",
		condition:   `length(var.allowed_ranges) > 0 && alltrue([for c in var.allowed_ranges : !endswith(c, "/0")])`,
		errMsg:      "allowed_ranges must list at least one range and must not contain a /0 range."}
	varBucketReader = varSpec{name: "bucket_reader", typ: "string",
		description: "REQUIRED: the principal that should read the bucket instead of the public (e.g. group:readers@example.com).",
		condition:   `!startswith(var.bucket_reader, "all")`,
		errMsg:      "bucket_reader must be a specific principal, not a public member."}
)

type fixResult struct {
	explanation string
	confidence  float64
	applied     bool
	vars        []varSpec
}

func done(expl string, conf float64, vars ...varSpec) fixResult {
	return fixResult{explanation: expl, confidence: conf, applied: true, vars: vars}
}

// exprTokens parses an HCL expression into tokens for SetAttributeRaw.
func exprTokens(expr string) hclwrite.Tokens {
	f, d := hclwrite.ParseConfig([]byte("x = "+expr+"\n"), "expr.tf", hcl.Pos{Line: 1, Column: 1})
	if d.HasErrors() {
		return nil
	}
	return f.Body().GetAttribute("x").Expr().BuildTokens(nil)
}

// literalList returns the string literals of a list attribute written as a static list, or
// ok=false when the expression is not a static list of strings.
func literalList(body *hclwrite.Body, name string) ([]string, bool) {
	a := body.GetAttribute(name)
	if a == nil {
		return nil, false
	}
	src := a.Expr().BuildTokens(nil).Bytes()
	e, d := hclsyntax.ParseExpression(src, "expr.tf", hcl.Pos{Line: 1, Column: 1})
	if d.HasErrors() {
		return nil, false
	}
	if _, ok := e.(*hclsyntax.TupleConsExpr); !ok {
		return nil, false
	}
	v, ok := safeValue(e)
	if !ok {
		return nil, false
	}
	return stringElems(v), true
}

func hclList(items []string) string {
	q := make([]string, len(items))
	for i, s := range items {
		q[i] = fmt.Sprintf("%q", s)
	}
	return "[" + strings.Join(q, ", ") + "]"
}

// narrowList replaces world-open entries of a list attribute with varName, keeping every other
// entry (least change). It reports whether the attribute contained a world-open entry.
func narrowList(body *hclwrite.Body, attr string, isWorld func(string) bool, varName string) bool {
	a := body.GetAttribute(attr)
	if a == nil {
		return false
	}
	items, static := literalList(body, attr)
	if !static {
		if !strings.Contains(string(a.Expr().BuildTokens(nil).Bytes()), "0.0.0.0/0") {
			return false
		}
		body.SetAttributeRaw(attr, exprTokens("var."+varName))
		return true
	}
	var keep []string
	world := false
	for _, s := range items {
		if isWorld(s) {
			world = true
			continue
		}
		keep = append(keep, s)
	}
	if !world {
		return false
	}
	if len(keep) == 0 {
		body.SetAttributeRaw(attr, exprTokens("var."+varName))
	} else {
		body.SetAttributeRaw(attr, exprTokens(fmt.Sprintf("concat(%s, var.%s)", hclList(keep), varName)))
	}
	return true
}

func isV4World(s string) bool { return s == "0.0.0.0/0" }

func applyFix(b *hclwrite.Block, canonical string) fixResult {
	body := b.Body()
	typ := b.Labels()[0]
	switch canonical {
	case "S3_PUBLIC_BUCKET":
		if typ == "aws_s3_bucket" || typ == "aws_s3_bucket_acl" {
			body.SetAttributeValue("acl", cty.StringVal("private"))
			return done("Set acl = \"private\"; add an aws_s3_bucket_public_access_block with all four flags true to block policy-based exposure.", 1)
		}
		if typ == "aws_s3_bucket_public_access_block" {
			for _, k := range []string{"block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"} {
				body.SetAttributeValue(k, cty.True)
			}
			return done("Enabled all four public access block settings.", 1)
		}
	case "EC2_SG_OPEN_SSH", "EC2_SG_OPEN_RDP", "EC2_SG_OPEN_ALL":
		changed := false
		var vars []varSpec
		for _, nb := range body.Blocks() {
			if nb.Type() != "ingress" {
				continue
			}
			if narrowList(nb.Body(), "cidr_blocks", isV4World, "allowed_cidrs") {
				changed = true
				vars = []varSpec{varAllowedCIDRs}
			}
			if items, ok := literalList(nb.Body(), "ipv6_cidr_blocks"); ok && contains(items, "::/0") {
				var keep []string
				for _, s := range items {
					if s != "::/0" {
						keep = append(keep, s)
					}
				}
				if len(keep) == 0 {
					nb.Body().RemoveAttribute("ipv6_cidr_blocks")
				} else {
					nb.Body().SetAttributeRaw("ipv6_cidr_blocks", exprTokens(hclList(keep)))
				}
				changed = true
			}
		}
		if typ == "aws_security_group_rule" && narrowList(body, "cidr_blocks", isV4World, "allowed_cidrs") {
			changed = true
			vars = []varSpec{varAllowedCIDRs}
		}
		if typ == "aws_vpc_security_group_ingress_rule" {
			if v, st := attrStringW(body, "cidr_ipv4"); st == stKnown && isV4World(v) {
				body.SetAttributeRaw("cidr_ipv4", exprTokens("var.allowed_cidr"))
				changed = true
				vars = []varSpec{varAllowedCIDR}
			}
		}
		if changed {
			return done("Replaced the world-open source (0.0.0.0/0, ::/0) with an explicit allow-list variable; other sources on the rule are kept.", 0.8, vars...)
		}
	case "EC2_IMDSV1":
		var mo *hclwrite.Block
		for _, nb := range body.Blocks() {
			if nb.Type() == "metadata_options" {
				mo = nb
			}
		}
		if mo == nil {
			mo = body.AppendNewBlock("metadata_options", nil)
		}
		mo.Body().SetAttributeValue("http_endpoint", cty.StringVal("enabled"))
		mo.Body().SetAttributeValue("http_tokens", cty.StringVal("required"))
		if mo.Body().GetAttribute("http_put_response_hop_limit") == nil {
			// Hop limit 1 blocks containers on the host from reaching IMDS; keep an explicit value.
			mo.Body().SetAttributeValue("http_put_response_hop_limit", cty.NumberIntVal(1))
		}
		return done("Require IMDSv2 (http_tokens = \"required\"); hop limit 1 unless one was set. Check that SDKs on the instance support IMDSv2.", 0.9)
	case "EC2_PUBLIC_IP":
		body.SetAttributeValue("associate_public_ip_address", cty.False)
		return done("Disabled public IP association. NOTE: this forces replacement of an existing aws_instance; review the plan and front the instance with a load balancer or NAT.", 0.6)
	case "EBS_UNENCRYPTED":
		body.SetAttributeValue("encrypted", cty.True)
		return done("Enabled EBS encryption with the account default KMS key. NOTE: forces replacement of an existing volume; snapshot first.", 0.7)
	case "RDS_PUBLIC":
		body.SetAttributeValue("publicly_accessible", cty.False)
		return done("Made the RDS instance private. Clients outside the VPC lose access.", 0.9)
	case "RDS_UNENCRYPTED":
		body.SetAttributeValue("storage_encrypted", cty.True)
		return done("Enabled storage encryption (note: forces replacement for an existing instance; snapshot first).", 0.6)
	case "CLOUDTRAIL_NO_LOG_VALIDATION":
		body.SetAttributeValue("enable_log_file_validation", cty.True)
		return done("Enabled log file validation.", 1)
	case "CLOUDTRAIL_DISABLED":
		body.SetAttributeValue("is_multi_region_trail", cty.True)
		body.SetAttributeValue("include_global_service_events", cty.True)
		return done("Made the trail multi-region including global service events.", 1)
	case "KMS_ROTATION_DISABLED":
		body.SetAttributeValue("enable_key_rotation", cty.True)
		return done("Enabled annual key rotation.", 1)
	case "EKS_PUBLIC_ENDPOINT":
		for _, nb := range body.Blocks() {
			if nb.Type() == "vpc_config" {
				nb.Body().SetAttributeValue("endpoint_public_access", cty.False)
				nb.Body().SetAttributeValue("endpoint_private_access", cty.True)
				return done("Disabled the public API endpoint and enabled private access. kubectl/CI outside the VPC lose access.", 0.8)
			}
		}
	case "AZ_STORAGE_PUBLIC_BLOB":
		body.SetAttributeValue("allow_nested_items_to_be_public", cty.False)
		return done("Disabled anonymous blob access.", 1)
	case "AZ_STORAGE_HTTP_ALLOWED":
		attr := "https_traffic_only_enabled"
		if body.GetAttribute("enable_https_traffic_only") != nil {
			attr = "enable_https_traffic_only" // keep the provider-version-specific name in use
		}
		body.SetAttributeValue(attr, cty.True)
		if body.GetAttribute("min_tls_version") == nil {
			body.SetAttributeValue("min_tls_version", cty.StringVal("TLS1_2"))
		}
		return done("Enforced HTTPS (and TLS 1.2 when no minimum was set).", 1)
	case "AZ_NSG_OPEN_SSH", "AZ_NSG_OPEN_RDP":
		body.SetAttributeRaw("source_address_prefix", exprTokens("var.allowed_source"))
		return done("Replaced the Internet/Any source with var.allowed_source.", 0.8, varAllowedSource)
	case "GCP_BUCKET_PUBLIC":
		if a := body.GetAttribute("member"); a != nil {
			body.SetAttributeRaw("member", exprTokens("var.bucket_reader"))
			return done("Replaced the public member with var.bucket_reader (a specific principal).", 0.8, varBucketReader)
		}
		if body.GetAttribute("members") != nil {
			if items, ok := literalList(body, "members"); ok {
				var keep []string
				for _, m := range items {
					if !isGCPPublic(m) {
						keep = append(keep, m)
					}
				}
				if len(keep) > 0 && len(keep) < len(items) {
					body.SetAttributeRaw("members", exprTokens(hclList(keep)))
					return done("Removed allUsers/allAuthenticatedUsers from the binding; the named members are kept.", 0.9)
				}
				if len(keep) == 0 {
					body.SetAttributeRaw("members", exprTokens("[var.bucket_reader]"))
					return done("Replaced the public members with var.bucket_reader.", 0.8, varBucketReader)
				}
			}
		}
	case "GCP_FIREWALL_OPEN_SSH", "GCP_FIREWALL_OPEN_RDP":
		if narrowList(body, "source_ranges", isV4World, "allowed_ranges") {
			return done("Replaced 0.0.0.0/0 with var.allowed_ranges; other ranges are kept. Every port in this rule's allow blocks is narrowed.", 0.8, varAllowedRanges)
		}
	case "GCP_SQL_PUBLIC":
		for _, s := range body.Blocks() {
			if s.Type() == "settings" {
				for _, ip := range s.Body().Blocks() {
					if ip.Type() == "ip_configuration" {
						ip.Body().SetAttributeValue("ipv4_enabled", cty.False)
						return done("Disabled the public IPv4 address; requires private IP (private_network) or the Cloud SQL Auth Proxy.", 0.7)
					}
				}
			}
		}
	}
	return fixResult{}
}

// attrStringW evaluates a literal string attribute of an hclwrite body.
func attrStringW(body *hclwrite.Body, name string) (string, attrState) {
	a := body.GetAttribute(name)
	if a == nil {
		return "", stAbsent
	}
	e, d := hclsyntax.ParseExpression(a.Expr().BuildTokens(nil).Bytes(), "expr.tf", hcl.Pos{Line: 1, Column: 1})
	if d.HasErrors() {
		return "", stUnknown
	}
	v, ok := safeValue(e)
	if !ok || v.IsNull() || v.Type() != cty.String {
		return "", stUnknown
	}
	return v.AsString(), stKnown
}

// widens is the "never widen access" guardrail: the patch must not introduce new world-open CIDRs,
// public ACLs, wildcard policies or publicly_accessible = true.
func widens(before, after string) bool {
	count := func(s, sub string) int { return strings.Count(s, sub) }
	for _, bad := range []string{"0.0.0.0/0", "::/0", "public-read", "allUsers", "allAuthenticatedUsers", "publicly_accessible = true", "\"Action\": \"*\""} {
		if count(after, bad) > count(before, bad) {
			return true
		}
	}
	return false
}

package cli

import (
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"

	"github.com/DreadpiratePickles/nimbus/internal/iac"
	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// patchVerdict is what re-scanning a patched file proved about the finding it targets.
type patchVerdict int

const (
	// verdictVerified: the re-scan evaluated the same check on the same resource in the
	// same file and it passes.
	verdictVerified patchVerdict = iota
	// verdictNotFixed: the same finding is still present after the patch.
	verdictNotFixed
	// verdictUnverified: the re-scan could not decide (unmapped finding, unusable temp
	// dir, no scanner check for this canonical id, values not statically known, ...).
	verdictUnverified
)

func (v patchVerdict) String() string {
	return [...]string{"verified", "not fixed", "unverified"}[v]
}

type verifyResult struct {
	Verdict patchVerdict
	Reason  string
}

func verified() verifyResult { return verifyResult{Verdict: verdictVerified} }
func unverifiedf(format string, a ...any) verifyResult {
	return verifyResult{Verdict: verdictUnverified, Reason: fmt.Sprintf(format, a...)}
}
func notFixed(canonical, where string) verifyResult {
	return verifyResult{Verdict: verdictNotFixed, Reason: fmt.Sprintf("not fixed: %s still present (%s)", canonical, where)}
}

// verifyPatch reports whether the patch is proven to remove the finding.
func verifyPatch(f model.Finding, p iac.Patch) bool {
	return verifyPatchResult(f, p).Verdict == verdictVerified
}

// tfAddress matches a (module-stripped, key-stripped) Terraform resource address.
var tfAddress = regexp.MustCompile(`^(data\.)?[A-Za-z][A-Za-z0-9_-]*\.[A-Za-z_][A-Za-z0-9_-]*$`)

// verifyPatchResult re-scans the patched file in a temp copy (same root-relative path)
// and requires the SPECIFIC finding — same canonical id, same resource address, same
// file — to be evaluated and passing. Anything less is not success: a finding that is
// not mapped to a Terraform address, a temp dir that cannot be used, a canonical id
// the scanner has no check for, or values that are not statically known are
// "unverified"; the same finding failing again is "not fixed".
func verifyPatchResult(f model.Finding, p iac.Patch) verifyResult {
	want := shortAddress(f.Resource.ID)
	if !tfAddress.MatchString(want) {
		return unverifiedf("finding resource %q is not mapped to a Terraform address (use --tfstate)", f.Resource.ID)
	}
	if p.Address != "" && shortAddress(p.Address) != want {
		return unverifiedf("the patch changed %s but the finding is on %s", p.Address, f.Resource.ID)
	}
	rel := filepath.ToSlash(filepath.Clean(firstNonEmpty(p.File, f.File, "main.tf")))
	if filepath.IsAbs(rel) || rel == ".." || strings.HasPrefix(rel, "../") {
		rel = filepath.Base(rel)
	}
	if isAWSSGCheck(f.CanonicalID) {
		return verifySGPatch(f.CanonicalID, want, rel, []byte(p.After))
	}
	tmp, err := os.MkdirTemp("", "cp-verify")
	if err != nil {
		return unverifiedf("re-scan temp dir: %v", err)
	}
	defer os.RemoveAll(tmp)
	path := filepath.Join(tmp, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return unverifiedf("re-scan temp dir: %v", err)
	}
	if err := os.WriteFile(path, []byte(p.After), 0o644); err != nil {
		return unverifiedf("re-scan temp file: %v", err)
	}
	sr, err := iac.ScanTerraformResult(tmp, time.Now())
	if reason, ok := sr.UnscannedReasons[rel]; ok {
		// The patched file does not parse: nothing in it was examined (UnscannedFiles contract).
		return unverifiedf("the patched %s was not scanned (%s)", rel, reason)
	}
	if err != nil {
		return unverifiedf("re-scan failed: %v", err)
	}
	fs := sr.Findings
	seen, passed := false, false
	for _, x := range fs {
		if x.CanonicalID != f.CanonicalID || shortAddress(x.Resource.ID) != want || filepath.ToSlash(x.File) != rel {
			continue
		}
		switch x.Status {
		case model.Fail:
			return notFixed(f.CanonicalID, want+" in "+rel)
		case model.Pass:
			passed = true
		}
		seen = true
	}
	switch {
	case passed:
		return verified()
	case seen:
		return unverifiedf("the re-scan could not evaluate %s on %s (values not statically known)", f.CanonicalID, want)
	}
	return unverifiedf("the re-scan has no %s result for %s in %s", f.CanonicalID, want, rel)
}

// ---------------------------------------------------------------- AWS security groups

func isAWSSGCheck(c string) bool {
	return c == "EC2_SG_OPEN_SSH" || c == "EC2_SG_OPEN_RDP" || c == "EC2_SG_OPEN_ALL"
}

// tri is a three-valued truth: no, maybe (not statically known), yes.
type tri int

const (
	triNo tri = iota
	triMaybe
	triYes
)

func triOr(a, b tri) tri {
	if a > b {
		return a
	}
	return b
}

// sgRule is one ingress rule's attributes plus the evaluation context they need.
type sgRule struct {
	body  *hclsyntax.Body
	ctx   *hcl.EvalContext
	where string
	// kind: "inline" (aws_security_group ingress), "rule" (aws_security_group_rule),
	// "vpc" (aws_vpc_security_group_ingress_rule).
	kind string
}

// verifySGPatch decides port exposure itself because the scanner's SG rule is not
// port-aware (it reports any world-open ingress as EC2_SG_OPEN_SSH) and does not see
// dynamic "ingress" blocks. EC2_SG_OPEN_SSH is port 22, EC2_SG_OPEN_RDP port 3389 and
// EC2_SG_OPEN_ALL any world-open ingress. Rules are the group's inline ingress and
// dynamic "ingress" blocks plus standalone rules in the file whose security_group_id
// references the group.
func verifySGPatch(canonical, address, rel string, src []byte) verifyResult {
	file, diags := hclsyntax.ParseConfig(src, rel, hcl.InitialPos)
	if diags.HasErrors() || file == nil {
		return unverifiedf("patched %s does not parse: %s", rel, diags.Error())
	}
	body, ok := file.Body.(*hclsyntax.Body)
	if !ok {
		return unverifiedf("patched %s: unexpected body", rel)
	}
	typ, name, _ := strings.Cut(address, ".")
	var target *hclsyntax.Block
	for _, b := range body.Blocks {
		if b.Type == "resource" && len(b.Labels) == 2 && b.Labels[0] == typ && b.Labels[1] == name {
			target = b
		}
	}
	if target == nil {
		return unverifiedf("%s is not in the patched %s", address, rel)
	}
	var rules []sgRule
	undecided := []string{}
	switch typ {
	case "aws_security_group":
		if _, ok := target.Body.Attributes["ingress"]; ok {
			undecided = append(undecided, "ingress given as an attribute")
		}
		for _, nb := range target.Body.Blocks {
			switch {
			case nb.Type == "ingress":
				rules = append(rules, sgRule{body: nb.Body, where: fmt.Sprintf("%s ingress at line %d", address, nb.DefRange().Start.Line), kind: "inline"})
			case nb.Type == "dynamic" && len(nb.Labels) == 1 && nb.Labels[0] == "ingress":
				rs, why := expandDynamic(nb, address)
				rules = append(rules, rs...)
				if why != "" {
					undecided = append(undecided, why)
				}
			}
		}
		for _, b := range body.Blocks {
			if b.Type == "resource" && len(b.Labels) == 2 && (b.Labels[0] == "aws_security_group_rule" || b.Labels[0] == "aws_vpc_security_group_ingress_rule") && referencesSG(b.Body, name) {
				kind := "rule"
				if b.Labels[0] == "aws_vpc_security_group_ingress_rule" {
					kind = "vpc"
				}
				rules = append(rules, sgRule{body: b.Body, where: b.Labels[0] + "." + b.Labels[1], kind: kind})
			}
		}
	case "aws_security_group_rule":
		rules = append(rules, sgRule{body: target.Body, where: address, kind: "rule"})
	case "aws_vpc_security_group_ingress_rule":
		rules = append(rules, sgRule{body: target.Body, where: address, kind: "vpc"})
	default:
		return unverifiedf("%s is not a security group or rule", address)
	}
	port := map[string]int{"EC2_SG_OPEN_SSH": 22, "EC2_SG_OPEN_RDP": 3389, "EC2_SG_OPEN_ALL": -1}[canonical]
	for _, r := range rules {
		open, covers := r.exposure(port)
		switch {
		case open == triYes && covers == triYes:
			return notFixed(canonical, r.where)
		case open != triNo && covers != triNo:
			undecided = append(undecided, r.where)
		}
	}
	if len(undecided) > 0 {
		return unverifiedf("cannot confirm %s is closed on %s: %s not statically known", canonical, address, strings.Join(undecided, ", "))
	}
	return verified()
}

// referencesSG reports a standalone rule whose security_group_id points at
// aws_security_group.<name>.
func referencesSG(b *hclsyntax.Body, name string) bool {
	a, ok := b.Attributes["security_group_id"]
	if !ok {
		return false
	}
	for _, tr := range a.Expr.Variables() {
		if tr.RootName() != "aws_security_group" || len(tr) < 2 {
			continue
		}
		if at, ok := tr[1].(hcl.TraverseAttr); ok && at.Name == name {
			return true
		}
	}
	return false
}

// expandDynamic turns a dynamic "ingress" block into one rule per for_each element
// (the iterator bound in an EvalContext). An unknown for_each yields one rule whose
// iterator is unknown, so only literal attributes can decide it.
func expandDynamic(b *hclsyntax.Block, address string) ([]sgRule, string) {
	iter := "ingress"
	if a, ok := b.Body.Attributes["iterator"]; ok {
		if tr, d := hcl.AbsTraversalForExpr(a.Expr); !d.HasErrors() {
			iter = tr.RootName()
		}
	}
	var content *hclsyntax.Block
	for _, nb := range b.Body.Blocks {
		if nb.Type == "content" {
			content = nb
		}
	}
	if content == nil {
		return nil, ""
	}
	where := fmt.Sprintf("%s dynamic ingress at line %d", address, b.DefRange().Start.Line)
	unknownRule := []sgRule{{body: content.Body, where: where, kind: "inline",
		ctx: &hcl.EvalContext{Variables: map[string]cty.Value{iter: cty.DynamicVal}}}}
	fe, ok := b.Body.Attributes["for_each"]
	if !ok {
		return unknownRule, ""
	}
	v, d := fe.Expr.Value(nil)
	if d.HasErrors() || !v.IsWhollyKnown() || v.IsNull() || !v.CanIterateElements() {
		return unknownRule, ""
	}
	var out []sgRule
	for it := v.ElementIterator(); it.Next(); {
		k, val := it.Element()
		out = append(out, sgRule{body: content.Body, where: where, kind: "inline",
			ctx: &hcl.EvalContext{Variables: map[string]cty.Value{iter: cty.ObjectVal(map[string]cty.Value{"key": k, "value": val})}}})
	}
	return out, ""
}

// value evaluates attribute name; ok is false when it is absent, and known is false
// when it is present but not statically known.
func (r sgRule) value(name string) (v cty.Value, present, known bool) {
	a, ok := r.body.Attributes[name]
	if !ok {
		return cty.NilVal, false, true
	}
	v, d := a.Expr.Value(r.ctx)
	if d.HasErrors() || !v.IsWhollyKnown() {
		return cty.NilVal, true, false
	}
	return v, true, true
}

func (r sgRule) str(name string) (string, tri) {
	v, present, known := r.value(name)
	switch {
	case !present:
		return "", triNo
	case !known || v.IsNull():
		return "", triMaybe
	}
	if v.Type() == cty.Number {
		return v.AsBigFloat().Text('f', -1), triYes
	}
	if v.Type() != cty.String {
		return "", triMaybe
	}
	return strings.ToLower(strings.TrimSpace(v.AsString())), triYes
}

func (r sgRule) num(name string) (int64, tri) {
	v, present, known := r.value(name)
	switch {
	case !present:
		return 0, triNo
	case !known || v.IsNull():
		return 0, triMaybe
	}
	if v.Type() == cty.String {
		var n big.Float
		if _, ok := n.SetString(strings.TrimSpace(v.AsString())); !ok {
			return 0, triMaybe
		}
		i, _ := n.Int64()
		return i, triYes
	}
	if v.Type() != cty.Number {
		return 0, triMaybe
	}
	i, _ := v.AsBigFloat().Int64()
	return i, triYes
}

// worldOpen reports whether the rule's sources include 0.0.0.0/0 or ::/0.
func (r sgRule) worldOpen() tri {
	res := triNo
	listAttrs, strAttrs := []string{"cidr_blocks", "ipv6_cidr_blocks"}, []string(nil)
	if r.kind == "vpc" {
		listAttrs, strAttrs = nil, []string{"cidr_ipv4", "cidr_ipv6"}
	}
	for _, name := range listAttrs {
		v, present, known := r.value(name)
		if !present {
			continue
		}
		if !known || v.IsNull() || !v.CanIterateElements() {
			res = triOr(res, triMaybe)
			continue
		}
		for it := v.ElementIterator(); it.Next(); {
			_, e := it.Element()
			if e.Type() != cty.String || e.IsNull() {
				res = triOr(res, triMaybe)
				continue
			}
			if s := strings.TrimSpace(e.AsString()); s == "0.0.0.0/0" || s == "::/0" {
				return triYes
			}
		}
	}
	for _, name := range strAttrs {
		s, t := r.str(name)
		if t == triYes && (s == "0.0.0.0/0" || s == "::/0") {
			return triYes
		}
		if t == triMaybe {
			res = triOr(res, triMaybe)
		}
	}
	return res
}

// exposure returns (world-open, covers port); port < 0 means "any port".
func (r sgRule) exposure(port int) (tri, tri) {
	open := r.worldOpen()
	if r.kind == "rule" {
		t, tt := r.str("type")
		switch {
		case tt == triMaybe:
			open = triOr(triNo, min(open, triMaybe))
		case tt == triYes && t != "ingress":
			return triNo, triNo
		}
	}
	if port < 0 {
		return open, triYes
	}
	protoAttr := "protocol"
	if r.kind == "vpc" {
		protoAttr = "ip_protocol"
	}
	proto, pt := r.str(protoAttr)
	if pt == triMaybe {
		return open, triMaybe
	}
	switch proto {
	case "-1", "all":
		return open, triYes
	case "tcp", "6":
	default:
		if pt == triNo && r.kind != "vpc" {
			return open, triMaybe
		}
		return open, triNo
	}
	from, ft := r.num("from_port")
	to, tt := r.num("to_port")
	if ft != triYes || tt != triYes {
		return open, triMaybe
	}
	if int64(port) >= from && int64(port) <= to {
		return open, triYes
	}
	return open, triNo
}

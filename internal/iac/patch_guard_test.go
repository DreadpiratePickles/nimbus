package iac

import (
	"errors"
	"sort"
	"strings"
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// mod3Tree is scratchpad verify-3/iac/mod3/infra: local, nested, shared, registry, git, escaping
// and slash-less module sources next to a same-named root block.
func mod3Tree(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	writeTree(t, d, map[string]string{
		"infra/main.tf": `module "a" {
  source = "./modules/a"
}
module "b" {
  source = "./modules/web"
  count  = 2
}
module "c" {
  source   = "./modules/web/"
  for_each = toset(["k"])
}
module "reg" {
  source = "terraform-aws-modules/ec2-instance/aws"
}
module "gitsrc" {
  source = "git::https://example.com/x.git//modules/web"
}
module "esc" {
  source = "../outside"
}
module "noslash" {
  source = "modules/a"
}
module "solo" {
  source = "./modules/solo"
  count  = 3
}
resource "aws_instance" "web" {
  ami = "ROOT"
}
`,
		"infra/modules/a/main.tf":     "module \"inner\" {\n  source = \"../inner\"\n}\nresource \"aws_instance\" \"web\" {\n  ami = \"A\"\n}\n",
		"infra/modules/inner/main.tf": "resource \"aws_instance\" \"web\" {\n  ami = \"INNER\"\n}\n",
		"infra/modules/web/main.tf":   "resource \"aws_instance\" \"web\" {\n  ami = \"WEB\"\n}\n",
		"infra/modules/solo/main.tf":  "resource \"aws_instance\" \"web\" {\n  ami = \"SOLO\"\n}\n",
		"outside/main.tf":             "resource \"aws_instance\" \"web\" {\n  ami = \"OUTSIDE\"\n}\n",
	})
	return d + "/infra"
}

// Verification 3 defect 7 (MEDIUM): PatchTerraform checked the module only when it resolved
// (`if dir, err := resolve(mod); err == nil`), so a registry, git, escaping or undeclared module
// fell through and patched the same-named ROOT block (verify-3/iac/mod3 find_failopen.json:
// module.reg.aws_instance.web → root aws_instance.web patched).
func TestPatchRefusesUnresolvableModule(t *testing.T) {
	root := mod3Tree(t)
	for _, c := range []struct{ id, file string }{
		{"module.reg.aws_instance.web", "main.tf"},
		{"module.gitsrc.aws_instance.web", "main.tf"},
		{"module.esc.aws_instance.web", "main.tf"},
		{"module.esc.aws_instance.web", "../outside/main.tf"},
		{"module.nosuch.aws_instance.web", "main.tf"},
		{"module.noslash.aws_instance.web", "main.tf"},
		{"module.noslash.aws_instance.web", "modules/a/main.tf"},
		{"module.a.module.nosuch.aws_instance.web", "modules/a/main.tf"},
	} {
		f := model.Finding{CanonicalID: "EC2_IMDSV1", File: c.file, Resource: model.Resource{ID: c.id, Type: "aws_instance"}}
		p, err := PatchTerraform(f, root)
		if p != nil || !errors.Is(err, ErrAmbiguousTarget) {
			addr := ""
			if p != nil {
				addr = p.File + " " + p.Address
			}
			t.Errorf("%s in %s: want a refusal, got patch %q err %v", c.id, c.file, addr, err)
		}
	}
	// The wrong_target fixture declares no module "app": a module address must not fall back to
	// the root block of the same name (this used to be expected to patch aws_instance.web).
	dir := copyFixture(t, "wrong_target")
	if p, err := PatchTerraform(imdsFinding(model.Resource{ID: "module.app.aws_instance.web"}), dir); p != nil || !errors.Is(err, ErrAmbiguousTarget) {
		t.Errorf("module.app (undeclared): want a refusal, got %v %v", p != nil, err)
	}
}

// Verification 3 defect 9 (MEDIUM): modules b (count = 2) and c (for_each) share ./modules/web, so
// a patch for module.b[0] also changes module.b[1] and module.c["k"]; it was applied with no
// warning and the patch address dropped the module (verify-3/iac/mod3 b0.db).
func TestPatchSharedModuleSourceNeedsAllCallers(t *testing.T) {
	root := mod3Tree(t)
	f := model.Finding{CanonicalID: "EC2_IMDSV1", File: "modules/web/main.tf", Resource: model.Resource{ID: "module.b[0].aws_instance.web", Type: "aws_instance"}}
	p, err := PatchTerraform(f, root)
	var te *TargetError
	if p != nil || !errors.As(err, &te) || !strings.Contains(te.Reason, `module.c`) || !strings.Contains(te.Reason, "--all-callers") {
		t.Fatalf("shared source: want a refusal naming module.c and --all-callers, got patch=%v err=%v", p != nil, err)
	}
	p, err = PatchTerraformWith(f, root, PatchOptions{AllCallers: true})
	if err != nil || p == nil {
		t.Fatalf("--all-callers: %v", err)
	}
	if p.Address != "module.b[0].aws_instance.web" || p.LocalAddress != "aws_instance.web" {
		t.Errorf("address = %q local = %q, want the module prefix kept", p.Address, p.LocalAddress)
	}
	sort.Strings(p.Callers)
	if strings.Join(p.Callers, ",") != `module.b,module.c` || !strings.Contains(p.Explanation, "module.c") {
		t.Errorf("callers = %v, explanation %q: want both module calls named", p.Callers, p.Explanation)
	}
	// One caller (instances of one count/for_each call share code by design): no flag needed,
	// and the address keeps every module segment.
	for _, c := range []struct{ id, file, want string }{
		{"module.solo[2].aws_instance.web", "modules/solo/main.tf", "module.solo[2].aws_instance.web"},
		{"module.a.aws_instance.web", "modules/a/main.tf", "module.a.aws_instance.web"},
		{"module.a.module.inner.aws_instance.web", "modules/inner/main.tf", "module.a.module.inner.aws_instance.web"},
	} {
		f := model.Finding{CanonicalID: "EC2_IMDSV1", File: c.file, Resource: model.Resource{ID: c.id, Type: "aws_instance"}}
		p, err := PatchTerraform(f, root)
		if err != nil || p == nil || p.Address != c.want {
			t.Errorf("%s: want a patch addressed %s, got %v %v", c.id, c.want, p, err)
		}
	}
}

// Verification 3 defect 8 (MEDIUM): only resource-block literals were trace candidates, so when
// the other resource got the same yor_trace through a local, var default, module input or a built
// string, the literal block was patched silently (verify-3/iac/trace_local → aws_instance.y
// patched for i-x's finding). A trace that is not a literal in exactly one block is ambiguous.
func TestYorTraceThroughNonLiteralIsAmbiguous(t *testing.T) {
	const T = "1f2e3d4c-aaaa-bbbb-cccc-000000000001"
	r := func(name, tags string) string {
		return "resource \"aws_instance\" \"" + name + "\" {\n  ami = \"a\"\n  tags = " + tags + "\n}\n"
	}
	lit := r("y", `{ yor_trace = "`+T+`" }`)
	refuse := map[string]string{
		"trace_local (verify-3 repro)": "locals {\n  common = { yor_trace = \"" + T + "\" }\n}\n" + r("x", "local.common") + lit,
		"merge_local":                  "locals {\n  common = { yor_trace = \"" + T + "\" }\n}\n" + r("x", `merge(local.common, {a = "b"})`) + lit,
		"var_default":                  "variable \"t\" {\n  default = { yor_trace = \"" + T + "\" }\n}\n" + r("x", "var.t") + lit,
		"var_other_file":               r("x", "var.t") + lit,
		"heredoc":                      r("x", "{ yor_trace = chomp(<<EOT\n"+T+"\nEOT\n) }") + lit,
		"interp_split":                 "locals {\n  p = \"1f2e3d4c\"\n}\n" + r("x", `{ yor_trace = "${local.p}-aaaa-bbbb-cccc-000000000001" }`) + lit,
		"interp_literal":               r("x", `{ yor_trace = "${"`+T+`"}" }`) + lit,
		"module_input":                 "module \"m\" {\n  source = \"./m\"\n  tags = { yor_trace = \"" + T + "\" }\n}\n" + lit,
		"module_dynamic":               "module \"m\" {\n  source = \"./m\"\n  tags = var.t\n}\n" + lit,
		"key_from_local":               "locals {\n  k = \"yor_trace\"\n}\n" + r("x", `{ (local.k) = "`+T+`" }`) + lit,
		"lookup":                       r("x", `{ yor_trace = lookup(var.m, "k") }`) + lit,
		"tags_all":                     "resource \"aws_instance\" \"x\" {\n  ami = \"a\"\n  tags_all = local.t\n}\n" + lit,
		"merge_both":                   r("x", `merge({yor_trace = "`+T+`"}, var.x)`) + r("y", `merge(var.y, {yor_trace = "`+T+`"})`),
		"conditional":                  r("x", `var.c ? { yor_trace = "`+T+`" } : {}`) + lit,
		"for_expr":                     r("x", `{ for k, v in { yor_trace = "`+T+`" } : k => v }`) + lit,
		"target_only_via_local":        "locals {\n  common = { yor_trace = \"" + T + "\" }\n}\n" + r("x", "local.common"),
	}
	for name, src := range refuse {
		f := model.Finding{CanonicalID: "EC2_IMDSV1", File: "main.tf", Resource: model.Resource{ID: "arn:aws:ec2:us-east-1:1:instance/i-x", Type: "aws_instance", Name: "i-x"}, Tags: map[string]string{"yor_trace": T}}
		p, err := patchSource(f, "main.tf", []byte(src), nil)
		if p != nil || !errors.Is(err, ErrAmbiguousTarget) {
			addr := ""
			if p != nil {
				addr = p.Address
			}
			t.Errorf("%s: want ErrAmbiguousTarget, got patch of %q (err %v)", name, addr, err)
		}
	}
	// Still resolved: the trace is a literal in exactly one block and every other block's trace
	// is known (common Yor layout: merge(local.common, { yor_trace = "…" }) with a unique literal).
	ok := map[string]string{
		"single":        r("y", `{ yor_trace = "`+T+`" }`) + r("x", `{ yor_trace = "other" }`),
		"merge_last":    "locals {\n  common = { team = \"a\" }\n}\n" + r("y", `merge(local.common, { yor_trace = "`+T+`" })`) + r("x", `merge(local.common, { yor_trace = "other" })`),
		"no_tags_other": r("y", `{ yor_trace = "`+T+`" }`) + "resource \"aws_instance\" \"x\" {\n  ami = \"a\"\n}\n",
	}
	for name, src := range ok {
		f := model.Finding{CanonicalID: "EC2_IMDSV1", File: "main.tf", Resource: model.Resource{ID: "arn:aws:ec2:us-east-1:1:instance/i-y", Type: "aws_instance", Name: "i-y"}, Tags: map[string]string{"yor_trace": T}}
		p, err := patchSource(f, "main.tf", []byte(src), nil)
		if err != nil || p == nil || p.Address != "aws_instance.y" {
			t.Errorf("%s: want aws_instance.y patched, got %v %v", name, p, err)
		}
	}
}

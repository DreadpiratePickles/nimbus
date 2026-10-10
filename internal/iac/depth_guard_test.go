package iac

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/model"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
)

// Verification 3 defect 1: the pre-parse depth guard missed constructs the recursive hclsyntax
// parser recurses on. `a[*][*]…` (600 KB, scratchpad verify-3/iac/cliscan/splat_200000.tf) and
// `(!\n!\n…` (800 KB, verify-3/iac/cliscan2/bangnl_400000.tf) killed `scan --iac` with an
// uncatchable `fatal error: stack overflow`. A stack overflow cannot be recovered in-process, so
// every shape runs in a child process and a crash fails the test instead of the test binary.

const guardRes = "resource \"aws_instance\" \"x\" {\n  ami = \"a\"\n}\n"

func guardLocal(expr string) string { return guardRes + "locals {\n v = " + expr + "\n}\n" }

// hostileShapes are inputs that must be rejected with IAC_PARSE_LIMIT, never parsed.
func hostileShapes() map[string]string {
	r := strings.Repeat
	return map[string]string{
		// The two verify-3 crash repros, byte-for-byte shapes.
		"splat_full_200k":   guardLocal("a" + r("[*]", 200000)),
		"bang_nl_400k":      guardLocal("(" + r("!\n", 400000) + "true)"),
		"bang_comment_300k": guardLocal("(" + r("!/**/", 300000) + "true)"),
		"bang_hash_300k":    guardLocal("(" + r("!#\n", 300000) + "true)"),
		"minus_nl_400k":     guardLocal("(" + r("-\n", 400000) + "1)"),
		"minus_cmt_300k":    guardLocal("(" + r("/**/-", 300000) + "1)"),
		"bang_minus_300k":   guardLocal("(" + r("!-\n", 300000) + "1)"),
		"splat_idx_200k":    guardLocal("a" + r("[*].b", 200000)),
		"splat_mix_150k":    guardLocal("a" + r("[*][0]", 150000)),
		"splat_nl_200k":     guardLocal("(a" + r("[*]\n", 200000) + ")"),
		"splat_attr_400k":   guardLocal("a" + r(".*", 400000)),
		"index_expr_200k":   guardLocal("a" + r("[x]", 200000)),
		"index_lit_300k":    guardLocal("a" + r("[0]", 300000)),
		"attr_chain_900k":   guardLocal("a" + r(".b", 900000)),
		"plus_chain_900k":   guardLocal("1" + r("+1", 900000)),
		"mixed_ops_600k":    guardLocal("1" + r("+1*1", 300000)),
		"unary_in_paren":    guardLocal(r("(!!!!", 60000) + "true" + r(")", 60000)),
		"cond_chain_300k":   guardLocal(r("x?1:", 300000) + "2"),
		"cond_true_300k":    guardLocal("(" + r("x?\n", 300000) + "1" + r(":2", 300000) + ")"),
		"cond_nl_paren":     guardLocal("(" + r("true ? 1 :\n", 150000) + "2)"),
		"cond_for_if":       guardLocal("[for x in y : x if " + r("x ? ", 300000) + "x]"),
		"for_obj_nl_bang":   guardLocal("{for k, v in x : k => " + r("!\n", 300000) + "v}"),
		"for_nest_60k":      guardLocal(r("[for x in ", 60000) + "[1]" + r(" : x]", 60000)),
		"obj_nest_200k":     guardLocal(r("{a=", 200000) + "1" + r("}", 200000)),
		"call_nest_200k":    guardLocal(r("f(", 200000) + "1" + r(")", 200000)),
		"interp_nest_150k":  guardLocal(r("\"${", 150000) + "1" + r("}\"", 150000)),
		"heredoc_nest_50k":  guardLocal(r("<<EOT\n${", 50000) + "1" + r("}\nEOT\n", 50000)),
		"tmpl_if_100k":      guardLocal("\"" + r("%{ if true }", 80000) + "y" + r("%{ endif }", 80000) + "\""),
		"tmpl_for_80k":      guardLocal("\"" + r("%{ for x in [1] }", 60000) + "y" + r("%{ endfor }", 60000) + "\""),
		"blocks_200k":       guardRes + "resource \"aws_instance\" \"y\" {\n" + r("b {\n", 200000) + r("}\n", 200000) + "}\n",
		"brackets_300k":     guardLocal(r("[", 300000) + r("]", 300000)),
		"neg_paren_300k":    guardLocal(r("(-", 300000) + "1" + r(")", 300000)),
		"unclosed_400k":     guardLocal(r("[", 400000)),
		"mismatch_200k":     guardLocal(r("[)", 200000)),
		"bang_splat_mix":    guardLocal("(" + r("!a[*]\n", 150000) + ")"),
	}
}

// benignShapes are real-looking files with lots of repetition that must still be scanned.
func benignShapes() map[string]string {
	r := strings.Repeat
	deep := r("[", 300) + r("{", 300) + r("(", 300)
	return map[string]string{
		"heredoc_text":      guardLocal("<<EOT\n" + deep + "\nEOT\n"),
		"hash_comment":      guardRes + "# " + deep + "\n",
		"slash_comment":     guardRes + "// " + deep + "\n",
		"block_comment":     guardRes + "/* " + deep + " */\n",
		"string_text":       guardLocal("\"" + deep + "\""),
		"escaped_interp":    guardLocal("\"" + r("$${", 300) + "\""),
		"escaped_directive": guardLocal("\"" + r("%%{ if x }", 300) + "\""),
		"ternary_obj_lines": guardLocal("{\n" + r("  a = true ? 1 : 2\n", 400) + "}"),
		"ternary_list":      guardLocal("[" + r("true ? 1 : 2, ", 400) + "]"),
		"neg_list":          guardLocal("[" + r("-1, ", 400) + "]"),
		"bang_list":         guardLocal("[" + r("!x, ", 400) + "]"),
		"many_attrs":        guardRes + "locals {\n" + r("  a = -1\n  b = !x\n  c = x[*].id\n", 3000) + "}\n",
		"many_splat_args":   guardLocal("concat(" + r("a[*].id, ", 400) + "[])"),
		"tmpl_if_seq":       guardLocal("\"" + r("%{ if true }a%{ endif }", 400) + "\""),
		"tmpl_for_if_seq":   guardLocal("\"" + r("%{ for x in [1] }%{ if x == 1 }a%{ endif }%{ endfor }", 400) + "\""),
		"interp_seq":        guardLocal("\"" + r("${1}", 5000) + "\""),
		"blocks_flat":       guardRes + "resource \"aws_instance\" \"y\" {\n" + r("  b {}\n", 5000) + "}\n",
		"nest_100":          guardLocal(r("(", 100) + "true" + r(")", 100)),
		"real_sg":           "resource \"aws_security_group\" \"s\" {\n" + r("  ingress {\n    from_port = 22\n    to_port = 22\n    protocol = \"tcp\"\n    cidr_blocks = [\"10.0.0.0/8\", var.x[0], local.y.z]\n  }\n", 500) + "}\n",
		"for_obj_lines":     guardLocal("{\n for k, v in x :\n k => v\n if v != null\n}"),
		"chain_200":         guardLocal("a" + r(".b", 200)),
		"plus_200":          guardLocal("1" + r(" + 1", 200)),
	}
}

func TestDepthGuardRejectsEveryRecursiveConstruct(t *testing.T) {
	if os.Getenv("NIMBUS_IAC_GUARD_CHILD") != "" {
		t.Skip("child process")
	}
	shapes := hostileShapes()
	names := make([]string, 0, len(shapes))
	for n := range shapes {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		name := name
		t.Run(name, func(t *testing.T) {
			if len(shapes[name]) > DefaultMaxFileBytes {
				t.Fatalf("shape is %d bytes, over the size limit: it would not exercise the depth guard", len(shapes[name]))
			}
			out, err := runGuardChild(t, name)
			if err != nil {
				t.Fatalf("scanner crashed on %s (%v): %s", name, err, fatalLine(out))
			}
			if !strings.Contains(out, "GUARD scan=limit patch=refused symbols=refused") {
				t.Fatalf("%s was not rejected by the parse-limit guard:\n%s", name, tail(out, 600))
			}
		})
	}
}

func TestDepthGuardKeepsBenignFiles(t *testing.T) {
	for name, src := range benignShapes() {
		if err := checkParseLimits([]byte(src), name+".tf"); err != nil {
			t.Errorf("%s: false positive: %v", name, err)
		}
	}
}

// TestDepthGuardChild is the child half of TestDepthGuardRejectsEveryRecursiveConstruct.
func TestDepthGuardChild(t *testing.T) {
	name := os.Getenv("NIMBUS_IAC_GUARD_CHILD")
	if name == "" {
		t.Skip("parent process")
	}
	src := []byte(hostileShapes()[name])
	fs, err := ScanHCL(src, name+".tf", time.Unix(0, 0))
	scan := "parsed"
	if err != nil && len(fs) == 1 && fs[0].CanonicalID == "IAC_PARSE_LIMIT" && fs[0].Status == model.Error {
		scan = "limit"
	}
	patch := "accepted"
	if _, err := patchSource(model.Finding{CanonicalID: "EC2_IMDSV1", Resource: model.Resource{ID: "aws_instance.x"}}, name+".tf", src, nil); err != nil {
		patch = "refused"
	}
	syms := "accepted"
	if _, err := UndeclaredSymbols(src, name+".tf"); err != nil {
		syms = "refused"
	}
	fmt.Printf("GUARD scan=%s patch=%s symbols=%s\n", scan, patch, syms)
}

func runGuardChild(t *testing.T, name string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestDepthGuardChild$", "-test.v", "-test.count=1")
	cmd.Env = append(os.Environ(), "NIMBUS_IAC_GUARD_CHILD="+name)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// fatalLine returns the runtime's crash reason ("goroutine stack exceeds …", "fatal error: …").
func fatalLine(out string) string {
	var got []string
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, "stack exceeds") || strings.HasPrefix(l, "fatal error") || strings.HasPrefix(l, "panic:") {
			got = append(got, strings.TrimSpace(l))
		}
	}
	if len(got) == 0 {
		return tail(out, 400)
	}
	return strings.Join(got, " | ")
}

func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return "…" + s[len(s)-n:]
}

// astDepth is the deepest nesting of the parsed syntax tree. Every recursive descent of the
// parser, and every recursive walk or evaluation of its result, is bounded by it.
func astDepth(n hclsyntax.Node) int {
	w := &depthWalker{}
	hclsyntax.Walk(n, w)
	return w.max
}

type depthWalker struct{ cur, max int }

func (w *depthWalker) Enter(hclsyntax.Node) hcl.Diagnostics {
	w.cur++
	if w.cur > w.max {
		w.max = w.cur
	}
	return nil
}
func (w *depthWalker) Exit(hclsyntax.Node) hcl.Diagnostics { w.cur--; return nil }

// guardBoundHolds is the property FuzzScanHCL checks on every input the guard accepts: the real
// syntax-tree depth never exceeds a small multiple of what the guard measured. A construct the
// guard does not count shows up here on small inputs, long before it can overflow the stack.
func guardBoundHolds(src []byte) (ok bool, ast int, m guardMeasure) {
	m = measureNesting(src, 1<<30)
	f, _ := hclsyntax.ParseConfig(src, "g.tf", hcl.Pos{Line: 1, Column: 1})
	if f == nil {
		return true, 0, m
	}
	body, isBody := f.Body.(*hclsyntax.Body)
	if !isBody {
		return true, 0, m
	}
	ast = astDepth(body)
	return ast <= 4*(m.depth+m.chain)+8, ast, m
}

func TestDepthGuardBoundsTheSyntaxTree(t *testing.T) {
	r := strings.Repeat
	cases := map[string]string{}
	for name, gen := range map[string]func(int) string{
		"splat":      func(n int) string { return guardLocal("a" + r("[*]", n)) },
		"bang_nl":    func(n int) string { return guardLocal("(" + r("!\n", n) + "true)") },
		"index":      func(n int) string { return guardLocal("a" + r("[x]", n)) },
		"plus":       func(n int) string { return guardLocal("1" + r("+1", n)) },
		"cond":       func(n int) string { return guardLocal(r("x?1:", n) + "2") },
		"attr_splat": func(n int) string { return guardLocal("a" + r(".*", n)) },
		"for_bang":   func(n int) string { return guardLocal("{for k, v in x : k => " + r("!\n", n) + "v}") },
		"heredoc":    func(n int) string { return guardLocal(r("<<EOT\n${", n) + "1" + r("}\nEOT\n", n)) },
	} {
		for _, n := range []int{1, 10, 100} {
			cases[fmt.Sprintf("%s_%d", name, n)] = gen(n)
		}
	}
	for name, src := range cases {
		if ok, ast, m := guardBoundHolds([]byte(src)); !ok {
			t.Errorf("%s: syntax tree depth %d but the guard measured depth %d, chain %d", name, ast, m.depth, m.chain)
		}
	}
}

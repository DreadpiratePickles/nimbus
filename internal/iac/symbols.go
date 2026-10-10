package iac

import (
	"fmt"
	"sort"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
)

// UndeclaredSymbols parses one Terraform file and returns every `var.X` / `local.X` reference
// that is not declared by a variable/locals block in that file or in moduleSrc (the module's
// other files). An error means the file does not parse.
func UndeclaredSymbols(src []byte, filename string, moduleSrc ...[]byte) ([]string, error) {
	f, d := parseConfig(src, filename)
	if d.HasErrors() {
		return nil, fmt.Errorf("parse %s: %s", filename, d.Error())
	}
	body := f.Body.(*hclsyntax.Body)
	bodies := []*hclsyntax.Body{body}
	for i, m := range moduleSrc {
		mf, d := parseConfig(m, fmt.Sprintf("module-%d.tf", i))
		if d.HasErrors() {
			return nil, fmt.Errorf("parse module file %d: %s", i, d.Error())
		}
		bodies = append(bodies, mf.Body.(*hclsyntax.Body))
	}
	vars, locals := map[string]bool{}, map[string]bool{}
	for _, b := range bodies {
		for _, blk := range b.Blocks {
			switch {
			case blk.Type == "variable" && len(blk.Labels) == 1:
				vars[blk.Labels[0]] = true
			case blk.Type == "locals":
				for name := range blk.Body.Attributes {
					locals[name] = true
				}
			}
		}
	}
	seen := map[string]bool{}
	var walk func(b *hclsyntax.Body)
	walk = func(b *hclsyntax.Body) {
		for _, a := range b.Attributes {
			for _, tr := range a.Expr.Variables() {
				if len(tr) < 2 {
					continue
				}
				attr, ok := tr[1].(hcl.TraverseAttr)
				if !ok {
					continue
				}
				switch root := tr.RootName(); {
				case root == "var" && !vars[attr.Name], root == "local" && !locals[attr.Name]:
					seen[root+"."+attr.Name] = true
				}
			}
		}
		for _, nb := range b.Blocks {
			// dynamic "x" { for_each = ...; content { ... } } and every other nested block
			walk(nb.Body)
		}
	}
	walk(body)
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out, nil
}

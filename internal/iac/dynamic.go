package iac

import (
	"fmt"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/function"
	"github.com/zclconf/go-cty/cty/function/stdlib"
)

// staticFuncs are the pure Terraform functions a dynamic block's for_each commonly uses.
var staticFuncs = map[string]function.Function{
	"toset": stdlib.MakeToFunc(cty.Set(cty.DynamicPseudoType)), "tolist": stdlib.MakeToFunc(cty.List(cty.DynamicPseudoType)),
	"tomap": stdlib.MakeToFunc(cty.Map(cty.DynamicPseudoType)), "concat": stdlib.ConcatFunc, "flatten": stdlib.FlattenFunc,
	"merge": stdlib.MergeFunc,
}

// maxDynamicInstances bounds the expansion of one file's dynamic blocks (the for_each values are
// literals from the file itself, so this only guards against pathological input).
const maxDynamicInstances = 10000

// valueIn evaluates e in ectx without panicking; ok is false for errors and unknown values.
func valueIn(e hclsyntax.Expression, ectx *hcl.EvalContext) (v cty.Value, ok bool) {
	defer func() {
		if recover() != nil {
			v, ok = cty.NilVal, false
		}
	}()
	if e == nil {
		return cty.NilVal, false
	}
	v, d := e.Value(ectx)
	if d.HasErrors() || v == cty.NilVal || !v.IsWhollyKnown() {
		return cty.NilVal, false
	}
	return v, true
}

// dynamicInstance is one expansion of a dynamic block: its content body and the iterator binding.
type dynamicInstance struct {
	content *hclsyntax.Body
	ectx    *hcl.EvalContext
}

// expandDynamic expands every `dynamic "<typ>"` block of body whose for_each is statically known.
// unknown lists a reason for each block that could not be expanded.
func expandDynamic(body *hclsyntax.Body, typ string) (out []dynamicInstance, unknown []string) {
	if body == nil {
		return nil, nil
	}
	for _, d := range body.Blocks {
		if d.Type != "dynamic" || len(d.Labels) != 1 || d.Labels[0] != typ || d.Body == nil {
			continue
		}
		var content *hclsyntax.Body
		for _, c := range d.Body.Blocks {
			if c.Type == "content" {
				content = c.Body
			}
		}
		if content == nil {
			continue
		}
		iter := typ
		if a, ok := d.Body.Attributes["iterator"]; ok {
			if tr, diags := hcl.AbsTraversalForExpr(a.Expr); !diags.HasErrors() && len(tr) == 1 {
				iter = tr.RootName()
			}
		}
		fe, ok := d.Body.Attributes["for_each"]
		if !ok {
			continue
		}
		coll, ok := valueIn(fe.Expr, &hcl.EvalContext{Functions: staticFuncs})
		if !ok || coll.IsNull() || !coll.CanIterateElements() || coll.LengthInt()+len(out) > maxDynamicInstances {
			unknown = append(unknown, fmt.Sprintf("dynamic %s for_each", typ))
			continue
		}
		for it := coll.ElementIterator(); it.Next(); {
			k, v := it.Element()
			if coll.Type().IsSetType() {
				k = v // Terraform: a set element is its own key
			}
			out = append(out, dynamicInstance{content: content, ectx: &hcl.EvalContext{
				Variables: map[string]cty.Value{iter: cty.ObjectVal(map[string]cty.Value{"key": k, "value": v})},
				Functions: staticFuncs,
			}})
		}
	}
	return out, unknown
}

// attrStringsIn is attrStringsBody evaluated in ectx (dynamic block content).
func attrStringsIn(body *hclsyntax.Body, name string, ectx *hcl.EvalContext) ([]string, attrState) {
	a, ok := body.Attributes[name]
	if !ok {
		return nil, stAbsent
	}
	v, ok := valueIn(a.Expr, ectx)
	if !ok {
		return nil, stUnknown
	}
	if v.IsNull() {
		return nil, stAbsent
	}
	return stringElems(v), stKnown
}

func portRangeIn(body *hclsyntax.Body, ectx *hcl.EvalContext) string {
	p := func(name string) string {
		a, ok := body.Attributes[name]
		if !ok {
			return "?"
		}
		v, ok := valueIn(a.Expr, ectx)
		if !ok || v.IsNull() {
			return "?"
		}
		if v.Type() == cty.Number {
			n, _ := v.AsBigFloat().Int64()
			return fmt.Sprint(n)
		}
		if v.Type() == cty.String {
			return v.AsString()
		}
		return "?"
	}
	return p("from_port") + "-" + p("to_port")
}

package output

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

// Schema is a minimal JSON Schema (draft-07 / 2020-12 subset) validator, vendored so that
// outbound formats and the finding contract can be checked in `go test` without a new
// dependency. Supported keywords: type, properties, required, additionalProperties (bool or
// schema), items (schema), enum, const, $ref (local "#/$defs/..." and "#/definitions/..."),
// anyOf, oneOf, allOf, not, minimum, maximum, minLength, maxLength, minItems, maxItems,
// pattern. Annotation keywords (title, description, format, $id, $schema, examples, default)
// are ignored. An unsupported assertion keyword makes CompileSchema fail, so a schema update
// that needs more is noticed rather than silently under-validated.
type Schema struct {
	root map[string]any
	res  map[string]*regexp.Regexp
}

var schemaIgnored = map[string]bool{
	"title": true, "description": true, "format": true, "$id": true, "$schema": true, "$comment": true,
	"examples": true, "default": true, "$defs": true, "definitions": true, "readOnly": true, "deprecated": true,
}

var schemaAsserts = map[string]bool{
	"type": true, "properties": true, "required": true, "additionalProperties": true, "items": true,
	"enum": true, "const": true, "$ref": true, "anyOf": true, "oneOf": true, "allOf": true, "not": true,
	"minimum": true, "maximum": true, "minLength": true, "maxLength": true, "minItems": true, "maxItems": true,
	"pattern": true,
}

// CompileSchema parses a schema document and checks it only uses supported keywords.
func CompileSchema(data []byte) (*Schema, error) {
	var root map[string]any
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(&root); err != nil {
		return nil, fmt.Errorf("schema: %w", err)
	}
	s := &Schema{root: root, res: map[string]*regexp.Regexp{}}
	if err := s.check(root, "#"); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Schema) check(node map[string]any, at string) error {
	for k, v := range node {
		switch {
		case k == "$defs" || k == "definitions" || k == "properties":
			m, ok := v.(map[string]any)
			if !ok {
				return fmt.Errorf("schema %s/%s: not an object", at, k)
			}
			for name, sub := range m {
				sm, ok := sub.(map[string]any)
				if !ok {
					return fmt.Errorf("schema %s/%s/%s: not an object", at, k, name)
				}
				if err := s.check(sm, at+"/"+k+"/"+name); err != nil {
					return err
				}
			}
		case k == "items" || k == "not" || (k == "additionalProperties" && isObject(v)):
			sm, ok := v.(map[string]any)
			if !ok {
				return fmt.Errorf("schema %s/%s: only a single schema is supported", at, k)
			}
			if err := s.check(sm, at+"/"+k); err != nil {
				return err
			}
		case k == "anyOf" || k == "oneOf" || k == "allOf":
			arr, ok := v.([]any)
			if !ok {
				return fmt.Errorf("schema %s/%s: not an array", at, k)
			}
			for i, sub := range arr {
				sm, ok := sub.(map[string]any)
				if !ok {
					return fmt.Errorf("schema %s/%s/%d: not an object", at, k, i)
				}
				if err := s.check(sm, fmt.Sprintf("%s/%s/%d", at, k, i)); err != nil {
					return err
				}
			}
		case k == "pattern":
			p, _ := v.(string)
			re, err := regexp.Compile(p)
			if err != nil {
				return fmt.Errorf("schema %s/pattern: %w", at, err)
			}
			s.res[p] = re
		case k == "$ref":
			ref, _ := v.(string)
			if _, err := s.resolve(ref); err != nil {
				return fmt.Errorf("schema %s: %w", at, err)
			}
		case schemaIgnored[k] || schemaAsserts[k]:
		default:
			return fmt.Errorf("schema %s: unsupported keyword %q", at, k)
		}
	}
	return nil
}

func isObject(v any) bool { _, ok := v.(map[string]any); return ok }

func (s *Schema) resolve(ref string) (map[string]any, error) {
	if ref == "#" {
		return s.root, nil
	}
	if !strings.HasPrefix(ref, "#/") {
		return nil, fmt.Errorf("unsupported $ref %q (only local refs)", ref)
	}
	var cur any = s.root
	for _, part := range strings.Split(ref[2:], "/") {
		part = strings.ReplaceAll(strings.ReplaceAll(part, "~1", "/"), "~0", "~")
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("$ref %q does not resolve", ref)
		}
		if cur, ok = m[part]; !ok {
			return nil, fmt.Errorf("$ref %q does not resolve", ref)
		}
	}
	m, ok := cur.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("$ref %q is not a schema", ref)
	}
	return m, nil
}

// ValidateJSON decodes doc (numbers kept exact) and validates it.
func (s *Schema) ValidateJSON(doc []byte) []error {
	var v any
	dec := json.NewDecoder(bytes.NewReader(doc))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return []error{err}
	}
	return s.Validate(v)
}

// Validate checks a decoded value (decode with UseNumber for exact integer checks; float64
// numbers are accepted too). It returns every violation with its JSON path.
func (s *Schema) Validate(v any) []error {
	var errs []error
	s.validate(s.root, v, "$", &errs, 0)
	return errs
}

// ValidateAt validates v against the subschema at a local ref such as "#/$defs/finding".
func (s *Schema) ValidateAt(ref string, v any) []error {
	sub, err := s.resolve(ref)
	if err != nil {
		return []error{err}
	}
	var errs []error
	s.validate(sub, v, "$", &errs, 0)
	return errs
}

func (s *Schema) validate(sch map[string]any, v any, path string, errs *[]error, depth int) {
	if depth > 64 {
		*errs = append(*errs, fmt.Errorf("%s: schema nesting too deep", path))
		return
	}
	fail := func(format string, a ...any) {
		*errs = append(*errs, fmt.Errorf("%s: "+format, append([]any{path}, a...)...))
	}
	if ref, ok := sch["$ref"].(string); ok {
		target, err := s.resolve(ref)
		if err != nil {
			fail("%v", err)
			return
		}
		s.validate(target, v, path, errs, depth+1)
	}
	if t, ok := sch["type"]; ok {
		var types []string
		switch tt := t.(type) {
		case string:
			types = []string{tt}
		case []any:
			for _, x := range tt {
				if s, ok := x.(string); ok {
					types = append(types, s)
				}
			}
		}
		matched := false
		for _, ty := range types {
			if typeMatches(ty, v) {
				matched = true
				break
			}
		}
		if !matched {
			fail("type %s expected, got %s", strings.Join(types, "|"), jsonType(v))
			return
		}
	}
	if enum, ok := sch["enum"].([]any); ok {
		found := false
		for _, e := range enum {
			if jsonEqual(e, v) {
				found = true
				break
			}
		}
		if !found {
			fail("value %s not in enum %s", short(compact(v), 80), short(compact(enum), 120))
		}
	}
	if c, ok := sch["const"]; ok && !jsonEqual(c, v) {
		fail("const %s expected, got %s", compact(c), short(compact(v), 80))
	}
	if n, ok := toFloat(v); ok {
		if m, ok := toFloat(sch["minimum"]); ok && n < m {
			fail("minimum %v, got %v", m, n)
		}
		if m, ok := toFloat(sch["maximum"]); ok && n > m {
			fail("maximum %v, got %v", m, n)
		}
	}
	if str, ok := v.(string); ok {
		if m, ok := toFloat(sch["minLength"]); ok && float64(utf8.RuneCountInString(str)) < m {
			fail("minLength %v, got %d", m, utf8.RuneCountInString(str))
		}
		if m, ok := toFloat(sch["maxLength"]); ok && float64(utf8.RuneCountInString(str)) > m {
			fail("maxLength %v, got %d", m, utf8.RuneCountInString(str))
		}
		if p, ok := sch["pattern"].(string); ok && !s.res[p].MatchString(str) {
			fail("pattern %s does not match %q", p, short(str, 60))
		}
	}
	if arr, ok := v.([]any); ok {
		if m, ok := toFloat(sch["minItems"]); ok && float64(len(arr)) < m {
			fail("minItems %v, got %d", m, len(arr))
		}
		if m, ok := toFloat(sch["maxItems"]); ok && float64(len(arr)) > m {
			fail("maxItems %v, got %d", m, len(arr))
		}
		if items, ok := sch["items"].(map[string]any); ok {
			for i, x := range arr {
				s.validate(items, x, fmt.Sprintf("%s[%d]", path, i), errs, depth+1)
			}
		}
	}
	if obj, ok := v.(map[string]any); ok {
		if req, ok := sch["required"].([]any); ok {
			for _, r := range req {
				name, _ := r.(string)
				if _, ok := obj[name]; !ok {
					fail("required property %q missing", name)
				}
			}
		}
		props, _ := sch["properties"].(map[string]any)
		keys := make([]string, 0, len(obj))
		for k := range obj {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if ps, ok := props[k].(map[string]any); ok {
				s.validate(ps, obj[k], path+"."+k, errs, depth+1)
				continue
			}
			switch ap := sch["additionalProperties"].(type) {
			case bool:
				if !ap {
					fail("additional property %q not allowed", k)
				}
			case map[string]any:
				s.validate(ap, obj[k], path+"."+k, errs, depth+1)
			}
		}
	}
	if all, ok := sch["allOf"].([]any); ok {
		for _, sub := range all {
			s.validate(sub.(map[string]any), v, path, errs, depth+1)
		}
	}
	if anyOf, ok := sch["anyOf"].([]any); ok {
		matched := false
		for _, sub := range anyOf {
			var e []error
			s.validate(sub.(map[string]any), v, path, &e, depth+1)
			if len(e) == 0 {
				matched = true
				break
			}
		}
		if !matched {
			fail("anyOf: no alternative matched")
		}
	}
	if oneOf, ok := sch["oneOf"].([]any); ok {
		n := 0
		for _, sub := range oneOf {
			var e []error
			s.validate(sub.(map[string]any), v, path, &e, depth+1)
			if len(e) == 0 {
				n++
			}
		}
		if n != 1 {
			fail("oneOf: %d alternatives matched, want exactly 1", n)
		}
	}
	if not, ok := sch["not"].(map[string]any); ok {
		var e []error
		s.validate(not, v, path, &e, depth+1)
		if len(e) == 0 {
			fail("not: value must not match the subschema")
		}
	}
}

func typeMatches(ty string, v any) bool {
	switch ty {
	case "object":
		_, ok := v.(map[string]any)
		return ok
	case "array":
		_, ok := v.([]any)
		return ok
	case "string":
		_, ok := v.(string)
		return ok
	case "boolean":
		_, ok := v.(bool)
		return ok
	case "null":
		return v == nil
	case "number":
		_, ok := toFloat(v)
		return ok
	case "integer":
		switch n := v.(type) {
		case json.Number:
			if _, err := n.Int64(); err == nil {
				return true
			}
			f, err := n.Float64()
			return err == nil && f == math.Trunc(f) && !strings.ContainsAny(string(n), ".eE")
		case float64:
			return n == math.Trunc(n)
		case int, int64:
			return true
		}
	}
	return false
}

func jsonType(v any) string {
	switch v.(type) {
	case nil:
		return "null"
	case map[string]any:
		return "object"
	case []any:
		return "array"
	case string:
		return "string"
	case bool:
		return "boolean"
	}
	if _, ok := toFloat(v); ok {
		return "number"
	}
	return fmt.Sprintf("%T", v)
}

func toFloat(v any) (float64, bool) {
	switch n := v.(type) {
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	case float64:
		return n, true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	}
	return 0, false
}

func jsonEqual(a, b any) bool {
	if fa, ok := toFloat(a); ok {
		fb, ok := toFloat(b)
		return ok && fa == fb
	}
	return compact(a) == compact(b)
}

func compact(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

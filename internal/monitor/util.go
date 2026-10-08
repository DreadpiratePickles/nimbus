package monitor

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// get walks nested maps by key (case-insensitive on each segment).
func get(v any, path ...string) any {
	cur := v
	for _, p := range path {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		next, ok := m[p]
		if !ok {
			for k, val := range m {
				if strings.EqualFold(k, p) {
					next, ok = val, true
					break
				}
			}
		}
		if !ok {
			return nil
		}
		cur = next
	}
	return cur
}

func str(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(x)
	}
	return fmt.Sprint(v)
}

func gets(v any, path ...string) string { return str(get(v, path...)) }

func num(v any) (float64, bool) {
	switch x := v.(type) {
	case float64:
		return x, true
	case int:
		return float64(x), true
	case int32:
		return float64(x), true
	case int64:
		return float64(x), true
	case string:
		f, err := strconv.ParseFloat(x, 64)
		return f, err == nil
	}
	return 0, false
}

func isFalse(v any) bool {
	switch x := v.(type) {
	case bool:
		return !x
	case string:
		return strings.EqualFold(x, "false")
	}
	return false
}

func isTrue(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case string:
		return strings.EqualFold(x, "true")
	}
	return false
}

// list normalises a scalar-or-array value, also unwrapping CloudTrail {"items":[...]} shapes.
func list(v any) []any {
	switch x := v.(type) {
	case nil:
		return nil
	case []any:
		return x
	case map[string]any:
		if items, ok := x["items"].([]any); ok {
			return items
		}
		return []any{x}
	}
	return []any{v}
}

func strs(v any) []string {
	var out []string
	for _, x := range list(v) {
		if s := str(x); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// walk visits every key/value pair in a nested JSON structure.
func walk(v any, fn func(key string, val any)) {
	switch x := v.(type) {
	case map[string]any:
		for k, val := range x {
			fn(k, val)
			walk(val, fn)
		}
	case []any:
		for _, val := range x {
			walk(val, fn)
		}
	}
}

// containsString reports whether any string leaf contains one of needles.
func containsString(v any, needles ...string) bool {
	found := false
	var visit func(any)
	visit = func(v any) {
		if found {
			return
		}
		switch x := v.(type) {
		case string:
			for _, n := range needles {
				if strings.Contains(x, n) {
					found = true
					return
				}
			}
		case map[string]any:
			for _, val := range x {
				visit(val)
			}
		case []any:
			for _, val := range x {
				visit(val)
			}
		}
	}
	visit(v)
	return found
}

// jsonish decodes a value that may be an embedded JSON string into a structure.
func jsonish(v any) any {
	s, ok := v.(string)
	if !ok {
		return v
	}
	var out any
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		return v
	}
	return out
}

func openSource(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "0.0.0.0/0", "::/0", "*", "internet", "any", "0.0.0.0":
		return true
	}
	return false
}

// portSpanCovers parses "22", "20-25", "*" and reports coverage of port.
func portSpanCovers(spec string, port int) bool {
	spec = strings.TrimSpace(spec)
	if spec == "*" || spec == "" {
		return spec == "*"
	}
	if lo, hi, ok := strings.Cut(spec, "-"); ok {
		l, e1 := strconv.Atoi(strings.TrimSpace(lo))
		h, e2 := strconv.Atoi(strings.TrimSpace(hi))
		return e1 == nil && e2 == nil && port >= l && port <= h
	}
	p, err := strconv.Atoi(spec)
	return err == nil && p == port
}

func allPorts(spec string) bool {
	spec = strings.TrimSpace(spec)
	return spec == "*" || spec == "0-65535" || spec == "1-65535"
}

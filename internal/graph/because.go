package graph

import (
	"fmt"
	"sort"
	"strings"
)

// DescribeEdge derives the per-hop "why" for an edge from the attributes collectors attach
// (security-group/firewall name and ports, trust principal, policy type, granted actions,
// RBAC binding, GCP role). It never invents detail: when the collector recorded nothing,
// the string says which relationship exists and that no rule detail was collected.
func DescribeEdge(from, to *Node, kind string, attr map[string]any) string {
	f, t := label(from), label(to)
	a := func(k string) string { return attrString(attr, k) }
	var b strings.Builder
	switch kind {
	case EdgeExposes:
		fmt.Fprintf(&b, "internet reaches %s", t)
		if v := a("via"); v != "" {
			fmt.Fprintf(&b, " via %s", v)
		}
		detail(&b, "ports", a("ports"), "security groups", a("security_groups"), "sources", a("sources"), "public IP", a("public_ip"), "url", a("url"))
		if len(attr) == 0 {
			b.WriteString(" (exposure reported; no rule detail collected)")
		}
	case EdgeAllowsTrafficTo:
		fmt.Fprintf(&b, "%s allows inbound traffic to %s", f, t)
		detail(&b, "ports", a("ports"), "internet ports", a("internet_ports"), "sources", a("sources"), "via", a("via"))
	case EdgeCanAssume:
		if p := a("principal"); p != "" {
			fmt.Fprintf(&b, "trust policy of %s allows principal %s", t, p)
			if c, _ := attr["conditional"].(bool); c {
				b.WriteString(" (with a condition)")
			}
		} else {
			fmt.Fprintf(&b, "%s may assume %s", f, t)
		}
	case EdgeTrusts:
		fmt.Fprintf(&b, "%s trusts %s", f, firstNon(a("principal"), t))
	case EdgeHasPolicy:
		if r := a("role"); r != "" {
			fmt.Fprintf(&b, "%s is granted %s", f, r)
			detail(&b, "member", a("member"), "on", a("resource"))
		} else {
			kindOf := firstNon(a("type"), "attached")
			fmt.Fprintf(&b, "%s has %s policy %s", f, kindOf, idOf(to))
		}
		detail(&b, "statement", a("statement"))
	case EdgeGrantsAccessTo:
		if acts := a("actions"); acts != "" {
			fmt.Fprintf(&b, "%s allows %s on %s", f, acts, firstNon(a("resource_pattern"), t))
		} else {
			fmt.Fprintf(&b, "%s grants access to %s", f, t)
		}
		detail(&b, "statement", a("statement"))
	case EdgeRunsAs:
		fmt.Fprintf(&b, "%s runs as %s", f, t)
		detail(&b, "instance profile", a("instance_profile"), "scopes", a("scopes"))
	case EdgeBoundTo:
		fmt.Fprintf(&b, "%s is bound to %s", f, t)
		if v := a("binding"); v != "" {
			fmt.Fprintf(&b, " by binding %s", v)
		}
	case EdgeMemberOf:
		fmt.Fprintf(&b, "%s is a member of %s", f, t)
		if v := a("binding"); v != "" {
			fmt.Fprintf(&b, " (binding %s)", v)
		}
	case EdgeAttachedTo:
		if h, _ := attr["hint"].(bool); h {
			fmt.Fprintf(&b, "scanner lists %s as related to %s (attachment not verified)", t, f)
		} else {
			fmt.Fprintf(&b, "%s is attached to %s", f, t)
			detail(&b, "device", a("device"))
		}
	case EdgeContains:
		fmt.Fprintf(&b, "%s contains %s", f, t)
	case EdgeRunsOn:
		fmt.Fprintf(&b, "%s runs on %s", f, t)
	case EdgeStoresDataIn:
		fmt.Fprintf(&b, "%s stores data in %s", f, t)
	default:
		fmt.Fprintf(&b, "%s %s %s", f, strings.ReplaceAll(kind, "_", " "), t)
	}
	return b.String()
}

func label(n *Node) string {
	if n == nil {
		return "?"
	}
	if n.ID == InternetNodeID {
		return "internet"
	}
	if n.Name != "" {
		return n.Name
	}
	return n.ID
}

func idOf(n *Node) string {
	if n == nil {
		return "?"
	}
	return n.ID
}

func firstNon(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// detail appends " (k1 v1, k2 v2)" for the non-empty pairs.
func detail(b *strings.Builder, kv ...string) {
	var parts []string
	for i := 0; i+1 < len(kv); i += 2 {
		if kv[i+1] != "" {
			parts = append(parts, kv[i]+" "+kv[i+1])
		}
	}
	if len(parts) > 0 {
		b.WriteString(" (" + strings.Join(parts, ", ") + ")")
	}
}

// attrString renders scalars, string lists and maps compactly; "" when absent.
func attrString(attr map[string]any, k string) string {
	v, ok := attr[k]
	if !ok || v == nil {
		return ""
	}
	switch x := v.(type) {
	case string:
		return x
	case []string:
		return strings.Join(x, ",")
	case []any:
		parts := make([]string, 0, len(x))
		for _, e := range x {
			parts = append(parts, fmt.Sprint(e))
		}
		return strings.Join(parts, ",")
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			parts = append(parts, fmt.Sprintf("%s=%v", k, x[k]))
		}
		return strings.Join(parts, ",")
	case bool:
		if x {
			return "true"
		}
		return ""
	}
	return fmt.Sprint(v)
}

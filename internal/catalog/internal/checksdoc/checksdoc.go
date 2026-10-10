// Package checksdoc renders the canonical check catalog (internal/catalog/catalog.yaml) as the
// generated section of docs/checks.md. Source and compliance keys keep their catalog.yaml order.
package checksdoc

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Markers delimit the generated block in docs/checks.md; prose outside them is hand-written.
const (
	Begin = "<!-- BEGIN GENERATED CATALOG: go generate ./internal/catalog/... (do not edit by hand) -->"
	End   = "<!-- END GENERATED CATALOG -->"
)

type kv struct {
	key  string
	vals []string
}

type entry struct {
	id, title, provider, severity, resource string
	weaknesses, remediation                 []string
	aliases, compliance                     []kv
}

// Render returns the markdown for every catalog entry, sorted by canonical id.
func Render(catalogYAML []byte) (string, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(catalogYAML, &doc); err != nil {
		return "", err
	}
	if len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return "", errors.New("catalog: top level is not a mapping")
	}
	top := doc.Content[0]
	var entries []entry
	for i := 0; i+1 < len(top.Content); i += 2 {
		e, err := parseEntry(top.Content[i].Value, top.Content[i+1])
		if err != nil {
			return "", err
		}
		entries = append(entries, e)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].id < entries[j].id })
	var b strings.Builder
	for i, e := range entries {
		if i > 0 {
			b.WriteString("\n")
		}
		fmt.Fprintf(&b, "## %s\n\n**%s** — provider `%s`, default severity `%s`, resource `%s`\n\n", e.id, e.title, e.provider, e.severity, e.resource)
		if len(e.weaknesses) > 0 {
			fmt.Fprintf(&b, "- Weaknesses: %s\n", strings.Join(e.weaknesses, ", "))
		}
		for _, a := range e.aliases {
			q := make([]string, len(a.vals))
			for j, v := range a.vals {
				q[j] = "`" + v + "`"
			}
			fmt.Fprintf(&b, "- %s: %s\n", a.key, strings.Join(q, ", "))
		}
		for _, c := range e.compliance {
			fmt.Fprintf(&b, "- %s: %s\n", c.key, strings.Join(c.vals, ", "))
		}
		if len(e.remediation) > 0 {
			fmt.Fprintf(&b, "- Fix templates: %s\n", strings.Join(e.remediation, ", "))
		}
	}
	return b.String(), nil
}

func parseEntry(id string, n *yaml.Node) (entry, error) {
	e := entry{id: id}
	if n.Kind != yaml.MappingNode {
		return e, fmt.Errorf("catalog %s: not a mapping", id)
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, v := n.Content[i].Value, n.Content[i+1]
		var err error
		switch k {
		case "title":
			e.title = v.Value
		case "provider":
			e.provider = v.Value
		case "severity":
			e.severity = v.Value
		case "resource_type":
			e.resource = v.Value
		case "weaknesses":
			err = v.Decode(&e.weaknesses)
		case "remediation":
			err = v.Decode(&e.remediation)
		case "aliases":
			e.aliases, err = orderedLists(v)
		case "compliance":
			e.compliance, err = orderedLists(v)
		}
		if err != nil {
			return e, fmt.Errorf("catalog %s.%s: %w", id, k, err)
		}
	}
	return e, nil
}

func orderedLists(n *yaml.Node) ([]kv, error) {
	if n.Kind != yaml.MappingNode {
		return nil, errors.New("not a mapping")
	}
	var out []kv
	for i := 0; i+1 < len(n.Content); i += 2 {
		var vals []string
		if err := n.Content[i+1].Decode(&vals); err != nil {
			return nil, err
		}
		out = append(out, kv{n.Content[i].Value, vals})
	}
	return out, nil
}

// Splice replaces the text between the Begin and End markers of doc with generated.
func Splice(doc, generated string) (string, error) {
	i := strings.Index(doc, Begin)
	j := strings.Index(doc, End)
	if i < 0 || j < 0 || j < i {
		return "", fmt.Errorf("docs/checks.md: markers %q / %q missing or out of order", Begin, End)
	}
	if strings.Count(doc, Begin) != 1 || strings.Count(doc, End) != 1 {
		return "", errors.New("docs/checks.md: generated-block markers must appear exactly once")
	}
	return doc[:i+len(Begin)] + "\n\n" + generated + "\n" + doc[j:], nil
}

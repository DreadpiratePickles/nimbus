package mcp

import (
	"fmt"
	"sort"
	"strings"
)

// toolNames lists every tool this server implements. All are read-only.
var toolNames = []string{"coverage", "draft_fix", "explain", "issue", "paths", "prioritize", "schema", "simulate_fix", "sql", "summary", "verify", "who_can"}

// readTools is the default scope (no --scope): every tool that only reads stored results.
// The change-shaped tools (simulate_fix, draft_fix) need an explicit `--scope fix` or `all`
// (bar: Sysdig's token-scoped MCP server, write tools opt-in).
var readTools = []string{"coverage", "explain", "issue", "paths", "prioritize", "schema", "sql", "summary", "verify", "who_can"}

// DefaultScope is the scope of a session started without --scope.
const DefaultScope = "read"

// scopeGrants maps a scope name to the tools it grants. A scope is a capability label, not a
// permission to write: no scope grants a write, because no tool writes (verify reports what a
// verification would check and the stored state; it never re-collects or changes an Issue).
// "fix" groups the two change-shaped tools (simulate_fix, draft_fix).
var scopeGrants = map[string][]string{
	"all":          toolNames,
	"read":         readTools,
	"who_can":      {"who_can"},
	"prioritize":   {"prioritize"},
	"verify":       {"verify"},
	"summary":      {"summary"},
	"fix":          {"draft_fix", "simulate_fix"},
	"sql":          {"schema", "sql"},
	"schema":       {"schema"},
	"paths":        {"paths"},
	"issues":       {"explain", "issue"},
	"issue":        {"issue"},
	"explain":      {"explain"},
	"coverage":     {"coverage"},
	"simulate":     {"simulate_fix"},
	"simulate_fix": {"simulate_fix"},
	"draft":        {"draft_fix"},
	"draft_fix":    {"draft_fix"},
}

// Scope is the set of tools one session may list and call.
type Scope struct {
	names []string
	tools map[string]bool
}

// ParseScopes parses `--scope` values (each may be comma-separated). Empty means DefaultScope
// ("read": no draft_fix / simulate_fix).
// Unknown scope names are an error, so a typo never silently widens or narrows access.
func ParseScopes(values []string) (Scope, error) {
	s := Scope{tools: map[string]bool{}}
	for _, v := range values {
		for _, name := range strings.Split(v, ",") {
			name = strings.ToLower(strings.TrimSpace(name))
			if name == "" {
				continue
			}
			grants, ok := scopeGrants[name]
			if !ok {
				return Scope{}, fmt.Errorf("unknown MCP scope %q (known: %s)", name, strings.Join(KnownScopes(), ", "))
			}
			s.names = append(s.names, name)
			for _, t := range grants {
				s.tools[t] = true
			}
		}
	}
	if len(s.names) == 0 {
		s.names = []string{DefaultScope}
		for _, t := range scopeGrants[DefaultScope] {
			s.tools[t] = true
		}
	}
	return s, nil
}

// KnownScopes lists the accepted scope names.
func KnownScopes() []string {
	var out []string
	for k := range scopeGrants {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Allows reports whether tool may be listed and called.
func (s Scope) Allows(tool string) bool { return s.tools[tool] }

// Tools lists the granted tools, sorted.
func (s Scope) Tools() []string {
	var out []string
	for t := range s.tools {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// Names are the scope names as given (for the audit log).
func (s Scope) Names() []string { return append([]string{}, s.names...) }

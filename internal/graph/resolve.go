package graph

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Errors returned by ResolveNodeName.
var (
	ErrNoSuchName    = errors.New("no resource with that name in the graph")
	ErrAmbiguousName = errors.New("name is shared by more than one resource")
)

// ResolveNodeName is the one rule that maps a resource given by name ("customer-pii") to its
// graph node id, shared by `who-can` (cli/whocan.go) and the MCP who_can tool (mcp/tools.go) so
// both answer the same question for "customer-pii" and "arn:aws:s3:::customer-pii" (the IAM
// evaluator matches resource policies by ARN).
//
// A node id, an ARN, or anything containing "/" is returned as given. Otherwise exactly one node
// (never the Internet node) must carry the name; an unknown name wraps ErrNoSuchName and a
// shared name wraps ErrAmbiguousName with up to five candidate ids in the message.
func ResolveNodeName(g *Graph, r string) (string, error) {
	if _, ok := g.Node(r); ok || strings.HasPrefix(r, "arn:") || strings.Contains(r, "/") {
		return r, nil
	}
	var ids []string
	for _, n := range g.Nodes() {
		if n.Name == r && n.ID != InternetNodeID {
			ids = append(ids, n.ID)
		}
	}
	sort.Strings(ids)
	switch len(ids) {
	case 1:
		return ids[0], nil
	case 0:
		return "", fmt.Errorf("%w: %q: pass its ARN or node id (cloud-posture query \"SELECT id, type FROM graph_nodes WHERE name LIKE '%%%s%%'\")", ErrNoSuchName, r, r)
	}
	if len(ids) > 5 {
		ids = append(ids[:5], "…")
	}
	return "", fmt.Errorf("%w: %q (%s): pass the ARN or node id", ErrAmbiguousName, r, strings.Join(ids, ", "))
}

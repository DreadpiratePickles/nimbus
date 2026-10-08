package core

import (
	"fmt"
	"strings"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/graph"
	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// AccountNodeID matches the ID scheme graph.AttachFindings uses for account nodes.
func AccountNodeID(provider, account string) string { return provider + ":account:" + account }

// AccountType is the node type for a provider's top-level scope.
func AccountType(provider string) string {
	switch provider {
	case model.ProviderAWS:
		return "aws_account"
	case model.ProviderAzure:
		return "azure_subscription"
	case model.ProviderGCP:
		return "gcp_project"
	case model.ProviderKubernetes:
		return "k8s_cluster_account"
	case model.ProviderM365:
		return "m365_tenant"
	case model.ProviderOkta:
		return "okta_tenant"
	case model.ProviderGitHub:
		return "github_account"
	}
	return provider + "_account"
}

// EnsureAccount adds the account node and returns its ID.
func EnsureAccount(g *graph.Graph, provider, account, label string) string {
	id := AccountNodeID(provider, account)
	name := account
	if label != "" {
		name = label
	}
	g.AddNode(&graph.Node{ID: id, Type: AccountType(provider), Class: graph.ClassAccount, Name: name, Provider: provider, Account: account,
		Criticality: Criticality(name, nil)})
	return id
}

// Res bundles what a collector knows about one resource for AddResource.
type Res struct {
	Provider, Account, Region string
	Resource                  model.Resource
	Tags                      map[string]string
	Created                   time.Time
	// ForceSensitive marks crown jewels (e.g. secrets) regardless of hints.
	ForceSensitive bool
	MonthlyCost    float64
}

// Node converts the resource into a graph node with context fields derived from tags and name.
func (r Res) Node() *graph.Node {
	attrs := map[string]any{}
	for k, v := range r.Resource.Attributes {
		attrs[k] = v
	}
	if len(r.Tags) > 0 {
		attrs["tags"] = TagsAny(r.Tags)
	}
	n := &graph.Node{
		ID: r.Resource.ID, Type: r.Resource.Type, Name: r.Resource.Name, Provider: r.Provider, Account: r.Account, Region: r.Region,
		Attributes:  attrs,
		Sensitive:   r.ForceSensitive || Sensitive(r.Resource.Name, r.Resource.Type, r.Tags),
		Criticality: Criticality(r.Resource.Name, r.Tags),
		Owner:       Owner(r.Tags),
		MonthlyCost: r.MonthlyCost,
	}
	if !r.Created.IsZero() {
		n.ModifiedAt = r.Created.UTC().Format(time.RFC3339)
	}
	return n
}

// AddResource adds the node and the account→resource contains edge. It returns the node ID.
func AddResource(g *graph.Graph, r Res) string {
	if r.Resource.ID == "" {
		return ""
	}
	if r.Resource.Attributes == nil {
		r.Resource.Attributes = map[string]any{}
	}
	if len(r.Tags) > 0 {
		r.Resource.Attributes["tags"] = TagsAny(r.Tags)
	}
	n := g.AddNode(r.Node())
	if r.Account != "" {
		acct := AccountNodeID(r.Provider, r.Account)
		if _, ok := g.Node(acct); !ok {
			EnsureAccount(g, r.Provider, r.Account, "")
		}
		g.AddEdge(acct, n.ID, graph.EdgeContains, nil)
	}
	return n.ID
}

// TagsAny converts string tags into the map[string]any shape graph heuristics read.
func TagsAny(tags map[string]string) map[string]any {
	out := make(map[string]any, len(tags))
	for k, v := range tags {
		out[k] = v
	}
	return out
}

var sensitiveClass = map[string]bool{"pii": true, "confidential": true, "phi": true, "pci": true, "restricted": true, "secret": true}

var sensitiveNameHints = []string{"prod", "customer", "payment", "db", "pii", "billing", "finance", "secret", "credential", "patient", "backup"}

// Sensitive reports crown-jewel resources: classification tags of pii/confidential/phi/pci,
// or data stores whose name carries production / customer / payment / db hints.
func Sensitive(name, typ string, tags map[string]string) bool {
	for k, v := range tags {
		lk := strings.ToLower(k)
		if strings.Contains(lk, "classification") || strings.Contains(lk, "sensitivity") || lk == "data" || lk == "compliance" {
			if sensitiveClass[strings.ToLower(strings.TrimSpace(v))] {
				return true
			}
		}
	}
	if graph.ClassFor(typ) != graph.ClassDataStore {
		return false
	}
	l := strings.ToLower(name)
	for _, h := range sensitiveNameHints {
		if strings.Contains(l, h) {
			return true
		}
	}
	return false
}

// Criticality derives production | staging | dev | unknown from env tags, then the name.
func Criticality(name string, tags map[string]string) string {
	for k, v := range tags {
		switch strings.ToLower(k) {
		case "environment", "env", "stage", "tier", "environment_type":
			if c := envClass(v); c != "" {
				return c
			}
		}
	}
	if c := envClass(name); c != "" {
		return c
	}
	return "unknown"
}

func envClass(s string) string {
	l := strings.ToLower(s)
	switch {
	case strings.Contains(l, "preprod") || strings.Contains(l, "stag") || strings.Contains(l, "uat"):
		return "staging"
	case strings.Contains(l, "prod") || strings.Contains(l, "prd") || strings.Contains(l, "live"):
		return "production"
	case strings.Contains(l, "dev") || strings.Contains(l, "test") || strings.Contains(l, "sandbox") || strings.Contains(l, "qa"):
		return "dev"
	}
	return ""
}

// Owner returns the owner/team tag value.
func Owner(tags map[string]string) string {
	for _, k := range []string{"owner", "Owner", "OWNER", "team", "Team", "contact", "Contact", "created_by", "CreatedBy"} {
		if v, ok := tags[k]; ok && v != "" {
			return v
		}
	}
	for k, v := range tags {
		if strings.EqualFold(k, "owner") || strings.EqualFold(k, "team") {
			return v
		}
	}
	return ""
}

// Ports renders a port range for edge attributes.
func Ports(from, to int32) string {
	switch {
	case from <= 0 && to <= 0, from == 0 && to == 65535, from == -1:
		return "all"
	case from == to:
		return fmt.Sprint(from)
	}
	return fmt.Sprintf("%d-%d", from, to)
}

// PortInRange reports whether port falls within [from,to]; -1/0..65535 means all.
func PortInRange(port, from, to int32) bool {
	if from == -1 || (from == 0 && to == 0) || (from == 0 && to == 65535) {
		return true
	}
	return port >= from && port <= to
}

// IsOpenCIDR reports internet-wide sources across clouds.
func IsOpenCIDR(s string) bool {
	switch strings.TrimSpace(strings.ToLower(s)) {
	case "0.0.0.0/0", "::/0", "*", "internet", "any", "0.0.0.0":
		return true
	}
	return false
}

package core

import (
	"context"
	"strings"

	"github.com/DreadpiratePickles/nimbus/internal/graph"
)

// Targeted re-collection (plan v3 RM4, `cloud-posture verify`): a collector that can
// re-read a handful of resources by id, so a fix is confirmed against the cloud without a
// full scan (Prowler partial scans, Orca rescan-on-close, XM Cyber remediation confirmation).

// TargetResult is what one targeted read produced. Result carries the findings of the
// requested resources and their one-hop neighbours (plus partial errors); Graph is the
// matching fragment (anchor + one-hop neighbours and the edges among them).
type TargetResult struct {
	Result
	Graph *graph.Graph
	// Observed are the requested ids that exist; Missing the requested ids the provider
	// confirmed absent (deleted); Unsupported the ids of resource types this collector
	// cannot target.
	Observed    []string
	Missing     []string
	Unsupported []string
}

// Inconclusive reports a read that cannot confirm a fix: a partial error (denied,
// throttled, timed out) or an id the collector could not target. Absence of evidence in
// such a read is not evidence of a fix.
func (r *TargetResult) Inconclusive() bool {
	return r == nil || len(r.Errors) > 0 || len(r.Unsupported) > 0
}

// Targeted is implemented by collectors that can re-collect specific resources.
type Targeted interface {
	Target(ctx context.Context, spec AccountSpec, ids []string) (*TargetResult, error)
}

// TargetReader names the targeted reader that re-reads resource id of provider ("aws:rds",
// "azure:nsg", ...), or "" when no collector targets that type yet (verify then needs
// --from-file). It mirrors the parsers of the AWS and Azure targeted collectors (their tests
// assert they agree), so read-only surfaces (the MCP verify tool) can say what a verification
// would re-read without loading a collector.
func TargetReader(provider, id string) string {
	low := strings.ToLower(id)
	switch strings.ToLower(provider) {
	case "aws":
		switch {
		case strings.HasPrefix(id, "arn:aws:s3:::") && !strings.Contains(strings.TrimPrefix(id, "arn:aws:s3:::"), "/"):
			return "aws:s3"
		case strings.HasPrefix(id, "arn:aws:iam::") && strings.Contains(id, ":role/"):
			return "aws:iam-role"
		case strings.HasPrefix(id, "arn:aws:iam::") && strings.Contains(id, ":user/"):
			return "aws:iam-user"
		case strings.HasPrefix(id, "arn:aws:rds:") && strings.Contains(id, ":db:"):
			return "aws:rds"
		case strings.HasPrefix(id, "arn:aws:lambda:") && strings.Contains(id, ":function:"):
			return "aws:lambda"
		case strings.HasPrefix(id, "arn:aws:eks:") && strings.Contains(id, ":cluster/"):
			return "aws:eks"
		case strings.HasPrefix(id, "arn:aws:secretsmanager:") && strings.Count(id, ":") >= 6 && strings.Split(id, ":")[5] == "secret" && strings.SplitN(id, ":", 7)[6] != "":
			return "aws:secretsmanager"
		case strings.HasPrefix(id, "arn:aws:kms:") && strings.Count(id, ":") == 5 && strings.HasPrefix(strings.Split(id, ":")[5], "key/") && len(strings.Split(id, ":")[5]) > len("key/"):
			return "aws:kms"
		case strings.HasPrefix(id, "arn:aws:ec2:") && strings.Contains(id, ":instance/"), strings.HasPrefix(id, "i-"):
			return "aws:ec2"
		case strings.HasPrefix(id, "arn:aws:ec2:") && strings.Contains(id, ":security-group/"), strings.HasPrefix(id, "sg-"):
			return "aws:security-group"
		}
	case "kubernetes":
		p := strings.Split(id, "/")
		if len(p) != 3 || p[0] == "" || p[2] == "" {
			return ""
		}
		switch {
		case p[0] == "cluster" && p[1] == "clusterrolebinding":
			return "kubernetes:clusterrolebinding"
		case p[0] == "cluster":
			return ""
		case p[1] == "pod", p[1] == "service", p[1] == "serviceaccount":
			return "kubernetes:" + p[1]
		}
	case "gcp":
		if b, ok := strings.CutPrefix(id, "//storage.googleapis.com/projects/_/buckets/"); ok {
			if b != "" && !strings.Contains(b, "/") {
				return "gcp:bucket"
			}
			return ""
		}
		if i := strings.Index(id, "/projects/"); i >= 0 && strings.Contains(id[:i], "compute") {
			p := strings.Split(strings.TrimPrefix(id[i:], "/"), "/")
			switch {
			case len(p) == 5 && p[2] == "global" && p[3] == "firewalls" && p[1] != "" && p[4] != "":
				return "gcp:firewall"
			case len(p) == 6 && p[2] == "zones" && p[4] == "instances" && p[1] != "" && p[3] != "" && p[5] != "":
				return "gcp:instance"
			}
		}
	case "azure":
		if strings.HasPrefix(low, "/subscriptions/") && strings.Count(strings.Trim(low, "/"), "/") == 7 {
			switch {
			case strings.Contains(low, "/providers/microsoft.storage/storageaccounts/"):
				return "azure:storage"
			case strings.Contains(low, "/providers/microsoft.network/networksecuritygroups/"):
				return "azure:nsg"
			case strings.Contains(low, "/providers/microsoft.compute/virtualmachines/"):
				return "azure:vm"
			case strings.Contains(low, "/providers/microsoft.sql/servers/"):
				return "azure:sql"
			case strings.Contains(low, "/providers/microsoft.keyvault/vaults/"):
				return "azure:keyvault"
			}
		}
	}
	return ""
}

// OneHop is ids (those present in g) plus every node one edge away in either direction, plus
// the internet pseudo-node when any kept node is exposed: the caller (verify) replaces the
// internet edges of every node the fragment covers, so a neighbour's exposure must travel with
// it (a security group / firewall rule / NSG anchor still carries the instance it guards).
func OneHop(g *graph.Graph, ids []string) map[string]bool {
	keep := oneHop(g, ids)
	for id := range keep {
		for _, e := range g.In(id) {
			if e.From == graph.InternetNodeID {
				keep[graph.InternetNodeID] = true
			}
		}
	}
	return keep
}

func oneHop(g *graph.Graph, ids []string) map[string]bool {
	keep := map[string]bool{}
	for _, id := range ids {
		if _, ok := g.Node(id); !ok {
			continue
		}
		keep[id] = true
		for _, e := range g.Out(id) {
			keep[e.To] = true
		}
		for _, e := range g.In(id) {
			keep[e.From] = true
		}
	}
	return keep
}

// Subgraph copies the nodes in keep (weaknesses, finding ids and attributes are copied, not
// shared) and every edge whose two ends are both kept.
func Subgraph(g *graph.Graph, keep map[string]bool) *graph.Graph {
	out := graph.New()
	for _, n := range g.Nodes() {
		if !keep[n.ID] {
			continue
		}
		c := *n
		c.Weaknesses = append([]string(nil), n.Weaknesses...)
		c.FindingIDs = append([]string(nil), n.FindingIDs...)
		c.Attributes = make(map[string]any, len(n.Attributes))
		for k, v := range n.Attributes {
			c.Attributes[k] = v
		}
		out.AddNode(&c)
	}
	for _, e := range g.Edges() {
		if keep[e.From] && keep[e.To] {
			out.AddEdge(e.From, e.To, e.Kind, e.Attr)
		}
	}
	return out
}

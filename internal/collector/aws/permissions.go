package aws

import (
	"net/url"
	"sort"
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"

	"github.com/DreadpiratePickles/nimbus/internal/graph"
	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// Raw policy material for the IAM evaluator (graph.EvaluatePermissions, docs/iam/evaluator.md
// "Inputs"). Policies are not secrets: documents are stored verbatim (URL-decoded).

// decodeDoc URL-decodes an IAM API document (GetAccountAuthorizationDetails returns them
// percent-encoded).
func decodeDoc(doc string) string {
	doc = strings.TrimSpace(doc)
	if strings.HasPrefix(doc, "%7B") || strings.HasPrefix(doc, "%7b") {
		if d, err := url.QueryUnescape(doc); err == nil {
			return d
		}
	}
	return doc
}

// setResourcePolicy records a resource-based policy and its read status (collected | none |
// denied | error). Unknown status keeps decisions on the resource from being "verified".
func setResourcePolicy(attrs map[string]any, policy, status string) {
	if status == "" {
		return
	}
	attrs["resource_policy_status"] = status
	if policy != "" {
		attrs["resource_policy"] = decodeDoc(policy)
	}
}

func boundaryARN(b *iamtypes.AttachedPermissionsBoundary) string {
	if b == nil {
		return ""
	}
	return awssdk.ToString(b.PermissionsBoundaryArn)
}

// markComplete flags a principal whose every identity policy (and boundary) document was
// collected and parsed: the evaluator then generates its data-store edges.
func (a *analyzer) markComplete(arn string, complete bool, boundary any) {
	if b, _ := boundary.(string); b != "" {
		if n, ok := a.g.Node(b); !ok || n.Attributes["policy_document"] == nil || n.Attributes["policy_parse_error"] != nil {
			complete = false
		}
	}
	a.g.AddNode(&graph.Node{ID: arn, Attributes: map[string]any{"iam_policies_complete": complete}})
}

// orgPolicies writes the account's SCP / RCP chain on the account node: scp_status and
// scp_levels / rcp_levels ([[{id, name, arn, document}]], root first).
func (a *analyzer) orgPolicies() {
	op := a.inv.org
	status := "not_collected"
	attrs := map[string]any{}
	if op != nil {
		status = op.status
		conv := func(levels [][]scpPolicy) []any {
			out := make([]any, 0, len(levels))
			for _, l := range levels {
				level := make([]any, 0, len(l))
				for _, p := range l {
					level = append(level, map[string]any{"id": p.ID, "name": p.Name, "arn": p.ARN, "document": p.Document})
				}
				out = append(out, level)
			}
			return out
		}
		if len(op.levels) > 0 {
			attrs["scp_levels"] = conv(op.levels)
			attrs["org_path"] = op.path
		}
		if len(op.rcps) > 0 {
			attrs["rcp_levels"] = conv(op.rcps)
		}
	}
	attrs["scp_status"] = status
	// Organisation id (W7-ENGINE r5 #15): DescribeOrganization, else the organisation named by a
	// customer SCP / RCP ARN of the chain; unknown otherwise (status says why).
	oi := orgIdentity{status: "not_collected"}
	if a.inv.orgID != nil {
		oi = *a.inv.orgID
	}
	if oi.id == "" && op != nil {
		for _, levels := range [][][]scpPolicy{op.levels, op.rcps} {
			for _, l := range levels {
				for _, p := range l {
					if id := orgIDFromPolicyARN(p.ARN); id != "" && oi.id == "" {
						oi = orgIdentity{id: id, status: "collected", source: "scp-policy-arn"}
					}
				}
			}
		}
		if oi.id == "" && op.status == "not_in_org" {
			oi.status = "not_in_org"
		}
	}
	if oi.id != "" {
		attrs["organization_id"] = oi.id
		attrs["organization_id_source"] = oi.source
	}
	attrs["organization_id_status"] = oi.status
	a.g.AddNode(&graph.Node{ID: a.acctN, Type: "aws_account", Class: graph.ClassAccount, Attributes: attrs})
}

// heuristicFallback keeps the former statement heuristic for documents the evaluator cannot
// parse: principal -> store edges marked confidence hint.
func (a *analyzer) heuristicFallback(holders map[string][]string) {
	for _, pid := range sortedKeysOf(holders) {
		n, ok := a.g.Node(pid)
		if !ok || n.Attributes["policy_parse_error"] == nil {
			continue
		}
		raw, _ := n.Attributes["policy_document"].(string)
		doc, err := ParsePolicy(raw)
		if err != nil {
			continue
		}
		for _, da := range doc.DataAccess() {
			for _, target := range a.datastores[da.Service] {
				for _, pat := range da.Resources {
					if !MatchesResource(pat, target) {
						continue
					}
					for _, h := range holders[pid] {
						if strings.Contains(h, ":group/") {
							continue
						}
						a.g.AddEdge(h, target, graph.EdgeGrantsAccessTo, map[string]any{"actions": da.Actions, "service": da.Service,
							"resource_pattern": pat, "policy_arn": pid, "derived_from": "statement_heuristic", model.AttrConfidence: string(model.ConfidenceHint)})
					}
					break
				}
			}
		}
	}
}

func sortedKeysOf(m map[string][]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

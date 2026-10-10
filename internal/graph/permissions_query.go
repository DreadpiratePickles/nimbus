package graph

import (
	"github.com/DreadpiratePickles/nimbus/internal/iam"
)

// ActionDecision is the IAM evaluator's answer to "may this principal perform action on
// resource", for path rules (internal/attackpath/pathrules.go). Additive helper over
// principalPolicies; it does not change any edge.
type ActionDecision struct {
	Effect    iam.Effect // allow | unknown | implicit_deny | explicit_deny
	Statement string     // enabling identity statement (<policy>#<sid|index>), when one matched
	DeniedBy  string
	// Exact: the principal's policy material is complete and exact and its SCP status known,
	// so an Allow here is a verified fact rather than an inference.
	Exact bool
	// Known: at least one identity policy document was found for the principal.
	Known bool
}

// IsAWSPrincipal reports whether id is an AWS IAM user or role node the evaluator can model.
func (g *Graph) IsAWSPrincipal(id string) bool {
	n, ok := g.Node(id)
	return ok && isAWSPrincipal(n)
}

// EvaluatePrincipalAction evaluates action on resource for the principal node principalID.
func (g *Graph) EvaluatePrincipalAction(principalID, action, resource string) ActionDecision {
	n, ok := g.Node(principalID)
	if !ok || !isAWSPrincipal(n) {
		return ActionDecision{Effect: iam.ImplicitDeny}
	}
	pp := g.principalPolicies(n)
	if !pp.known {
		return ActionDecision{Effect: iam.ImplicitDeny}
	}
	d := iam.EvaluateSet(iam.Request{Principal: pp.principal, Action: action, Resource: resource, ResourceAccount: pp.account}, pp.ps)
	out := ActionDecision{Effect: d.Effect, Known: true, Exact: pp.complete && pp.exact && !pp.scpUnknown, DeniedBy: refText(d.DeniedBy)}
	if ref := firstAllow(d); ref != nil {
		out.Statement = ref.String()
	}
	return out
}

// EvaluatePrincipalActionWith is EvaluatePrincipalAction with request context the caller knows
// (W7-ENGINE, verification 7 defect 5: a path rule supplies iam:PassedToService = the service it
// exploits, so a PassRole statement conditioned on another service is refused and one on that
// service is an exact Allow). Other condition keys stay unknown (ContextComplete false).
func (g *Graph) EvaluatePrincipalActionWith(principalID, action, resource string, ctx map[string]iam.ConditionValue) ActionDecision {
	n, ok := g.Node(principalID)
	if !ok || !isAWSPrincipal(n) {
		return ActionDecision{Effect: iam.ImplicitDeny}
	}
	pp := g.principalPolicies(n)
	if !pp.known {
		return ActionDecision{Effect: iam.ImplicitDeny}
	}
	d := iam.EvaluateSet(iam.Request{Principal: pp.principal, Action: action, Resource: resource, ResourceAccount: pp.account, Context: ctx}, pp.ps)
	out := ActionDecision{Effect: d.Effect, Known: true, Exact: pp.complete && pp.exact && !pp.scpUnknown, DeniedBy: refText(d.DeniedBy)}
	if ref := firstAllow(d); ref != nil {
		out.Statement = ref.String()
	}
	return out
}

// PrincipalIsAdmin reports whether the principal already holds admin rights after guardrails
// (the same test escalationEdges uses to skip principals an escalation adds nothing to).
func (g *Graph) PrincipalIsAdmin(principalID string) bool {
	n, ok := g.Node(principalID)
	if !ok || !isAWSPrincipal(n) {
		return false
	}
	pp := g.principalPolicies(n)
	return pp.known && iam.IsAdmin(iam.AdminDecision(pp.principal, pp.account, pp.ps)) != iam.AdminNone
}

// TrustsService reports whether a role node's trust policy admits the service principal.
func (g *Graph) TrustsService(roleID, service string) bool {
	n, ok := g.Node(roleID)
	return ok && trustsService(n, service)
}

// AccountOf returns the node's AWS account (attribute or ARN segment).
func (g *Graph) AccountOf(id string) string {
	if n, ok := g.Node(id); ok {
		return accountOf(n)
	}
	return ""
}

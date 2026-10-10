package graph

import (
	"fmt"
	"sort"
	"strings"

	"github.com/DreadpiratePickles/nimbus/internal/iam"
	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// Permission-bearing edges (plan v3 P1-IAM items 2-4, DEC decisions 2-3). EvaluatePermissions
// runs the internal/iam evaluator over the AWS identity part of the graph, from whatever policy
// material the nodes carry (the AWS collector's raw documents, or an ingested inventory's
// inline_policy_document / attached_policies / trust_policy / governing_scps attributes):
//
//   - grants_access_to principal -> data store: the curated read actions of the store's type
//     (iam.ResourceProbes) are evaluated. Allow keeps the edge with a PermissionAttr; Unknown keeps
//     it as inferred; an explicit Deny anywhere (identity, boundary, SCP, resource policy) removes
//     it and records the denial on the principal (denied_edges, denied_by).
//   - can_assume caller -> role: the trust policy AND, for an IAM caller, the caller's
//     sts:AssumeRole must allow; a cross-account caller whose policies were not collected keeps
//     the edge as inferred with caller_permission "unknown".
//   - iam:PassRole + ec2:RunInstances on an EC2-trusting role with an instance profile adds a
//     can_assume edge with technique TechniquePassRoleEC2 (not for principals already admin).
//   - an admin principal (OVERPRIVILEGED_IDENTITY / AdministratorAccess) whose admin rights an
//     SCP or permission boundary removes is neutralised in the graph view: the weakness and the
//     admin attachment move to neutralised_weaknesses / attached_policies_denied, with denied_by.
//   - principals marked iam_policies_complete (the AWS collector) get evaluator-generated
//     grants_access_to edges to every data store they can read.
//
// Confidence (docs/iam/evaluator.md "Edge confidence"): verified when the decision is Allow from
// complete, exact documents with no undecidable condition and known SCP / resource-policy
// status; inferred when the decision is Unknown, or Allow resting on an approximated managed
// policy, a synthesised trust policy, an incomplete principal or an unknown caller; a declared
// typed relationship with no policy documents keeps verified (typed inventory relationship) and
// a scanner hint keeps hint. The pass is idempotent (AttachFindings runs it after every call).

const (
	AttrDeniedEdges      = "denied_edges"
	AttrDeniedBy         = "denied_by"
	AttrCallerPermission = "caller_permission"
	AttrTechnique        = "technique"
	// TechniquePassRoleEC2 is pathfinding.cloud's iam:PassRole + ec2:RunInstances escalation.
	TechniquePassRoleEC2 = "iam:PassRole+ec2:RunInstances"
	derivedFromEvaluator = "iam_evaluator"
	placeholderPolicyID  = "declared-relationship"
)

var allowAll = func() iam.Policy {
	p, _ := iam.ParsePolicy([]byte(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`))
	p.ID = placeholderPolicyID
	return p
}()

// policySet is everything known about one principal's policies.
type policySet struct {
	principal, account string
	ps                 iam.PolicySet
	known              bool // at least one identity document
	complete           bool // every identity source resolved to a document
	exact              bool // no approximated built-in managed policy
	scpUnknown         bool // the account's SCPs could not be read (verified impossible)
}

func isAWSPrincipal(n *Node) bool {
	return n != nil && (n.Type == "aws_iam_role" || n.Type == "aws_iam_user") && strings.HasPrefix(n.ID, "arn:aws:iam::")
}

func toStringList(v any) []string {
	switch x := v.(type) {
	case []string:
		return x
	case []any:
		out := make([]string, 0, len(x))
		for _, e := range x {
			if s, ok := e.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	case string:
		if x != "" {
			return []string{x}
		}
	}
	return nil
}

func accountOf(n *Node) string {
	if n.Account != "" {
		return n.Account
	}
	if parts := strings.SplitN(n.ID, ":", 6); len(parts) == 6 {
		return parts[4]
	}
	return ""
}

// principalPolicies collects n's identity policies (inline, attached, has_policy, groups),
// permission boundary and SCP levels.
func (g *Graph) principalPolicies(n *Node) policySet {
	pp := policySet{principal: n.ID, account: accountOf(n), complete: true, exact: true}
	seen := map[string]bool{}
	var collect func(n *Node, depth int)
	add := func(p iam.Policy, exact bool) {
		if seen[p.ID] {
			return
		}
		seen[p.ID] = true
		pp.ps.Identity = append(pp.ps.Identity, p)
		pp.known = true
		pp.exact = pp.exact && exact
	}
	resolve := func(ref string) (iam.Policy, bool, bool) {
		if pn, ok := g.Node(ref); ok && pn.Attributes != nil {
			if d, ok := pn.Attributes["policy_document"]; ok && d != nil {
				if p, err := iam.ParseAny(d); err == nil {
					p.ID = ref
					return p, true, true
				}
			}
		}
		return iam.ManagedPolicy(ref)
	}
	collect = func(n *Node, depth int) {
		a := n.Attributes
		if d, ok := a["inline_policy_document"]; ok && d != nil {
			if p, err := iam.ParseAny(d); err == nil {
				p.ID = n.ID + "/inline-policy"
				add(p, true)
			} else {
				pp.complete = false
			}
		}
		switch docs := a["inline_policy_documents"].(type) {
		case map[string]any:
			for _, name := range sortedMapKeys(docs) {
				if p, err := iam.ParseAny(docs[name]); err == nil {
					p.ID = n.ID + "/inline-policy/" + name
					add(p, true)
				} else {
					pp.complete = false
				}
			}
		case []any:
			for i, d := range docs {
				if p, err := iam.ParseAny(d); err == nil {
					p.ID = fmt.Sprintf("%s/inline-policy/%d", n.ID, i)
					add(p, true)
				} else {
					pp.complete = false
				}
			}
		}
		if s, ok := a["inline_policy"].(string); ok && s != "" {
			pp.complete = false // free text: not a document
		}
		for _, k := range []string{"attached_policies", "attached_policies_denied"} {
			for _, ref := range toStringList(a[k]) {
				if p, exact, ok := resolve(ref); ok {
					add(p, exact)
				} else {
					pp.complete = false
				}
			}
		}
		for _, e := range g.Out(n.ID) {
			switch e.Kind {
			case EdgeHasPolicy:
				if seen[e.To] {
					continue
				}
				if p, exact, ok := resolve(e.To); ok {
					add(p, exact)
				} else if pn, ok := g.Node(e.To); ok && pn.Type == "aws_iam_policy" {
					pp.complete = false
				}
			case EdgeMemberOf:
				if gn, ok := g.Node(e.To); ok && gn.Type == "aws_iam_group" && depth < 2 {
					collect(gn, depth+1)
				}
			}
		}
	}
	collect(n, 0)
	if b := n.Attributes["permissions_boundary_document"]; b != nil {
		if p, err := iam.ParseAny(b); err == nil {
			p.ID = n.ID + "/permissions-boundary"
			pp.ps.Boundary = &p
		}
	} else if ref, _ := n.Attributes["permissions_boundary"].(string); ref != "" {
		if p, exact, ok := resolve(ref); ok {
			pp.ps.Boundary = &p
			pp.exact = pp.exact && exact
		} else {
			pp.complete = false
		}
	}
	pp.ps.SCPs, pp.scpUnknown = g.scpLevels(n, pp.account)
	pp.ps.RCPs = g.rcpLevels(pp.account)
	return pp
}

// scpLevels reads scp_levels ([[{id, document}]], root first; the AWS collector puts them on the
// account node) or the flat governing_scps list ([{id, name, statement|document}], one level
// beside FullAWSAccess). unknown: the account node says its SCPs could not be read.
func (g *Graph) scpLevels(n *Node, account string) ([][]iam.Policy, bool) {
	srcs := []map[string]any{n.Attributes}
	unknown := false
	if an, ok := g.Node(accountNodeID("aws", account)); ok && an.Attributes != nil {
		srcs = append(srcs, an.Attributes)
		if st, _ := an.Attributes["scp_status"].(string); st == "denied" || st == "error" {
			unknown = true
		}
	}
	parse := func(m map[string]any, i int) (iam.Policy, bool) {
		id, _ := m["id"].(string)
		if id == "" {
			id = fmt.Sprintf("scp-%d", i)
		}
		src := m["document"]
		if src == nil {
			src = m["statement"]
		}
		if src == nil {
			src = m["content"]
		}
		p, err := iam.ParseAny(src)
		if err != nil {
			return iam.Policy{}, false
		}
		p.ID = id
		return p, true
	}
	for _, a := range srcs {
		if a == nil {
			continue
		}
		if lv, ok := a["scp_levels"].([]any); ok && len(lv) > 0 {
			var out [][]iam.Policy
			for _, l := range lv {
				var level []iam.Policy
				items, _ := l.([]any)
				for i, it := range items {
					if m, ok := it.(map[string]any); ok {
						if p, ok := parse(m, i); ok {
							level = append(level, p)
						}
					}
				}
				out = append(out, level)
			}
			return out, unknown
		}
		if gs, ok := a["governing_scps"].([]any); ok && len(gs) > 0 {
			full, _, _ := iam.ManagedPolicy("FullAWSAccess")
			level := []iam.Policy{full}
			for i, it := range gs {
				if m, ok := it.(map[string]any); ok {
					if p, ok := parse(m, i); ok {
						level = append(level, p)
					}
				}
			}
			return [][]iam.Policy{level}, unknown
		}
	}
	return nil, unknown
}

// rcpLevels reads rcp_levels from the account node (deny-only in the evaluator). RCPs govern
// the resource's account; v1 applies the principal's account chain, which is the same account
// for every same-account request (cross-account RCPs: docs/iam/evaluator.md deferred).
func (g *Graph) rcpLevels(account string) [][]iam.Policy {
	an, ok := g.Node(accountNodeID("aws", account))
	if !ok || an.Attributes == nil {
		return nil
	}
	lv, _ := an.Attributes["rcp_levels"].([]any)
	var out [][]iam.Policy
	for _, l := range lv {
		var level []iam.Policy
		items, _ := l.([]any)
		for i, it := range items {
			m, _ := it.(map[string]any)
			if m == nil {
				continue
			}
			p, err := iam.ParseAny(m["document"])
			if err != nil {
				continue
			}
			p.ID, _ = m["id"].(string)
			if p.ID == "" {
				p.ID = fmt.Sprintf("rcp-%d", i)
			}
			level = append(level, p)
		}
		out = append(out, level)
	}
	return out
}

func sortedMapKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// resourcePolicy returns the target's resource-based policy, whether its status is known, and
// whether the returned policy is exact (KMS keys without a collected key policy get the
// default key policy, which is not exact).
func resourcePolicy(t *Node) (*iam.Policy, bool, bool) {
	known := true
	if st, _ := t.Attributes["resource_policy_status"].(string); st == "denied" || st == "error" || st == "unknown" {
		known = false
	}
	for _, k := range []string{"resource_policy", "key_policy", "bucket_policy"} {
		if d := t.Attributes[k]; d != nil {
			if p, err := iam.ParseAny(d); err == nil {
				p.ID = t.ID + "/" + k
				return &p, known, true
			}
		}
	}
	if t.Type == "aws_kms_key" {
		acct := accountOf(t)
		p, err := iam.ParsePolicy([]byte(`{"Version":"2012-10-17","Statement":[{"Sid":"Enable IAM User Permissions","Effect":"Allow","Principal":{"AWS":"arn:aws:iam::` + acct + `:root"},"Action":"kms:*","Resource":"*"}]}`))
		if err == nil {
			p.ID = t.ID + "/default-key-policy"
			return &p, known, false
		}
	}
	return nil, known, true
}

type probeResult struct {
	allowed, unknown []string
	resources        []string
	allowRef         *iam.Ref
	denied           *iam.Ref
	deniedAction     string
	unknownKeys      []string
	conditional      []string
}

// evaluateProbes evaluates every probe of the tiers given; ImpliesRead admin probes count as
// read when TierRead is asked for.
func evaluateProbes(pp policySet, t *Node, tiers ...iam.Tier) probeResult {
	want := map[iam.Tier]bool{}
	for _, tr := range tiers {
		want[tr] = true
	}
	rp, _, _ := resourcePolicy(t)
	ps := pp.ps
	ps.Resource = rp
	var r probeResult
	seenKey := map[string]bool{}
	for _, pr := range iam.ResourceProbes(t.Type, t.ID) {
		if !want[pr.Tier] && !(want[iam.TierRead] && pr.ImpliesRead) {
			continue
		}
		d := iam.EvaluateSet(iam.Request{Principal: pp.principal, Action: pr.Action, Resource: pr.Resource, ResourceAccount: accountOf(t)}, ps)
		switch d.Effect {
		case iam.Allow:
			r.allowed = append(r.allowed, pr.Action)
			r.resources = appendUnique(r.resources, pr.Resource)
			if r.allowRef == nil {
				r.allowRef = firstAllow(d)
			}
		case iam.Unknown:
			r.unknown = append(r.unknown, pr.Action)
			r.resources = appendUnique(r.resources, pr.Resource)
			if r.allowRef == nil {
				r.allowRef = firstAllow(d)
			}
			for _, k := range d.UnknownConditionKeys {
				if !seenKey[k] {
					seenKey[k] = true
					r.unknownKeys = append(r.unknownKeys, k)
				}
			}
			for _, m := range d.MatchedStatements {
				if m.Conditional {
					r.conditional = appendUnique(r.conditional, m.String())
				}
			}
		case iam.ExplicitDeny:
			if r.denied == nil {
				r.denied, r.deniedAction = d.DeniedBy, pr.Action
			}
		}
	}
	return r
}

// firstAllow prefers the identity statement (the grant the operator edits), then any Allow.
func firstAllow(d iam.Decision) *iam.Ref {
	var any *iam.Ref
	for i := range d.MatchedStatements {
		m := d.MatchedStatements[i]
		if m.Effect != "Allow" || m.Layer == iam.LayerSCP || m.Layer == iam.LayerBoundary {
			continue
		}
		if m.Layer == iam.LayerIdentity {
			return &m
		}
		if any == nil {
			any = &m
		}
	}
	return any
}

func refText(r *iam.Ref) string {
	if r == nil {
		return ""
	}
	return string(r.Layer) + " " + r.String()
}

// EvaluatePermissions runs the permission pass (see the file comment). Safe to call repeatedly.
func (g *Graph) EvaluatePermissions() {
	var principals, stores, roles []*Node
	for _, n := range g.Nodes() {
		switch {
		case isAWSPrincipal(n):
			principals = append(principals, n)
			if n.Type == "aws_iam_role" {
				roles = append(roles, n)
			}
		}
		if n.Class == ClassDataStore && len(iam.ResourceProbes(n.Type, n.ID)) > 0 {
			stores = append(stores, n)
		}
	}
	cache := map[string]policySet{}
	policies := func(n *Node) policySet {
		if pp, ok := cache[n.ID]; ok {
			return pp
		}
		pp := g.principalPolicies(n)
		cache[n.ID] = pp
		return pp
	}
	for _, n := range principals {
		g.neutraliseAdmin(n, policies(n))
	}
	for _, n := range principals {
		if c, _ := n.Attributes["iam_policies_complete"].(bool); c {
			g.generateDataEdges(n, policies(n), stores)
		}
	}
	for _, n := range principals {
		g.escalationEdges(n, policies(n), roles)
	}
	for _, e := range g.Edges() {
		from, ok1 := g.Node(e.From)
		to, ok2 := g.Node(e.To)
		if !ok1 || !ok2 {
			continue
		}
		switch {
		case e.Kind == EdgeGrantsAccessTo && isAWSPrincipal(from) && len(iam.ResourceProbes(to.Type, to.ID)) > 0:
			g.evaluateGrant(e, from, to, policies(from))
		case e.Kind == EdgeCanAssume && to.Type == "aws_iam_role" && e.Attr[AttrTechnique] == nil:
			var pp *policySet
			if isAWSPrincipal(from) {
				p := policies(from)
				pp = &p
			}
			g.evaluateAssume(e, from, to, pp)
		}
	}
}

// setNodeAttrs copies the node's attribute map before writing (Clone shares it).
func (g *Graph) setNodeAttrs(n *Node, kv map[string]any) {
	g.mu.Lock()
	defer g.mu.Unlock()
	m := make(map[string]any, len(n.Attributes)+len(kv))
	for k, v := range n.Attributes {
		m[k] = v
	}
	for k, v := range kv {
		if v == nil {
			delete(m, k)
		} else {
			m[k] = v
		}
	}
	n.Attributes = m
}

// recordDenied removes the edge and appends the denial to the principal's denied_edges.
func (g *Graph) recordDenied(e *Edge, from, to *Node, actions []string, deniedBy string, because string) {
	g.RemoveEdge(e.From, e.To, e.Kind)
	g.recordDenial(from, to, e.Kind, actions, deniedBy, because)
}

// recordDenial appends one denial to the principal's denied_edges (replacing the same pair).
func (g *Graph) recordDenial(from, to *Node, kind string, actions []string, deniedBy string, because string) {
	rec := map[string]any{"to": to.ID, "kind": kind, "actions": actions, AttrDeniedBy: deniedBy, "because": because}
	var list []any
	if prev, ok := from.Attributes[AttrDeniedEdges].([]any); ok {
		for _, p := range prev {
			if m, ok := p.(map[string]any); ok && m["to"] == to.ID && m["kind"] == kind {
				continue
			}
			list = append(list, p)
		}
	}
	list = append(list, rec)
	kv := map[string]any{AttrDeniedEdges: list}
	if s, _ := from.Attributes[AttrDeniedBy].(string); s == "" {
		kv[AttrDeniedBy] = deniedBy
	}
	g.setNodeAttrs(from, kv)
}

func priorConfidence(e *Edge) model.Confidence {
	if h, _ := e.Attr["hint"].(bool); h {
		return model.ConfidenceHint
	}
	if c := e.Confidence(); c != "" {
		return c
	}
	if d, _ := e.Attr["declared"].(bool); d {
		return model.ConfidenceVerified
	}
	return model.ConfidenceHint
}

func (g *Graph) evaluateGrant(e *Edge, from, to *Node, pp policySet) {
	placeholder := !pp.known
	if placeholder {
		pp.ps.Identity = []iam.Policy{allowAll}
	}
	r := evaluateProbes(pp, to, iam.TierRead)
	if len(r.allowed) == 0 && len(r.unknown) == 0 {
		switch {
		case r.denied != nil:
			why := fmt.Sprintf("%s denies %s on %s (read edge removed)", refText(r.denied), r.deniedAction, to.ID)
			g.recordDenied(e, from, to, []string{r.deniedAction}, refText(r.denied), why)
			return
		case !placeholder && pp.complete:
			why := fmt.Sprintf("no policy of %s allows reading %s (implicit deny; read edge removed)", from.ID, to.ID)
			g.recordDenied(e, from, to, nil, "implicit_deny", why)
			return
		}
		// Incomplete documents: keep the claim, as a hint.
		e.SetConfidence(model.ConfidenceHint)
		e.SetBecause(fmt.Sprintf("%s grants access to %s per the inventory; the collected policies do not show a read (incomplete documents)", label(from), label(to)))
		return
	}
	if placeholder {
		// No documents: nothing new is learned about the grant beyond "no guardrail denies it";
		// keep the declared attributes and say so.
		if e.Confidence() == "" {
			e.SetConfidence(priorConfidence(e))
		}
		e.cowAttr()["evaluated_by"] = derivedFromEvaluator + " (guardrails only: no identity document)"
		return
	}
	_, rpKnown, rpExact := resourcePolicy(to)
	perm := model.PermissionAttr{Actions: append(append([]string(nil), r.allowed...), r.unknown...), Effect: model.EffectAllow, Resources: r.resources,
		UnknownConditions: r.unknownKeys, RequiresConditions: r.conditional}
	if r.allowRef != nil && r.allowRef.PolicyID != placeholderPolicyID {
		perm.Statement, perm.PolicyARN = r.allowRef.String(), r.allowRef.PolicyID
	}
	if w := g.otherTiers(pp, to); len(w) > 0 {
		e.cowAttr()["other_actions"] = w
	}
	var conf model.Confidence
	switch {
	case len(r.allowed) == 0:
		conf = model.ConfidenceInferred
	case pp.complete && pp.exact && rpKnown && rpExact && !pp.scpUnknown && len(r.conditional) == 0 && len(r.unknownKeys) == 0:
		conf = model.ConfidenceVerified
	default:
		conf = model.ConfidenceInferred
	}
	e.SetPermission(perm)
	e.SetConfidence(conf)
	e.cowAttr()["evaluated_by"] = derivedFromEvaluator
	src := perm.Statement
	if src == "" {
		src = "the declared relationship (no policy document; SCPs / boundary / resource policy checked)"
	}
	verb := "can read"
	if len(r.allowed) == 0 {
		verb = "may read (undecidable conditions: " + strings.Join(r.unknownKeys, ", ") + ")"
	}
	e.SetBecause(fmt.Sprintf("%s %s %s: %s allowed by %s (confidence %s)", label(from), verb, label(to), strings.Join(perm.Actions, ","), src, conf))
}

// otherTiers lists the allowed write / admin actions (attribute only; v1 edges model reads).
func (g *Graph) otherTiers(pp policySet, t *Node) []string {
	r := evaluateProbes(pp, t, iam.TierWrite, iam.TierAdmin)
	return r.allowed
}

func (g *Graph) generateDataEdges(n *Node, pp policySet, stores []*Node) {
	for _, t := range stores {
		if accountOf(t) != pp.account {
			if rp, _, _ := resourcePolicy(t); rp == nil || t.Type == "aws_kms_key" && t.Attributes["key_policy"] == nil && t.Attributes["resource_policy"] == nil {
				continue
			}
		}
		r := evaluateProbes(pp, t, iam.TierRead)
		switch {
		case len(r.allowed)+len(r.unknown) > 0:
			g.AddEdge(n.ID, t.ID, EdgeGrantsAccessTo, map[string]any{"derived_from": derivedFromEvaluator})
		case r.denied != nil && r.denied.Layer != iam.LayerIdentity || r.denied != nil && pp.grantsWithoutDenies(t):
			// A guardrail (SCP, boundary, resource policy) or an identity Deny removes a read the
			// principal's allows would otherwise give: record it so "because" can say why.
			g.recordDenial(n, t, EdgeGrantsAccessTo, []string{r.deniedAction}, refText(r.denied),
				fmt.Sprintf("%s denies %s on %s (no read edge)", refText(r.denied), r.deniedAction, t.ID))
		}
	}
}

func trustsService(r *Node, svc string) bool {
	for _, p := range toStringList(r.Attributes["trust_principals"]) {
		if p == svc {
			return true
		}
	}
	for _, p := range toStringList(r.Attributes["trusted_services"]) {
		if p == svc {
			return true
		}
	}
	if d := r.Attributes["trust_policy"]; d != nil {
		if p, err := iam.ParseAny(d); err == nil {
			for _, st := range p.Statement {
				if st.Effect == "Allow" && st.Principal != nil {
					for _, v := range st.Principal.Values["Service"] {
						if v == svc {
							return true
						}
					}
				}
			}
		}
	}
	return false
}

func (g *Graph) escalationEdges(n *Node, pp policySet, roles []*Node) {
	if !pp.known {
		return
	}
	if iam.IsAdmin(iam.AdminDecision(pp.principal, pp.account, pp.ps)) != iam.AdminNone {
		return // already admin: an escalation edge adds nothing
	}
	for _, r := range roles {
		if r.ID == n.ID || accountOf(r) != pp.account || !trustsService(r, "ec2.amazonaws.com") {
			continue
		}
		if len(toStringList(r.Attributes["instance_profile"]))+len(toStringList(r.Attributes["instance_profiles"])) == 0 {
			continue
		}
		region := r.Region
		if region == "" {
			region = "us-east-1"
		}
		pass := iam.EvaluateSet(iam.Request{Principal: pp.principal, Action: "iam:PassRole", Resource: r.ID, ResourceAccount: pp.account}, pp.ps)
		run := iam.EvaluateSet(iam.Request{Principal: pp.principal, Action: "ec2:RunInstances", Resource: "arn:aws:ec2:" + region + ":" + pp.account + ":instance/*", ResourceAccount: pp.account}, pp.ps)
		ok := func(d iam.Decision) bool { return d.Effect == iam.Allow || d.Effect == iam.Unknown }
		if !ok(pass) || !ok(run) {
			continue
		}
		conf := model.ConfidenceInferred
		if pass.Effect == iam.Allow && run.Effect == iam.Allow && pp.complete && pp.exact && !pp.scpUnknown {
			conf = model.ConfidenceVerified
		}
		ref := firstAllow(pass)
		perm := model.PermissionAttr{Actions: []string{"iam:PassRole", "ec2:RunInstances"}, Effect: model.EffectAllow, Resources: []string{r.ID}}
		if ref != nil {
			perm.Statement, perm.PolicyARN = ref.String(), ref.PolicyID
		}
		attr := model.EdgeAttrs{PermissionAttr: &perm, Confidence: conf,
			Because: fmt.Sprintf("%s can launch an EC2 instance with %s's instance profile (iam:PassRole by %s + ec2:RunInstances) and read its credentials (confidence %s)", label(n), label(r), perm.Statement, conf)}.Map()
		attr[AttrTechnique] = TechniquePassRoleEC2
		attr["derived_from"] = derivedFromEvaluator
		g.AddEdge(n.ID, r.ID, EdgeCanAssume, attr)
	}
}

// synthTrust builds a trust policy from trust_principals (ARNs, account ids, service names).
func synthTrust(r *Node) (*iam.Policy, bool) {
	ps := toStringList(r.Attributes["trust_principals"])
	if len(ps) == 0 {
		return nil, false
	}
	var aws, svc, fed []string
	for _, p := range ps {
		switch {
		case strings.HasSuffix(p, ".amazonaws.com"):
			svc = append(svc, p)
		case strings.Contains(p, ":oidc-provider/") || strings.Contains(p, ":saml-provider/"):
			fed = append(fed, p)
		default:
			aws = append(aws, p)
		}
	}
	pol := iam.Policy{ID: r.ID + "/trust-policy (from trust_principals)", Version: "2012-10-17"}
	add := func(kind string, vals []string, action string) {
		if len(vals) > 0 {
			pol.Statement = append(pol.Statement, iam.Statement{Effect: "Allow", Principal: &iam.PrincipalSet{Values: map[string][]string{kind: vals}}, Action: []string{action}})
		}
	}
	add("AWS", aws, "sts:AssumeRole")
	add("Service", svc, "sts:AssumeRole")
	add("Federated", fed, "sts:AssumeRoleWithWebIdentity")
	return &pol, true
}

func (g *Graph) evaluateAssume(e *Edge, from, to *Node, pp *policySet) {
	var trust *iam.Policy
	trustExact := false
	if d := to.Attributes["trust_policy"]; d != nil {
		if p, err := iam.ParseAny(d); err == nil {
			p.ID = to.ID + "/trust-policy"
			trust, trustExact = &p, true
		}
	} else if d := to.Attributes["assume_role_policy"]; d != nil {
		if p, err := iam.ParseAny(d); err == nil {
			p.ID = to.ID + "/trust-policy"
			trust, trustExact = &p, true
		}
	}
	if trust == nil {
		trust, _ = synthTrust(to)
	}
	toAcct := accountOf(to)
	caller, action := "", "sts:AssumeRole"
	var ps iam.PolicySet
	callerKnown := false
	switch {
	case pp != nil:
		caller = pp.principal
		ps = pp.ps
		callerKnown = pp.known
		if !pp.known {
			ps.Identity = []iam.Policy{allowAll}
		}
	case strings.HasPrefix(from.ID, "arn:aws:iam::") && strings.HasSuffix(from.ID, ":root"):
		caller = from.ID
		ps.Identity = []iam.Policy{allowAll}
	case strings.HasPrefix(from.ID, "aws:account:"):
		caller = "arn:aws:iam::" + strings.TrimPrefix(from.ID, "aws:account:") + ":root"
		ps.Identity = []iam.Policy{allowAll}
	case strings.Contains(from.ID, ":oidc-provider/"):
		caller, action = from.ID, "sts:AssumeRoleWithWebIdentity"
	case strings.Contains(from.ID, ":saml-provider/"):
		caller, action = from.ID, "sts:AssumeRoleWithSAML"
	default:
		return // internet, services, SaaS and Kubernetes identities: out of scope here
	}
	callerAcct := ""
	if parts := strings.SplitN(caller, ":", 6); len(parts) == 6 {
		callerAcct = parts[4]
	}
	cross := callerAcct != "" && toAcct != "" && callerAcct != toAcct
	if trust == nil {
		// No trust information: the declared relationship stands for the trust side; only a
		// cross-account caller's own policies can still be checked.
		if !cross {
			return
		}
		if pp == nil || !pp.known {
			e.cowAttr()[AttrCallerPermission] = "unknown"
			e.SetConfidence(model.ConfidenceInferred)
			return
		}
		t := iam.Policy{ID: placeholderPolicyID, Statement: []iam.Statement{{Effect: "Allow", Principal: &iam.PrincipalSet{Any: true}, Action: []string{"sts:*"}}}}
		trust = &t
	}
	ps.Resource = trust
	d := iam.EvaluateSet(iam.Request{Principal: caller, Action: action, Resource: to.ID, ResourceAccount: toAcct}, ps)
	switch d.Effect {
	case iam.ExplicitDeny:
		why := fmt.Sprintf("%s denies %s on %s (can_assume removed)", refText(d.DeniedBy), action, to.ID)
		g.recordDenied(e, from, to, []string{action}, refText(d.DeniedBy), why)
		return
	case iam.ImplicitDeny:
		if trustExact && (!cross || callerKnown && pp.complete) {
			g.recordDenied(e, from, to, []string{action}, "implicit_deny", fmt.Sprintf("neither the trust policy of %s nor %s's policies allow %s (can_assume removed): %s", to.ID, caller, action, strings.Join(d.Reasons, "; ")))
			return
		}
		e.SetConfidence(model.ConfidenceHint)
		return
	}
	perm := model.PermissionAttr{Actions: []string{action}, Effect: model.EffectAllow, Resources: []string{to.ID}, UnknownConditions: d.UnknownConditionKeys}
	for _, m := range d.MatchedStatements {
		if m.Conditional {
			perm.RequiresConditions = append(perm.RequiresConditions, m.String())
		}
	}
	if ref := firstAllow(d); ref != nil && ref.PolicyID != placeholderPolicyID {
		perm.Statement, perm.PolicyARN = ref.String(), ref.PolicyID
	}
	callerPerm := "allow"
	conf := model.ConfidenceVerified
	switch {
	case cross && !callerKnown:
		callerPerm = "unknown"
		conf = model.ConfidenceInferred
	case d.Effect == iam.Unknown, !trustExact:
		conf = model.ConfidenceInferred
	case pp != nil && cross && (!pp.complete || !pp.exact || pp.scpUnknown):
		conf = model.ConfidenceInferred
	}
	if !cross {
		callerPerm = ""
	}
	e.SetPermission(perm)
	e.SetConfidence(conf)
	if callerPerm != "" {
		e.cowAttr()[AttrCallerPermission] = callerPerm
	}
	e.cowAttr()["evaluated_by"] = derivedFromEvaluator
}

// grantsWithoutDenies: the identity allows alone (no deny statements) would read t.
func (pp policySet) grantsWithoutDenies(t *Node) bool {
	q := pp
	q.ps = iam.PolicySet{}
	for _, p := range pp.ps.Identity {
		c := iam.Policy{ID: p.ID, Version: p.Version}
		for _, st := range p.Statement {
			if st.Effect == "Allow" {
				c.Statement = append(c.Statement, st)
			}
		}
		q.ps.Identity = append(q.ps.Identity, c)
	}
	r := evaluateProbes(q, t, iam.TierRead)
	return len(r.allowed)+len(r.unknown) > 0
}

// adminClaim: the node is presented as admin (weakness or an AdministratorAccess attachment).
func adminClaim(n *Node) bool {
	if n.HasWeakness("OVERPRIVILEGED_IDENTITY") {
		return true
	}
	for _, p := range toStringList(n.Attributes["attached_policies"]) {
		if strings.HasSuffix(strings.ToLower(p), "administratoraccess") {
			return true
		}
	}
	return false
}

func (g *Graph) neutraliseAdmin(n *Node, pp policySet) {
	if pp.ps.Boundary == nil && len(pp.ps.SCPs) == 0 {
		return
	}
	if !adminClaim(n) && !n.HasWeakness("OVERPRIVILEGED_IDENTITY") {
		return
	}
	identity := pp.ps.Identity
	if !pp.known {
		identity = []iam.Policy{allowAll} // the finding says admin: grant it, then apply the guardrails
	}
	free := iam.PolicySet{Identity: identity}
	full := iam.PolicySet{Identity: identity, Boundary: pp.ps.Boundary, SCPs: pp.ps.SCPs}
	if iam.IsAdmin(iam.AdminDecision(pp.principal, pp.account, free)) == iam.AdminNone {
		return
	}
	if iam.IsAdmin(iam.AdminDecision(pp.principal, pp.account, full)) != iam.AdminNone {
		return
	}
	probe := iam.AdminDecision(pp.principal, pp.account, full)("iam:PutRolePolicy", "arn:aws:iam::123456789012:role/x")
	deniedBy := refText(probe.DeniedBy)
	if deniedBy == "" {
		deniedBy = "implicit_deny: " + strings.Join(probe.Reasons, "; ")
	}
	var keep, moved []string
	for _, p := range toStringList(n.Attributes["attached_policies"]) {
		if strings.HasSuffix(strings.ToLower(p), "administratoraccess") {
			moved = append(moved, p)
		} else {
			keep = append(keep, p)
		}
	}
	kv := map[string]any{"effective_admin": "none", AttrDeniedBy: deniedBy,
		"effective_admin_because": fmt.Sprintf("%s removes every privilege-escalation action from %s (admin policy neutralised)", deniedBy, n.ID)}
	if len(moved) > 0 {
		prev := toStringList(n.Attributes["attached_policies_denied"])
		for _, m := range moved {
			prev = appendUnique(prev, m)
		}
		kv["attached_policies_denied"] = prev
		if len(keep) > 0 {
			kv["attached_policies"] = keep
		} else {
			kv["attached_policies"] = nil
		}
	}
	if g.RemoveWeakness(n.ID, "OVERPRIVILEGED_IDENTITY") {
		kv["neutralised_weaknesses"] = appendUnique(toStringList(n.Attributes["neutralised_weaknesses"]), "OVERPRIVILEGED_IDENTITY")
	}
	g.setNodeAttrs(n, kv)
}

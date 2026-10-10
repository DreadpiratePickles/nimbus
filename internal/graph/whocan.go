package graph

import (
	"sort"
	"strings"

	"github.com/DreadpiratePickles/nimbus/internal/iam"
	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// WhoCanResult is one principal that can perform an action on a resource, directly or by
// assuming roles.
type WhoCanResult struct {
	Principal string `json:"principal"`
	// Via is the can_assume chain from Principal to the principal that holds the permission
	// (empty when Principal holds it itself).
	Via        []string         `json:"via,omitempty"`
	Holder     string           `json:"holder"`
	Decision   string           `json:"decision"` // allow | unknown | declared
	Statement  string           `json:"statement,omitempty"`
	PolicyARN  string           `json:"policy_arn,omitempty"`
	Confidence model.Confidence `json:"confidence"`
	Because    string           `json:"because"`
}

var confRank = map[model.Confidence]int{model.ConfidenceVerified: 3, model.ConfidenceInferred: 2, model.ConfidenceHint: 1, "": 0}

func weaker(a, b model.Confidence) model.Confidence {
	if confRank[a] <= confRank[b] {
		return a
	}
	return b
}

// resourceNode finds the graph node a request resource belongs to: the exact id, else the
// longest node id that prefixes it (an S3 object belongs to its bucket).
func (g *Graph) resourceNode(resource string) *Node {
	if n, ok := g.Node(resource); ok {
		return n
	}
	var best *Node
	for _, n := range g.Nodes() {
		if strings.HasPrefix(resource, n.ID+"/") || strings.HasPrefix(resource, n.ID+":") {
			if best == nil || len(n.ID) > len(best.ID) {
				best = n
			}
		}
	}
	return best
}

// WhoCan lists the principals that can perform action on resource: direct holders (evaluated
// from their policies; for principals without documents, a declared grants_access_to edge to the
// resource) and, transitively, every principal that reaches a holder through can_assume edges
// (at most maxDepth hops). Explicit denies (SCP, boundary, identity, resource policy) exclude.
func WhoCan(g *Graph, action, resource string, maxDepth int) []WhoCanResult {
	if maxDepth <= 0 {
		maxDepth = 4
	}
	target := g.resourceNode(resource)
	acct := ""
	if target != nil {
		acct = accountOf(target)
	} else if parts := strings.SplitN(resource, ":", 6); len(parts) == 6 {
		acct = parts[4]
	}
	var rp *iam.Policy
	rpExact := true
	assume := strings.HasPrefix(strings.ToLower(action), "sts:assumerole")
	if target != nil {
		rp, _, rpExact = resourcePolicy(target)
		if target.Type == "aws_iam_role" && assume {
			rp, rpExact = roleTrust(target)
		}
	}
	best := map[string]WhoCanResult{}
	consider := func(r WhoCanResult) {
		if old, ok := best[r.Principal]; ok && (len(old.Via) < len(r.Via) || len(old.Via) == len(r.Via) && confRank[old.Confidence] >= confRank[r.Confidence]) {
			return
		}
		best[r.Principal] = r
	}
	for _, n := range g.Nodes() {
		if !isAWSPrincipal(n) {
			continue
		}
		pp := g.principalPolicies(n)
		if !pp.known {
			// No documents: a declared read edge to the resource node, if the action is a read.
			if target == nil {
				continue
			}
			for _, e := range g.Out(n.ID) {
				if e.To != target.ID || e.Kind != EdgeGrantsAccessTo {
					continue
				}
				if p, ok := e.Permission(); ok && len(p.Actions) > 0 && !containsFold(p.Actions, action) {
					continue
				}
				if !isReadAction(target, action) {
					continue
				}
				consider(WhoCanResult{Principal: n.ID, Holder: n.ID, Decision: "declared", Confidence: e.Confidence(), Because: e.Because()})
			}
			continue
		}
		ps := pp.ps
		ps.Resource = rp
		d := iam.EvaluateSet(iam.Request{Principal: n.ID, Action: action, Resource: resource, ResourceAccount: acct}, ps)
		if d.Effect != iam.Allow && d.Effect != iam.Unknown {
			continue
		}
		conf := model.ConfidenceInferred
		if d.Effect == iam.Allow && pp.complete && pp.exact && rpExact && !pp.scpUnknown && len(d.UnknownConditionKeys) == 0 {
			conf = model.ConfidenceVerified
		}
		r := WhoCanResult{Principal: n.ID, Holder: n.ID, Decision: string(d.Effect), Confidence: conf}
		if ref := firstAllow(d); ref != nil {
			r.Statement, r.PolicyARN = ref.String(), ref.PolicyID
		}
		r.Because = label(n) + " is allowed " + action + " on " + resource + " by " + firstNon(r.Statement, "its policies")
		if d.Effect == iam.Unknown {
			r.Because += " (undecidable: " + strings.Join(d.UnknownConditionKeys, ", ") + ")"
		}
		consider(r)
	}
	// Assuming a role: every can_assume edge into it is a direct holder too (federated, external
	// and service callers carry no IAM policies of their own in the graph).
	if target != nil && assume {
		for _, e := range g.In(target.ID) {
			if e.Kind != EdgeCanAssume || e.From == InternetNodeID {
				continue
			}
			r := WhoCanResult{Principal: e.From, Holder: e.From, Decision: "declared", Confidence: e.Confidence(), Because: e.Because()}
			if p, ok := e.Permission(); ok {
				r.Statement, r.PolicyARN = p.Statement, p.PolicyARN
			}
			if r.Confidence == "" {
				r.Confidence = model.ConfidenceHint
			}
			if _, ok := best[e.From]; !ok {
				consider(r)
			}
		}
	}
	// Transitive: walk can_assume edges backwards from every holder.
	type item struct {
		id   string
		via  []string
		conf model.Confidence
		base WhoCanResult
	}
	var queue []item
	for _, r := range best {
		queue = append(queue, item{id: r.Principal, conf: r.Confidence, base: r})
	}
	sort.Slice(queue, func(i, j int) bool { return queue[i].id < queue[j].id })
	for len(queue) > 0 {
		it := queue[0]
		queue = queue[1:]
		if len(it.via) >= maxDepth {
			continue
		}
		for _, e := range g.In(it.id) {
			if e.Kind != EdgeCanAssume || e.From == InternetNodeID {
				continue
			}
			if containsFold(it.via, e.From) || e.From == it.base.Holder {
				continue
			}
			via := append([]string{it.id}, it.via...)
			conf := weaker(it.conf, e.Confidence())
			if conf == "" {
				conf = model.ConfidenceHint
			}
			r := it.base
			r.Principal, r.Via, r.Confidence = e.From, via, conf
			r.Because = e.From + " can assume " + strings.Join(via, " -> ") + "; " + it.base.Because
			if old, ok := best[e.From]; ok && len(old.Via) <= len(via) {
				continue
			}
			best[e.From] = r
			queue = append(queue, item{id: e.From, via: via, conf: conf, base: it.base})
		}
	}
	out := make([]WhoCanResult, 0, len(best)+1)
	for _, r := range best {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool {
		if len(out[i].Via) != len(out[j].Via) {
			return len(out[i].Via) < len(out[j].Via)
		}
		return out[i].Principal < out[j].Principal
	})
	if target != nil {
		if r, ok := g.anonymousAccess(target, action, resource); ok {
			out = append([]WhoCanResult{r}, out...)
		}
	}
	return out
}

// Synthetic principals who-can lists first (competitive delta r2 #5).
const (
	AnonymousPrincipal = "anonymous (internet)"
	OrgWidePrincipal   = "anyone in the organisation (org-wide)"
)

// anonymousAccess is the anonymous principal for a resource an anonymous internet caller can
// perform action on (anonymousReach: the S3 public access block first, then the resource policy
// evaluated with internal/iam for this action, Deny honoured, then ACL grants, an auth-less
// function URL, allUsers, a public blob container). A policy only an in-organisation caller
// satisfies (aws:PrincipalOrgID & co., by operator and value) gives the org-wide principal
// (Decision "conditional"). A resource REACH proved unreachable from the internet gets neither.
func (g *Graph) anonymousAccess(n *Node, action, resource string) (WhoCanResult, bool) {
	r := anonymousReach(n, action, resource)
	if r.v == "" || r.v == AnonPrivate && !r.org {
		return WhoCanResult{}, false
	}
	if !r.actionChecked {
		// A grant that does not name actions (auth-less URL, allUsers, a flattened policy flag):
		// the action must be one the resource policy's Principal * statements name when there is
		// a document, else a read.
		ok := isReadAction(n, action)
		if acts, doc := wildcardActions(n.Attributes); doc {
			ok = false
			for _, a := range acts {
				if actionGlob(a, action) {
					ok = true
					break
				}
			}
		}
		if !ok {
			return WhoCanResult{}, false
		}
	}
	if g.Verdict(n.ID).Blocked() {
		return WhoCanResult{}, false
	}
	conf := model.ConfidenceInferred
	if r.doc {
		conf = model.ConfidenceVerified
	}
	if r.v == AnonPrivate {
		return WhoCanResult{Principal: OrgWidePrincipal, Holder: "*", Decision: "conditional", Confidence: conf,
			Because: "any principal of the organisation can " + action + " on " + resource + ": " + r.why}, true
	}
	return WhoCanResult{Principal: AnonymousPrincipal, Holder: "*", Decision: "allow", Confidence: conf,
		Because: "anyone on the internet can " + action + " on " + resource + " without credentials: " + r.why}, true
}

// wildcardActions lists the actions of the Principal * Allow statements of a resource's policy
// document (doc=false when the resource carries no parseable document).
func wildcardActions(attrs map[string]any) (acts []string, doc bool) {
	pol, ok := resourcePolicyDoc(attrs)
	if !ok {
		return nil, false
	}
	for _, st := range pol.Statement {
		if st.Effect == "Allow" && widePrincipal(st) {
			acts = append(acts, st.Action...)
		}
	}
	return acts, true
}

// actionGlob matches an IAM action pattern (case-insensitive, * and ?).
func actionGlob(pattern, action string) bool {
	p, a := strings.ToLower(pattern), strings.ToLower(action)
	var m func(i, j int) bool
	m = func(i, j int) bool {
		for i < len(p) {
			switch p[i] {
			case '*':
				for k := j; k <= len(a); k++ {
					if m(i+1, k) {
						return true
					}
				}
				return false
			case '?':
				if j >= len(a) {
					return false
				}
			default:
				if j >= len(a) || p[i] != a[j] {
					return false
				}
			}
			i++
			j++
		}
		return j == len(a)
	}
	return m(0, 0)
}

func containsFold(list []string, s string) bool {
	for _, x := range list {
		if strings.EqualFold(x, s) {
			return true
		}
	}
	return false
}

func isReadAction(t *Node, action string) bool {
	for _, p := range iam.ResourceProbes(t.Type, t.ID) {
		if (p.Tier == iam.TierRead || p.ImpliesRead) && strings.EqualFold(p.Action, action) {
			return true
		}
	}
	return false
}

// roleTrust is the role's trust policy (collected / declared document, else synthesised from
// trust_principals: not exact).
func roleTrust(r *Node) (*iam.Policy, bool) {
	for _, k := range []string{"trust_policy", "assume_role_policy"} {
		if d := r.Attributes[k]; d != nil {
			if p, err := iam.ParseAny(d); err == nil {
				p.ID = r.ID + "/trust-policy"
				return &p, true
			}
		}
	}
	p, _ := synthTrust(r)
	return p, false
}

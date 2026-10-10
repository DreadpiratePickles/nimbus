package iam

import (
	"fmt"
	"sort"
	"strings"
)

// Effect is the outcome of an authorization decision.
type Effect string

const (
	Allow        Effect = "allow"
	ExplicitDeny Effect = "explicit_deny"
	ImplicitDeny Effect = "implicit_deny"
	// Unknown: the request may be allowed, but the inputs do not decide it
	// (a condition key missing from the context, an unsupported operator, an
	// unresolvable policy variable, an unknown resource owner).
	Unknown Effect = "unknown"
)

func (e Effect) String() string { return string(e) }

// ConditionValue is the value of one request-context key; multi-valued keys
// (aws:TagKeys, aws:CalledVia, ...) carry several entries.
type ConditionValue []string

// Request is one (principal, action, resource) triple to authorize.
type Request struct {
	// Principal is the caller: an IAM user or role ARN, an assumed-role
	// session ARN, a service principal (lambda.amazonaws.com), an identity
	// provider ARN for web identity / SAML, or "" for anonymous.
	Principal string
	Action    string
	Resource  string
	// ResourceAccount is the account owning the resource. Optional when the
	// ARN carries it; required for cross-account decisions on ARNs without an
	// account segment (S3).
	ResourceAccount string
	// Context holds the request context keys. Keys are case-insensitive.
	// aws:PrincipalArn, aws:PrincipalAccount, aws:PrincipalType,
	// aws:username and aws:ResourceAccount are derived from the request when
	// not supplied.
	Context map[string]ConditionValue
	// ContextComplete asserts that every catalogued global key absent from
	// Context is absent from the request, so AWS's missing-key semantics
	// apply. When false (the default) a missing key makes the statement
	// undecidable unless the operator is ...IfExists or Null.
	ContextComplete bool
}

// Decision is the result of Evaluate.
type Decision struct {
	Effect Effect
	// MatchedStatements lists every statement that applies to the request,
	// in evaluation order (SCPs, RCPs, resource, identity, boundary, session).
	// Statements whose applicability is undecidable carry Conditional.
	MatchedStatements []Ref
	// DeniedBy is the first statement that explicitly denies, if any.
	DeniedBy *Ref
	Reasons  []string
	// UnknownConditionKeys lists the context keys, policy variables and
	// unsupported operators that left some matching statement undecidable.
	UnknownConditionKeys []string
}

// PolicySet groups the policies that govern one request.
type PolicySet struct {
	Identity []Policy
	Resource *Policy // resource-based policy: bucket/key/queue policy, role trust policy
	Boundary *Policy
	Session  *Policy
	// SCPs and RCPs hold one slice per level of the OU chain (root, each OU,
	// the account). Each level needs an Allow for SCPs; RCPs are evaluated as
	// deny-only (their Allow statements are assumed to be RCPFullAWSAccess).
	SCPs [][]Policy
	RCPs [][]Policy
}

// Evaluate authorizes req against identity-based policies, an optional
// resource-based policy, permission boundary and session policy, and the SCPs
// of the principal's OU chain (one slice per level).
func Evaluate(req Request, identity []Policy, resource, boundary *Policy, scps [][]Policy, session *Policy) Decision {
	return EvaluateSet(req, PolicySet{Identity: identity, Resource: resource, Boundary: boundary, SCPs: scps, Session: session})
}

type evaluator struct {
	req     Request
	p       principal
	ctx     map[string]ConditionValue
	version string
	pending []string
	unknown map[string]bool
	matched []Ref
}

func newEvaluator(req Request) *evaluator {
	e := &evaluator{req: req, p: parsePrincipal(req.Principal), ctx: map[string]ConditionValue{}, unknown: map[string]bool{}}
	for k, v := range req.Context {
		e.ctx[strings.ToLower(k)] = v
	}
	derive := func(key, val string) {
		if _, ok := e.ctx[key]; !ok && val != "" {
			e.ctx[key] = ConditionValue{val}
		}
	}
	switch e.p.kind {
	case kindUser:
		derive("aws:principalarn", e.p.arn)
		derive("aws:username", e.p.name)
		derive("aws:principaltype", "User")
	case kindSession:
		derive("aws:principalarn", e.p.roleARN)
		derive("aws:principaltype", "AssumedRole")
	case kindRole:
		derive("aws:principalarn", e.p.arn)
	case kindRoot:
		derive("aws:principalarn", e.p.arn)
		derive("aws:principaltype", "Account")
	case kindFederatedUser:
		derive("aws:principalarn", e.p.arn)
		derive("aws:principaltype", "FederatedUser")
	}
	if e.p.kind != kindService && e.p.kind != kindFederated {
		derive("aws:principalaccount", e.p.account)
	}
	derive("aws:resourceaccount", e.resourceAccount())
	return e
}

func (e *evaluator) resourceAccount() string {
	if e.req.ResourceAccount != "" {
		return e.req.ResourceAccount
	}
	return arnAccount(e.req.Resource)
}

func (e *evaluator) lookup(key string) (ConditionValue, bool) {
	v, ok := e.ctx[strings.ToLower(key)]
	return v, ok && len(v) > 0
}

func (e *evaluator) note(key string) { e.pending = append(e.pending, key) }

func (e *evaluator) actionMatch(st Statement) tri {
	list, negate := st.Action, false
	if len(st.NotAction) > 0 {
		list, negate = st.NotAction, true
	}
	if len(list) == 0 {
		return no
	}
	hit := false
	for _, a := range list {
		if matchAction(a, e.req.Action) {
			hit = true
			break
		}
	}
	return triOf(hit != negate)
}

func (e *evaluator) resourceMatch(st Statement) tri {
	list, negate := st.Resource, false
	if len(st.NotResource) > 0 {
		list, negate = st.NotResource, true
	}
	if len(list) == 0 {
		return yes // trust and key policies may omit Resource: the policy's own resource
	}
	r := no
	for _, pat := range list {
		s, t := e.substitute(pat, e.version)
		if t == maybe {
			r = or3(r, maybe)
			continue
		}
		if t == yes && matchARN(s, e.req.Resource) {
			r = yes
			break
		}
	}
	if negate {
		r = not3(r)
	}
	return r
}

// match evaluates one statement and records it when it may apply.
func (e *evaluator) match(layer Layer, pol Policy, idx int) (tri, grantKind) {
	st := pol.Statement[idx]
	e.pending = e.pending[:0]
	e.version = pol.Version
	if st.Effect != "Allow" && st.Effect != "Deny" {
		return no, grantNone
	}
	r := e.actionMatch(st)
	if r == no {
		return no, grantNone
	}
	if r = and3(r, e.resourceMatch(st)); r == no {
		return no, grantNone
	}
	g := grantNone
	if layer == LayerResource || layer == LayerRCP {
		switch {
		case st.Principal != nil:
			if g = principalGrant(st.Principal, e.p); g == grantNone {
				return no, grantNone
			}
		case st.NotPrincipal != nil:
			if e.p.inNotPrincipal(st.NotPrincipal) {
				return no, grantNone
			}
			g = principalGrant(&PrincipalSet{Any: true}, e.p)
		case layer == LayerRCP:
			g = grantFinal
		default:
			return no, grantNone // a resource-based statement without a principal applies to nobody
		}
	}
	if r = and3(r, e.evalCondition(st.Condition)); r == no {
		return no, grantNone
	}
	ref := Ref{Layer: layer, PolicyID: pol.ID, Sid: st.Sid, Index: idx, Effect: st.Effect, Conditional: r == maybe}
	e.matched = append(e.matched, ref)
	if r == maybe {
		for _, k := range e.pending {
			e.unknown[k] = true
		}
	}
	return r, g
}

func isKMSKey(req Request) bool {
	return arnService(req.Resource) == "kms" && strings.HasPrefix(arnResource(req.Resource), "key/")
}

func isRoleAssume(req Request) bool {
	switch strings.ToLower(req.Action) {
	case "sts:assumerole", "sts:assumerolewithwebidentity", "sts:assumerolewithsaml":
		return arnService(req.Resource) == "iam" && strings.HasPrefix(arnResource(req.Resource), "role/")
	}
	return false
}

// EvaluateSet implements the AWS policy evaluation logic:
//
//  1. an explicit Deny in any applicable policy (SCP, RCP, resource,
//     identity, boundary, session) denies;
//  2. every SCP level of the principal's OU chain must allow (service
//     principals and service-linked roles are exempt);
//  3. same account: a resource-based policy naming the user / session /
//     service grants on its own; one naming the role ARN is limited by the
//     boundary and session policy; one naming the account delegates to IAM;
//     otherwise identity ∩ boundary ∩ session must allow. KMS keys and role
//     trust require the resource-based policy (key policy, trust policy);
//  4. cross account: identity ∩ boundary ∩ session AND the resource-based
//     policy must allow.
//
// Undecidable inputs yield Unknown whenever Allow is possible but not certain.
func EvaluateSet(req Request, ps PolicySet) Decision {
	e := newEvaluator(req)
	var d Decision
	deny := no

	onDeny := func(r tri) {
		deny = or3(deny, r)
		if r == yes && d.DeniedBy == nil {
			ref := e.matched[len(e.matched)-1]
			d.DeniedBy = &ref
		}
	}
	walk := func(layer Layer, pol Policy, onAllow func(tri, grantKind)) {
		for i, st := range pol.Statement {
			if layer == LayerRCP && st.Effect == "Allow" {
				continue // RCPs are modelled deny-only
			}
			r, g := e.match(layer, pol, i)
			if r == no {
				continue
			}
			if st.Effect == "Deny" {
				onDeny(r)
			} else if onAllow != nil {
				onAllow(r, g)
			}
		}
	}

	scpGate := yes
	scpExempt := e.p.kind == kindService || e.p.kind == kindAnonymous || e.p.kind == kindFederated || e.serviceLinked()
	var failedLevels []int
	// Exempt principals are not evaluated against SCPs at all: an SCP Deny
	// does not apply to them either (verify-4 defect 8: the exemption used to
	// override only the Allow gate, after the Deny had already been recorded).
	scpLevels := ps.SCPs
	if scpExempt {
		scpLevels = nil
	}
	for lvl, policies := range scpLevels {
		levelAllow := no
		for _, pol := range policies {
			walk(LayerSCP, pol, func(r tri, _ grantKind) { levelAllow = or3(levelAllow, r) })
		}
		if levelAllow == no {
			failedLevels = append(failedLevels, lvl)
		}
		scpGate = and3(scpGate, levelAllow)
	}
	if scpExempt {
		scpGate = yes
	}
	for _, policies := range ps.RCPs {
		for _, pol := range policies {
			walk(LayerRCP, pol, nil)
		}
	}
	rpFinal, rpLimited, rpAccount := no, no, no
	if ps.Resource != nil {
		walk(LayerResource, *ps.Resource, func(r tri, g grantKind) {
			switch g {
			case grantFinal:
				rpFinal = or3(rpFinal, r)
			case grantLimited:
				rpLimited = or3(rpLimited, r)
			case grantAccount:
				rpAccount = or3(rpAccount, r)
			}
		})
	}
	idAllow := no
	for _, pol := range ps.Identity {
		walk(LayerIdentity, pol, func(r tri, _ grantKind) { idAllow = or3(idAllow, r) })
	}
	bAllow, sAllow := yes, yes
	if ps.Boundary != nil {
		bAllow = no
		walk(LayerBoundary, *ps.Boundary, func(r tri, _ grantKind) { bAllow = or3(bAllow, r) })
	}
	if ps.Session != nil {
		sAllow = no
		walk(LayerSession, *ps.Session, func(r tri, _ grantKind) { sAllow = or3(sAllow, r) })
	}

	requiresRP := isKMSKey(req) || isRoleAssume(req)
	gIdentity := and3(idAllow, and3(bAllow, sAllow))
	gLimited := and3(rpLimited, and3(bAllow, sAllow))
	var same tri
	if requiresRP {
		same = or3(rpFinal, or3(gLimited, and3(gIdentity, rpAccount)))
	} else {
		same = or3(rpFinal, or3(gLimited, gIdentity))
	}
	rpAny := or3(rpFinal, or3(rpLimited, rpAccount))
	cross := and3(gIdentity, rpAny)

	crossAccount := no
	pAcct, rAcct := e.p.account, e.resourceAccount()
	switch {
	case pAcct == "" || e.p.kind == kindFederated:
	case rAcct == "" && ps.Resource != nil:
		crossAccount = maybe
	case rAcct != "":
		crossAccount = triOf(pAcct != rAcct)
	}
	var grant tri
	switch crossAccount {
	case no:
		grant = same
	case yes:
		grant = cross
	default:
		grant = both(same, cross)
	}
	allow := and3(scpGate, grant)

	d.MatchedStatements = e.matched
	for k := range e.unknown {
		d.UnknownConditionKeys = append(d.UnknownConditionKeys, k)
	}
	sort.Strings(d.UnknownConditionKeys)

	switch {
	case deny == yes:
		d.Effect = ExplicitDeny
		d.Reasons = append(d.Reasons, fmt.Sprintf("explicit deny in %s policy statement %s", d.DeniedBy.Layer, d.DeniedBy))
		return d
	case allow == no:
		d.Effect = ImplicitDeny
	case allow == yes && deny == no:
		d.Effect = Allow
		return d
	default:
		d.Effect = Unknown
	}

	// Explain an implicit deny or an unknown outcome.
	if scpGate != yes && !scpExempt {
		for _, lvl := range failedLevels {
			d.Reasons = append(d.Reasons, fmt.Sprintf("no SCP at SCP level %d allows %s", lvl, req.Action))
		}
		if len(failedLevels) == 0 {
			d.Reasons = append(d.Reasons, "an SCP allow depends on undecidable conditions")
		}
	}
	if grant != yes {
		switch {
		case crossAccount == maybe:
			d.Reasons = append(d.Reasons, "resource owner account unknown: same-account and cross-account rules disagree")
		case crossAccount == yes:
			if gIdentity != yes {
				d.Reasons = append(d.Reasons, "cross-account: the principal's identity-based policies (within boundary and session policy) must allow")
			}
			if rpAny != yes {
				d.Reasons = append(d.Reasons, "cross-account: the resource-based policy must allow the principal")
			}
		case requiresRP && isKMSKey(req):
			d.Reasons = append(d.Reasons, "KMS: the key policy must allow the principal or enable IAM policies for its account")
		case requiresRP:
			d.Reasons = append(d.Reasons, "the role trust policy must allow the principal to assume the role (or allow its account and the caller's identity policy must allow)")
		default:
			if idAllow != yes && rpAny != yes {
				d.Reasons = append(d.Reasons, "no identity-based or resource-based policy allows the request")
			}
		}
		if idAllow != no && bAllow != yes {
			d.Reasons = append(d.Reasons, "the permission boundary does not allow the request")
		}
		if (idAllow != no || rpLimited != no) && sAllow != yes {
			d.Reasons = append(d.Reasons, "the session policy does not allow the request")
		}
	}
	if deny == maybe {
		d.Reasons = append(d.Reasons, "an explicit deny may apply (undecidable conditions)")
	}
	if len(d.UnknownConditionKeys) > 0 && d.Effect == Unknown {
		d.Reasons = append(d.Reasons, "undecidable: "+strings.Join(d.UnknownConditionKeys, ", "))
	}
	return d
}

// serviceLinked reports a service-linked role principal (exempt from SCPs).
func (e *evaluator) serviceLinked() bool {
	v, ok := e.lookup("aws:PrincipalArn")
	if ok && strings.Contains(v[0], ":role/aws-service-role/") {
		return true
	}
	// A service-linked role session (arn:aws:sts::<acct>:assumed-role/
	// AWSServiceRoleFor…/…) does not carry the role path; the reserved
	// AWSServiceRoleFor name prefix identifies it (customers cannot create
	// roles with that prefix outside the aws-service-role/ path).
	return strings.HasPrefix(e.req.Principal, "arn:") &&
		strings.Contains(e.req.Principal, ":sts::") &&
		strings.Contains(e.req.Principal, ":assumed-role/AWSServiceRoleFor")
}

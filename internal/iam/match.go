package iam

import "strings"

// tri is a three-valued (Kleene) truth value: no < maybe < yes.
type tri int8

const (
	no tri = iota
	maybe
	yes
)

func (t tri) String() string { return [...]string{"no", "maybe", "yes"}[t] }

func and3(a, b tri) tri {
	if a < b {
		return a
	}
	return b
}

func or3(a, b tri) tri {
	if a > b {
		return a
	}
	return b
}

func not3(a tri) tri { return yes - a }

func triOf(b bool) tri {
	if b {
		return yes
	}
	return no
}

// both combines the outcomes of two alternative worlds (for example
// same-account and cross-account when the resource owner is unknown): definite
// only when both agree.
func both(a, b tri) tri {
	if a == b {
		return a
	}
	return maybe
}

// Literal markers produced by the ${*} and ${?} policy variables and by
// substituted variable values: they match the literal character only.
const (
	litStar     = ''
	litQuestion = ''
)

// glob matches an IAM pattern: '*' is any sequence (possibly empty), '?' any
// single character, the literal markers match '*' / '?' only. fold makes the
// match case-insensitive.
func glob(pattern, value string, fold bool) bool {
	if fold {
		pattern, value = strings.ToLower(pattern), strings.ToLower(value)
	}
	p := []rune(pattern)
	v := []rune(value)
	pi, vi := 0, 0
	starP, starV := -1, 0
	for vi < len(v) {
		if pi < len(p) {
			switch p[pi] {
			case '*':
				starP, starV = pi, vi
				pi++
				continue
			case '?':
				pi++
				vi++
				continue
			case litStar:
				if v[vi] == '*' {
					pi++
					vi++
					continue
				}
			case litQuestion:
				if v[vi] == '?' {
					pi++
					vi++
					continue
				}
			default:
				if p[pi] == v[vi] {
					pi++
					vi++
					continue
				}
			}
		}
		if starP < 0 {
			return false
		}
		starV++
		pi, vi = starP+1, starV
	}
	for pi < len(p) && p[pi] == '*' {
		pi++
	}
	return pi == len(p)
}

// matchAction matches an Action pattern against an action, case-insensitively.
func matchAction(pattern, action string) bool {
	return pattern == "*" || glob(pattern, action, true)
}

// matchARN matches a Resource pattern against a resource ARN, segment by
// segment (arn:partition:service:region:account:resource). A wildcard inside
// one of the first five segments never crosses a ':'; the final pattern
// segment covers the rest of the ARN, so "arn:*" and "arn:aws:*" cover
// everything. Matching is case-sensitive.
func matchARN(pattern, arn string) bool {
	if pattern == "*" {
		return true
	}
	ps := strings.SplitN(pattern, ":", 6)
	as := strings.SplitN(arn, ":", 6)
	if len(ps) == 1 || len(as) == 1 {
		return glob(pattern, arn, false)
	}
	if len(as) < len(ps) {
		return false
	}
	last := len(ps) - 1
	for i := 0; i < last; i++ {
		if !glob(ps[i], as[i], false) {
			return false
		}
	}
	return glob(ps[last], strings.Join(as[last:], ":"), false)
}

// principalKind classifies the request principal.
type principalKind int

const (
	kindAnonymous principalKind = iota
	kindUser
	kindRole    // a role ARN evaluated directly (analysis of the role itself)
	kindSession // arn:aws:sts::<acct>:assumed-role/<role>/<session>
	kindRoot
	kindService
	kindFederated     // an identity provider ARN (web identity / SAML)
	kindFederatedUser // arn:aws:sts::<acct>:federated-user/<name>
	kindOther
)

type principal struct {
	arn     string
	kind    principalKind
	account string
	name    string // user name or role name
	roleARN string // for sessions and roles: arn:aws:iam::<acct>:role/<name> (path unknown for sessions)
}

func parsePrincipal(s string) principal {
	p := principal{arn: s}
	if s == "" || s == "*" {
		p.kind = kindAnonymous
		return p
	}
	if !strings.HasPrefix(s, "arn:") {
		p.kind = kindService // e.g. lambda.amazonaws.com, cognito-identity.amazonaws.com
		return p
	}
	parts := strings.SplitN(s, ":", 6)
	if len(parts) < 6 {
		p.kind = kindOther
		return p
	}
	partition, svc, acct, res := parts[1], parts[2], parts[4], parts[5]
	p.account = acct
	switch {
	case svc == "iam" && res == "root":
		p.kind = kindRoot
	case svc == "iam" && strings.HasPrefix(res, "user/"):
		p.kind = kindUser
		p.name = res[strings.LastIndex(res, "/")+1:]
	case svc == "iam" && strings.HasPrefix(res, "role/"):
		p.kind = kindRole
		p.name = res[strings.LastIndex(res, "/")+1:]
		p.roleARN = s
	case svc == "iam" && (strings.HasPrefix(res, "oidc-provider/") || strings.HasPrefix(res, "saml-provider/")):
		p.kind = kindFederated
	case svc == "sts" && strings.HasPrefix(res, "assumed-role/"):
		p.kind = kindSession
		rest := strings.SplitN(strings.TrimPrefix(res, "assumed-role/"), "/", 2)
		p.name = rest[0]
		p.roleARN = "arn:" + partition + ":iam::" + acct + ":role/" + p.name
	case svc == "sts" && strings.HasPrefix(res, "federated-user/"):
		p.kind = kindFederatedUser
		p.name = strings.TrimPrefix(res, "federated-user/")
	default:
		p.kind = kindOther
	}
	return p
}

// sameRole reports whether a role ARN from a policy names the principal's role
// (the path is ignored because assumed-role ARNs do not carry it).
func (p principal) sameRole(policyARN string) bool {
	if p.roleARN == "" {
		return false
	}
	q := parsePrincipal(policyARN)
	return q.kind == kindRole && q.account == p.account && q.name == p.name
}

// accountRef reports whether a principal-element value names an account
// ("123456789012" or arn:aws:iam::123456789012:root) and returns it.
func accountRef(v string) (string, bool) {
	if len(v) == 12 && strings.Trim(v, "0123456789") == "" {
		return v, true
	}
	q := parsePrincipal(v)
	if q.kind == kindRoot {
		return q.account, true
	}
	return "", false
}

// grantKind is how a resource-policy statement names the request principal;
// it decides whether that grant is sufficient on its own (same account).
type grantKind int

const (
	grantNone grantKind = iota
	// grantAccount: the account is named; the account must delegate via an
	// identity-based policy (the identity must also allow).
	grantAccount
	// grantLimited: the role ARN (or "*" for a role session) is named; the
	// grant is added to the role's permissions and is limited by the
	// permission boundary and session policy.
	grantLimited
	// grantFinal: the user ARN, the session ARN, a service or federated
	// principal, or "*" for a non-role principal: sufficient on its own.
	grantFinal
)

// principalGrant classifies how a Principal element covers the request principal.
func principalGrant(ps *PrincipalSet, p principal) grantKind {
	if ps == nil {
		return grantNone
	}
	best := grantNone
	up := func(g grantKind) {
		if g > best {
			best = g
		}
	}
	wildcard := func() {
		if p.kind == kindSession || p.kind == kindRole {
			up(grantLimited)
		} else {
			up(grantFinal)
		}
	}
	if ps.Any {
		wildcard()
	}
	for _, typ := range sortedKeys(ps.Values) {
		for _, v := range ps.Values[typ] {
			switch strings.ToLower(typ) {
			case "aws":
				switch {
				case v == "*":
					wildcard()
				case v == p.arn && p.arn != "":
					if p.kind == kindRole {
						up(grantLimited)
					} else {
						up(grantFinal)
					}
				case p.sameRole(v):
					up(grantLimited)
				default:
					if acct, ok := accountRef(v); ok && acct == p.account && p.account != "" {
						if p.kind == kindRoot {
							up(grantFinal)
						} else {
							up(grantAccount)
						}
					}
				}
			case "service", "federated", "canonicaluser":
				if v == "*" || (v == p.arn && p.arn != "") {
					up(grantFinal)
				}
			}
		}
	}
	return best
}

// identities lists the principal identities AWS evaluates against a
// NotPrincipal element: the principal itself, its role, and its account.
func (p principal) inNotPrincipal(ps *PrincipalSet) bool {
	if ps.Any {
		return true
	}
	listed := func(match func(typ, v string) bool) bool {
		for _, typ := range sortedKeys(ps.Values) {
			for _, v := range ps.Values[typ] {
				if v == "*" || match(strings.ToLower(typ), v) {
					return true
				}
			}
		}
		return false
	}
	self := listed(func(typ, v string) bool { return v == p.arn && p.arn != "" })
	if !self {
		return false
	}
	if p.kind == kindSession && !listed(func(typ, v string) bool { return typ == "aws" && p.sameRole(v) }) {
		return false
	}
	if p.account != "" && p.kind != kindRoot && p.kind != kindFederated {
		if !listed(func(typ, v string) bool {
			acct, ok := accountRef(v)
			return typ == "aws" && ok && acct == p.account
		}) {
			return false
		}
	}
	return true
}

// arnAccount returns the account segment of an ARN, if any.
func arnAccount(arn string) string {
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) < 6 {
		return ""
	}
	return parts[4]
}

func arnService(arn string) string {
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) < 6 {
		return ""
	}
	return parts[2]
}

func arnResource(arn string) string {
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) < 6 {
		return ""
	}
	return parts[5]
}

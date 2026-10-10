package attackpath

import "testing"

// Verify-5 C1: trust conditions are judged by operator and value (through internal/iam's
// condition evaluator), not by key. A condition the external principal can satisfy (a negated
// operator, a wildcard, a Null check, an IfExists form, a foreign organisation, the trusted
// account itself) is no restriction and must not delete or downgrade the path.
func v5tDoc(stmts ...map[string]any) map[string]any {
	var s []any
	for _, x := range stmts {
		s = append(s, x)
	}
	return map[string]any{"Version": "2012-10-17", "Statement": s}
}

func v5tAllow(cond map[string]any) map[string]any {
	st := map[string]any{"Effect": "Allow", "Action": "sts:AssumeRole", "Principal": map[string]any{"AWS": "arn:aws:iam::222222222222:root"}}
	if cond != nil {
		st["Condition"] = cond
	}
	return st
}

func v5tC(op, k string, v any) map[string]any { return map[string]any{op: map[string]any{k: v}} }

func TestV5TrustConditionOperators(t *testing.T) {
	root := []any{"arn:aws:iam::222222222222:root"}
	const (
		open  = "open"  // external entry, likelihood >= 0.7 (0.8 for a foreign root)
		org   = "org"   // limited to the organisation / own account: no entry
		unk   = "unk"   // limited to an organisation while the role's own is unknown: inferred entry (W7)
		bound = "bound" // ExternalId / SourceIdentity required: 0.3
	)
	deny := v5tAllow(v5tC("StringNotEquals", "aws:PrincipalOrgID", "o-mine"))
	deny["Effect"] = "Deny"
	cases := []struct {
		name   string
		doc    map[string]any
		ownOrg string
		want   string
	}{
		// organisation conditions
		{"StringEquals PrincipalOrgID own org (org unknown)", v5tDoc(v5tAllow(v5tC("StringEquals", "aws:PrincipalOrgID", "o-mine"))), "", unk},
		{"StringEquals PrincipalOrgID own org (org known)", v5tDoc(v5tAllow(v5tC("StringEquals", "aws:PrincipalOrgID", "o-mine"))), "o-mine", org},
		{"StringEquals PrincipalOrgID foreign org", v5tDoc(v5tAllow(v5tC("StringEquals", "aws:PrincipalOrgID", "o-attacker"))), "o-mine", open},
		{"odd case key AWS:PRINCIPALORGID", v5tDoc(v5tAllow(v5tC("StringEquals", "AWS:PRINCIPALORGID", "o-mine"))), "o-mine", org},
		{"odd case key AWS:PRINCIPALORGID (org unknown)", v5tDoc(v5tAllow(v5tC("StringEquals", "AWS:PRINCIPALORGID", "o-mine"))), "", unk},
		{"StringNotEquals PrincipalOrgID", v5tDoc(v5tAllow(v5tC("StringNotEquals", "aws:PrincipalOrgID", "o-mine"))), "", open},
		{"StringNotLike PrincipalOrgID", v5tDoc(v5tAllow(v5tC("StringNotLike", "aws:PrincipalOrgID", "o-mine*"))), "", open},
		{"StringLike PrincipalOrgID *", v5tDoc(v5tAllow(v5tC("StringLike", "aws:PrincipalOrgID", "*"))), "", open},
		{"ForAnyValue:StringLike PrincipalOrgID o-*", v5tDoc(v5tAllow(v5tC("ForAnyValue:StringLike", "aws:PrincipalOrgID", "o-*"))), "", open},
		{"ForAllValues:StringEquals PrincipalOrgPaths (empty set passes)", v5tDoc(v5tAllow(v5tC("ForAllValues:StringEquals", "aws:PrincipalOrgPaths", "o-mine/r-1/"))), "", open},
		{"ForAnyValue:StringLike PrincipalOrgPaths own org", v5tDoc(v5tAllow(v5tC("ForAnyValue:StringLike", "aws:PrincipalOrgPaths", "o-mine/*"))), "o-mine", org},
		{"StringEqualsIfExists PrincipalOrgID", v5tDoc(v5tAllow(v5tC("StringEqualsIfExists", "aws:PrincipalOrgID", "o-mine"))), "", open},
		{"Null PrincipalOrgID true (caller in no org)", v5tDoc(v5tAllow(v5tC("Null", "aws:PrincipalOrgID", "true"))), "", open},
		{"Null PrincipalOrgID false (caller in any org)", v5tDoc(v5tAllow(v5tC("Null", "aws:PrincipalOrgID", "false"))), "", open},
		{"PrincipalAccount = the trusted foreign account", v5tDoc(v5tAllow(v5tC("StringEquals", "aws:PrincipalAccount", "222222222222"))), "", open},
		{"PrincipalAccount = own account", v5tDoc(v5tAllow(v5tC("StringEquals", "aws:PrincipalAccount", "111111111111"))), "", org},
		{"ArnLike PrincipalArn *", v5tDoc(v5tAllow(v5tC("ArnLike", "aws:PrincipalArn", "*"))), "", open},
		{"ArnLike PrincipalArn own account roles", v5tDoc(v5tAllow(v5tC("ArnLike", "aws:PrincipalArn", "arn:aws:iam::111111111111:role/*"))), "", org},
		{"Deny unless own org (Allow unconditioned)", v5tDoc(v5tAllow(nil), deny), "o-mine", org},
		{"Deny unless own org (Allow unconditioned, org unknown)", v5tDoc(v5tAllow(nil), deny), "", unk},
		{"org on one of two Allow statements", v5tDoc(v5tAllow(v5tC("StringEquals", "aws:PrincipalOrgID", "o-mine")), v5tAllow(nil)), "", open},
		{"unrelated MFA condition does not limit", v5tDoc(v5tAllow(v5tC("Bool", "aws:MultiFactorAuthPresent", "true"))), "", open},
		// ExternalId / SourceIdentity
		{"StringEquals ExternalId value", v5tDoc(v5tAllow(v5tC("StringEquals", "sts:ExternalId", "x-123"))), "", bound},
		{"odd case STS:EXTERNALID", v5tDoc(v5tAllow(v5tC("StringEquals", "STS:EXTERNALID", "x"))), "", bound},
		{"StringEquals SourceIdentity", v5tDoc(v5tAllow(v5tC("StringEquals", "sts:SourceIdentity", "alice"))), "", bound},
		{"StringLike ExternalId *", v5tDoc(v5tAllow(v5tC("StringLike", "sts:ExternalId", "*"))), "", open},
		{"StringNotEquals ExternalId", v5tDoc(v5tAllow(v5tC("StringNotEquals", "sts:ExternalId", "x-123"))), "", open},
		{"StringEqualsIfExists ExternalId", v5tDoc(v5tAllow(v5tC("StringEqualsIfExists", "sts:ExternalId", "x-123"))), "", open},
		{"Null ExternalId false (just present)", v5tDoc(v5tAllow(v5tC("Null", "sts:ExternalId", "false"))), "", open},
		{"Null ExternalId true (must be absent)", v5tDoc(v5tAllow(v5tC("Null", "sts:ExternalId", "true"))), "", open},
		{"ForAnyValue:StringLike ExternalId *", v5tDoc(v5tAllow(v5tC("ForAnyValue:StringLike", "sts:ExternalId", "*"))), "", open},
		{"control: no condition", v5tDoc(v5tAllow(nil)), "", open},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			attrs := map[string]any{"trust_principals": root, "trust_policy": c.doc}
			if c.ownOrg != "" {
				attrs["organization_id"] = c.ownOrg
			}
			g := v4tGraph(attrs)
			n, _ := g.Node(v4tRole)
			lik, why := crossAccountEntry(g, n)
			ok := false
			switch c.want {
			case open:
				ok = lik >= 0.7
			case org:
				ok = lik == 0
			case bound:
				ok = lik == ProtectedTrustEntry
			case unk:
				ok = lik == UnknownOrgTrustEntry
			}
			if !ok {
				t.Errorf("likelihood %.2f (%s), want %s", lik, why, c.want)
			}
		})
	}
}

// The flattened trust_conditions attribute is judged the same way.
func TestV5TrustConditionsAttribute(t *testing.T) {
	root := []any{"arn:aws:iam::222222222222:root"}
	for _, c := range []struct {
		cond map[string]any
		want float64
	}{
		{v5tC("ForAnyValue:StringLike", "aws:PrincipalOrgID", "o-*"), ExternalRootEntry},
		{v5tC("StringNotEquals", "aws:PrincipalOrgID", "o-abc"), ExternalRootEntry},
		{v5tC("StringEquals", "aws:PrincipalOrgID", "o-abc"), UnknownOrgTrustEntry}, // own org unknown: inferred, kept (W7)
		{v5tC("StringEquals", "sts:ExternalId", "x"), ProtectedTrustEntry},
		{v5tC("StringLike", "sts:ExternalId", "*"), ExternalRootEntry},
	} {
		g := v4tGraph(map[string]any{"trust_principals": root, "trust_conditions": c.cond})
		n, _ := g.Node(v4tRole)
		if lik, why := crossAccountEntry(g, n); lik != c.want {
			t.Errorf("%v: likelihood %.2f (%s), want %.2f", c.cond, lik, why, c.want)
		}
	}
}

// A path behind a non-restricting condition keeps its score (the 7.00 path the verifier saw deleted).
func TestV5TrustNonRestrictionKeepsPath(t *testing.T) {
	root := []any{"arn:aws:iam::222222222222:root"}
	base := v4tGraph(map[string]any{"trust_principals": root})
	want := 0.0
	for _, p := range Traverse(base, DefaultTraversalOptions()).Paths {
		if p.Score > want {
			want = p.Score
		}
	}
	if want == 0 {
		t.Fatal("control graph has no path")
	}
	g := v4tGraph(map[string]any{"trust_principals": root, "trust_policy": v5tDoc(v5tAllow(v5tC("StringNotEquals", "aws:PrincipalOrgID", "o-mine")))})
	best := 0.0
	for _, p := range Traverse(g, DefaultTraversalOptions()).Paths {
		if p.Score > best {
			best = p.Score
		}
	}
	if best != want {
		t.Errorf("StringNotEquals PrincipalOrgID: best path %.2f, want %.2f (unconditioned)", best, want)
	}
}

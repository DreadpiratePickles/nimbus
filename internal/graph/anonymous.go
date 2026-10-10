package graph

import (
	"encoding/json"
	"sort"
	"strings"

	"github.com/DreadpiratePickles/nimbus/internal/iam"
)

// Anonymous access (moved from internal/attackpath so the path engine's entry check and
// who-can's anonymous principal read one implementation; competitive delta r2 #5).
const (
	AnonPrivate   = "private"
	AnonAnonymous = "anonymous"
)

// Authentication types that require a signed / authenticated caller.
var authRequired = map[string]bool{"AWS_IAM": true, "IAM": true, "COGNITO_USER_POOLS": true, "CUSTOM": true, "JWT": true, "FUNCTION": true}

// anonVerdict is the anonymous-reach decision for a resource (and, for who-can, one action).
type anonVerdict struct {
	v, why string
	// doc: decided by evaluating a resource policy document (who-can confidence verified).
	doc bool
	// org: private because only callers inside the organisation / account / VPC are allowed
	// (who-can lists the org-wide principal).
	org bool
	// actionChecked: the requested action was evaluated (policy or ACL permission); otherwise
	// who-can still has to check that the action fits the anonymous grant.
	actionChecked bool
}

// AnonymousReach reads what a resource's attributes say about anonymous internet access:
// "private" (with the reason), "anonymous", or "" when no attribute decides it.
func AnonymousReach(typ string, attrs map[string]any) (string, string) {
	r := anonymousReach(&Node{Type: typ, Attributes: attrs}, "", "")
	return r.v, r.why
}

// AnonymousReachOf is AnonymousReach for a node: its id names the resource the resource
// policy's statements are evaluated against.
func AnonymousReachOf(n *Node) (string, string) {
	if n == nil {
		return "", ""
	}
	r := anonymousReach(n, "", "")
	return r.v, r.why
}

// anonymousReach decides anonymous internet access to n (for action on resource when action is
// set, else for any action). Order (verify-5 C3/C4/C9):
//
//  1. an authentication type on a function URL / API decides;
//  2. the S3 public access block, bucket and account level, read FIRST: all four settings (or
//     the collector's verdict that Block Public Access neutralises the grant) make the bucket
//     private; a partial block is remembered (RestrictPublicBuckets neutralises a public policy,
//     IgnorePublicAcls a public ACL; BlockPublicPolicy / BlockPublicAcls only refuse new ones);
//  3. the resource policy is evaluated with internal/iam for an anonymous caller from the
//     internet (Deny statements, Resource / NotAction and every condition honoured): an explicit
//     Deny is final (it overrides an ACL grant too); an Allow is anonymous unless
//     RestrictPublicBuckets neutralises it; an Allow only an in-organisation caller (aws:
//     PrincipalOrgID, PrincipalAccount, SourceVpc(e)…, by operator and value) gets is org-wide;
//  4. other storage settings, then ACL grants (unless IgnorePublicAcls), the flattened
//     bucket_policy_principal, allUsers members and public blob access;
//  5. org-wide, neutralised and condition-limited (aws:SourceIp…) grants are private.
func anonymousReach(n *Node, action, resource string) anonVerdict {
	attrs := n.Attributes
	if attrs == nil {
		return anonVerdict{}
	}
	for _, k := range []string{"function_url_auth_type", "auth_type", "url_auth_type", "authorization_type", "authorizer_type"} {
		v, _ := attrs[k].(string)
		switch u := strings.ToUpper(strings.TrimSpace(v)); {
		case authRequired[u]:
			return anonVerdict{v: AnonPrivate, why: "auth required (" + k + " " + u + ")"}
		case u == "NONE":
			return anonVerdict{v: AnonAnonymous, why: k + " NONE"}
		}
	}
	pab := readPAB(attrs)
	if pab.all {
		return anonVerdict{v: AnonPrivate, why: "anonymous access disabled (S3 public access block on" + pab.src + ")"}
	}
	var orgWhy, condWhy string
	var blocked []string
	if pol, ok := resourcePolicyDoc(attrs); ok {
		r := evalAnonPolicy(pol, n, action, resource)
		switch r.kind {
		case anonAllowed:
			if !pab.restrictPolicy {
				return anonVerdict{v: AnonAnonymous, why: r.why, doc: true, actionChecked: true}
			}
			blocked = append(blocked, "RestrictPublicBuckets neutralises the public bucket policy"+pab.restrictSrc)
		case anonDenied:
			return anonVerdict{v: AnonPrivate, why: r.why, doc: true, actionChecked: true}
		case anonOrg:
			orgWhy = r.why
		case anonConditional:
			condWhy = r.why
		}
	}
	lt := strings.ToLower(n.Type)
	if v, ok := attrs["allow_blob_public_access"].(bool); ok && !v {
		why := "anonymous access disabled (allow_blob_public_access=false"
		if pna, _ := attrs["public_network_access"].(string); strings.EqualFold(pna, "Disabled") {
			why += ", public_network_access=Disabled"
		}
		return anonVerdict{v: AnonPrivate, why: why + ")"}
	}
	if pna, _ := attrs["public_network_access"].(string); strings.EqualFold(pna, "Disabled") && strings.Contains(lt, "storage") {
		return anonVerdict{v: AnonPrivate, why: "anonymous access disabled (public_network_access=Disabled)"}
	}
	if pap, _ := attrs["public_access_prevention"].(string); strings.EqualFold(pap, "enforced") {
		return anonVerdict{v: AnonPrivate, why: "anonymous access disabled (public_access_prevention=enforced)"}
	}
	if grant, why := aclGrant(attrs); grant != "" {
		switch {
		case pab.ignoreACLs:
			blocked = append(blocked, "IgnorePublicAcls neutralises the public ACL"+pab.ignoreSrc)
		case action == "":
			return anonVerdict{v: AnonAnonymous, why: why}
		case isReadAction(n, action) || grant == "read-write" && aclWriteAction(action):
			return anonVerdict{v: AnonAnonymous, why: why, actionChecked: true}
		}
	}
	if p, _ := attrs["bucket_policy_principal"].(string); p == "*" {
		if pab.restrictPolicy {
			blocked = append(blocked, "RestrictPublicBuckets neutralises the public bucket policy"+pab.restrictSrc)
		} else if acts := anonStrings(attrs["bucket_policy_actions"]); action != "" && len(acts) > 0 {
			for _, a := range acts {
				if actionGlob(a, action) {
					return anonVerdict{v: AnonAnonymous, why: "bucket policy Principal *", actionChecked: true}
				}
			}
		} else {
			return anonVerdict{v: AnonAnonymous, why: "bucket policy Principal *"}
		}
	}
	for _, m := range anonStrings(attrs["iam_members"]) {
		if strings.HasPrefix(m, "allUsers") {
			return anonVerdict{v: AnonAnonymous, why: "IAM member allUsers"}
		}
	}
	if v, ok := attrs["allow_blob_public_access"].(bool); ok && v {
		return anonVerdict{v: AnonAnonymous, why: "allow_blob_public_access=true"}
	}
	switch {
	case orgWhy != "":
		return anonVerdict{v: AnonPrivate, why: orgWhy, doc: true, org: true, actionChecked: true}
	case len(blocked) > 0:
		return anonVerdict{v: AnonPrivate, why: "anonymous access disabled (S3 public access block: " + strings.Join(uniqStrings(blocked), "; ") + ")"}
	case condWhy != "":
		return anonVerdict{v: AnonPrivate, why: condWhy, doc: true, actionChecked: true}
	}
	return anonVerdict{}
}

// pabState is the effective S3 public access block (bucket OR account level).
type pabState struct {
	all, ignoreACLs, restrictPolicy bool
	src, ignoreSrc, restrictSrc     string
}

// readPAB reads public_access_block / account_public_access_block (a bool meaning all four
// settings, or a map of the settings in AWS or snake_case spelling; an absent key is off) and
// the collector's effective verdict (acl_public / policy_public with public=false: Block Public
// Access, possibly partial, neutralises the grant).
func readPAB(attrs map[string]any) pabState {
	var s pabState
	for _, lvl := range []struct{ key, name string }{{"public_access_block", "bucket"}, {"account_public_access_block", "account"}} {
		var ign, res bool
		switch b := attrs[lvl.key].(type) {
		case bool:
			ign, res = b, b
			if b {
				s.all = true
				if s.src == "" {
					s.src = ", " + lvl.name + " level"
				}
			}
		case map[string]any:
			flag := func(names ...string) bool {
				for k, v := range b {
					for _, nm := range names {
						if strings.EqualFold(strings.ReplaceAll(k, "_", ""), nm) {
							if t, _ := v.(bool); t {
								return true
							}
						}
					}
				}
				return false
			}
			ign, res = flag("IgnorePublicAcls"), flag("RestrictPublicBuckets")
			if ign && res && flag("BlockPublicAcls") && flag("BlockPublicPolicy") {
				s.all = true
				if s.src == "" {
					s.src = ", " + lvl.name + " level"
				}
			}
		}
		if ign && !s.ignoreACLs {
			s.ignoreACLs, s.ignoreSrc = true, " ("+lvl.name+" level)"
		}
		if res && !s.restrictPolicy {
			s.restrictPolicy, s.restrictSrc = true, " ("+lvl.name+" level)"
		}
	}
	_, aclKey := attrs["acl_public"]
	_, polKey := attrs["policy_public"]
	if pub, ok := attrs["public"].(bool); ok && !pub && (aclKey || polKey) {
		if t, _ := attrs["acl_public"].(bool); t && !s.ignoreACLs {
			s.ignoreACLs, s.ignoreSrc = true, " (collector: public=false)"
		}
		if t, _ := attrs["policy_public"].(bool); t && !s.restrictPolicy {
			s.restrictPolicy, s.restrictSrc = true, " (collector: public=false)"
		}
	}
	return s
}

// aclGrant is the anonymous ACL grant: "read", "read-write" or "" (with the reason).
func aclGrant(attrs map[string]any) (string, string) {
	for _, k := range []string{"acl", "canned_acl", "bucket_acl"} {
		a, _ := attrs[k].(string)
		switch {
		case strings.EqualFold(a, "public-read-write"):
			return "read-write", "ACL public-read-write"
		case strings.EqualFold(a, "public-read"):
			return "read", "ACL public-read"
		}
	}
	for _, gr := range anonStrings(attrs["acl_grantees"]) {
		if strings.Contains(gr, "/global/AllUsers") || gr == "AllUsers" {
			return "read", "ACL grant to AllUsers"
		}
	}
	if t, _ := attrs["acl_public"].(bool); t {
		return "read", "ACL grants public access (acl_public)"
	}
	return "", ""
}

func aclWriteAction(action string) bool {
	switch strings.ToLower(action) {
	case "s3:putobject", "s3:deleteobject":
		return true
	}
	return false
}

// resourcePolicyDoc parses the resource's policy (resource_policy, policy, bucket_policy: a
// document, a bare statement or a statement list, as a map or JSON text). A statement with no
// Effect reads as Allow (as the previous reader did); Effect is matched case-insensitively.
func resourcePolicyDoc(attrs map[string]any) (iam.Policy, bool) {
	for _, k := range []string{"resource_policy", "policy", "bucket_policy"} {
		var doc any
		switch x := attrs[k].(type) {
		case nil:
			continue
		case string:
			if strings.TrimSpace(x) == "" || json.Unmarshal([]byte(x), &doc) != nil {
				continue
			}
		default:
			doc = x
		}
		var stmts []any
		version := "2012-10-17"
		switch d := doc.(type) {
		case map[string]any:
			if v, _ := d["Version"].(string); v != "" {
				version = v
			}
			if st, ok := d["Statement"]; ok {
				switch t := st.(type) {
				case []any:
					stmts = t
				default:
					stmts = []any{t}
				}
			} else {
				stmts = []any{d}
			}
		case []any:
			stmts = d
		}
		var norm []any
		for _, raw := range stmts {
			st, _ := raw.(map[string]any)
			if st == nil {
				continue
			}
			c := make(map[string]any, len(st))
			for sk, sv := range st {
				c[sk] = sv
			}
			_, act := c["Action"]
			_, notAct := c["NotAction"]
			if !act && !notAct {
				c["Action"] = "*" // a bare statement without actions (a flattened collector shape) reads as any action
			}
			eff, _ := c["Effect"].(string)
			switch {
			case eff == "" || strings.EqualFold(eff, "Allow"):
				c["Effect"] = "Allow"
			case strings.EqualFold(eff, "Deny"):
				c["Effect"] = "Deny"
			}
			norm = append(norm, c)
		}
		if len(norm) == 0 {
			continue
		}
		p, err := iam.ParseAny(map[string]any{"Version": version, "Statement": norm})
		if err != nil || len(p.Statement) == 0 {
			continue
		}
		p.ID = k
		return p, true
	}
	return iam.Policy{}, false
}

type anonKind int

const (
	anonNone        anonKind = iota // no statement grants the anonymous caller (or anyone wide)
	anonAllowed                     // an anonymous internet caller is allowed
	anonDenied                      // an explicit Deny refuses the anonymous caller
	anonOrg                         // only a caller inside the organisation / account / VPC
	anonConditional                 // a Principal * grant whose other conditions (aws:SourceIp…) the anonymous caller fails
)

type anonPolicyResult struct {
	kind anonKind
	why  string
}

// Two unrelated internet source addresses: an anonymous grant must hold from anywhere, so a
// grant limited to some source range is not anonymous internet access.
var anonSourceIPs = []string{"192.0.2.10", "198.51.100.77"}

const anonProbeAccount = "000000000001"

var anonOrgIdentity = iam.Policy{ID: "org-caller-identity", Version: "2012-10-17",
	Statement: []iam.Statement{{Effect: "Allow", Action: []string{"*"}, Resource: []string{"*"}}}}

type anonProbe struct{ action, resource string }

// anonProbes are the requests evaluated: the given action, else every (action, resource) a
// wide-principal Allow statement names (wildcards made concrete).
func anonProbes(pol iam.Policy, n *Node, action, resource string) []anonProbe {
	if action != "" {
		if resource == "" {
			resource = n.ID
		}
		return []anonProbe{{action, resource}}
	}
	concrete := func(s string) string { return strings.NewReplacer("*", "x", "?", "x").Replace(s) }
	// own: the node's own request resources for an action (S3 object actions act on objects,
	// bucket actions on the bucket).
	own := func(a string) []string {
		if n.ID == "" {
			return []string{""}
		}
		if strings.Contains(strings.ToLower(n.Type), "s3_bucket") {
			la := strings.ToLower(a)
			switch {
			case strings.HasPrefix(la, "s3:") && strings.Contains(la, "object"):
				return []string{n.ID + "/x"}
			case strings.HasPrefix(la, "s3:") && !strings.HasSuffix(la, ":x"):
				return []string{n.ID}
			}
			return []string{n.ID + "/x", n.ID}
		}
		return []string{n.ID}
	}
	seen := map[anonProbe]bool{}
	var out []anonProbe
	for _, st := range pol.Statement {
		if st.Effect != "Allow" || !widePrincipal(st) {
			continue
		}
		var acts []string
		for _, a := range st.Action {
			acts = append(acts, concrete(a))
		}
		if len(st.NotAction) > 0 {
			for _, p := range iam.ResourceProbes(n.Type, n.ID) {
				acts = append(acts, p.Action)
			}
			acts = append(acts, "s3:GetObject", "lambda:InvokeFunctionUrl", "x:x")
		}
		for _, a := range acts {
			var ress []string
			for _, r := range st.Resource {
				if r == "*" {
					ress = append(ress, own(a)...)
				} else {
					ress = append(ress, concrete(r))
				}
			}
			if len(st.Resource) == 0 {
				ress = own(a)
			}
			for _, r := range ress {
				p := anonProbe{a, r}
				if !seen[p] {
					seen[p] = true
					out = append(out, p)
				}
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].action != out[j].action {
			return out[i].action < out[j].action
		}
		return out[i].resource < out[j].resource
	})
	return out
}

// widePrincipal: a statement whose Principal is * / {"AWS": "*"} (or a NotPrincipal).
func widePrincipal(st iam.Statement) bool {
	if st.NotPrincipal != nil {
		return true
	}
	if st.Principal == nil {
		return false
	}
	if st.Principal.Any {
		return true
	}
	for _, vs := range st.Principal.Values {
		for _, v := range vs {
			if v == "*" {
				return true
			}
		}
	}
	return false
}

// condKeysOf lists the condition keys of the Allow statements (lower-cased, sorted).
func condKeysOf(pol iam.Policy, effect string) []string {
	var out []string
	for _, st := range pol.Statement {
		if st.Effect != effect {
			continue
		}
		for _, kv := range st.Condition {
			for k := range kv {
				out = append(out, strings.ToLower(k))
			}
		}
	}
	out = uniqStrings(out)
	sort.Strings(out)
	return out
}

func condValues(pol iam.Policy, key string) []string {
	var out []string
	for _, st := range pol.Statement {
		for _, kv := range st.Condition {
			for k, vs := range kv {
				if strings.EqualFold(k, key) {
					out = append(out, vs...)
				}
			}
		}
	}
	return uniqStrings(out)
}

// evalAnonPolicy evaluates pol for an anonymous internet caller, then for a caller inside the
// organisation (an own-account and a foreign-account principal presenting the organisation /
// account / VPC values the policy names), with internal/iam's evaluator.
func evalAnonPolicy(pol iam.Policy, n *Node, action, resource string) anonPolicyResult {
	probes := anonProbes(pol, n, action, resource)
	if len(probes) == 0 {
		return anonPolicyResult{}
	}
	acct := accountOf(n)
	allowed := func(d iam.Decision) bool { return d.Effect == iam.Allow || d.Effect == iam.Unknown }
	anon := func(p iam.Policy, pr anonProbe, ip string) iam.Decision {
		return iam.EvaluateSet(iam.Request{Principal: "", Action: pr.action, Resource: pr.resource, ResourceAccount: acct,
			Context:         map[string]iam.ConditionValue{"aws:SourceIp": {ip}, "aws:SecureTransport": {"true"}},
			ContextComplete: true}, iam.PolicySet{Resource: &p})
	}
	denied := 0
	for _, pr := range probes {
		all, deny := true, false
		for _, ip := range anonSourceIPs {
			d := anon(pol, pr, ip)
			if !allowed(d) {
				all = false
			}
			if d.Effect == iam.ExplicitDeny {
				deny = true
			}
		}
		if all {
			return anonPolicyResult{kind: anonAllowed, why: "resource policy allows an anonymous caller " + pr.action + " (Principal * without an organisation / account / network condition it fails)"}
		}
		if deny {
			denied++
		}
	}
	// A caller inside the organisation / account / VPC.
	ctx := map[string]iam.ConditionValue{"aws:SecureTransport": {"true"}}
	concrete := func(s string) string { return strings.NewReplacer("*", "x", "?", "x").Replace(s) }
	var orgKeys []string
	for _, k := range []string{"aws:PrincipalOrgID", "aws:PrincipalOrgPaths", "aws:SourceVpc", "aws:SourceVpce", "aws:SourceAccount"} {
		var vs []string
		for _, v := range condValues(pol, k) {
			vs = append(vs, concrete(v))
		}
		if len(vs) > 0 {
			ctx[k] = vs
			orgKeys = append(orgKeys, k)
		}
	}
	accts := uniqStrings(append([]string{acct, anonProbeAccount}, condValues(pol, "aws:PrincipalAccount")...))
	if len(condValues(pol, "aws:PrincipalAccount")) > 0 {
		orgKeys = append(orgKeys, "aws:PrincipalAccount")
	}
	if len(orgKeys) > 0 {
		for _, pr := range probes {
			for _, a := range accts {
				if a == "" || strings.ContainsAny(a, "*?") {
					continue
				}
				d := iam.EvaluateSet(iam.Request{Principal: "arn:aws:iam::" + a + ":role/nimbus-org-probe", Action: pr.action, Resource: pr.resource,
					ResourceAccount: acct, Context: ctx, ContextComplete: true}, iam.PolicySet{Identity: []iam.Policy{anonOrgIdentity}, Resource: &pol})
				if allowed(d) {
					return anonPolicyResult{kind: anonOrg, why: "org-conditioned (Principal * limited by " + strings.Join(orgKeys, ", ") + ")"}
				}
			}
		}
	}
	if denied == len(probes) {
		return anonPolicyResult{kind: anonDenied, why: "resource policy explicitly denies the anonymous caller (Deny statement)"}
	}
	// Would the anonymous caller get in without the Allow statements' conditions (and the
	// conditional Denies)? Then those conditions (aws:SourceIp…) are what limit the grant.
	loose := iam.Policy{ID: pol.ID, Version: pol.Version}
	for _, st := range pol.Statement {
		if st.Effect == "Deny" && len(st.Condition) > 0 {
			continue
		}
		if st.Effect == "Allow" {
			st.Condition = nil
		}
		loose.Statement = append(loose.Statement, st)
	}
	for _, pr := range probes {
		if allowed(anon(loose, pr, anonSourceIPs[0])) {
			keys := uniqStrings(append(condKeysOf(pol, "Allow"), condKeysOf(pol, "Deny")...))
			return anonPolicyResult{kind: anonConditional, why: "resource policy grants Principal * only under conditions an anonymous internet caller does not meet (" + strings.Join(keys, ", ") + ")"}
		}
	}
	return anonPolicyResult{}
}

func anonStrings(v any) []string {
	switch x := v.(type) {
	case string:
		return []string{x}
	case []string:
		return x
	case []any:
		var out []string
		for _, e := range x {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func uniqStrings(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

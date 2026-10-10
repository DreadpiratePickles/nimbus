package iam

import (
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// opSpec describes one base condition operator.
type opSpec struct {
	negated bool
	null    bool
	// subst: policy variables are substituted in the policy values (String*
	// and Arn* operators).
	subst bool
	match func(requestValue, policyValue string) bool
}

func strEq(r, p string) bool     { return r == unmark(p) }
func strEqFold(r, p string) bool { return strings.EqualFold(r, unmark(p)) }
func strLike(r, p string) bool   { return glob(p, r, false) }
func arnLike(r, p string) bool   { return matchARN(p, r) }
func boolEq(r, p string) bool    { return strings.EqualFold(r, p) }
func binEq(r, p string) bool     { return r == p }

func numCmp(cmp func(a, b float64) bool) func(string, string) bool {
	return func(r, p string) bool {
		a, err1 := strconv.ParseFloat(strings.TrimSpace(r), 64)
		b, err2 := strconv.ParseFloat(strings.TrimSpace(p), 64)
		return err1 == nil && err2 == nil && cmp(a, b)
	}
}

func parseDate(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05Z0700", "2006-01-02T15:04Z07:00", "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, true
		}
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		return time.Unix(n, 0).UTC(), true
	}
	return time.Time{}, false
}

func dateCmp(cmp func(a, b int64) bool) func(string, string) bool {
	return func(r, p string) bool {
		a, ok1 := parseDate(r)
		b, ok2 := parseDate(p)
		return ok1 && ok2 && cmp(a.UnixNano(), b.UnixNano())
	}
}

func ipIn(r, p string) bool {
	addr, err := netip.ParseAddr(strings.TrimSpace(r))
	if err != nil {
		return false
	}
	p = strings.TrimSpace(p)
	if !strings.Contains(p, "/") {
		a, err := netip.ParseAddr(p)
		return err == nil && a.Unmap() == addr.Unmap()
	}
	pre, err := netip.ParsePrefix(p)
	return err == nil && pre.Contains(addr)
}

var (
	eqF = func(a, b float64) bool { return a == b }
	ltF = func(a, b float64) bool { return a < b }
	leF = func(a, b float64) bool { return a <= b }
	gtF = func(a, b float64) bool { return a > b }
	geF = func(a, b float64) bool { return a >= b }
	eqI = func(a, b int64) bool { return a == b }
	ltI = func(a, b int64) bool { return a < b }
	leI = func(a, b int64) bool { return a <= b }
	gtI = func(a, b int64) bool { return a > b }
	geI = func(a, b int64) bool { return a >= b }
	ops = map[string]opSpec{
		"stringequals":              {match: strEq, subst: true},
		"stringnotequals":           {match: strEq, subst: true, negated: true},
		"stringequalsignorecase":    {match: strEqFold, subst: true},
		"stringnotequalsignorecase": {match: strEqFold, subst: true, negated: true},
		"stringlike":                {match: strLike, subst: true},
		"stringnotlike":             {match: strLike, subst: true, negated: true},
		"numericequals":             {match: numCmp(eqF)},
		"numericnotequals":          {match: numCmp(eqF), negated: true},
		"numericlessthan":           {match: numCmp(ltF)},
		"numericlessthanequals":     {match: numCmp(leF)},
		"numericgreaterthan":        {match: numCmp(gtF)},
		"numericgreaterthanequals":  {match: numCmp(geF)},
		"dateequals":                {match: dateCmp(eqI)},
		"datenotequals":             {match: dateCmp(eqI), negated: true},
		"datelessthan":              {match: dateCmp(ltI)},
		"datelessthanequals":        {match: dateCmp(leI)},
		"dategreaterthan":           {match: dateCmp(gtI)},
		"dategreaterthanequals":     {match: dateCmp(geI)},
		"bool":                      {match: boolEq},
		"binaryequals":              {match: binEq},
		"ipaddress":                 {match: ipIn},
		"notipaddress":              {match: ipIn, negated: true},
		"arnequals":                 {match: arnLike, subst: true},
		"arnlike":                   {match: arnLike, subst: true},
		"arnnotequals":              {match: arnLike, subst: true, negated: true},
		"arnnotlike":                {match: arnLike, subst: true, negated: true},
		"null":                      {null: true},
	}
)

// parseOperator splits "ForAnyValue:StringLikeIfExists" into its base
// operator, set qualifier ("", "any", "all") and IfExists flag.
func parseOperator(op string) (spec opSpec, set string, ifExists bool, ok bool) {
	l := strings.ToLower(op)
	switch {
	case strings.HasPrefix(l, "foranyvalue:"):
		set, l = "any", strings.TrimPrefix(l, "foranyvalue:")
	case strings.HasPrefix(l, "forallvalues:"):
		set, l = "all", strings.TrimPrefix(l, "forallvalues:")
	case strings.Contains(l, ":"):
		return opSpec{}, "", false, false
	}
	if strings.HasSuffix(l, "ifexists") {
		ifExists, l = true, strings.TrimSuffix(l, "ifexists")
	}
	spec, ok = ops[l]
	if ok && spec.null && (ifExists || set != "") {
		return opSpec{}, "", false, false
	}
	return spec, set, ifExists, ok
}

// evalCondition evaluates a Condition block: operators and keys are ANDed.
func (e *evaluator) evalCondition(c map[string]map[string][]string) tri {
	r := yes
	for _, op := range sortedKeys(c) {
		for _, key := range sortedKeys(c[op]) {
			r = and3(r, e.evalConditionKey(op, key, c[op][key]))
		}
	}
	return r
}

func (e *evaluator) evalConditionKey(op, key string, policyVals []string) tri {
	spec, set, ifExists, ok := parseOperator(op)
	if !ok {
		e.note(op)
		return maybe
	}
	reqVals, present := e.lookup(key)
	if spec.null {
		want := len(policyVals) > 0 && strings.EqualFold(policyVals[0], "true")
		return triOf(!present == want)
	}
	if !present {
		if ifExists {
			return yes
		}
		if e.req.ContextComplete && knownKey(key) {
			switch set {
			case "all":
				return yes
			case "any":
				return no
			}
			return triOf(spec.negated)
		}
		e.note(key)
		return maybe
	}
	var pv []string
	unresolved := false
	for _, v := range policyVals {
		if spec.subst {
			s, t := e.substitute(v, e.version)
			switch t {
			case no:
				continue
			case maybe:
				unresolved = true
				continue
			}
			v = s
		}
		pv = append(pv, v)
	}
	perValue := func(rv string) tri {
		m := no
		for _, p := range pv {
			if spec.match(rv, p) {
				m = yes
				break
			}
		}
		if m == no && unresolved {
			m = maybe
		}
		if spec.negated {
			m = not3(m)
		}
		return m
	}
	anyOf := func() tri {
		r := no
		for _, rv := range reqVals {
			r = or3(r, perValue(rv))
		}
		return r
	}
	allOf := func() tri {
		r := yes
		for _, rv := range reqVals {
			r = and3(r, perValue(rv))
		}
		return r
	}
	switch {
	case set == "any":
		return anyOf()
	case set == "all":
		return allOf()
	case spec.negated:
		// a negated operator holds when no request value matches
		return allOf()
	default:
		return anyOf()
	}
}

// unmark turns literal markers back into the characters they stand for.
func unmark(s string) string {
	if !strings.ContainsAny(s, string([]rune{litStar, litQuestion})) {
		return s
	}
	return strings.NewReplacer(string(litStar), "*", string(litQuestion), "?").Replace(s)
}

func mark(s string) string {
	return strings.NewReplacer("*", string(litStar), "?", string(litQuestion)).Replace(s)
}

// substitute replaces policy variables (${key} and ${key, 'default'}) in a
// Resource or condition value. Version 2012-10-17 is required; older
// documents keep the text literally. The result is yes with the substituted
// pattern, no when a variable is known to be absent (ContextComplete), and
// maybe when a variable cannot be resolved (recorded as an unknown key).
func (e *evaluator) substitute(s, version string) (string, tri) {
	if version != "2012-10-17" || !strings.Contains(s, "${") {
		return s, yes
	}
	var b strings.Builder
	result := yes
	for {
		i := strings.Index(s, "${")
		if i < 0 {
			b.WriteString(s)
			break
		}
		j := strings.Index(s[i:], "}")
		if j < 0 {
			b.WriteString(s)
			break
		}
		b.WriteString(s[:i])
		inner := strings.TrimSpace(s[i+2 : i+j])
		s = s[i+j+1:]
		switch inner {
		case "*":
			b.WriteRune(litStar)
			continue
		case "?":
			b.WriteRune(litQuestion)
			continue
		case "$":
			b.WriteByte('$')
			continue
		}
		key, def, hasDef := inner, "", false
		if k := strings.Index(inner, ","); k >= 0 {
			key = strings.TrimSpace(inner[:k])
			d := strings.TrimSpace(inner[k+1:])
			if len(d) >= 2 && d[0] == '\'' && d[len(d)-1] == '\'' {
				def, hasDef = d[1:len(d)-1], true
			}
		}
		vals, present := e.lookup(key)
		switch {
		case present && len(vals) == 1:
			b.WriteString(mark(vals[0]))
		case present:
			e.note(key) // multi-valued keys cannot be used as variables
			result = and3(result, maybe)
		case hasDef:
			b.WriteString(mark(def))
		case e.req.ContextComplete && knownKey(key):
			result = no
		default:
			e.note(key)
			result = and3(result, maybe)
		}
	}
	if result != yes {
		return "", result
	}
	return b.String(), yes
}

// knownGlobalKeys are the condition keys whose absence from a request context
// marked ContextComplete is meaningful (AWS semantics: the key is absent). Any
// other key that is missing stays unknown.
var knownGlobalKeys = func() map[string]bool {
	m := map[string]bool{}
	for _, k := range []string{
		"aws:CalledVia", "aws:CalledViaFirst", "aws:CalledViaLast", "aws:CurrentTime", "aws:EpochTime",
		"aws:FederatedProvider", "aws:MultiFactorAuthAge", "aws:MultiFactorAuthPresent",
		"aws:PrincipalAccount", "aws:PrincipalArn", "aws:PrincipalIsAWSService", "aws:PrincipalOrgID",
		"aws:PrincipalOrgPaths", "aws:PrincipalServiceName", "aws:PrincipalServiceNamesList", "aws:PrincipalType",
		"aws:Referer", "aws:RequestedRegion", "aws:ResourceAccount", "aws:ResourceOrgID", "aws:ResourceOrgPaths",
		"aws:SecureTransport", "aws:SourceAccount", "aws:SourceArn", "aws:SourceIdentity", "aws:SourceIp",
		"aws:SourceOrgID", "aws:SourceOrgPaths", "aws:SourceVpc", "aws:SourceVpcArn", "aws:SourceVpce",
		"aws:TagKeys", "aws:TokenIssueTime", "aws:UserAgent", "aws:userid", "aws:username",
		"aws:ViaAWSService", "aws:VpcSourceIp", "aws:VpceAccount", "aws:VpceOrgID", "aws:VpceOrgPaths",
		"aws:Ec2InstanceSourceVpc", "aws:Ec2InstanceSourcePrivateIPv4",
		"s3:prefix", "s3:delimiter", "s3:max-keys",
		"sts:ExternalId", "sts:RoleSessionName", "sts:SourceIdentity",
		"kms:ViaService", "kms:CallerAccount",
		"token.actions.githubusercontent.com:sub", "token.actions.githubusercontent.com:aud",
	} {
		m[strings.ToLower(k)] = true
	}
	return m
}()

var knownKeyPrefixes = []string{"aws:principaltag/", "aws:resourcetag/", "aws:requesttag/"}

func knownKey(key string) bool {
	l := strings.ToLower(key)
	if knownGlobalKeys[l] {
		return true
	}
	for _, p := range knownKeyPrefixes {
		if strings.HasPrefix(l, p) && len(l) > len(p) {
			return true
		}
	}
	return false
}

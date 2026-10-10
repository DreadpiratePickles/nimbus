package iam

import (
	"reflect"
	"strings"
	"testing"
)

func mustParse(t *testing.T, id, doc string) Policy {
	t.Helper()
	p, err := ParsePolicy([]byte(doc))
	if err != nil {
		t.Fatalf("parse %s: %v", id, err)
	}
	p.ID = id
	return p
}

func TestParsePolicyShapes(t *testing.T) {
	p := mustParse(t, "p", `{"Version":"2012-10-17","Statement":{"Sid":"One","Effect":"Allow","Action":"s3:GetObject","Resource":"*","Principal":"*",
		"Condition":{"Bool":{"aws:SecureTransport":true},"NumericLessThan":{"s3:max-keys":10},"StringEquals":{"aws:TagKeys":["a","b"]}}}}`)
	if len(p.Statement) != 1 {
		t.Fatalf("statements = %d", len(p.Statement))
	}
	s := p.Statement[0]
	if s.Sid != "One" || !reflect.DeepEqual(s.Action, []string{"s3:GetObject"}) || s.Principal == nil || !s.Principal.Any {
		t.Fatalf("bad statement %+v", s)
	}
	if got := s.Condition["Bool"]["aws:SecureTransport"]; !reflect.DeepEqual(got, []string{"true"}) {
		t.Fatalf("bool value = %v", got)
	}
	if got := s.Condition["NumericLessThan"]["s3:max-keys"]; !reflect.DeepEqual(got, []string{"10"}) {
		t.Fatalf("numeric value = %v", got)
	}
	enc := "%7B%22Statement%22%3A%5B%7B%22Effect%22%3A%22Allow%22%2C%22Action%22%3A%22*%22%2C%22Resource%22%3A%22*%22%7D%5D%7D"
	q, err := ParsePolicy([]byte(enc))
	if err != nil || len(q.Statement) != 1 || q.Statement[0].Action[0] != "*" {
		t.Fatalf("url-encoded parse: %v %+v", err, q)
	}
	r := mustParse(t, "r", `{"Statement":[{"Effect":"Allow","Principal":{"AWS":["arn:aws:iam::111111111111:root","222222222222"],"Service":"lambda.amazonaws.com"},"NotPrincipal":{"AWS":"*"},"Action":["sts:AssumeRole"]}]}`)
	if got := r.Statement[0].Principal.Values["AWS"]; len(got) != 2 {
		t.Fatalf("principal AWS = %v", got)
	}
	if r.Statement[0].NotPrincipal == nil {
		t.Fatal("NotPrincipal not parsed")
	}
	for _, bad := range []string{`not json`, `{"Statement":"x"}`, `{"Statement":{"Effect":1}}`, `{"Statement":[{"Effect":"Allow","Condition":{"Bool":"x"}}]}`, `{"Statement":[{"Effect":"Allow","Principal":5}]}`, `{"Statement":[{"Effect":"Allow","Action":{"a":1}}]}`} {
		if _, err := ParsePolicy([]byte(bad)); err == nil {
			t.Errorf("ParsePolicy(%s) accepted invalid input", bad)
		}
	}
	empty := mustParse(t, "e", `{"Version":"2012-10-17"}`)
	if len(empty.Statement) != 0 {
		t.Fatal("expected no statements")
	}
}

func TestRefString(t *testing.T) {
	if got := (Ref{PolicyID: "p", Sid: "S"}).String(); got != "p#S" {
		t.Fatal(got)
	}
	if got := (Ref{PolicyID: "p", Index: 2}).String(); got != "p#2" {
		t.Fatal(got)
	}
	if got := (Ref{PolicyID: "p", Sid: "S", Conditional: true}).String(); got != "p#S?" {
		t.Fatal(got)
	}
}

func TestMatchAction(t *testing.T) {
	cases := []struct {
		pat, act string
		want     bool
	}{
		{"*", "s3:GetObject", true},
		{"s3:*", "S3:getobject", true},
		{"s3:Get*", "s3:GetObjectAcl", true},
		{"s3:Get*", "s3:PutObject", false},
		{"iam:?etRole", "iam:GetRole", true},
		{"iam:?etRole", "iam:GetRoles", false},
		{"*:*", "ec2:RunInstances", true},
		{"ec2:*Instances", "ec2:DescribeInstances", true},
	}
	for _, c := range cases {
		if got := matchAction(c.pat, c.act); got != c.want {
			t.Errorf("matchAction(%q,%q)=%v", c.pat, c.act, got)
		}
	}
}

func TestMatchARN(t *testing.T) {
	cases := []struct {
		pat, arn string
		want     bool
	}{
		{"*", "arn:aws:s3:::b", true},
		{"arn:*", "arn:aws:ec2:us-east-1:1:instance/i-1", true},
		{"arn:aws:*", "arn:aws:iam::1:role/x", true},
		{"arn:aws:s3:::bucket/*", "arn:aws:s3:::bucket/a/b:c", true},
		{"arn:aws:s3:::bucket/*", "arn:aws:s3:::bucket", false},
		{"arn:aws:s3:::Bucket", "arn:aws:s3:::bucket", false},
		{"arn:aws:iam::*:role/*", "arn:aws:iam::123456789012:role/a/b", true},
		{"arn:aws:iam::12*:role/x", "arn:aws:iam::123:role/x", true},
		// a wildcard in a non-final segment does not cross into the next segment
		{"arn:aws:ec2:*", "arn:aws:ec2:us-east-1:1:instance/i", true},
		{"arn:aws:ec2:us-*:1:instance/*", "arn:aws:ec2:eu-west-1:1:instance/i", false},
		{"arn:aws:ec2:us-east-?:1:instance/i", "arn:aws:ec2:us-east-1:1:instance/i", true},
		{"arn:aws:iam::1:role/x", "notanarn", false},
		{"bucket*", "bucket-1", true},
		{"arn:aws:s3:::a", "arn:aws:s3", false},
	}
	for _, c := range cases {
		if got := matchARN(c.pat, c.arn); got != c.want {
			t.Errorf("matchARN(%q,%q)=%v", c.pat, c.arn, got)
		}
	}
}

func TestGlobLiteralMarkers(t *testing.T) {
	if !glob(string(litStar)+"x", "*x", false) || glob(string(litStar)+"x", "ax", false) {
		t.Fatal("literal * marker")
	}
	if !glob(string(litQuestion), "?", false) || glob(string(litQuestion), "a", false) {
		t.Fatal("literal ? marker")
	}
	if !glob("a*b*c", "aXXbYYc", false) || glob("a*b*c", "aXXbYY", false) {
		t.Fatal("multi star")
	}
	if !glob("ABC", "abc", true) {
		t.Fatal("fold")
	}
}

func TestTri(t *testing.T) {
	if and3(yes, maybe) != maybe || and3(no, maybe) != no || or3(no, maybe) != maybe || or3(yes, maybe) != yes || not3(maybe) != maybe || not3(yes) != no {
		t.Fatal("kleene logic")
	}
	if both(yes, yes) != yes || both(no, no) != no || both(yes, no) != maybe {
		t.Fatal("both")
	}
	if yes.String() != "yes" || maybe.String() != "maybe" || no.String() != "no" {
		t.Fatal("tri string")
	}
}

// condReq builds a request whose only policy is one Allow statement with the
// given condition JSON, and returns the decision.
func condDecision(t *testing.T, cond string, ctx map[string]ConditionValue, complete bool) Effect {
	t.Helper()
	p := mustParse(t, "p", `{"Version":"2012-10-17","Statement":[{"Sid":"S","Effect":"Allow","Action":"s3:GetObject","Resource":"*","Condition":`+cond+`}]}`)
	d := Evaluate(Request{Principal: "arn:aws:iam::111111111111:user/alice", Action: "s3:GetObject", Resource: "arn:aws:s3:::b/k", ResourceAccount: "111111111111", Context: ctx, ContextComplete: complete},
		[]Policy{p}, nil, nil, nil, nil)
	return d.Effect
}

func TestConditionOperators(t *testing.T) {
	v := func(s ...string) ConditionValue { return ConditionValue(s) }
	cases := []struct {
		name     string
		cond     string
		ctx      map[string]ConditionValue
		complete bool
		want     Effect
	}{
		{"StringEquals hit", `{"StringEquals":{"aws:RequestedRegion":"us-east-1"}}`, map[string]ConditionValue{"aws:RequestedRegion": v("us-east-1")}, false, Allow},
		{"StringEquals key case-insensitive", `{"StringEquals":{"AWS:requestedregion":"us-east-1"}}`, map[string]ConditionValue{"aws:RequestedRegion": v("us-east-1")}, false, Allow},
		{"StringEquals value case-sensitive", `{"StringEquals":{"aws:RequestedRegion":"US-EAST-1"}}`, map[string]ConditionValue{"aws:RequestedRegion": v("us-east-1")}, false, ImplicitDeny},
		{"StringEqualsIgnoreCase", `{"StringEqualsIgnoreCase":{"aws:RequestedRegion":"US-EAST-1"}}`, map[string]ConditionValue{"aws:RequestedRegion": v("us-east-1")}, false, Allow},
		{"StringNotEqualsIgnoreCase", `{"StringNotEqualsIgnoreCase":{"aws:RequestedRegion":"US-EAST-1"}}`, map[string]ConditionValue{"aws:RequestedRegion": v("us-east-1")}, false, ImplicitDeny},
		{"StringNotEquals multiple values is NOR", `{"StringNotEquals":{"aws:RequestedRegion":["us-east-1","eu-west-1"]}}`, map[string]ConditionValue{"aws:RequestedRegion": v("eu-west-1")}, false, ImplicitDeny},
		{"StringLike glob", `{"StringLike":{"s3:prefix":"home/*"}}`, map[string]ConditionValue{"s3:prefix": v("home/alice/x")}, false, Allow},
		{"StringNotLike", `{"StringNotLike":{"s3:prefix":"home/*"}}`, map[string]ConditionValue{"s3:prefix": v("tmp/")}, false, Allow},
		{"NumericLessThan", `{"NumericLessThan":{"s3:max-keys":"10"}}`, map[string]ConditionValue{"s3:max-keys": v("5")}, false, Allow},
		{"NumericLessThanEquals edge", `{"NumericLessThanEquals":{"s3:max-keys":"10"}}`, map[string]ConditionValue{"s3:max-keys": v("10")}, false, Allow},
		{"NumericGreaterThan miss", `{"NumericGreaterThan":{"s3:max-keys":"10"}}`, map[string]ConditionValue{"s3:max-keys": v("10")}, false, ImplicitDeny},
		{"NumericGreaterThanEquals", `{"NumericGreaterThanEquals":{"s3:max-keys":"10"}}`, map[string]ConditionValue{"s3:max-keys": v("10.0")}, false, Allow},
		{"NumericEquals", `{"NumericEquals":{"s3:max-keys":"10"}}`, map[string]ConditionValue{"s3:max-keys": v("10")}, false, Allow},
		{"NumericNotEquals", `{"NumericNotEquals":{"s3:max-keys":"10"}}`, map[string]ConditionValue{"s3:max-keys": v("11")}, false, Allow},
		{"Numeric unparsable request value", `{"NumericEquals":{"s3:max-keys":"10"}}`, map[string]ConditionValue{"s3:max-keys": v("ten")}, false, ImplicitDeny},
		{"DateGreaterThan ISO", `{"DateGreaterThan":{"aws:CurrentTime":"2026-01-01T00:00:00Z"}}`, map[string]ConditionValue{"aws:CurrentTime": v("2026-06-01T00:00:00Z")}, false, Allow},
		{"DateLessThan date-only", `{"DateLessThan":{"aws:CurrentTime":"2026-01-01"}}`, map[string]ConditionValue{"aws:CurrentTime": v("2026-06-01T00:00:00Z")}, false, ImplicitDeny},
		{"DateLessThanEquals epoch", `{"DateLessThanEquals":{"aws:EpochTime":"1767225600"}}`, map[string]ConditionValue{"aws:EpochTime": v("1767225600")}, false, Allow},
		{"DateEquals", `{"DateEquals":{"aws:CurrentTime":"2026-01-01T00:00:00Z"}}`, map[string]ConditionValue{"aws:CurrentTime": v("2026-01-01T00:00:00Z")}, false, Allow},
		{"DateNotEquals", `{"DateNotEquals":{"aws:CurrentTime":"2026-01-01T00:00:00Z"}}`, map[string]ConditionValue{"aws:CurrentTime": v("2026-01-01T00:00:00Z")}, false, ImplicitDeny},
		{"DateGreaterThanEquals with millis", `{"DateGreaterThanEquals":{"aws:CurrentTime":"2026-01-01T00:00:00.000Z"}}`, map[string]ConditionValue{"aws:CurrentTime": v("2026-01-01T00:00:00Z")}, false, Allow},
		{"Date unparsable", `{"DateEquals":{"aws:CurrentTime":"yesterday"}}`, map[string]ConditionValue{"aws:CurrentTime": v("2026-01-01T00:00:00Z")}, false, ImplicitDeny},
		{"Bool case-insensitive", `{"Bool":{"aws:SecureTransport":"TRUE"}}`, map[string]ConditionValue{"aws:SecureTransport": v("true")}, false, Allow},
		{"BinaryEquals", `{"BinaryEquals":{"aws:UserAgent":"QmluYXJ5"}}`, map[string]ConditionValue{"aws:UserAgent": v("QmluYXJ5")}, false, Allow},
		{"IpAddress v6", `{"IpAddress":{"aws:SourceIp":"2001:db8::/32"}}`, map[string]ConditionValue{"aws:SourceIp": v("2001:db8::1")}, false, Allow},
		{"IpAddress bare IP", `{"IpAddress":{"aws:SourceIp":"203.0.113.7"}}`, map[string]ConditionValue{"aws:SourceIp": v("203.0.113.7")}, false, Allow},
		{"IpAddress bad request ip", `{"IpAddress":{"aws:SourceIp":"203.0.113.0/24"}}`, map[string]ConditionValue{"aws:SourceIp": v("nope")}, false, ImplicitDeny},
		{"IpAddress bad policy cidr", `{"IpAddress":{"aws:SourceIp":"300.0.0.0/8"}}`, map[string]ConditionValue{"aws:SourceIp": v("10.0.0.1")}, false, ImplicitDeny},
		{"ArnEquals wildcard", `{"ArnEquals":{"aws:SourceArn":"arn:aws:sns:*:111111111111:topic"}}`, map[string]ConditionValue{"aws:SourceArn": v("arn:aws:sns:us-east-1:111111111111:topic")}, false, Allow},
		{"ArnNotEquals", `{"ArnNotEquals":{"aws:SourceArn":"arn:aws:sns:*:111111111111:topic"}}`, map[string]ConditionValue{"aws:SourceArn": v("arn:aws:sns:us-east-1:111111111111:topic")}, false, ImplicitDeny},
		{"ArnNotLike", `{"ArnNotLike":{"aws:SourceArn":"arn:aws:sns:*:222222222222:*"}}`, map[string]ConditionValue{"aws:SourceArn": v("arn:aws:sns:us-east-1:111111111111:topic")}, false, Allow},
		{"Null true absent", `{"Null":{"aws:TokenIssueTime":"true"}}`, nil, false, Allow},
		{"Null false present", `{"Null":{"aws:TokenIssueTime":"false"}}`, map[string]ConditionValue{"aws:TokenIssueTime": v("2026-01-01T00:00:00Z")}, false, Allow},
		{"Null true present", `{"Null":{"aws:TokenIssueTime":"true"}}`, map[string]ConditionValue{"aws:TokenIssueTime": v("2026-01-01T00:00:00Z")}, false, ImplicitDeny},
		{"StringEqualsIfExists absent", `{"StringEqualsIfExists":{"ec2:InstanceType":"t3.micro"}}`, nil, false, Allow},
		{"StringEqualsIfExists present miss", `{"StringEqualsIfExists":{"ec2:InstanceType":"t3.micro"}}`, map[string]ConditionValue{"ec2:InstanceType": v("m5.large")}, false, ImplicitDeny},
		{"ForAnyValue hit", `{"ForAnyValue:StringEquals":{"aws:TagKeys":["env","team"]}}`, map[string]ConditionValue{"aws:TagKeys": v("owner", "team")}, false, Allow},
		{"ForAnyValue miss", `{"ForAnyValue:StringEquals":{"aws:TagKeys":["env"]}}`, map[string]ConditionValue{"aws:TagKeys": v("owner", "team")}, false, ImplicitDeny},
		{"ForAllValues all in set", `{"ForAllValues:StringEquals":{"aws:TagKeys":["env","team"]}}`, map[string]ConditionValue{"aws:TagKeys": v("env", "team")}, false, Allow},
		{"ForAllValues one outside", `{"ForAllValues:StringEquals":{"aws:TagKeys":["env","team"]}}`, map[string]ConditionValue{"aws:TagKeys": v("env", "owner")}, false, ImplicitDeny},
		{"ForAnyValue negated", `{"ForAnyValue:StringNotEquals":{"aws:TagKeys":["env"]}}`, map[string]ConditionValue{"aws:TagKeys": v("env", "owner")}, false, Allow},
		{"ForAllValues absent complete is true", `{"ForAllValues:StringEquals":{"aws:TagKeys":["env"]}}`, nil, true, Allow},
		{"ForAnyValue absent complete is false", `{"ForAnyValue:StringEquals":{"aws:TagKeys":["env"]}}`, nil, true, ImplicitDeny},
		{"negated absent complete is true", `{"StringNotEquals":{"aws:RequestedRegion":"us-east-1"}}`, nil, true, Allow},
		{"positive absent complete is false", `{"StringEquals":{"aws:RequestedRegion":"us-east-1"}}`, nil, true, ImplicitDeny},
		{"positive absent incomplete is unknown", `{"StringEquals":{"aws:RequestedRegion":"us-east-1"}}`, nil, false, Unknown},
		{"unknown service key with complete context stays unknown", `{"StringEquals":{"madeup:Key":"x"}}`, nil, true, Unknown},
		{"unknown operator", `{"StringSortOfEquals":{"aws:RequestedRegion":"x"}}`, map[string]ConditionValue{"aws:RequestedRegion": v("x")}, false, Unknown},
		{"Null with IfExists is not an operator", `{"NullIfExists":{"aws:RequestedRegion":"true"}}`, nil, false, Unknown},
		{"bad set prefix", `{"ForSomeValues:StringEquals":{"aws:TagKeys":"x"}}`, map[string]ConditionValue{"aws:TagKeys": v("x")}, false, Unknown},
		{"two operators are ANDed", `{"StringEquals":{"aws:RequestedRegion":"us-east-1"},"Bool":{"aws:SecureTransport":"true"}}`, map[string]ConditionValue{"aws:RequestedRegion": v("us-east-1"), "aws:SecureTransport": v("false")}, false, ImplicitDeny},
		{"multi-valued context without qualifier matches any", `{"StringEquals":{"aws:TagKeys":"env"}}`, map[string]ConditionValue{"aws:TagKeys": v("owner", "env")}, false, Allow},
		{"empty context value counts as absent", `{"StringEquals":{"aws:RequestedRegion":"x"}}`, map[string]ConditionValue{"aws:RequestedRegion": {}}, false, Unknown},
		{"tag key catalog known", `{"StringEquals":{"aws:ResourceTag/env":"prod"}}`, nil, true, ImplicitDeny},
	}
	for _, c := range cases {
		if got := condDecision(t, c.cond, c.ctx, c.complete); got != c.want {
			t.Errorf("%s: got %s want %s", c.name, got, c.want)
		}
	}
}

func TestVariables(t *testing.T) {
	ctx := map[string]ConditionValue{"aws:PrincipalTag/team": {"blue"}, "multi": {"a", "b"}}
	e := newEvaluator(Request{Principal: "arn:aws:iam::111111111111:user/division/alice", Context: ctx})
	cases := []struct {
		in, want string
		res      tri
	}{
		{"arn:aws:s3:::b/${aws:username}/*", "arn:aws:s3:::b/alice/*", yes},
		{"x/${aws:PrincipalTag/team}", "x/blue", yes},
		{"x/${aws:userid, 'nobody'}", "x/nobody", yes},
		{"x/${*}${?}${$}", "x/" + string(litStar) + string(litQuestion) + "$", yes},
		{"x/${aws:userid}", "", maybe},
		{"x/${multi}", "", maybe},
		{"x/${unterminated", "x/${unterminated", yes},
	}
	for _, c := range cases {
		got, r := e.substitute(c.in, "2012-10-17")
		if r != c.res || (r == yes && got != c.want) {
			t.Errorf("substitute(%q) = %q,%v want %q,%v", c.in, got, r, c.want, c.res)
		}
	}
	if got, r := e.substitute("x/${aws:username}", "2008-10-17"); got != "x/${aws:username}" || r != yes {
		t.Errorf("old version must not substitute: %q", got)
	}
	ec := newEvaluator(Request{Principal: "arn:aws:iam::111111111111:user/alice", ContextComplete: true})
	if _, r := ec.substitute("x/${aws:userid}", "2012-10-17"); r != no {
		t.Errorf("complete context, known key absent: want no, got %v", r)
	}
	if _, r := ec.substitute("x/${madeup:thing}", "2012-10-17"); r != maybe {
		t.Errorf("complete context, unknown key: want maybe, got %v", r)
	}
}

func TestPrincipalParsing(t *testing.T) {
	cases := []struct {
		arn     string
		kind    principalKind
		account string
	}{
		{"arn:aws:iam::111111111111:user/a", kindUser, "111111111111"},
		{"arn:aws:sts::111111111111:assumed-role/R/s", kindSession, "111111111111"},
		{"arn:aws:iam::111111111111:role/p/R", kindRole, "111111111111"},
		{"arn:aws:iam::111111111111:root", kindRoot, "111111111111"},
		{"lambda.amazonaws.com", kindService, ""},
		{"arn:aws:iam::111111111111:oidc-provider/token.actions.githubusercontent.com", kindFederated, "111111111111"},
		{"cognito-identity.amazonaws.com", kindService, ""},
		{"", kindAnonymous, ""},
		{"arn:aws:sts::111111111111:federated-user/bob", kindFederatedUser, "111111111111"},
	}
	for _, c := range cases {
		p := parsePrincipal(c.arn)
		if p.kind != c.kind || p.account != c.account {
			t.Errorf("parsePrincipal(%q) = %+v", c.arn, p)
		}
	}
	if p := parsePrincipal("arn:aws:sts::1:assumed-role/R/s"); p.roleARN != "arn:aws:iam::1:role/R" || p.name != "R" {
		t.Errorf("session role arn = %+v", p)
	}
}

func TestEvaluatePositionalAndReasons(t *testing.T) {
	id := mustParse(t, "id", `{"Version":"2012-10-17","Statement":[{"Sid":"A","Effect":"Allow","Action":"s3:*","Resource":"*"}]}`)
	scpFull := mustParse(t, "FullAWSAccess", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`)
	scpNone := mustParse(t, "OnlyEC2", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"ec2:*","Resource":"*"}]}`)
	req := Request{Principal: "arn:aws:iam::111111111111:user/alice", Action: "s3:GetObject", Resource: "arn:aws:s3:::b/k", ResourceAccount: "111111111111"}
	d := Evaluate(req, []Policy{id}, nil, nil, [][]Policy{{scpFull}, {scpNone}}, nil)
	if d.Effect != ImplicitDeny || !strings.Contains(strings.Join(d.Reasons, ";"), "SCP level 1") {
		t.Fatalf("got %+v", d)
	}
	if d.DeniedBy != nil {
		t.Fatalf("implicit deny must not set DeniedBy")
	}
	// service-linked roles are not governed by SCPs
	slr := req
	slr.Principal = "arn:aws:sts::111111111111:assumed-role/AWSServiceRoleForX/s"
	slr.Context = map[string]ConditionValue{"aws:PrincipalArn": {"arn:aws:iam::111111111111:role/aws-service-role/x.amazonaws.com/AWSServiceRoleForX"}}
	if d := Evaluate(slr, []Policy{id}, nil, nil, [][]Policy{{scpNone}}, nil); d.Effect != Allow {
		t.Fatalf("service-linked role: %+v", d)
	}
	deny := mustParse(t, "deny", `{"Version":"2012-10-17","Statement":[{"Sid":"D","Effect":"Deny","Action":"s3:GetObject","Resource":"*"}]}`)
	d = Evaluate(req, []Policy{id, deny}, nil, nil, nil, nil)
	if d.Effect != ExplicitDeny || d.DeniedBy == nil || d.DeniedBy.String() != "deny#D" {
		t.Fatalf("explicit deny: %+v", d)
	}
	// determinism: identical inputs give identical output
	d2 := Evaluate(req, []Policy{id, deny}, nil, nil, nil, nil)
	if !reflect.DeepEqual(d, d2) {
		t.Fatal("non-deterministic decision")
	}
	if Allow.String() != "allow" {
		t.Fatal("effect string")
	}
}

func TestIsAdmin(t *testing.T) {
	cases := []struct {
		name string
		doc  string
		want AdminLevel
	}{
		{"NotAction iam:* only", `{"Statement":[{"Effect":"Allow","NotAction":"iam:*","Resource":"*"}]}`, AdminNone},
		{"NotAction iam:Put* leaves Attach/PassRole", `{"Statement":[{"Effect":"Allow","NotAction":["iam:Put*"],"Resource":"*"}]}`, AdminFull},
		{"NotAction uppercase IAM:*", `{"Statement":[{"Effect":"Allow","NotAction":["IAM:*"],"Resource":"*"}]}`, AdminNone},
		{"Action *:*", `{"Statement":[{"Effect":"Allow","Action":"*:*","Resource":"*"}]}`, AdminFull},
		{"Action list with *", `{"Statement":[{"Effect":"Allow","Action":["s3:*","*"],"Resource":["arn:aws:s3:::x","*"]}]}`, AdminFull},
		{"Action iam:* on *", `{"Statement":[{"Effect":"Allow","Action":"iam:*","Resource":"*"}]}`, AdminFull},
		{"Action iam:* on one role is not admin", `{"Statement":[{"Effect":"Allow","Action":"iam:*","Resource":"arn:aws:iam::1:role/x"}]}`, AdminNone},
		{"Action * on arn:*", `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"arn:*"}]}`, AdminFull},
		{"Allow * + Deny *", `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"},{"Effect":"Deny","Action":"*","Resource":"*"}]}`, AdminNone},
		{"Allow * + Deny iam:*", `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"},{"Effect":"Deny","Action":"iam:*","Resource":"*"}]}`, AdminNone},
		{"Allow * + Deny s3:* is still admin", `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"},{"Effect":"Deny","Action":"s3:*","Resource":"*"}]}`, AdminFull},
		// Differs from the collector heuristic (full): the Deny may apply, so the
		// evaluator cannot prove admin without aws:SecureTransport in the context.
		{"Allow * + conditioned Deny * is conditional", `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"},{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"Bool":{"aws:SecureTransport":"false"}}}]}`, AdminConditional},
		{"Allow * + Deny NotAction s3:* (denies iam)", `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"},{"Effect":"Deny","NotAction":"s3:*","Resource":"*"}]}`, AdminNone},
		{"Allow * with MFA condition", `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"Bool":{"aws:MultiFactorAuthPresent":"true"}}}]}`, AdminConditional},
		{"Allow * NotResource *", `{"Statement":[{"Effect":"Allow","Action":"*","NotResource":"*"}]}`, AdminNone},
		{"Condition empty object", `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*","Condition":{}}]}`, AdminFull},
		{"Condition whitespace object", `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*","Condition":{ }}]}`, AdminFull},
		{"Effect lowercase allow (invalid)", `{"Statement":[{"Effect":"allow","Action":"*","Resource":"*"}]}`, AdminNone},
		// Differs from the collector heuristic (none): one self-grant action on every resource is admin.
		{"single iam:PutRolePolicy on * is admin", `{"Statement":[{"Effect":"Allow","Action":"iam:PutRolePolicy","Resource":"*"}]}`, AdminFull},
		{"read-only is not admin", `{"Statement":[{"Effect":"Allow","Action":["s3:Get*","ec2:Describe*"],"Resource":"*"}]}`, AdminNone},
	}
	for _, c := range cases {
		p := mustParse(t, "p", c.doc)
		fn := func(action, resource string) Decision {
			return Evaluate(Request{Principal: "arn:aws:iam::123456789012:role/probe", Action: action, Resource: resource}, []Policy{p}, nil, nil, nil, nil)
		}
		if got := IsAdmin(fn); got != c.want {
			t.Errorf("%s: IsAdmin=%v want %v", c.name, got, c.want)
		}
	}
	if AdminFull.String() != "full" || AdminNone.String() != "none" || AdminConditional.String() != "conditional" {
		t.Fatal("AdminLevel strings must match the collector's")
	}
}

func TestAllowedActions(t *testing.T) {
	p := mustParse(t, "p", `{"Version":"2012-10-17","Statement":[
		{"Effect":"Allow","Action":["s3:*","sqs:SendMessage"],"Resource":"*"},
		{"Effect":"Deny","Action":"s3:PutObject","Resource":"*"},
		{"Effect":"Allow","Action":"kms:Decrypt","Resource":"*","Condition":{"StringEquals":{"kms:ViaService":"s3.us-east-1.amazonaws.com"}}},
		{"Effect":"Allow","NotAction":"iam:*","Resource":"arn:aws:dynamodb:*:*:table/other"}]}`)
	allowed, unknown := AllowedActions("arn:aws:s3:::bucket/key", p)
	want := []string{"s3:GetObject", "s3:ListBucket", "sqs:SendMessage"}
	if !reflect.DeepEqual(allowed, want) {
		t.Errorf("allowed = %v want %v", allowed, want)
	}
	if !reflect.DeepEqual(unknown, []string{"kms:Decrypt"}) {
		t.Errorf("unknown = %v", unknown)
	}
	if a, u := AllowedActions("arn:aws:s3:::x"); len(a) != 0 || len(u) != 0 {
		t.Errorf("no policies: %v %v", a, u)
	}
	cat := ActionCatalog(p)
	for _, w := range []string{"s3:GetObject", "sqs:SendMessage", "s3:PutObject", "kms:Decrypt"} {
		found := false
		for _, c := range cat {
			if c == w {
				found = true
			}
		}
		if !found {
			t.Errorf("catalog missing %s: %v", w, cat)
		}
	}
}

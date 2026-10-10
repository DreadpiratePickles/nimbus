package mcp

import (
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/graph"
	"github.com/DreadpiratePickles/nimbus/internal/model"
	"github.com/DreadpiratePickles/nimbus/internal/risk"
	"github.com/DreadpiratePickles/nimbus/internal/store"
)

// Shortfall #7 (competitive delta r3): MCP parity with the CLI. Bars: Sysdig's token-scoped MCP
// server (read by default, write tools opt-in), the AWS MCP servers, Prowler Lighthouse
// (who-can / prioritise / verify questions answered from the engine, not re-derived).

var readToolsWant = []string{"coverage", "explain", "issue", "paths", "prioritize", "schema", "sql", "summary", "verify", "who_can"}

func TestDefaultScopeIsRead(t *testing.T) {
	fx := newFixture(t)
	c := startServer(t, fx.st, Options{NoRedact: true})
	c.initialize()
	if got := sorted(c.toolNames()); !reflect.DeepEqual(got, readToolsWant) {
		t.Fatalf("default tools = %v, want the read scope %v (no draft_fix / simulate_fix)", got, readToolsWant)
	}
	if _, r := c.tool("draft_fix", map[string]any{"finding_id": fx.hostiles[0].ID}); r.Error == nil {
		t.Error("draft_fix callable without --scope fix")
	}
	recs := readAudit(t, c.audit)
	if len(recs) == 0 || strings.Join(recs[len(recs)-1].Scope, ",") != "read" {
		t.Errorf("audit scope %v, want read", recs)
	}
	c2 := startServer(t, fx.st, Options{NoRedact: true, Scopes: []string{"all"}})
	c2.initialize()
	if got := sorted(c2.toolNames()); !reflect.DeepEqual(got, allTools) {
		t.Fatalf("--scope all tools = %v, want %v", got, allTools)
	}
}

// paths returns path Issues (grouped), each with its hop variants: the unit every surface
// counts (19 Issues / 22 variants in the lab), never a variant count presented as paths.
func TestPathsReturnsIssuesWithVariants(t *testing.T) {
	fx := newFixture(t)
	c := startServer(t, fx.st, Options{NoRedact: true})
	c.initialize()
	res := c.toolOK("paths", map[string]any{"limit": 200})
	if _, ok := res["paths"]; ok {
		t.Error(`paths still returns a flat "paths" variant list`)
	}
	rows := res["issues"].([]any)
	stored, _ := fx.st.AttackPaths()
	issueOf := pathIssueIndex(storeReader{fx.st})
	wantIssues := map[string]bool{}
	for _, p := range stored {
		wantIssues[firstNonEmptyStr(issueOf[p.ID], "path:"+p.ID)] = true
	}
	if len(rows) != len(wantIssues) || int(res["matched_issues"].(float64)) != len(wantIssues) || int(res["matched_variants"].(float64)) != len(stored) {
		t.Fatalf("issues %d (matched %v, variants %v), want %d Issues / %d variants", len(rows), res["matched_issues"], res["matched_variants"], len(wantIssues), len(stored))
	}
	variants, prev := 0, 11.0
	for _, r := range rows {
		m := r.(map[string]any)
		vs := m["variants"].([]any)
		variants += len(vs)
		if int(m["variant_count"].(float64)) != len(vs) || len(vs) == 0 {
			t.Errorf("issue %v: variant_count %v vs %d", m["issue_id"], m["variant_count"], len(vs))
		}
		if s := m["score"].(float64); s > prev {
			t.Errorf("issues not ordered by score: %v after %v", s, prev)
		} else {
			prev = s
		}
		if m["verdict"] == nil {
			t.Errorf("issue %v has no verdict", m["issue_id"])
		}
	}
	if variants != len(stored) {
		t.Errorf("variants %d, want %d", variants, len(stored))
	}
	is := c.toolOK("issue", map[string]any{"id": firstPathIssue(t, fx.st).ID})
	if _, ok := is["variants"]; !ok {
		t.Errorf("issue lacks variants: %v", keys(is))
	}
}

func firstPathIssue(t *testing.T, st *store.Store) model.Issue {
	t.Helper()
	is, err := st.Issues(store.IssueFilter{Kind: model.IssuePath})
	if err != nil || len(is) == 0 {
		t.Fatalf("no path Issue: %v", err)
	}
	return is[0]
}

func keys(m map[string]any) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

// who_can answers from graph.WhoCan (the CLI's engine): same principals, same order.
func TestWhoCanMatchesEngine(t *testing.T) {
	fx := newFixture(t)
	g, _ := storeReader{fx.st}.LoadGraph()
	want := graph.WhoCan(g, "s3:GetObject", "arn:aws:s3:::nimbus-lab-customer-pii/*", 4)
	if len(want) == 0 {
		t.Fatal("engine returns nobody for the lab bucket")
	}
	c := startServer(t, fx.st, Options{NoRedact: true})
	c.initialize()
	res := c.toolOK("who_can", map[string]any{"action": "s3:GetObject", "resource": "arn:aws:s3:::nimbus-lab-customer-pii/*"})
	got := res["principals"].([]any)
	if len(got) != len(want) || int(res["count"].(float64)) != len(want) {
		t.Fatalf("who_can %d principals, engine %d", len(got), len(want))
	}
	for i := range want {
		if p := got[i].(map[string]any)["principal"]; p != want[i].Principal {
			t.Errorf("row %d principal %v, engine %v", i, p, want[i].Principal)
		}
	}
	if tr, _ := c.tool("who_can", map[string]any{"action": "", "resource": "x"}); !tr.IsError {
		t.Error("empty action accepted")
	}
}

// prioritize is risk.PrioritizeWith (the CLI's ranking): same order, same scores and bands.
func TestPrioritizeMatchesEngine(t *testing.T) {
	fx := newFixture(t)
	rd := storeReader{fx.st}
	fs, _ := rd.Findings(store.Filter{Status: string(model.Fail)})
	g, _ := rd.LoadGraph()
	ps, _ := rd.AttackPaths()
	want := risk.PrioritizeWith(fs, g, ps, risk.Options{})
	c := startServer(t, fx.st, Options{NoRedact: true})
	c.initialize()
	got := c.toolOK("prioritize", map[string]any{"limit": 10})["findings"].([]any)
	if len(got) != 10 {
		t.Fatalf("prioritize returned %d, want 10", len(got))
	}
	for i, r := range got {
		m := r.(map[string]any)
		if m["finding_id"] != fx.st.ExternalFindingID(want[i].Finding.ID) || m["score"].(float64) != want[i].Score || m["band"] != want[i].Band {
			t.Errorf("rank %d: %v %v %v, engine %s %v %s", i+1, m["finding_id"], m["score"], m["band"], want[i].Finding.ID, want[i].Score, want[i].Band)
		}
	}
}

// verify is read-only: it reports what `cloud-posture verify` would check and the stored
// verification state, and never writes (the database digest is unchanged).
func TestVerifyToolIsReadOnly(t *testing.T) {
	fx := newFixture(t)
	is := firstPathIssue(t, fx.st)
	before := dbDigest(t, fx.st)
	c := startServer(t, fx.st, Options{NoRedact: true})
	c.initialize()
	res := c.toolOK("verify", map[string]any{"issue_id": is.ID})
	if res["mutates"] != false || res["state"] != string(is.State) || res["command"] != "cloud-posture verify "+is.ID {
		t.Errorf("verify: %v", res)
	}
	targets := res["would_check"].([]any)
	if len(targets) == 0 {
		t.Fatal("verify reports nothing to check")
	}
	found := false
	for _, x := range targets {
		if x.(map[string]any)["resource"] == is.AnchorID {
			found = true
		}
	}
	if !found {
		t.Errorf("would_check %v lacks the anchor %s", targets, is.AnchorID)
	}
	if _, ok := res["verifications"].([]any); !ok {
		t.Errorf("no verifications list: %v", res)
	}
	if tr, _ := c.tool("verify", map[string]any{"issue_id": "nope"}); !tr.IsError {
		t.Error("unknown Issue accepted")
	}
	if after := dbDigest(t, fx.st); after != before {
		t.Fatal("verify tool wrote to the database")
	}
}

// summary is store.Headline(): the Issue counts every surface prints.
func TestSummaryIsHeadline(t *testing.T) {
	fx := newFixture(t)
	h, err := fx.st.Headline()
	if err != nil {
		t.Fatal(err)
	}
	c := startServer(t, fx.st, Options{NoRedact: true})
	c.initialize()
	res := c.toolOK("summary", map[string]any{})
	hd := res["headline"].(map[string]any)
	if int(hd["issues"].(float64)) != h.Issues || int(hd["path_issues"].(float64)) != h.PathIssues || int(hd["path_variants"].(float64)) != h.PathVariants || hd["unit"] != "issues" {
		t.Errorf("summary %v, headline %+v", hd, h)
	}
}

// Redaction corpus for verdict / because text (delta r3 #7, verify-5 MCP-4): resource ids and
// ARN accounts become placeholders; human names (roles, buckets, hosts) stay readable unless
// they embed an account id; a project id placeholder does not mangle names that start with it.
func TestRedactionCorpusVerdictText(t *testing.T) {
	r := newRedactor()
	r.placeholder("ACCT", "nimbus-lab") // a GCP project / tag-like account value seen this session
	cases := []struct {
		in       string
		gone     []string // must not survive
		kept     []string // must survive verbatim
		wantPHes int      // at least this many placeholders
	}{
		{"not exposed (blocked: route table rtb-0a1b2c3d4e5f60001 has no route to an internet gateway)", []string{"rtb-0a1b2c3d4e5f60001"}, []string{"route table", "internet gateway"}, 1},
		{"blocked: network ACL acl-0123abcd denies tcp/22; security group sg-0fixture000000001 allows 0.0.0.0/0", []string{"acl-0123abcd"}, []string{"0.0.0.0/0", "network ACL"}, 1},
		{"subnet subnet-0aa11bb22cc33dd44 in vpc-0123456789abcdef0 via igw-0abcdef12 and nat-0123456789abcdef0", []string{"subnet-0aa11bb22cc33dd44", "vpc-0123456789abcdef0", "igw-0abcdef12", "nat-0123456789abcdef0"}, []string{"subnet ", " via "}, 4},
		{"instance i-0123456789abcdef0 (eni-0a1b2c3d) runs as arn:aws:iam::111111111111:role/nimbus-lab-admin", []string{"i-0123456789abcdef0", "eni-0a1b2c3d", "111111111111"}, []string{"role/nimbus-lab-admin", "runs as"}, 3},
		{"bucket nimbus-lab-customer-pii is reachable (wide) from the internet", nil, []string{"nimbus-lab-customer-pii"}, 0},
		{"db:nimbus-lab-ledger is blocked", nil, []string{"db:nimbus-lab-ledger"}, 0},
		{"bucket logs-111111111111-us-east-1 is public", []string{"111111111111"}, []string{"logs-", "-us-east-1"}, 1},
		{"projects/nimbus-lab/zones/us-central1-a/instances/web", []string{"projects/nimbus-lab/"}, []string{"zones/us-central1-a/instances/web"}, 1},
		{"projects/nimbus-lab-gcp/global/firewalls/allow-ssh", []string{"nimbus-lab-gcp"}, []string{"global/firewalls/allow-ssh"}, 1},
		{"role nimbus-lab-ops-jane can assume admin", nil, []string{"nimbus-lab-ops-jane"}, 0},
	}
	ph := regexp.MustCompile(`\b(?:ACCT|IP|SUB|TAG|RES)_[0-9a-f]{8}\b`)
	for _, c := range cases {
		got := r.knownValues(r.str(c.in))
		for _, g := range c.gone {
			if strings.Contains(got, g) {
				t.Errorf("%q → %q still contains %q", c.in, got, g)
			}
		}
		for _, k := range c.kept {
			if !strings.Contains(got, k) {
				t.Errorf("%q → %q over-redacted %q", c.in, got, k)
			}
		}
		if n := len(ph.FindAllString(got, -1)); n < c.wantPHes {
			t.Errorf("%q → %q: %d placeholders, want ≥ %d", c.in, got, n, c.wantPHes)
		}
		if back := r.restore(got); c.wantPHes > 0 && back != c.in {
			t.Errorf("restore(%q) = %q, want the original", got, back)
		}
	}
}

// End to end: no verdict label / reason or hop because string leaves the server with a raw AWS
// resource id, in paths, issue and who_can.
var rawAWSID = regexp.MustCompile(`\b(?:rtb|acl|sg|subnet|vpc|igw|nat|eni|i|vpce|pcx|tgw)-[0-9a-f]{8,17}\b`)

func TestVerdictTextRedactedEndToEnd(t *testing.T) {
	fx := newFixture(t)
	c := startServer(t, fx.st, Options{})
	c.initialize()
	tr, _ := c.tool("paths", map[string]any{"limit": 200})
	if tr.IsError {
		t.Fatalf("paths: %v", tr.Content)
	}
	is := firstPathIssue(t, fx.st)
	tr2, _ := c.tool("issue", map[string]any{"id": is.ID})
	for _, x := range []toolResult{tr, tr2} {
		for _, ct := range x.Content {
			if m := rawAWSID.FindString(ct.Text); m != "" {
				t.Errorf("raw resource id %q in a redacted result", m)
			}
		}
	}
}

// verify-5 MCP-3: a raw non-AWS account (a GCP project id) under an account key is an oracle;
// a redacted session refuses it like a raw 12-digit account.
func TestRawNonAWSAccountArgRefused(t *testing.T) {
	fx := newFixture(t)
	c := startServer(t, fx.st, Options{})
	c.initialize()
	tr, r := c.tool("paths", map[string]any{"account": "nimbus-lab-gcp"})
	if r.Error == nil && !tr.IsError {
		t.Errorf("raw project id accepted as an account filter: %v", tr.Structured)
	}
}

// variantsOf flattens a paths result (Issues with variants) into its path variants.
func variantsOf(res map[string]any) []any {
	out := []any{}
	for _, r := range res["issues"].([]any) {
		out = append(out, r.(map[string]any)["variants"].([]any)...)
	}
	return out
}

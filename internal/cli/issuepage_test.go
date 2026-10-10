package cli

// Integration pass 3, item 2 (#4): the Issue page — `issues show` renders hops with
// because, the score explanation, confidence, owner/SLA/due, linked Issues, the fix with its
// sidecar steps, ticket links, the timeline and suppression state (Wiz Issue page bar).

import (
	"context"
	"encoding/json"
	"regexp"
	"strings"
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/model"
	"github.com/DreadpiratePickles/nimbus/internal/store"
)

func issueFor(t *testing.T, pred func(model.Issue) bool) model.Issue {
	t.Helper()
	st, err := store.Open(flagDB)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	all, err := st.Issues(store.IssueFilter{})
	if err != nil {
		t.Fatal(err)
	}
	for _, is := range all {
		if pred(is) {
			return is
		}
	}
	t.Fatal("no Issue matches")
	return model.Issue{}
}

func TestIssueShowSingleIssuePage(t *testing.T) {
	labDB(t)
	// The public PII bucket (lab W01): on attack paths, owner data-platform, a typed fix.
	bucket := issueFor(t, func(is model.Issue) bool {
		return is.Kind != model.IssuePath && is.ResourceID == "arn:aws:s3:::nimbus-lab-customer-pii" && is.CanonicalID == "S3_PUBLIC_BUCKET"
	})
	pathIs := issueFor(t, func(is model.Issue) bool {
		return is.Kind == model.IssuePath && is.AnchorID == "arn:aws:s3:::nimbus-lab-customer-pii"
	})
	st, _ := store.Open(flagDB)
	if err := st.MarkAlerted("lab-W01", "jira", "SEC-42"); err != nil {
		t.Fatal(err)
	}
	st.Close()

	out := run(t, "issues", "show", bucket.ID)
	for _, want := range []string{
		"owner:", "data-platform", "SLA", "due",
		"score:", "factors", // score explanation
		"confidence:",
		"Attack paths through this resource", pathIs.ID, // linked path Issue
		"because:",                                         // hop reasons
		"s3_public_bucket.tf",                              // fix template id
		"1. prerequisite", "s3:PutBucketPublicAccessBlock", // sidecar actions_required
		"2. snapshot", "3. fix", "4. verify", "no rows", "5. rollback", "delete-public-access-block",
		"breaks function", "mitigation", "effort",
		"ticket", "jira", "SEC-42",
		"Timeline", "first seen",
		"suppression: none",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("issues show (single) lacks %q:\n%s", want, out)
		}
	}

	run(t, "issues", "suppress", bucket.ID, "--reason", "compensated by WAF", "--expires", suppressUntil, "--approved-by", "alice")
	out = run(t, "issues", "show", bucket.ID)
	for _, want := range []string{"suppressed", "compensated by WAF", suppressUntil, "alice"} {
		if !strings.Contains(out, want) {
			t.Errorf("suppressed Issue page lacks %q:\n%s", want, out)
		}
	}
}

func TestIssueShowPathIssuePage(t *testing.T) {
	labDB(t)
	pathIs := issueFor(t, func(is model.Issue) bool {
		return is.Kind == model.IssuePath && strings.Contains(is.AnchorID, "web-instance-role")
	})
	out := run(t, "issues", "show", pathIs.ID)
	for _, want := range []string{
		"Hops", "because:", "IMDSv1", // hop-by-hop with reasons
		"score:", "band", "confidence:",
		"owner:", "Evidence Issues", // linked finding Issues
		"Fix", "1. prerequisite", "4. verify", "5. rollback",
		"Timeline", "opened",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("issues show (path) lacks %q:\n%s", want, out)
		}
	}
	var page map[string]json.RawMessage
	if err := json.Unmarshal([]byte(run(t, "issues", "show", pathIs.ID, "--json")), &page); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"issue", "findings", "hops", "paths", "score", "confidence", "owner", "linked_issues", "fixes", "tickets", "timeline", "suppression"} {
		if _, ok := page[k]; !ok {
			t.Errorf("issues show --json lacks %q", k)
		}
	}
	var hops []struct {
		Because string `json:"because"`
	}
	json.Unmarshal(page["hops"], &hops)
	if len(hops) < 2 || hops[len(hops)-1].Because == "" {
		t.Errorf("hops lack because: %s", page["hops"])
	}
}

// The dashboard Issue pane reads issue_pages: one Issue page record per Issue in the payload.
func TestDashboardPayloadCarriesIssuePages(t *testing.T) {
	labDB(t)
	res, st, err := loadResult(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	st.Close()
	html, err := renderDashboard(res, "static", "")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?s)<script id="data" type="application/json">(.*?)</script>`).FindSubmatch(html)
	if m == nil {
		t.Fatal("no data blob")
	}
	var d struct {
		Issues []model.Issue `json:"issues"`
		Pages  map[string]struct {
			Owner struct {
				Owner   string `json:"owner"`
				SLADays int    `json:"sla_days"`
			} `json:"owner"`
			Fixes []struct {
				Template string                  `json:"template"`
				Phases   []struct{ Name string } `json:"phases"`
			} `json:"fixes"`
			Timeline []json.RawMessage `json:"timeline"`
		} `json:"issue_pages"`
	}
	if err := json.Unmarshal(m[1], &d); err != nil {
		t.Fatal(err)
	}
	if len(d.Pages) != len(d.Issues) || len(d.Issues) == 0 {
		t.Fatalf("issue_pages has %d records for %d Issues", len(d.Pages), len(d.Issues))
	}
	for _, is := range d.Issues {
		if is.ResourceID == "arn:aws:s3:::nimbus-lab-customer-pii" && is.CanonicalID == "S3_PUBLIC_BUCKET" {
			pg := d.Pages[is.ID]
			if pg.Owner.Owner != "data-platform" || pg.Owner.SLADays == 0 || len(pg.Fixes) == 0 || len(pg.Fixes[0].Phases) != 5 || len(pg.Timeline) == 0 {
				t.Errorf("bucket Issue page incomplete: %+v", pg)
			}
			return
		}
	}
	t.Error("bucket Issue not in payload")
}

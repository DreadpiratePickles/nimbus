package store

import (
	"testing"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/attackpath"
	"github.com/DreadpiratePickles/nimbus/internal/model"
)

func credentialPath() model.AttackPath {
	return model.AttackPath{ID: "p-jane", RuleID: "GRAPH_TRAVERSAL", Name: "ops-jane → ops-jane", Provider: "aws", Account: "111",
		Score: 7.2, Severity: model.High, Steps: []model.Step{
			{Stage: 1, Relation: "entry", Resource: "arn:aws:iam::111:user/ops-jane", Weakness: "NO_MFA"}}}
}

// r3 E7: the stored path Issue title of a credential entry names what it reaches.
func TestPathIssueTitleFromGraph(t *testing.T) {
	st := openTemp(t)
	t0 := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	if err := st.ReplaceGraph([]GraphNode{{ID: "arn:aws:iam::111:user/ops-jane", Type: "aws_iam_user", Name: "ops-jane",
		Doc: []byte(`{"id":"arn:aws:iam::111:user/ops-jane","name":"ops-jane","attributes":{"attached_policies":["arn:aws:iam::aws:policy/AdministratorAccess"]}}`)}}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := st.RebuildPathIssues("s1", &attackpath.Analysis{Paths: []model.AttackPath{credentialPath()}}, t0); err != nil {
		t.Fatal(err)
	}
	if got := onlyPathIssue(t, st).Title; got != "credential compromise of ops-jane → AdministratorAccess" {
		t.Fatalf("title %q", got)
	}
}

// r3 #4 / E10: the default Issue order is path Issues by score, then finding Issues by severity.
func TestIssuesOrderPathIssuesFirst(t *testing.T) {
	st := openTemp(t)
	t0 := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	fs := []model.Finding{
		mkFinding("prowler", "blob_public", "AZ_BLOB_PUBLIC", "blob-1", model.Critical, "PUBLIC_DATA_STORE"),
		mkFinding("prowler", "s3_enc", "S3_UNENCRYPTED", "bucket-1", model.Medium),
		mkFinding("prowler", "s3_log", "S3_NO_LOGGING", "bucket-1", model.High),
	}
	if _, err := st.ApplyScan("s1", fs, t0, ApplyOptions{Scopes: ScopesOf(fs)}); err != nil {
		t.Fatal(err)
	}
	if err := st.RebuildIssues(t0); err != nil {
		t.Fatal(err)
	}
	low := syntheticPath("sg-1", 7.0)
	low.Steps[2].Resource = "role/batch"
	if _, err := st.RebuildPathIssues("s1", &attackpath.Analysis{Paths: []model.AttackPath{low, syntheticPath("sg-2", 10)}}, t0); err != nil {
		t.Fatal(err)
	}
	is, err := st.Issues(IssueFilter{})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, i := range is {
		got = append(got, i.Kind+":"+w5label(i.CanonicalID, i.ResourceID))
	}
	want := []string{"path:role/web", "path:role/batch", "single:AZ_BLOB_PUBLIC", "single:S3_NO_LOGGING", "single:S3_UNENCRYPTED"}
	if len(got) != len(want) {
		t.Fatalf("order %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("order %v, want %v", got, want)
		}
	}
}

func w5label(v ...string) string {
	for _, s := range v {
		if s != "" && s != "traversal" {
			return s
		}
	}
	return ""
}

// r3 #4: one headline, Issues as the unit, "critical" = the Issue's band / verdict severity.
func TestHeadlineCountsIssuesNotVariants(t *testing.T) {
	st := openTemp(t)
	t0 := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	fs := []model.Finding{
		mkFinding("prowler", "blob_public", "AZ_BLOB_PUBLIC", "blob-1", model.Critical, "PUBLIC_DATA_STORE"),
		mkFinding("nimbus", "blob-public", "AZ_BLOB_PUBLIC", "blob-1", model.High, "PUBLIC_DATA_STORE"), // same Issue, 2nd source
		mkFinding("prowler", "s3_enc", "S3_UNENCRYPTED", "bucket-1", model.Medium),
	}
	if _, err := st.ApplyScan("s1", fs, t0, ApplyOptions{Scopes: ScopesOf(fs)}); err != nil {
		t.Fatal(err)
	}
	if err := st.RebuildIssues(t0); err != nil {
		t.Fatal(err)
	}
	v1, v2 := syntheticPath("sg-1", 10), syntheticPath("sg-2", 9.2) // two hop variants of one Issue
	other := syntheticPath("sg-3", 7.5)
	other.Steps[2].Resource = "role/batch"
	if _, err := st.RebuildPathIssues("s1", &attackpath.Analysis{Paths: []model.AttackPath{v1, v2, other}}, t0); err != nil {
		t.Fatal(err)
	}
	h, err := st.Headline()
	if err != nil {
		t.Fatal(err)
	}
	if h.Unit != "issues" || h.PathIssues != 2 || h.PathVariants != 3 || h.PathCritical != 1 || h.FindingIssues != 2 || h.FindingCritical != 1 ||
		h.Issues != 4 || h.Critical != 2 || h.OpenFindings != 3 {
		t.Fatalf("headline %+v", h)
	}
	if h.BySeverity["CRITICAL"] != 2 || h.BySeverity["HIGH"] != 1 || h.BySeverity["MEDIUM"] != 1 {
		t.Errorf("by severity %v", h.BySeverity)
	}
	if want := "4 open Issues: 2 attack path Issues (3 hop variants) + 2 finding Issues; 2 critical (1 path, 1 finding)"; h.Text() != want {
		t.Errorf("text %q\nwant %q", h.Text(), want)
	}
	// Closed states are counted apart and never as open.
	if err := st.MarkPendingVerification(onlyPathIssueOf(t, st, "role/batch").ID, "cli", t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	h, _ = st.Headline()
	if h.PathIssues != 1 || h.PendingVerification != 1 || h.Issues != 3 {
		t.Errorf("after pending %+v", h)
	}
}

func onlyPathIssueOf(t *testing.T, st *Store, anchor string) model.Issue {
	t.Helper()
	is, _ := st.Issues(IssueFilter{Kind: model.IssuePath})
	for _, i := range is {
		if i.AnchorID == anchor {
			return i
		}
	}
	t.Fatalf("no path Issue anchored at %s", anchor)
	return model.Issue{}
}

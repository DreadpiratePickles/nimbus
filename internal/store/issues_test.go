package store

import (
	"context"
	"testing"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/model"
)

func mkFinding(source, check, canonical, resource string, sev model.Severity, weak ...string) model.Finding {
	f := model.Finding{Source: source, CheckID: check, CanonicalID: canonical, Title: canonical, Severity: sev, Status: model.Fail,
		Provider: "aws", Account: "123", Resource: model.Resource{ID: resource, Type: "aws_s3_bucket", Name: resource}, Weaknesses: weak, ScanID: "s1"}
	f.Finalize(time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC))
	return f
}

// O3: one Issue per (canonical_id, resource); findings are evidence; two agreeing sources
// raise confidence; toxic combinations become a separate `combination` Issue.
func TestIssuesFromFindings(t *testing.T) {
	st := openTemp(t)
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	bucket := "arn:aws:s3:::pii"
	fs := []model.Finding{
		mkFinding("prowler", "s3_bucket_public_access", "S3_PUBLIC_BUCKET", bucket, model.High, "PUBLIC_DATA_STORE"),
		mkFinding("nimbus", "aws-s3-public", "S3_PUBLIC_BUCKET", bucket, model.Critical, "PUBLIC_DATA_STORE"),
		mkFinding("prowler", "s3_bucket_default_encryption", "S3_UNENCRYPTED", bucket, model.Medium, "UNENCRYPTED_AT_REST"),
		mkFinding("prowler", "s3_bucket_public_access", "S3_PUBLIC_BUCKET", "arn:aws:s3:::logs", model.High, "PUBLIC_DATA_STORE"),
	}
	if _, err := st.ApplyScan("s1", fs, now, ApplyOptions{Scopes: ScopesOf(fs)}); err != nil {
		t.Fatal(err)
	}
	// mark the bucket sensitive in the graph (crown jewel)
	if err := st.ReplaceGraph([]GraphNode{{ID: bucket, Type: "aws_s3_bucket", Sensitive: true, Doc: []byte(`{}`)}}, nil); err != nil {
		t.Fatal(err)
	}
	if err := st.RebuildIssues(now); err != nil {
		t.Fatal(err)
	}
	issues, err := st.Issues(IssueFilter{})
	if err != nil {
		t.Fatal(err)
	}
	byKey := map[string]model.Issue{}
	for _, is := range issues {
		byKey[is.CanonicalID+"|"+is.ResourceID] = is
	}
	if len(issues) != 4 {
		t.Fatalf("issues = %d (%v), want 3 single + 1 combination", len(issues), keys(byKey))
	}
	pub := byKey["S3_PUBLIC_BUCKET|"+bucket]
	if pub.Kind != model.IssueSingle || len(pub.FindingIDs) != 2 || len(pub.Sources) != 2 || pub.Severity != model.Critical || pub.State != model.StateOpen {
		t.Fatalf("public-bucket issue: %+v", pub)
	}
	single := byKey["S3_PUBLIC_BUCKET|arn:aws:s3:::logs"]
	if !(pub.Confidence > single.Confidence) || single.Confidence <= 0 {
		t.Errorf("two agreeing sources must raise confidence: %v vs %v", pub.Confidence, single.Confidence)
	}
	combo, ok := byKey["TOXIC_PUBLIC_UNENCRYPTED_SENSITIVE|"+bucket]
	if !ok || combo.Kind != model.IssueCombination || combo.Severity != model.Critical || len(combo.FindingIDs) != 3 {
		t.Fatalf("toxic combination issue: %+v (have %v)", combo, keys(byKey))
	}
	if _, ok := byKey["TOXIC_PUBLIC_UNENCRYPTED_SENSITIVE|arn:aws:s3:::logs"]; ok {
		t.Errorf("logs bucket is public only; no combination expected")
	}

	counts, err := st.IssueCounts()
	if err != nil {
		t.Fatal(err)
	}
	if counts.Open != 4 || counts.Combinations != 1 || counts.BySeverity["CRITICAL"] != 2 || counts.ByProvider["aws"] != 4 {
		t.Errorf("IssueCounts = %+v", counts)
	}

	// The fix: encryption enabled -> the combination resolves; the single issue stays open.
	later := now.Add(time.Hour)
	enc := mkFinding("prowler", "s3_bucket_default_encryption", "S3_UNENCRYPTED", bucket, model.Medium, "UNENCRYPTED_AT_REST")
	enc.Status = model.Pass
	if _, err := st.ApplyScan("s2", []model.Finding{enc}, later, ApplyOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := st.RebuildIssues(later); err != nil {
		t.Fatal(err)
	}
	issues, _ = st.Issues(IssueFilter{})
	byKey = map[string]model.Issue{}
	for _, is := range issues {
		byKey[is.CanonicalID+"|"+is.ResourceID] = is
	}
	if s := byKey["TOXIC_PUBLIC_UNENCRYPTED_SENSITIVE|"+bucket].State; s != model.StateResolved {
		t.Errorf("combination after encryption fix: %s, want resolved", s)
	}
	if s := byKey["S3_PUBLIC_BUCKET|"+bucket]; s.State != model.StateOpen || !s.FirstSeen.Equal(now) {
		t.Errorf("public issue after unrelated fix: %+v", s)
	}
	if open, _ := st.Issues(IssueFilter{OpenOnly: true}); len(open) != 2 {
		t.Errorf("open issues = %d, want 2", len(open))
	}

	// SQL views: issues_summary is new, findings_summary keeps working.
	if _, err := st.EnsureViews(); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		"SELECT provider, account, severity, kind, state, count FROM issues_summary",
		"SELECT provider, account, severity, status, count FROM findings_summary",
	} {
		res, err := st.QueryReadOnly(context.Background(), q, ReadOnlyOptions{})
		if err != nil || len(res.Rows) == 0 {
			t.Errorf("%s: %v rows=%d", q, err, len(res.Rows))
		}
	}
}

func TestToxicCombinationsDeclared(t *testing.T) {
	want := map[string]bool{"TOXIC_PUBLIC_UNENCRYPTED_SENSITIVE": false, "TOXIC_PUBLIC_ADMIN": false, "TOXIC_NO_MFA_ADMIN": false}
	for _, c := range model.ToxicCombinations {
		if _, ok := want[c.ID]; ok {
			want[c.ID] = true
		}
		if len(c.AllOf) < 2 {
			t.Errorf("%s: a combination needs >= 2 weaknesses", c.ID)
		}
	}
	for id, ok := range want {
		if !ok {
			t.Errorf("toxic combination %s not declared", id)
		}
	}
	st := openTemp(t)
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	user := "arn:aws:iam::123:user/alice"
	fs := []model.Finding{
		mkFinding("nimbus", "iam-no-mfa", "IAM_USER_NO_MFA", user, model.Medium, "NO_MFA"),
		mkFinding("nimbus", "iam-admin", "IAM_ADMIN_POLICY", user, model.High, "OVERPRIVILEGED_IDENTITY"),
	}
	st.ApplyScan("s1", fs, now, ApplyOptions{})
	st.RebuildIssues(now)
	combos, _ := st.Issues(IssueFilter{Kind: model.IssueCombination})
	if len(combos) != 1 || combos[0].CanonicalID != "TOXIC_NO_MFA_ADMIN" {
		t.Fatalf("no-mfa + admin combination: %+v", combos)
	}
}

func keys(m map[string]model.Issue) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

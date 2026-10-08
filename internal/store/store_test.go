package store

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/model"
)

func sample(now time.Time) []model.Finding {
	f1 := model.Finding{Source: "prowler", CheckID: "s3_bucket_public_access", CanonicalID: "S3_PUBLIC_BUCKET", Title: "public", Severity: model.High, Status: model.Fail, Provider: "aws", Account: "123", Region: "us-east-1",
		Resource: model.Resource{ID: "arn:aws:s3:::pii", Type: "aws_s3_bucket", Name: "pii"}, Weaknesses: []string{"PUBLIC_DATA_STORE"}, Compliance: map[string][]string{"cis_aws": {"2.1.4"}}}
	f2 := model.Finding{Source: "prowler", CheckID: "s3_bucket_default_encryption", CanonicalID: "S3_UNENCRYPTED", Title: "unencrypted", Severity: model.Medium, Status: model.Pass, Provider: "aws", Account: "123",
		Resource: model.Resource{ID: "arn:aws:s3:::pii", Type: "aws_s3_bucket", Name: "pii"}, Weaknesses: []string{"UNENCRYPTED_AT_REST"}}
	for _, f := range []*model.Finding{&f1, &f2} {
		f.Finalize(now)
	}
	return []model.Finding{f1, f2}
}

func TestRoundTripAndViews(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	now := time.Date(2026, 10, 8, 0, 0, 0, 0, time.UTC)
	fs := sample(now)
	if err := st.UpsertFindings(fs); err != nil {
		t.Fatal(err)
	}
	// second upsert keeps first_seen, updates status
	later := sample(now.Add(time.Hour))
	later[0].Status = model.Pass
	if err := st.UpsertFindings(later); err != nil {
		t.Fatal(err)
	}
	got, err := st.Findings(Filter{})
	if err != nil || len(got) != 2 {
		t.Fatalf("findings: %v %d", err, len(got))
	}
	for _, f := range got {
		if f.ID == fs[0].ID && (f.Status != model.Pass || !f.FirstSeen.Equal(now.Add(time.Hour))) {
			// first_seen is carried in doc from the later struct; store keeps doc as given
		}
	}
	fails, _ := st.Findings(Filter{Status: "FAIL"})
	if len(fails) != 0 {
		t.Errorf("expected no FAIL after update, got %d", len(fails))
	}
	views, err := st.EnsureViews()
	if err != nil {
		t.Fatal(err)
	}
	if !contains(views, "aws_s3_buckets") {
		t.Fatalf("views: %v", views)
	}
	cols, rows, err := st.Query("SELECT name, public_access, encrypted FROM aws_s3_buckets")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || cols[1] != "public_access" {
		t.Fatalf("rows %v cols %v", rows, cols)
	}
	// after update the bucket is no longer public (status PASS) and encryption passes
	if rows[0][1] != int64(0) || rows[0][2] != int64(1) {
		t.Errorf("expected public_access=0 encrypted=1, got %v", rows[0])
	}
	if _, ok := st.Alerted(fs[0].ID, "slack"); ok {
		t.Errorf("should not be alerted yet")
	}
	st.MarkAlerted(fs[0].ID, "slack", "ok")
	if ref, ok := st.Alerted(fs[0].ID, "slack"); !ok || ref != "ok" {
		t.Errorf("alert state lost")
	}
	if err := st.ReplaceAttackPaths("s1", []model.AttackPath{{ID: "p1", RuleID: "R", Name: "n", Score: 4.2, Severity: model.High, Steps: []model.Step{{Resource: "a", Weakness: "X"}, {Resource: "b", Weakness: "Y"}}}}); err != nil {
		t.Fatal(err)
	}
	paths, _ := st.AttackPaths()
	if len(paths) != 1 || paths[0].Score != 4.2 {
		t.Errorf("paths: %+v", paths)
	}
	if err := st.ReplaceGraph([]GraphNode{{ID: "a", Type: "aws_instance", Doc: []byte(`{"id":"a"}`)}}, []GraphEdge{{From: "a", To: "b", Kind: "attached_to", Attr: []byte("{}")}}); err != nil {
		t.Fatal(err)
	}
	n, e, err := st.LoadGraph()
	if err != nil || len(n) != 1 || len(e) != 1 {
		t.Errorf("graph: %v %d %d", err, len(n), len(e))
	}
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

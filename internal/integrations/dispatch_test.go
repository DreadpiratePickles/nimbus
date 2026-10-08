package integrations

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/model"
	"github.com/DreadpiratePickles/nimbus/internal/store"
)

type fakeSink struct {
	name   string
	sent   []string
	closed []string
}

func (f *fakeSink) Name() string { return f.name }
func (f *fakeSink) Deliver(ctx context.Context, fd model.Finding, _ []model.AttackPath) (string, error) {
	f.sent = append(f.sent, fd.ID)
	return "ref-" + fd.ID, nil
}
func (f *fakeSink) Close(ctx context.Context, fd model.Finding, ref string) error {
	f.closed = append(f.closed, ref)
	return nil
}

func TestDispatchRulesSuppressionsAutoClose(t *testing.T) {
	st, _ := store.Open(filepath.Join(t.TempDir(), "a.db"))
	defer st.Close()
	hi := model.Finding{ID: "hi", Status: model.Fail, Severity: model.Critical, Provider: "aws", CanonicalID: "S3_PUBLIC_BUCKET", Resource: model.Resource{ID: "arn:aws:s3:::x"}}
	lo := model.Finding{ID: "lo", Status: model.Fail, Severity: model.Low, Provider: "aws", CanonicalID: "S3_NO_LOGGING"}
	muted := model.Finding{ID: "mu", Status: model.Fail, Severity: model.Critical, Provider: "gcp", CanonicalID: "GCP_SQL_PUBLIC", Resource: model.Resource{ID: "proj/sql/dev-1"}}
	sink := &fakeSink{name: "fake"}
	targets := []Target{{Sink: sink, Rule: Rule{MinSeverity: model.High}}}
	opts := Options{Suppressions: []Suppression{{ResourceID: "proj/sql/dev-*", Reason: "dev", ExpiresAt: time.Now().Add(time.Hour)}}, AutoClose: true}
	res := Dispatch(context.Background(), st, targets, []model.Finding{hi, lo, muted}, nil, opts)
	if len(sink.sent) != 1 || sink.sent[0] != "hi" {
		t.Fatalf("sent: %v (%+v)", sink.sent, res)
	}
	// second run: deduped
	Dispatch(context.Background(), st, targets, []model.Finding{hi}, nil, opts)
	if len(sink.sent) != 1 {
		t.Errorf("should dedupe")
	}
	// now passes: auto-close
	hi.Status = model.Pass
	Dispatch(context.Background(), st, targets, []model.Finding{hi}, nil, opts)
	if len(sink.closed) != 1 || sink.closed[0] != "ref-hi" {
		t.Errorf("auto close: %v", sink.closed)
	}
	// fails again later: re-alert allowed after close
	hi.Status = model.Fail
	Dispatch(context.Background(), st, targets, []model.Finding{hi}, nil, opts)
	if len(sink.sent) != 2 {
		t.Errorf("re-alert after close: %v", sink.sent)
	}
	expired := Suppression{CanonicalID: "S3_PUBLIC_BUCKET", ExpiresAt: time.Now().Add(-time.Hour)}
	if expired.Matches(hi, time.Now()) {
		t.Errorf("expired suppression should not match")
	}
	if !(Rule{CanonicalIDs: []string{"S3_*"}, OnlyOnAttackPath: true}).Matches(hi, true) || (Rule{Providers: []string{"azure"}}).Matches(hi, false) {
		t.Errorf("rule matching")
	}
}

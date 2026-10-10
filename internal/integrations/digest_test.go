package integrations

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/governance"
	"github.com/DreadpiratePickles/nimbus/internal/model"
)

var updateDigestGolden = flag.Bool("update-digest", false, "rewrite internal/integrations/testdata/digest/*.golden")

var (
	dNow   = time.Date(2026, 10, 9, 9, 0, 0, 0, time.UTC)
	dSince = dNow.Add(-7 * 24 * time.Hour)
)

func dd(month time.Month, d int) time.Time { return time.Date(2026, month, d, 0, 0, 0, 0, time.UTC) }

func digestFixture() []DigestItem {
	res := dd(10, 5)
	old := dd(9, 20)
	pay := "payments@example.com"
	return []DigestItem{
		{IssueID: "i-crit-overdue", Title: "Public S3 bucket payments-logs", Severity: model.Critical, State: model.StateOpen, Provider: "aws", Account: "aws-prod", ResourceID: "arn:aws:s3:::payments-logs", Owner: pay, DueAt: dd(10, 3), FixCommand: "cloud-posture fix --issue i-crit-overdue --apply"},
		{IssueID: "i-low-overdue", Title: "Log retention below 90 days", Severity: model.Low, State: model.StateOpen, Provider: "aws", Account: "aws-prod", ResourceID: "arn:aws:logs:::group/app", Owner: pay, DueAt: dd(10, 8)},
		{IssueID: "i-crit-open", Title: "Lambda <script> & admin role", Severity: model.Critical, State: model.StateReopened, Provider: "aws", Account: "aws-prod", ResourceID: "arn:aws:lambda:::fn", Owner: pay, DueAt: dd(10, 14), FixCommand: "cloud-posture fix --issue i-crit-open"},
		{IssueID: "i-high-open", Title: "Security group open to 0.0.0.0/0 on 22", Severity: model.High, State: model.StateOpen, Provider: "aws", Account: "aws-prod", ResourceID: "sg-123", Owner: pay, DueAt: dd(10, 20)},
		{IssueID: "i-med-open", Title: "EBS default encryption off", Severity: model.Medium, State: model.StateOpen, Provider: "aws", Account: "aws-prod", ResourceID: "ebs", Owner: pay, DueAt: dd(10, 30)},
		{IssueID: "i-resolved", Title: "IAM user without MFA", Severity: model.High, State: model.StateResolved, Provider: "aws", Account: "aws-prod", ResourceID: "arn:aws:iam:::user/bob", Owner: pay, DueAt: dd(10, 10), ResolvedAt: &res},
		{IssueID: "i-old-resolved", Title: "Old thing", Severity: model.High, State: model.StateResolved, Provider: "aws", Account: "aws-prod", ResourceID: "x", Owner: pay, ResolvedAt: &old},
		{IssueID: "i-suppressed", Title: "Accepted risk", Severity: model.Critical, State: model.StateSuppressed, Provider: "aws", Account: "aws-prod", ResourceID: "y", Owner: pay, DueAt: dd(9, 1)},
		{IssueID: "i-unassigned", Title: "Storage account allows public blob access", Severity: model.High, State: model.StateOpen, Provider: "azure", Account: "azure-sub", ResourceID: "/subscriptions/x/sa"},
		{IssueID: "i-platform", Title: "EKS API endpoint public", Severity: model.Critical, State: model.StateOpen, Provider: "aws", Account: "aws-stage", ResourceID: "arn:aws:eks:::cluster/stage", Owner: "platform@example.com", DueAt: dd(10, 5), FixCommand: "cloud-posture fix --issue i-platform"},
	}
}

func ids(items []DigestItem) []string {
	var out []string
	for _, it := range items {
		out = append(out, it.IssueID)
	}
	return out
}

func TestBuildDigestsSections(t *testing.T) {
	ds := BuildDigests(digestFixture(), DigestOptions{Now: dNow, Since: dSince})
	if len(ds) != 3 || ds[0].Key != governance.Unassigned || ds[1].Key != "payments@example.com" || ds[2].Key != "platform@example.com" {
		t.Fatalf("digest keys = %v", func() []string {
			var k []string
			for _, d := range ds {
				k = append(k, d.Key)
			}
			return k
		}())
	}
	p := ds[1]
	if got := ids(p.Overdue); !reflect.DeepEqual(got, []string{"i-crit-overdue", "i-low-overdue"}) {
		t.Errorf("overdue = %v", got)
	}
	if got := ids(p.OpenCritical); !reflect.DeepEqual(got, []string{"i-crit-open"}) {
		t.Errorf("open critical = %v", got)
	}
	if got := ids(p.OpenHigh); !reflect.DeepEqual(got, []string{"i-high-open"}) {
		t.Errorf("open high = %v", got)
	}
	if got := ids(p.Resolved); !reflect.DeepEqual(got, []string{"i-resolved"}) {
		t.Errorf("resolved = %v", got)
	}
	if p.OpenTotal != 5 || p.Counts.Overdue != 2 {
		t.Errorf("open total %d, overdue count %d", p.OpenTotal, p.Counts.Overdue)
	}
	if ds[0].Empty() || ds[2].Empty() {
		t.Error("unassigned and platform digests have content")
	}
	byAcct := BuildDigests(digestFixture(), DigestOptions{Now: dNow, Since: dSince, GroupBy: "account"})
	if len(byAcct) != 3 || byAcct[0].Key != "aws-prod" || byAcct[0].GroupBy != "account" {
		t.Errorf("group by account = %+v", byAcct)
	}
}

func golden(t *testing.T, name string, got []byte) {
	t.Helper()
	p := filepath.Join("testdata", "digest", name)
	if *updateDigestGolden {
		if err := os.WriteFile(p, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("%v (run go test ./internal/integrations/ -run Digest -update-digest)", err)
	}
	if string(want) != string(got) {
		t.Errorf("%s differs from golden:\n--- got ---\n%s\n--- want ---\n%s", name, got, want)
	}
}

func TestDigestGolden(t *testing.T) {
	ds := BuildDigests(digestFixture(), DigestOptions{Now: dNow, Since: dSince})
	var all strings.Builder
	for _, d := range ds {
		all.WriteString(d.Text())
		all.WriteString("\n")
	}
	golden(t, "all.txt.golden", []byte(all.String()))
	js, err := ds[1].SlackJSON()
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "payments.slack.json.golden", js)
	var v struct {
		Text   string           `json:"text"`
		Blocks []map[string]any `json:"blocks"`
	}
	if err := json.Unmarshal(js, &v); err != nil || v.Text == "" || len(v.Blocks) == 0 || len(v.Blocks) > 50 {
		t.Fatalf("slack payload invalid: %v %+v", err, v)
	}
	if strings.Contains(string(js), "<script>") {
		t.Error("slack mrkdwn must escape < > &")
	}
}

func TestDigestTruncation(t *testing.T) {
	var items []DigestItem
	for i := 0; i < 5; i++ {
		items = append(items, DigestItem{IssueID: "o" + string(rune('a'+i)), Title: "t", Severity: model.High, State: model.StateOpen, Owner: "x", DueAt: dd(10, 1+i)})
	}
	ds := BuildDigests(items, DigestOptions{Now: dNow, Since: dSince, MaxPerSection: 2})
	if len(ds) != 1 || len(ds[0].Overdue) != 2 || ds[0].Counts.Overdue != 5 {
		t.Fatalf("truncation: %+v", ds)
	}
	if txt := ds[0].Text(); !strings.Contains(txt, "... and 3 more") {
		t.Errorf("text does not say how many were cut:\n%s", txt)
	}
}

func TestDigestDedup(t *testing.T) {
	ds := BuildDigests(digestFixture(), DigestOptions{Now: dNow, Since: dSince})
	d := ds[1]
	l := NewMemoryLedger()
	week := 7 * 24 * time.Hour
	if !ShouldSend(d, l, week, dNow) {
		t.Fatal("first digest must be sent")
	}
	if err := l.Record(d.Key, d.Fingerprint(), dNow); err != nil {
		t.Fatal(err)
	}
	if ShouldSend(d, l, week, dNow.Add(time.Hour)) {
		t.Error("unchanged digest inside the window must not be re-sent")
	}
	// a day later the overdue counters changed but membership did not: still a duplicate
	later := BuildDigests(digestFixture(), DigestOptions{Now: dNow.Add(24 * time.Hour), Since: dSince.Add(24 * time.Hour)})[1]
	if later.Fingerprint() != d.Fingerprint() || ShouldSend(later, l, week, dNow.Add(24*time.Hour)) {
		t.Error("day-count changes alone must not change the fingerprint")
	}
	items := digestFixture()
	items[3].DueAt = dd(10, 8) // i-high-open becomes overdue
	changed := BuildDigests(items, DigestOptions{Now: dNow, Since: dSince})[1]
	if changed.Fingerprint() == d.Fingerprint() || !ShouldSend(changed, l, week, dNow.Add(time.Hour)) {
		t.Error("a changed digest must be sent")
	}
	if !ShouldSend(d, l, week, dNow.Add(week+time.Second)) {
		t.Error("an unchanged digest is re-sent once the window has passed")
	}
	empty := Digest{Key: "nobody"}
	if !empty.Empty() || ShouldSend(empty, l, week, dNow) {
		t.Error("empty digests are never sent")
	}
}

func TestSendDigests(t *testing.T) {
	ds := BuildDigests(digestFixture(), DigestOptions{Now: dNow, Since: dSince})
	ds = append(ds, Digest{Key: "empty@example.com"})
	l := NewMemoryLedger()
	var sent []string
	send := func(_ context.Context, d Digest) error {
		if d.Key == "platform@example.com" {
			return errors.New("boom")
		}
		sent = append(sent, d.Key)
		return nil
	}
	run, err := SendDigests(context.Background(), ds, l, 7*24*time.Hour, dNow, send)
	if err == nil || !strings.Contains(err.Error(), "platform@example.com") {
		t.Errorf("want aggregated error naming the failed owner, got %v", err)
	}
	if !reflect.DeepEqual(sent, []string{governance.Unassigned, "payments@example.com"}) || !reflect.DeepEqual(run.Sent, sent) {
		t.Errorf("sent = %v run = %+v", sent, run)
	}
	if !reflect.DeepEqual(run.Failed, []string{"platform@example.com"}) || !reflect.DeepEqual(run.Skipped, []string{"empty@example.com"}) {
		t.Errorf("run = %+v", run)
	}
	sent = nil
	run, _ = SendDigests(context.Background(), ds, l, 7*24*time.Hour, dNow.Add(time.Hour), send)
	if len(sent) != 0 || !reflect.DeepEqual(run.Failed, []string{"platform@example.com"}) || len(run.Skipped) != 3 {
		t.Errorf("second run must only retry the failed digest: sent %v run %+v", sent, run)
	}
}

func TestFileLedgerRoundTrip(t *testing.T) {
	p := filepath.Join(t.TempDir(), "sub", "digest-ledger.json")
	l := NewFileLedger(p)
	if _, _, ok := l.Last("a"); ok {
		t.Fatal("empty ledger")
	}
	if err := l.Record("a", "fp1", dNow); err != nil {
		t.Fatal(err)
	}
	fp, at, ok := NewFileLedger(p).Last("a")
	if !ok || fp != "fp1" || !at.Equal(dNow) {
		t.Errorf("reloaded = %q %v %v", fp, at, ok)
	}
}

func TestSlackDigestSender(t *testing.T) {
	srv, rec := newRecorder(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	d := BuildDigests(digestFixture(), DigestOptions{Now: dNow, Since: dSince})[1]
	if err := SlackDigestSender(srv.URL+"/hook", "#sec")(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	reqs := rec.all()
	if len(reqs) != 1 || reqs[0].Path != "/hook" {
		t.Fatalf("requests = %+v", reqs)
	}
	var body map[string]any
	if err := json.Unmarshal(reqs[0].Body, &body); err != nil || body["channel"] != "#sec" || body["blocks"] == nil {
		t.Errorf("body = %s", reqs[0].Body)
	}
	bad, _ := newRecorder(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) })
	if err := SlackDigestSender(bad.URL, "")(context.Background(), d); err == nil {
		t.Error("non-2xx must fail")
	}
	if err := SlackDigestSender("", "")(context.Background(), d); err == nil {
		t.Error("missing URL must fail")
	}
}

func TestDigestItemFromIssue(t *testing.T) {
	is := model.Issue{ID: "i1", Title: "t", Severity: model.High, State: model.StateOpen, Provider: "aws", Account: "a", ResourceID: "r"}
	a := governance.Assignment{Owner: "o@example.com", DueAt: dd(10, 1)}
	it := DigestItemFromIssue(is, a, "cloud-posture fix --issue i1")
	if it.IssueID != "i1" || it.Owner != "o@example.com" || !it.DueAt.Equal(dd(10, 1)) || it.FixCommand == "" || it.Severity != model.High {
		t.Errorf("item = %+v", it)
	}
}

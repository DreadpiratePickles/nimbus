package integrations

import (
	"context"
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/model"
	"github.com/DreadpiratePickles/nimbus/internal/store"
)

// ticketStore holds two Issues of three findings: i1 (CRITICAL, two findings) and i2 (LOW).
func ticketStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	_, err = st.DB().Exec(`INSERT INTO issues (id, canonical_id, resource_id, provider, account, severity, state, first_seen, last_seen, finding_ids, sources, confidence, kind, title)
	  VALUES ('i1','S3_PUBLIC_BUCKET','arn:aws:s3:::pii','aws','123','CRITICAL','open','2026-01-01T00:00:00Z','2026-01-02T00:00:00Z','["f1","f2"]','["nimbus","prowler"]',0.91,'single','S3 bucket allows public access'),
	         ('i2','S3_NO_LOGGING','arn:aws:s3:::logs','aws','123','LOW','open','2026-01-01T00:00:00Z','2026-01-02T00:00:00Z','["f3"]','["nimbus"]',0.7,'single','S3 logging off')`)
	if err != nil {
		t.Fatal(err)
	}
	due := time.Date(2026, 1, 8, 0, 0, 0, 0, time.UTC)
	if err := st.SetIssueGovernance([]store.IssueGovernance{
		{ID: "i1", Owner: "alice@example.com", Source: "rule", RuleID: "payments", Why: "rule payments", SLADays: 7, DueAt: &due},
		{ID: "i2", Owner: "@bob", Source: "codeowners", Why: "CODEOWNERS line 3", SLADays: 90},
	}); err != nil {
		t.Fatal(err)
	}
	return st
}

func storedIssue(t *testing.T, st *store.Store, id string) model.Issue {
	t.Helper()
	is, err := st.Issues(store.IssueFilter{})
	if err != nil {
		t.Fatal(err)
	}
	for _, i := range is {
		if i.ID == id {
			return i
		}
	}
	t.Fatalf("issue %s not stored", id)
	return model.Issue{}
}

func dispatchAll(t *testing.T, st *store.Store, tk IssueTicketer, min model.Severity) []Result {
	t.Helper()
	is, _ := st.Issues(store.IssueFilter{})
	return DispatchIssues(context.Background(), st, []IssueTarget{{Ticketer: tk, MinSeverity: min}}, is, IssueDispatchOptions{AutoClose: true})
}

// Jira: one ticket per Issue (not per finding), assignee from the owner (account id looked up by
// email), due date from due_at, idempotent through the stored ticket key, and closing / reopening
// the nimbus Issue transitions the ticket.
func TestJiraOneTicketPerIssue(t *testing.T) {
	var transitions []string
	srv, rec := newRecorder(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/rest/api/3/search"):
			w.Write([]byte(`{"issues":[]}`))
		case r.URL.Path == "/rest/api/3/user/search":
			if r.URL.Query().Get("query") == "alice@example.com" {
				w.Write([]byte(`[{"accountId":"acc-alice","emailAddress":"alice@example.com"}]`))
				return
			}
			w.Write([]byte(`[]`))
		case r.URL.Path == "/rest/api/3/issue" && r.Method == http.MethodPost:
			w.WriteHeader(201)
			w.Write([]byte(`{"id":"10","key":"SEC-42"}`))
		case r.URL.Path == "/rest/api/3/issue/SEC-42/transitions" && r.Method == http.MethodGet:
			w.Write([]byte(`{"transitions":[{"id":"11","name":"To Do","to":{"statusCategory":{"key":"new"}}},{"id":"31","name":"Done","to":{"statusCategory":{"key":"done"}}}]}`))
		case r.URL.Path == "/rest/api/3/issue/SEC-42/transitions" && r.Method == http.MethodPost:
			var b struct {
				Transition struct{ ID string } `json:"transition"`
			}
			// the recorder already consumed the body; the captured copy is checked below
			_ = b
			transitions = append(transitions, "post")
			w.WriteHeader(204)
		case r.URL.Path == "/rest/api/3/issue/SEC-42/comment":
			w.WriteHeader(201)
			w.Write([]byte(`{}`))
		case r.URL.Path == "/rest/api/3/issue/SEC-42" && r.Method == http.MethodPut:
			w.WriteHeader(204)
		default:
			w.WriteHeader(500)
		}
	})
	st := ticketStore(t)
	j := NewJira(srv.URL, "bot@example.com", "tok", "SEC", "")
	res := dispatchAll(t, st, j, model.High)
	creates := 0
	for _, r := range rec.all() {
		if r.Path == "/rest/api/3/issue" && r.Method == http.MethodPost {
			creates++
			var p struct {
				Fields map[string]any `json:"fields"`
			}
			json.Unmarshal(r.Body, &p)
			if a, _ := p.Fields["assignee"].(map[string]any); a["accountId"] != "acc-alice" {
				t.Errorf("assignee = %v, want accountId acc-alice", p.Fields["assignee"])
			}
			if p.Fields["duedate"] != "2026-01-08" {
				t.Errorf("duedate = %v, want 2026-01-08 (governance due_at)", p.Fields["duedate"])
			}
			labels, _ := json.Marshal(p.Fields["labels"])
			if !strings.Contains(string(labels), "cp-issue-i1") {
				t.Errorf("labels %s lack the Issue de-dup label", labels)
			}
			desc, _ := json.Marshal(p.Fields["description"])
			for _, want := range []string{"alice@example.com", "2026-01-08", "f1", "f2", "cloud-posture-issue: i1"} {
				if !strings.Contains(string(desc), want) {
					t.Errorf("description lacks %q", want)
				}
			}
		}
	}
	if creates != 1 {
		t.Fatalf("created %d Jira issues for one qualifying Issue of two findings, want 1 (results %+v)", creates, res)
	}
	i1 := storedIssue(t, st, "i1")
	if i1.TicketSink != "jira" || i1.TicketKey != "SEC-42" || i1.TicketURL != srv.URL+"/browse/SEC-42" || i1.TicketState != "open" {
		t.Fatalf("stored ticket = %+v", i1)
	}
	if storedIssue(t, st, "i2").TicketKey != "" {
		t.Error("LOW Issue below min severity got a ticket")
	}

	// Second run: idempotent through the stored key (no search, no create).
	n := len(rec.all())
	dispatchAll(t, st, j, model.High)
	if got := rec.all()[n:]; len(got) != 0 {
		t.Fatalf("second run made %d requests, want 0: %+v", len(got), got)
	}

	// The nimbus Issue resolves → the ticket transitions to a done status.
	st.DB().Exec("UPDATE issues SET state = 'resolved', resolved_at = '2026-01-05T00:00:00Z' WHERE id = 'i1'")
	n = len(rec.all())
	dispatchAll(t, st, j, model.High)
	var closedVia string
	for _, r := range rec.all()[n:] {
		if r.Method == http.MethodPost && strings.HasSuffix(r.Path, "/transitions") {
			closedVia = string(r.Body)
		}
	}
	if !strings.Contains(closedVia, `"31"`) {
		t.Fatalf("resolve did not transition SEC-42 to Done (31): %q", closedVia)
	}
	if storedIssue(t, st, "i1").TicketState != "closed" {
		t.Error("ticket_state not closed after the transition")
	}
	// Reopen → transition back to a not-done status and refresh the due date.
	st.DB().Exec("UPDATE issues SET state = 'reopened', resolved_at = NULL WHERE id = 'i1'")
	n = len(rec.all())
	dispatchAll(t, st, j, model.High)
	var reopenedVia string
	putDue := false
	for _, r := range rec.all()[n:] {
		if r.Method == http.MethodPost && strings.HasSuffix(r.Path, "/transitions") {
			reopenedVia = string(r.Body)
		}
		if r.Method == http.MethodPut && strings.Contains(string(r.Body), "duedate") {
			putDue = true
		}
	}
	if !strings.Contains(reopenedVia, `"11"`) || !putDue {
		t.Fatalf("reopen: transition %q, due date updated %v", reopenedVia, putDue)
	}
	if storedIssue(t, st, "i1").TicketState != "open" {
		t.Error("ticket_state not open after reopen")
	}
	_ = transitions
}

// GitHub Issues: one issue per nimbus Issue, assignee from an @user owner (teams and emails are
// not assignable), due date in the body, close/reopen follow the nimbus Issue.
func TestGitHubOneTicketPerIssue(t *testing.T) {
	srv, rec := newRecorder(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/search/issues":
			w.Write([]byte(`{"items":[]}`))
		case r.URL.Path == "/repos/acme/infra/issues" && r.Method == http.MethodPost:
			w.WriteHeader(201)
			w.Write([]byte(`{"number":7,"html_url":"https://github.com/acme/infra/issues/7"}`))
		case strings.HasPrefix(r.URL.Path, "/repos/acme/infra/issues/7"):
			w.Write([]byte(`{}`))
		default:
			w.WriteHeader(500)
		}
	})
	st := ticketStore(t)
	gh := &GitHubIssues{Repo: "acme/infra", Token: "t", APIBase: srv.URL}
	dispatchAll(t, st, gh, model.Low)
	var bodies []map[string]any
	for _, r := range rec.all() {
		if r.Path == "/repos/acme/infra/issues" && r.Method == http.MethodPost {
			var p map[string]any
			json.Unmarshal(r.Body, &p)
			bodies = append(bodies, p)
		}
	}
	if len(bodies) != 2 {
		t.Fatalf("created %d GitHub issues for 2 Issues (3 findings), want 2", len(bodies))
	}
	for _, p := range bodies {
		body, _ := p["body"].(string)
		as, _ := json.Marshal(p["assignees"])
		switch {
		case strings.Contains(body, "cloud-posture-issue: i1"):
			if !strings.Contains(body, "2026-01-08") || !strings.Contains(body, "alice@example.com") {
				t.Errorf("i1 body lacks due date / owner:\n%s", body)
			}
			if p["assignees"] != nil && string(as) != "[]" {
				t.Errorf("email owner assigned on GitHub: %s", as)
			}
		case strings.Contains(body, "cloud-posture-issue: i2"):
			if string(as) != `["bob"]` {
				t.Errorf("i2 assignees = %s, want [\"bob\"]", as)
			}
		default:
			t.Errorf("body without an Issue marker:\n%s", body)
		}
	}
	if i := storedIssue(t, st, "i1"); i.TicketSink != "github" || i.TicketKey != "7" || i.TicketURL != "https://github.com/acme/infra/issues/7" {
		t.Fatalf("stored ticket = %+v", i)
	}
	st.DB().Exec("UPDATE issues SET state = 'resolved' WHERE id = 'i1'")
	n := len(rec.all())
	dispatchAll(t, st, gh, model.Low)
	closed := false
	for _, r := range rec.all()[n:] {
		if r.Method == http.MethodPatch && strings.Contains(string(r.Body), `"closed"`) {
			closed = true
		}
	}
	if !closed {
		t.Fatal("resolving the nimbus Issue did not close the GitHub issue")
	}
	st.DB().Exec("UPDATE issues SET state = 'reopened' WHERE id = 'i1'")
	n = len(rec.all())
	dispatchAll(t, st, gh, model.Low)
	reopened := false
	for _, r := range rec.all()[n:] {
		if r.Method == http.MethodPatch && strings.Contains(string(r.Body), `"open"`) {
			reopened = true
		}
	}
	if !reopened || storedIssue(t, st, "i1").TicketState != "open" {
		t.Fatal("reopening the nimbus Issue did not reopen the GitHub issue")
	}
}

// A ticket opened in one sink is never duplicated in another ticketing sink.
func TestIssueTicketOwnedBySink(t *testing.T) {
	st := ticketStore(t)
	st.SetIssueTicket("i1", store.IssueTicket{Sink: "jira", Key: "SEC-1", URL: "u", State: "open"})
	srv, rec := newRecorder(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) })
	gh := &GitHubIssues{Repo: "acme/infra", Token: "t", APIBase: srv.URL}
	is, _ := st.Issues(store.IssueFilter{})
	res := DispatchIssues(context.Background(), st, []IssueTarget{{Ticketer: gh, MinSeverity: model.High}}, is, IssueDispatchOptions{DryRun: true})
	if len(rec.all()) != 0 {
		t.Fatalf("dry run / foreign ticket made requests: %+v", rec.all())
	}
	for _, r := range res {
		if r.IssueID == "i1" && (!r.Skipped || !strings.Contains(r.Ref, "jira")) {
			t.Errorf("i1 result %+v: want skipped, ticket in jira", r)
		}
	}
}

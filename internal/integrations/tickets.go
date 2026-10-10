package integrations

// One ticket per Issue (integration pass 4; Jira / Datadog Case Management bar): Jira and
// GitHub Issues open a single ticket for an Issue — never one per evidence finding — with the
// assignee taken from the governance owner when the tracker can assign it and the due date from
// the Issue's governance due_at. The ticket is idempotent through the key stored on the Issue
// (issues.ticket_*), with a body marker as a fallback when the store was lost; resolving the
// nimbus Issue closes (transitions) the ticket and reopening it reopens the ticket with the
// fresh due date.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/DreadpiratePickles/nimbus/internal/model"
	"github.com/DreadpiratePickles/nimbus/internal/store"
)

// TicketRequest is everything a tracker needs to open or update one Issue's ticket.
type TicketRequest struct {
	Issue      model.Issue
	Evidence   []model.Finding // the Issue's findings (may be empty: path Issues)
	FixCommand string
}

// TicketRef identifies a ticket in its tracker.
type TicketRef struct {
	Key string // Jira key (SEC-12) or GitHub issue number
	URL string
}

// IssueTicketer is a tracker that holds one ticket per Issue.
type IssueTicketer interface {
	Name() string
	OpenTicket(ctx context.Context, req TicketRequest) (TicketRef, error) // finds an existing ticket by marker first
	CloseTicket(ctx context.Context, ref TicketRef, req TicketRequest) error
	ReopenTicket(ctx context.Context, ref TicketRef, req TicketRequest) error
}

// IssueTarget is one ticketing sink and the minimum severity it opens tickets for.
type IssueTarget struct {
	Ticketer    IssueTicketer
	MinSeverity model.Severity
}

// IssueDispatchOptions control DispatchIssues.
type IssueDispatchOptions struct {
	DryRun    bool
	AutoClose bool // close tickets of resolved Issues, reopen tickets of reopened ones
	// Evidence returns an Issue's findings (nil: the ticket lists finding ids only).
	Evidence func(model.Issue) []model.Finding
	// FixCommand returns the command that fixes an Issue ("" for none).
	FixCommand func(model.Issue) string
}

// IssueMarker is the body marker that finds an Issue's ticket when the store lost the key.
func IssueMarker(id string) string { return "cloud-posture-issue: " + id }

// Ticket states stored in issues.ticket_state.
const (
	TicketOpen   = "open"
	TicketClosed = "closed"
)

// DispatchIssues reconciles one ticket per Issue with each target: an active Issue at or
// above the target's severity without a ticket gets one; a resolved Issue's open ticket is
// closed and a reopened Issue's closed ticket reopened (AutoClose); suppressed Issues are left
// alone. An Issue whose ticket lives in another sink is skipped, so two configured trackers
// never duplicate a ticket. Every outcome is a Result with IssueID set.
func DispatchIssues(ctx context.Context, st *store.Store, targets []IssueTarget, issues []model.Issue, opts IssueDispatchOptions) []Result {
	var results []Result
	for _, is := range issues {
		for _, t := range targets {
			name := t.Ticketer.Name()
			r := Result{Channel: name, IssueID: is.ID, FindingID: is.ID}
			if is.TicketSink != "" && is.TicketSink != name {
				r.Skipped, r.Ref = true, "ticket in "+is.TicketSink+" "+is.TicketKey
				results = append(results, r)
				continue
			}
			has := is.TicketKey != "" || is.TicketURL != ""
			req := TicketRequest{Issue: is}
			lazy := func() TicketRequest {
				if opts.Evidence != nil && req.Evidence == nil {
					req.Evidence = opts.Evidence(is)
				}
				if opts.FixCommand != nil && req.FixCommand == "" {
					req.FixCommand = opts.FixCommand(is)
				}
				return req
			}
			ref := TicketRef{Key: is.TicketKey, URL: is.TicketURL}
			switch {
			case model.IsActive(is.State) && !has:
				if t.MinSeverity != "" && is.Severity.Rank() < t.MinSeverity.Rank() {
					continue
				}
				if opts.DryRun {
					r.Skipped, r.Ref = true, "dry-run"
					break
				}
				got, err := t.Ticketer.OpenTicket(ctx, lazy())
				if err != nil {
					r.Err = err.Error()
					break
				}
				r.Ref = got.URL
				if err := st.SetIssueTicket(is.ID, store.IssueTicket{Sink: name, Key: got.Key, URL: got.URL, State: TicketOpen}); err != nil {
					r.Err = fmt.Sprintf("ticket opened but could not record: %v", err)
				}
			case model.IsActive(is.State) && is.TicketState == TicketClosed && opts.AutoClose:
				if opts.DryRun {
					r.Skipped, r.Ref = true, "dry-run reopen "+ref.URL
					break
				}
				if err := t.Ticketer.ReopenTicket(ctx, ref, lazy()); err != nil {
					r.Err = err.Error()
					break
				}
				r.Ref = "reopened:" + ref.URL
				_ = st.SetIssueTicket(is.ID, store.IssueTicket{Sink: name, Key: ref.Key, URL: ref.URL, State: TicketOpen})
			case is.State == model.StateResolved && has && is.TicketState != TicketClosed && opts.AutoClose:
				if opts.DryRun {
					r.Skipped, r.Ref = true, "dry-run close "+ref.URL
					break
				}
				if err := t.Ticketer.CloseTicket(ctx, ref, lazy()); err != nil {
					r.Err = err.Error()
					break
				}
				r.Ref = "closed:" + ref.URL
				_ = st.SetIssueTicket(is.ID, store.IssueTicket{Sink: name, Key: ref.Key, URL: ref.URL, State: TicketClosed})
			case has:
				r.Skipped, r.Ref = true, ref.URL
			default:
				continue // resolved/suppressed without a ticket: nothing to do
			}
			results = append(results, r)
		}
	}
	return results
}

// ticketTitle is "[SEV] title: resource".
func ticketTitle(is model.Issue, max int) string {
	res := is.ResourceID
	if i := strings.LastIndexAny(res, ":/"); i >= 0 && i < len(res)-1 {
		res = res[i+1:]
	}
	s := fmt.Sprintf("[%s] %s: %s", is.Severity, firstNonEmpty(is.Title, is.CanonicalID, is.RuleID), res)
	if len(s) > max {
		s = s[:max]
	}
	return s
}

func dueDate(is model.Issue) string {
	if is.DueAt == nil || is.DueAt.IsZero() {
		return ""
	}
	return is.DueAt.UTC().Format("2006-01-02")
}

// ticketFacts are the lines every ticket body shows.
func ticketFacts(req TicketRequest) []string {
	is := req.Issue
	facts := []string{
		"Issue: " + is.ID + " (" + is.Kind + ")",
		"Severity: " + string(is.Severity),
		"Resource: " + is.ResourceID,
		"Provider / Account: " + firstNonEmpty(is.Provider, "-") + " / " + firstNonEmpty(is.Account, "-"),
		"Owner: " + firstNonEmpty(is.Owner, "unassigned") + ownerSuffix(is),
	}
	if d := dueDate(is); d != "" {
		facts = append(facts, fmt.Sprintf("Due: %s (%d-day %s SLA)", d, is.SLADays, strings.ToLower(string(is.Severity))))
	} else {
		facts = append(facts, "Due: no SLA")
	}
	if is.OwnerWhy != "" {
		facts = append(facts, "Why this owner: "+is.OwnerWhy)
	}
	return facts
}

func ownerSuffix(is model.Issue) string {
	if is.OwnerSource == "" {
		return ""
	}
	return " (" + is.OwnerSource + ")"
}

func evidenceLines(req TicketRequest) []string {
	var out []string
	if len(req.Evidence) > 0 {
		ev := append([]model.Finding(nil), req.Evidence...)
		sort.Slice(ev, func(i, j int) bool { return ev[i].ID < ev[j].ID })
		for _, f := range ev {
			out = append(out, fmt.Sprintf("%s %s %s on %s (%s, finding %s)", f.Status, f.Severity, f.CanonicalID, firstNonEmpty(f.Resource.Name, f.Resource.ID, f.File), f.Source, f.ID))
		}
		return out
	}
	for _, id := range req.Issue.FindingIDs {
		out = append(out, "finding "+id)
	}
	return out
}

// IssueTicketBody is the Markdown body of an Issue's GitHub ticket.
func IssueTicketBody(req TicketRequest) string {
	var b strings.Builder
	fmt.Fprintf(&b, "## %s\n\n", firstNonEmpty(req.Issue.Title, req.Issue.CanonicalID, req.Issue.RuleID))
	for _, f := range ticketFacts(req) {
		fmt.Fprintf(&b, "- %s\n", f)
	}
	if ev := evidenceLines(req); len(ev) > 0 {
		b.WriteString("\n### Evidence\n")
		for _, l := range ev {
			fmt.Fprintf(&b, "- %s\n", l)
		}
	}
	if req.FixCommand != "" {
		fmt.Fprintf(&b, "\n### Fix\n```bash\n%s\n```\n", req.FixCommand)
	}
	fmt.Fprintf(&b, "\n```bash\ncloud-posture issues show %s\n```\n\n<!-- %s -->\n", req.Issue.ID, IssueMarker(req.Issue.ID))
	return b.String()
}

// doJSON sends method url with a JSON body (nil = none) and returns body and status.
func doJSON(ctx context.Context, method, rawURL string, headers map[string]string, body any) ([]byte, int, error) {
	var rd io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return nil, 0, err
		}
		rd = bytes.NewReader(buf)
	}
	req, err := newRequest(ctx, method, rawURL, rd)
	if err != nil {
		return nil, 0, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("User-Agent", "cloud-posture/0.1")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return data, resp.StatusCode, nil
}

// ---------------------------------------------------------------- Jira

// JiraIssueLabel is the de-duplication label of an Issue's Jira ticket.
func JiraIssueLabel(id string) string { return "cp-issue-" + id }

func (j *Jira) configured() error {
	if j.BaseURL == "" || j.Email == "" || j.APIToken == "" || j.ProjectKey == "" {
		return fmt.Errorf("jira requires base URL, email, API token and project key (JIRA_URL, JIRA_EMAIL, JIRA_API_TOKEN, JIRA_PROJECT)")
	}
	return nil
}

// OpenTicket creates the Issue's Jira ticket (or returns the one carrying its label) with the
// assignee looked up from an e-mail owner and duedate from due_at.
func (j *Jira) OpenTicket(ctx context.Context, req TicketRequest) (TicketRef, error) {
	if err := j.configured(); err != nil {
		return TicketRef{}, err
	}
	is := req.Issue
	label := JiraIssueLabel(is.ID)
	key, err := j.findExisting(ctx, label)
	if err != nil {
		return TicketRef{}, err
	}
	if key != "" {
		return TicketRef{Key: key, URL: j.base() + "/browse/" + key}, nil
	}
	labels := append([]string{"cloud-posture", label, "severity-" + strings.ToLower(string(is.Severity)), "kind-" + is.Kind}, j.Labels...)
	if is.Provider != "" {
		labels = append(labels, "provider-"+is.Provider)
	}
	fields := map[string]any{
		"project":     map[string]any{"key": j.ProjectKey},
		"issuetype":   map[string]any{"name": firstNonEmpty(j.IssueType, "Task")},
		"summary":     ticketTitle(is, 255),
		"description": jiraIssueADF(req),
		"labels":      labels,
	}
	if d := dueDate(is); d != "" {
		fields["duedate"] = d
	}
	if id := j.accountID(ctx, is.Owner); id != "" {
		fields["assignee"] = map[string]any{"accountId": id}
	}
	body, code, err := postJSON(ctx, j.base()+"/rest/api/3/issue", j.headers(), map[string]any{"fields": fields})
	if err != nil {
		return TicketRef{}, err
	}
	if code >= 300 {
		return TicketRef{}, fmt.Errorf("jira responded %d: %s", code, truncate(string(body), 300))
	}
	var created struct {
		Key string `json:"key"`
	}
	if err := json.Unmarshal(body, &created); err != nil || created.Key == "" {
		return TicketRef{}, fmt.Errorf("jira create: unexpected response %s", truncate(string(body), 200))
	}
	return TicketRef{Key: created.Key, URL: j.base() + "/browse/" + created.Key}, nil
}

// accountID finds the Jira account of an e-mail owner ("" when the owner is not an e-mail,
// the lookup fails or is ambiguous: the ticket is then created unassigned).
func (j *Jira) accountID(ctx context.Context, owner string) string {
	owner = strings.TrimSpace(owner)
	if !strings.Contains(owner, "@") || strings.HasPrefix(owner, "@") {
		return ""
	}
	data, code, err := doJSON(ctx, http.MethodGet, j.base()+"/rest/api/3/user/search?query="+url.QueryEscape(owner), j.headers(), nil)
	if err != nil || code >= 300 {
		return ""
	}
	var users []struct {
		AccountID string `json:"accountId"`
		Email     string `json:"emailAddress"`
	}
	if json.Unmarshal(data, &users) != nil {
		return ""
	}
	for _, u := range users {
		if strings.EqualFold(u.Email, owner) {
			return u.AccountID
		}
	}
	if len(users) == 1 {
		return users[0].AccountID
	}
	return ""
}

// transition moves key to the first transition whose target status category is done (close)
// or not done (reopen), preferring one named like the intent.
func (j *Jira) transition(ctx context.Context, key string, done bool) error {
	data, code, err := doJSON(ctx, http.MethodGet, j.base()+"/rest/api/3/issue/"+url.PathEscape(key)+"/transitions", j.headers(), nil)
	if err != nil {
		return err
	}
	if code >= 300 {
		return fmt.Errorf("jira transitions %s responded %d", key, code)
	}
	var out struct {
		Transitions []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
			To   struct {
				StatusCategory struct {
					Key string `json:"key"`
				} `json:"statusCategory"`
			} `json:"to"`
		} `json:"transitions"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return fmt.Errorf("jira transitions decode: %w", err)
	}
	prefer := []string{"done", "resolve", "close"}
	if !done {
		prefer = []string{"reopen", "to do", "open", "backlog"}
	}
	pick := ""
	for _, t := range out.Transitions {
		if (t.To.StatusCategory.Key == "done") != done {
			continue
		}
		if pick == "" {
			pick = t.ID
		}
		for _, p := range prefer {
			if strings.Contains(strings.ToLower(t.Name), p) {
				pick = t.ID
				goto chosen
			}
		}
	}
chosen:
	if pick == "" {
		return fmt.Errorf("jira %s: no transition to a %s status", key, map[bool]string{true: "done", false: "not-done"}[done])
	}
	body, code, err := doJSON(ctx, http.MethodPost, j.base()+"/rest/api/3/issue/"+url.PathEscape(key)+"/transitions", j.headers(), map[string]any{"transition": map[string]any{"id": pick}})
	if err != nil {
		return err
	}
	if code >= 300 {
		return fmt.Errorf("jira transition %s responded %d: %s", key, code, truncate(string(body), 200))
	}
	return nil
}

func (j *Jira) comment(ctx context.Context, key, text string) {
	doJSON(ctx, http.MethodPost, j.base()+"/rest/api/3/issue/"+url.PathEscape(key)+"/comment", j.headers(),
		map[string]any{"body": map[string]any{"type": "doc", "version": 1, "content": []map[string]any{adfPara(adfText(text))}}})
}

// CloseTicket transitions the ticket to a done status with a comment.
func (j *Jira) CloseTicket(ctx context.Context, ref TicketRef, req TicketRequest) error {
	if err := j.configured(); err != nil {
		return err
	}
	if err := j.transition(ctx, ref.Key, true); err != nil {
		return err
	}
	j.comment(ctx, ref.Key, fmt.Sprintf("cloud-posture: Issue %s is resolved (no active evidence). Closing.", req.Issue.ID))
	return nil
}

// ReopenTicket transitions the ticket back to a not-done status and sets the new due date
// (a reopened Issue starts a fresh SLA clock).
func (j *Jira) ReopenTicket(ctx context.Context, ref TicketRef, req TicketRequest) error {
	if err := j.configured(); err != nil {
		return err
	}
	if err := j.transition(ctx, ref.Key, false); err != nil {
		return err
	}
	if d := dueDate(req.Issue); d != "" {
		if body, code, err := doJSON(ctx, http.MethodPut, j.base()+"/rest/api/3/issue/"+url.PathEscape(ref.Key), j.headers(), map[string]any{"fields": map[string]any{"duedate": d}}); err != nil {
			return err
		} else if code >= 300 {
			return fmt.Errorf("jira due date %s responded %d: %s", ref.Key, code, truncate(string(body), 200))
		}
	}
	j.comment(ctx, ref.Key, fmt.Sprintf("cloud-posture: Issue %s is observed again. Reopening; due %s.", req.Issue.ID, firstNonEmpty(dueDate(req.Issue), "—")))
	return nil
}

func jiraIssueADF(req TicketRequest) map[string]any {
	is := req.Issue
	content := []map[string]any{
		{"type": "heading", "attrs": map[string]any{"level": 2}, "content": []map[string]any{adfText(firstNonEmpty(is.Title, is.CanonicalID, is.RuleID))}},
		adfBullets(ticketFacts(req)),
	}
	if ev := evidenceLines(req); len(ev) > 0 {
		content = append(content, map[string]any{"type": "heading", "attrs": map[string]any{"level": 3}, "content": []map[string]any{adfText("Evidence")}}, adfBullets(ev))
	}
	cmd := "cloud-posture issues show " + is.ID
	if req.FixCommand != "" {
		cmd = req.FixCommand + "\n" + cmd
	}
	content = append(content, map[string]any{"type": "codeBlock", "attrs": map[string]any{"language": "bash"}, "content": []map[string]any{adfText(cmd)}})
	content = append(content, adfPara(adfText(IssueMarker(is.ID))))
	return map[string]any{"type": "doc", "version": 1, "content": content}
}

// ---------------------------------------------------------------- GitHub Issues

// githubAssignee maps an owner to a GitHub login: "@user" → "user"; teams (@org/team) and
// e-mail owners are not assignable ("").
func githubAssignee(owner string) string {
	owner = strings.TrimSpace(owner)
	if !strings.HasPrefix(owner, "@") || strings.Contains(owner, "/") {
		return ""
	}
	return strings.TrimPrefix(owner, "@")
}

// OpenTicket creates the Issue's GitHub issue (or returns the one carrying its marker),
// assigned to an @user owner, with owner and due date in the body (GitHub issues have no due
// date field).
func (g *GitHubIssues) OpenTicket(ctx context.Context, req TicketRequest) (TicketRef, error) {
	if g.Token == "" {
		return TicketRef{}, fmt.Errorf("GitHub token not configured (GITHUB_TOKEN)")
	}
	if g.Repo == "" || !strings.Contains(g.Repo, "/") {
		return TicketRef{}, fmt.Errorf("github repo must be owner/name")
	}
	is := req.Issue
	if u, found := g.findExisting(ctx, IssueMarker(is.ID)); found {
		return TicketRef{Key: issueNumber(u), URL: u}, nil
	}
	labels := append([]string{"security", "cloud-posture", "severity:" + strings.ToLower(string(is.Severity))}, g.Labels...)
	if is.Provider != "" {
		labels = append(labels, "provider:"+is.Provider)
	}
	payload := map[string]any{"title": ticketTitle(is, 200), "body": IssueTicketBody(req), "labels": labels}
	if a := githubAssignee(is.Owner); a != "" {
		payload["assignees"] = []string{a}
	}
	resp, code, err := postJSON(ctx, fmt.Sprintf("%s/repos/%s/issues", g.api(), g.Repo), g.headers(), payload)
	if err != nil {
		return TicketRef{}, err
	}
	if code >= 300 {
		return TicketRef{}, fmt.Errorf("github responded %d: %s", code, truncate(string(resp), 300))
	}
	var created struct {
		Number  int    `json:"number"`
		HTMLURL string `json:"html_url"`
	}
	_ = json.Unmarshal(resp, &created)
	key := issueNumber(created.HTMLURL)
	if created.Number > 0 {
		key = strconv.Itoa(created.Number)
	}
	return TicketRef{Key: key, URL: created.HTMLURL}, nil
}

func issueNumber(htmlURL string) string {
	if i := strings.LastIndex(htmlURL, "/issues/"); i >= 0 {
		return htmlURL[i+len("/issues/"):]
	}
	return ""
}

func (g *GitHubIssues) setState(ctx context.Context, ref TicketRef, state, reason, comment string) error {
	num := firstNonEmpty(ref.Key, issueNumber(ref.URL))
	if num == "" {
		return fmt.Errorf("github ticket without a number: %q", ref.URL)
	}
	u := fmt.Sprintf("%s/repos/%s/issues/%s", g.api(), g.Repo, num)
	if _, code, err := postJSON(ctx, u+"/comments", g.headers(), map[string]any{"body": comment}); err != nil {
		return err
	} else if code >= 300 {
		return fmt.Errorf("github comment responded %d", code)
	}
	body := map[string]any{"state": state}
	if reason != "" {
		body["state_reason"] = reason
	}
	_, code, err := doJSON(ctx, http.MethodPatch, u, g.headers(), body)
	if err != nil {
		return err
	}
	if code >= 300 {
		return fmt.Errorf("github %s issue: %d", state, code)
	}
	return nil
}

// CloseTicket comments and closes the issue as completed.
func (g *GitHubIssues) CloseTicket(ctx context.Context, ref TicketRef, req TicketRequest) error {
	return g.setState(ctx, ref, "closed", "completed", fmt.Sprintf("✅ cloud-posture: Issue `%s` is resolved (no active evidence). Closing.", req.Issue.ID))
}

// ReopenTicket comments with the new due date and reopens the issue.
func (g *GitHubIssues) ReopenTicket(ctx context.Context, ref TicketRef, req TicketRequest) error {
	return g.setState(ctx, ref, "open", "reopened", fmt.Sprintf("cloud-posture: Issue `%s` is observed again. Reopening; due %s.", req.Issue.ID, firstNonEmpty(dueDate(req.Issue), "—")))
}

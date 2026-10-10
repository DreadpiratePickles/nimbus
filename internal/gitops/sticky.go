package gitops

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
)

// Sticky comment markers. A sticky comment is found by its marker and edited (PATCH); a second
// comment is never posted while one exists.
const (
	ScanMarker     = "<!-- cloud-posture-sticky -->"
	PlanDiffMarker = "<!-- nimbus-plan-diff -->"
)

// StickyOptions addresses one pull request's sticky comment.
type StickyOptions struct {
	BaseURL   string       // default https://api.github.com
	HTTP      *http.Client // default http.DefaultClient
	OwnerRepo string
	PR        int
	Token     string // default $GITHUB_TOKEN
	Marker    string
	// BotLogin restricts editing to comments by that author, so a human comment that starts
	// with the marker is never overwritten. Empty means the token's own identity: GET /user once
	// (a personal or app-user token); when that is refused inside GitHub Actions (the
	// installation GITHUB_TOKEN cannot read /user) it is github-actions[bot]; otherwise the
	// call fails rather than edit a comment it cannot attribute.
	BotLogin string
	MaxPages int // default 50 (5,000 comments)
}

var ownerRepoRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9_.-]+$`)

// StickyComment creates or updates the comment carrying o.Marker; it returns "created" or "updated".
func StickyComment(ctx context.Context, o StickyOptions, body string) (string, error) {
	if !ownerRepoRe.MatchString(o.OwnerRepo) || strings.Contains(o.OwnerRepo, "..") || o.PR <= 0 {
		return "", fmt.Errorf("sticky comment: invalid repository %q or pull request %d", o.OwnerRepo, o.PR)
	}
	if o.Marker == "" {
		return "", fmt.Errorf("sticky comment: marker required")
	}
	if o.BaseURL == "" {
		o.BaseURL = "https://api.github.com"
	}
	if o.HTTP == nil {
		o.HTTP = http.DefaultClient
	}
	if o.Token == "" {
		o.Token = os.Getenv("GITHUB_TOKEN")
	}
	if o.MaxPages <= 0 {
		o.MaxPages = 50
	}
	base := strings.TrimRight(o.BaseURL, "/")
	full := o.Marker + "\n" + body
	do := func(method, u string, payload any) (*http.Response, error) {
		var rd io.Reader
		if payload != nil {
			b, _ := json.Marshal(payload)
			rd = bytes.NewReader(b)
		}
		req, err := http.NewRequestWithContext(ctx, method, u, rd)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+o.Token)
		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
		if payload != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		return o.HTTP.Do(req)
	}
	if o.BotLogin == "" {
		login, err := tokenLogin(do, base)
		if err != nil {
			return "", err
		}
		o.BotLogin = login
	}
	next := fmt.Sprintf("%s/repos/%s/issues/%d/comments?per_page=100", base, o.OwnerRepo, o.PR)
	for page := 0; next != "" && page < o.MaxPages; page++ {
		resp, err := do(http.MethodGet, next, nil)
		if err != nil {
			return "", err
		}
		var comments []struct {
			ID   int64  `json:"id"`
			Body string `json:"body"`
			User struct {
				Login string `json:"login"`
			} `json:"user"`
		}
		err = json.NewDecoder(io.LimitReader(resp.Body, 32<<20)).Decode(&comments)
		resp.Body.Close()
		if resp.StatusCode >= 300 {
			return "", &APIError{Op: "list comments", Status: resp.StatusCode}
		}
		if err != nil {
			return "", fmt.Errorf("list comments: %w", err)
		}
		for _, c := range comments {
			if !strings.HasPrefix(c.Body, o.Marker) || !strings.EqualFold(c.User.Login, o.BotLogin) {
				continue
			}
			r, err := do(http.MethodPatch, fmt.Sprintf("%s/repos/%s/issues/comments/%d", base, o.OwnerRepo, c.ID), map[string]string{"body": full})
			if err != nil {
				return "", err
			}
			r.Body.Close()
			if r.StatusCode >= 300 {
				return "", &APIError{Op: "update comment", Status: r.StatusCode}
			}
			return "updated", nil
		}
		next = nextLink(resp.Header.Get("Link"), base)
	}
	r, err := do(http.MethodPost, fmt.Sprintf("%s/repos/%s/issues/%d/comments", base, o.OwnerRepo, o.PR), map[string]string{"body": full})
	if err != nil {
		return "", err
	}
	r.Body.Close()
	if r.StatusCode >= 300 {
		return "", &APIError{Op: "create comment", Status: r.StatusCode}
	}
	return "created", nil
}

// APIError is a GitHub API refusal of a sticky-comment call. Permission reports that the token
// may not write (a fork pull request's read-only token): a warning, not a failure. Anything
// else (422 "body is too long", 5xx) means the comment was not posted and must fail the step.
type APIError struct {
	Op     string
	Status int
}

func (e *APIError) Error() string {
	if e.Permission() {
		return fmt.Sprintf("%s: GitHub API %d (a fork pull request's token cannot comment)", e.Op, e.Status)
	}
	return fmt.Sprintf("%s: GitHub API %d", e.Op, e.Status)
}

// Permission reports a 401/403/404: the token cannot write to this pull request.
func (e *APIError) Permission() bool {
	return e.Status == http.StatusUnauthorized || e.Status == http.StatusForbidden || e.Status == http.StatusNotFound
}

// actionsBotLogin is the author of comments made with GitHub Actions' GITHUB_TOKEN.
const actionsBotLogin = "github-actions[bot]"

// tokenLogin returns the login the token acts as (see StickyOptions.BotLogin).
func tokenLogin(do func(method, u string, payload any) (*http.Response, error), base string) (string, error) {
	resp, err := do(http.MethodGet, base+"/user", nil)
	if err != nil {
		return "", fmt.Errorf("sticky comment: token identity: %w", err)
	}
	var u struct {
		Login string `json:"login"`
	}
	derr := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&u)
	resp.Body.Close()
	if resp.StatusCode == http.StatusOK && derr == nil && u.Login != "" {
		return u.Login, nil
	}
	if os.Getenv("GITHUB_ACTIONS") == "true" && (resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusNotFound) {
		return actionsBotLogin, nil
	}
	return "", fmt.Errorf("sticky comment: cannot determine the token's identity (GitHub /user responded %d); pass --bot-login with the login that authors the comment", resp.StatusCode)
}

var linkNext = regexp.MustCompile(`<([^>]+)>;\s*rel="next"`)

// nextLink returns the rel="next" URL when it stays on the API host (never follow elsewhere).
func nextLink(h, base string) string {
	m := linkNext.FindStringSubmatch(h)
	if m == nil {
		return ""
	}
	u, err := url.Parse(m[1])
	b, err2 := url.Parse(base)
	if err != nil || err2 != nil || u.Host != b.Host || u.Scheme != b.Scheme {
		return ""
	}
	return m[1]
}

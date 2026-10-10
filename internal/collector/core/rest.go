package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// REST is a small JSON client for SaaS APIs (GitHub, Okta, Microsoft Graph) with
// retries on 429/5xx (honouring Retry-After) and Link / @odata.nextLink pagination.
type REST struct {
	BaseURL    string
	Client     *http.Client
	Headers    map[string]string
	MaxRetries int
	// Backoff is the base retry delay (default 1s); tests set it to ~0.
	Backoff time.Duration
}

// HTTPError is a non-2xx response.
type HTTPError struct {
	Status int
	URL    string
	Body   string
	// RateLimited marks a throttled response (429, or GitHub's 403 with
	// X-RateLimit-Remaining: 0 / "rate limit" body) that could not be retried in time.
	RateLimited bool
	// RateLimitReset is when the provider says the limit resets (zero if unknown).
	RateLimitReset time.Time
}

func (e *HTTPError) Error() string {
	msg := fmt.Sprintf("GET %s: HTTP %d: %s", e.URL, e.Status, strings.TrimSpace(e.Body))
	if e.RateLimited {
		msg = "rate limited: " + msg
		if !e.RateLimitReset.IsZero() {
			msg += " (resets " + e.RateLimitReset.UTC().Format(time.RFC3339) + ")"
		}
	}
	return msg
}

// IsRateLimited reports a throttled HTTP response that exhausted its retries.
func IsRateLimited(err error) bool {
	var he *HTTPError
	return errors.As(err, &he) && he.RateLimited
}

// maxRateLimitWait is the longest a single rate-limit pause may last before the
// call is surfaced as a rate_limited collection error instead.
const maxRateLimitWait = 60 * time.Second

// rateLimitWait detects a rate-limit response and returns how long to wait (and
// the reset time when known). ok is false for ordinary 403s.
func rateLimitWait(status int, h http.Header, body []byte) (wait time.Duration, reset time.Time, ok bool) {
	if status != http.StatusForbidden && status != http.StatusTooManyRequests {
		return 0, time.Time{}, false
	}
	limited := status == http.StatusTooManyRequests || h.Get("X-RateLimit-Remaining") == "0" ||
		strings.Contains(strings.ToLower(string(body)), "rate limit")
	if !limited {
		return 0, time.Time{}, false
	}
	if ra := retryAfter(h); ra > 0 || h.Get("Retry-After") != "" {
		return ra, time.Now().Add(ra), true
	}
	if v := h.Get("X-RateLimit-Reset"); v != "" {
		if sec, err := strconv.ParseInt(v, 10, 64); err == nil {
			reset = time.Unix(sec, 0)
			return time.Until(reset), reset, true
		}
	}
	return 0, time.Time{}, true
}

// StatusOf returns the HTTP status of an *HTTPError (0 otherwise).
func StatusOf(err error) int {
	var he *HTTPError
	if errors.As(err, &he) {
		return he.Status
	}
	return 0
}

func (c *REST) resolve(p string) string {
	if strings.HasPrefix(p, "http://") || strings.HasPrefix(p, "https://") {
		return p
	}
	return strings.TrimRight(c.BaseURL, "/") + "/" + strings.TrimLeft(p, "/")
}

// sameOrigin reports whether u has the scheme, host and port of BaseURL (an empty
// BaseURL trusts every URL it is given explicitly).
func (c *REST) sameOrigin(u string) bool {
	if c.BaseURL == "" {
		return true
	}
	b, err1 := url.Parse(c.BaseURL)
	t, err2 := url.Parse(u)
	if err1 != nil || err2 != nil {
		return false
	}
	return strings.EqualFold(b.Scheme, t.Scheme) && strings.EqualFold(b.Host, t.Host)
}

// ErrInsecureRedirect is returned when a server redirects an https request to a
// non-https URL; the redirect is never followed.
var ErrInsecureRedirect = errors.New("refused redirect from https to a non-https URL")

// sameHostPort reports whether a and b share scheme, host and port (case-insensitive).
func sameHostPort(a, b *url.URL) bool {
	return strings.EqualFold(a.Scheme, b.Scheme) && strings.EqualFold(a.Host, b.Host)
}

// redirectSafeClient returns a shallow copy of client whose CheckRedirect refuses an
// https→http downgrade and strips Authorization, Cookie and every configured header
// (they carry credentials: API keys, SSWS / Bearer tokens) from any hop whose scheme,
// host or port differs from the original request. net/http copies the original
// request's headers onto each hop before CheckRedirect runs, so deleting them here
// keeps them off the wire. The caller's CheckRedirect (if any) still runs afterwards.
func (c *REST) redirectSafeClient(client *http.Client) *http.Client {
	cp := *client
	inner := client.CheckRedirect
	cp.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return errors.New("stopped after 10 redirects")
		}
		orig := via[0].URL
		for _, prev := range via {
			if strings.EqualFold(prev.URL.Scheme, "https") && !strings.EqualFold(req.URL.Scheme, "https") {
				return fmt.Errorf("%w: %s → %s", ErrInsecureRedirect, prev.URL.Redacted(), req.URL.Redacted())
			}
		}
		if !sameHostPort(orig, req.URL) {
			req.Header.Del("Authorization")
			req.Header.Del("Cookie")
			req.Header.Del("Proxy-Authorization")
			for k := range c.Headers {
				req.Header.Del(k)
			}
		}
		if inner != nil {
			return inner(req, via)
		}
		return nil
	}
	return &cp
}

// Get fetches pathOrURL and decodes JSON into out (when non-nil); it returns response headers.
func (c *REST) Get(ctx context.Context, pathOrURL string, out any) (http.Header, error) {
	u := c.resolve(pathOrURL)
	client := c.Client
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	client = c.redirectSafeClient(client)
	retries := c.MaxRetries
	if retries == 0 {
		retries = 4
	}
	backoff := c.Backoff
	if backoff == 0 {
		backoff = time.Second
	}
	var lastErr error
	for attempt := 0; attempt <= retries; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", "cloud-posture/0.1")
		if c.sameOrigin(u) {
			// Configured headers carry credentials (Authorization, API keys): never
			// send them to another host a pagination link points at.
			for k, v := range c.Headers {
				req.Header.Set(k, v)
			}
		}
		resp, err := client.Do(req)
		if err != nil {
			if errors.Is(err, ErrInsecureRedirect) {
				return nil, err // not transient: never retried
			}
			lastErr = err
		} else {
			body, rerr := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
			resp.Body.Close()
			switch {
			case rerr != nil:
				lastErr = rerr
			case resp.StatusCode >= 200 && resp.StatusCode < 300:
				if out != nil && len(body) > 0 {
					if err := json.Unmarshal(body, out); err != nil {
						return resp.Header, fmt.Errorf("decode %s: %w", u, err)
					}
				}
				return resp.Header, nil
			case resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests:
				wait, reset, limited := rateLimitWait(resp.StatusCode, resp.Header, body)
				if !limited {
					return resp.Header, &HTTPError{Status: resp.StatusCode, URL: u, Body: truncateStr(string(body), 300)}
				}
				he := &HTTPError{Status: resp.StatusCode, URL: u, Body: truncateStr(string(body), 300), RateLimited: true, RateLimitReset: reset}
				if wait > maxRateLimitWait || attempt >= retries {
					// Surface as a rate_limited collection error instead of sleeping for an hour.
					return resp.Header, he
				}
				lastErr = he
				if wait > 0 {
					if err := sleepCtx(ctx, wait); err != nil {
						return nil, err
					}
					continue
				}
			case resp.StatusCode >= 500:
				lastErr = &HTTPError{Status: resp.StatusCode, URL: u, Body: truncateStr(string(body), 300)}
				if ra := retryAfter(resp.Header); ra > 0 {
					if err := sleepCtx(ctx, min(ra, 60*time.Second)); err != nil {
						return nil, err
					}
					continue
				}
			default:
				return resp.Header, &HTTPError{Status: resp.StatusCode, URL: u, Body: truncateStr(string(body), 300)}
			}
		}
		if attempt < retries {
			if err := sleepCtx(ctx, backoff*time.Duration(1<<attempt)); err != nil {
				return nil, err
			}
		}
	}
	return nil, lastErr
}

// GetAll walks every page starting at pathOrURL. A page is either a JSON array or an
// object holding the items under "value" (Microsoft Graph) / "items"; the next page
// comes from the Link header (GitHub, Okta) or "@odata.nextLink".
// A repeated next link, or more than maxPages pages, stops the walk with an error (a silent
// stop would report a truncated listing as complete).
func (c *REST) GetAll(ctx context.Context, pathOrURL string, each func(item json.RawMessage) error) error {
	next := pathOrURL
	seen := map[string]bool{}
	for pages := 0; next != ""; pages++ {
		if pages >= maxPages {
			return fmt.Errorf("pagination stopped after %d pages at %s", maxPages, redactQuery(next))
		}
		key := c.resolve(next)
		if seen[key] {
			return fmt.Errorf("pagination stopped: the server repeated the next-page link %s", redactQuery(next))
		}
		seen[key] = true
		var raw json.RawMessage
		h, err := c.Get(ctx, next, &raw)
		if err != nil {
			return err
		}
		items, odataNext, err := splitPage(raw)
		if err != nil {
			return err
		}
		for _, it := range items {
			if err := each(it); err != nil {
				return err
			}
		}
		next = NextLink(h)
		if next == "" {
			next = odataNext
		}
	}
	return nil
}

// maxPages bounds one GetAll walk.
const maxPages = 10000

// redactQuery drops the query string (page cursors may embed tokens) from a URL for an error.
func redactQuery(u string) string {
	if i := strings.IndexAny(u, "?#"); i >= 0 {
		return u[:i] + "?…"
	}
	return u
}

func splitPage(raw json.RawMessage) ([]json.RawMessage, string, error) {
	t := strings.TrimSpace(string(raw))
	if t == "" || t == "null" {
		return nil, "", nil
	}
	if strings.HasPrefix(t, "[") {
		var items []json.RawMessage
		return items, "", json.Unmarshal(raw, &items)
	}
	var obj struct {
		Value    []json.RawMessage `json:"value"`
		Items    []json.RawMessage `json:"items"`
		NextLink string            `json:"@odata.nextLink"`
	}
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, "", err
	}
	if obj.Value != nil {
		return obj.Value, obj.NextLink, nil
	}
	return obj.Items, obj.NextLink, nil
}

var linkNextRE = regexp.MustCompile(`<([^>]+)>\s*;\s*rel="?next"?`)

// NextLink extracts rel="next" from an RFC 8288 Link header.
func NextLink(h http.Header) string {
	for _, l := range h.Values("Link") {
		for _, part := range strings.Split(l, ",") {
			if m := linkNextRE.FindStringSubmatch(part); m != nil {
				if _, err := url.Parse(m[1]); err == nil {
					return m[1]
				}
			}
		}
	}
	return ""
}

func retryAfter(h http.Header) time.Duration {
	v := h.Get("Retry-After")
	if v == "" {
		return 0
	}
	if s, err := strconv.Atoi(v); err == nil {
		return time.Duration(s) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		return time.Until(t)
	}
	return 0
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

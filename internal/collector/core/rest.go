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
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("GET %s: HTTP %d: %s", e.URL, e.Status, strings.TrimSpace(e.Body))
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

// Get fetches pathOrURL and decodes JSON into out (when non-nil); it returns response headers.
func (c *REST) Get(ctx context.Context, pathOrURL string, out any) (http.Header, error) {
	u := c.resolve(pathOrURL)
	client := c.Client
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
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
		for k, v := range c.Headers {
			req.Header.Set(k, v)
		}
		resp, err := client.Do(req)
		if err != nil {
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
			case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
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
func (c *REST) GetAll(ctx context.Context, pathOrURL string, each func(item json.RawMessage) error) error {
	next := pathOrURL
	for pages := 0; next != "" && pages < 10000; pages++ {
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

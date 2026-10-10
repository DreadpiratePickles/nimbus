package integrations

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
)

// redactURL keeps only scheme://host: webhook URLs (Slack, Teams, generic) carry their
// credential in the path or query, so neither may appear in errors or logs.
func redactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "<redacted-url>"
	}
	return u.Scheme + "://" + u.Host
}

// redactErr rewrites the URL inside *url.Error (net/http's error for both request
// construction and transport failures) to scheme://host.
func redactErr(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		ue.URL = redactURL(ue.URL)
	}
	return err
}

// redactingClient is http.Client.Do with redacted errors; every sink uses it via httpClient.
type redactingClient struct{ c *http.Client }

// Do validates the URL against the outbound policy (sinkurl.go) before anything is sent.
func (r *redactingClient) Do(req *http.Request) (*http.Response, error) {
	if err := validateURL(req.URL); err != nil {
		return nil, err
	}
	resp, err := r.c.Do(req)
	return resp, redactErr(err)
}

// newRequest is http.NewRequestWithContext with redacted URL-parse errors.
func newRequest(ctx context.Context, method, rawURL string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, rawURL, body)
	return req, redactErr(err)
}

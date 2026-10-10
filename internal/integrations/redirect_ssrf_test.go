package integrations

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// Verify-4 defect 4 (scratchpad/verify-4/tree-sec/internal/integrations/zz_verify4_redirect_test.go):
// sink credentials must not follow a redirect to another origin or over a downgrade, and sink
// URLs must not reach link-local / metadata / private addresses.

var sinkSecrets = []string{"DDSECRET", "HDRSECRET", "JIRASECRET", "GHSECRET", "SECRETPATH", "SPLUNKSECRET"}

type catcher struct {
	mu  sync.Mutex
	got []string
}

func (c *catcher) srv() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		c.mu.Lock()
		// Headers and body only: the redirecting server chose the target URL itself (it already
		// held the webhook path), so the URL is not something the client leaked.
		c.got = append(c.got, fmt.Sprintf("%s %v body=%s", r.Method, r.Header, b))
		c.mu.Unlock()
		w.WriteHeader(200)
		io.WriteString(w, `[]`)
	}))
}

func (c *catcher) leaked() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []string
	for _, g := range c.got {
		for _, s := range sinkSecrets {
			if strings.Contains(g, s) {
				out = append(out, s+" in "+g)
			}
		}
	}
	return out
}

func redirector(target string, tlsSrv bool) *httptest.Server {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target+r.URL.RequestURI(), http.StatusTemporaryRedirect)
	})
	if tlsSrv {
		return httptest.NewTLSServer(h)
	}
	return httptest.NewServer(h)
}

func sinkCases(ctx context.Context) []struct {
	name string
	run  func(base string) error
} {
	f := model.Finding{ID: "f1", Title: "t", Severity: model.High, CanonicalID: "X"}
	is := model.Issue{ID: "i1", Title: "issue", Severity: model.High}
	return []struct {
		name string
		run  func(base string) error
	}{
		{"datadog", func(b string) error {
			_, err := (&Datadog{APIKey: "DDSECRET", LogsURL: b + "/api/v2/logs", EventsURL: b + "/api/v1/events"}).Deliver(ctx, f, nil)
			return err
		}},
		{"webhook-custom-header", func(b string) error {
			_, err := (&SIEM{Type: "webhook", URL: b + "/hook", Headers: map[string]string{"X-Api-Key": "HDRSECRET"}}).Deliver(ctx, f, nil)
			return err
		}},
		{"splunk", func(b string) error {
			_, err := (&SIEM{Type: "splunk_hec", URL: b, Token: "SPLUNKSECRET"}).Deliver(ctx, f, nil)
			return err
		}},
		{"jira-ticket", func(b string) error {
			_, err := NewJira(b, "a@b.c", "JIRASECRET", "SEC", "").OpenTicket(ctx, TicketRequest{Issue: is})
			return err
		}},
		{"github-ticket", func(b string) error {
			_, err := (&GitHubIssues{Repo: "o/r", Token: "GHSECRET", APIBase: b}).OpenTicket(ctx, TicketRequest{Issue: is})
			return err
		}},
		{"slack-digest", func(b string) error {
			return SlackDigestSender(b+"/services/T/B/SECRETPATH", "")(ctx, Digest{Key: "k"})
		}},
	}
}

func TestSinkCredentialsNeverFollowCrossOriginRedirect(t *testing.T) {
	ctx := context.Background()
	for _, c := range sinkCases(ctx) {
		ev := &catcher{}
		es := ev.srv()
		// 127.0.0.1 -> localhost: another host (and port)
		rd := redirector(strings.Replace(es.URL, "127.0.0.1", "localhost", 1), false)
		_ = c.run(rd.URL)
		if l := ev.leaked(); len(l) > 0 {
			t.Errorf("%s: cross-origin redirect carried credentials: %v", c.name, l)
		}
		rd.Close()
		es.Close()
	}
}

func TestSinkRefusesHTTPSToHTTPRedirect(t *testing.T) {
	ctx := context.Background()
	for _, c := range sinkCases(ctx) {
		ev := &catcher{}
		es := ev.srv()
		rd := redirector(es.URL, true)
		old := httpClient.c.Transport
		httpClient.c.Transport = rd.Client().Transport
		err := c.run(rd.URL)
		httpClient.c.Transport = old
		ev.mu.Lock()
		n := len(ev.got)
		ev.mu.Unlock()
		if n > 0 {
			t.Errorf("%s: https->http downgrade was followed (%d plain-text requests): %v", c.name, n, ev.leaked())
		}
		if err == nil && c.name != "slack-digest" {
			t.Errorf("%s: downgrade not reported as an error", c.name)
		}
		rd.Close()
		es.Close()
	}
}

func TestSinkURLValidation(t *testing.T) {
	ctx := context.Background()
	f := model.Finding{ID: "f1", Title: "t", Severity: model.High}
	refused := []string{
		"http://169.254.169.254/latest/meta-data/",
		"https://169.254.169.254/latest/meta-data/",
		"http://[fd00:ec2::254]/latest/meta-data/",
		"https://[fe80::1]/x",
		"https://10.0.0.5/hook",
		"https://192.168.1.10/hook",
		"https://172.16.0.1/hook",
		"https://[fd12:3456::1]/hook",
		"https://0.0.0.0/hook",
		"http://example.com/hook", // plain http off loopback
		"file:///etc/passwd",
		"gopher://127.0.0.1:25/",
		"ftp://example.com/x",
		"https://user:pw@[::ffff:169.254.169.254]/x",
	}
	for _, u := range refused {
		_, err := (&SIEM{Type: "webhook", URL: u}).Deliver(ctx, f, nil)
		if err == nil {
			t.Errorf("sink URL %s accepted", u)
		}
		pu, _ := url.Parse(u)
		if pu != nil && ValidateSinkURL(u) == nil {
			t.Errorf("ValidateSinkURL(%s) = nil", u)
		}
	}
	for _, u := range []string{"https://hooks.slack.com/services/x", "http://127.0.0.1:8080/hook", "http://localhost:9/x", "http://[::1]:9/x", "https://example.com/x"} {
		if err := ValidateSinkURL(u); err != nil {
			t.Errorf("ValidateSinkURL(%s) = %v, want allowed", u, err)
		}
	}
	// private ranges are allowed only with the explicit opt-in; link-local/metadata never
	SetAllowPrivateSinks(true)
	defer SetAllowPrivateSinks(false)
	if err := ValidateSinkURL("https://10.0.0.5/hook"); err != nil {
		t.Errorf("private sink refused with --allow-private-sinks: %v", err)
	}
	for _, u := range []string{"http://169.254.169.254/", "https://[fd00:ec2::254]/", "http://10.0.0.5/hook"} {
		if ValidateSinkURL(u) == nil {
			t.Errorf("%s accepted even with --allow-private-sinks", u)
		}
	}
}

// A hostname that resolves to a forbidden address is refused at connect time (DNS rebinding).
func TestSinkDialRefusesForbiddenResolvedIP(t *testing.T) {
	for _, addr := range []string{"169.254.169.254:80", "[fd00:ec2::254]:80", "10.1.2.3:443", "[fe80::1]:443"} {
		if err := checkDialAddr(addr); err == nil {
			t.Errorf("dial to %s allowed", addr)
		}
	}
	for _, addr := range []string{"127.0.0.1:443", "[::1]:80", "93.184.216.34:443"} {
		if err := checkDialAddr(addr); err != nil {
			t.Errorf("dial to %s refused: %v", addr, err)
		}
	}
}

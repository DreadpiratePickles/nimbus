package cli

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/integrations"
)

// W7-VERIFY r5 #9: `issues export --to vanta` builds one flat custom resource per evaluated cloud
// resource and sends them in one full-state PUT; --dry-run sends nothing and names what Vanta
// would delete against the last sync; --recipe prints the custom test.
func TestIssuesExportVanta(t *testing.T) {
	labDB(t)
	var mu sync.Mutex
	puts := 0
	var last map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		b, _ := io.ReadAll(r.Body)
		if r.URL.Path == "/oauth/token" {
			w.Write([]byte(`{"access_token":"t"}`))
			return
		}
		puts++
		json.Unmarshal(b, &last)
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	integrations.SetAllowPrivateSinks(true)
	defer integrations.SetAllowPrivateSinks(false)
	t.Setenv("VANTA_BASE_URL", srv.URL)
	t.Setenv("VANTA_CLIENT_ID", "cid")
	t.Setenv("VANTA_CLIENT_SECRET", "s3cret")
	t.Setenv("VANTA_RESOURCE_ID", "rt")

	out := run(t, "issues", "export", "--to", "vanta", "--dry-run")
	if puts != 0 || !strings.Contains(out, "dry run: would send") || !strings.Contains(out, "would delete 0") {
		t.Fatalf("dry run (puts %d):\n%s", puts, out)
	}
	out = run(t, "issues", "export", "--to", "vanta", "--url", "https://nimbus.example.com")
	if puts != 1 || !strings.Contains(out, "Vanta synced") || strings.Contains(out, "s3cret") {
		t.Fatalf("sync (puts %d):\n%s", puts, out)
	}
	rs := last["resources"].([]any)
	if len(rs) < 10 {
		t.Fatalf("lab sync sent %d resources", len(rs))
	}
	// The next dry run diffs against the stored set: nothing new, nothing deleted.
	out = run(t, "issues", "export", "--to", "vanta", "--dry-run")
	if !strings.Contains(out, "0 new") || !strings.Contains(out, "would delete 0") {
		t.Errorf("second dry run:\n%s", out)
	}
	if out := run(t, "issues", "export", "--to", "vanta", "--recipe"); !strings.Contains(out, "nimbus_pass") {
		t.Errorf("recipe:\n%s", out)
	}
}

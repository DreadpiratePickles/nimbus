package cli

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/config"
	"github.com/DreadpiratePickles/nimbus/internal/governance"
	"github.com/DreadpiratePickles/nimbus/internal/graph"
	"github.com/DreadpiratePickles/nimbus/internal/store"
)

// W5-ISSUES item 3 (r3 #5 / E11 / E20), tightened by W6-POLISH (r4 #5): `governance init`
// proposes owners from the owner/team tags already in the estate, but never on a tie or from
// less than governance.defaults.min_owner_share (default 50%) of the tagged resources. On the lab
// "finance" tags 2 of 14 resources, so nothing becomes the default owner and finance never owns
// the Kubernetes, GitHub or Okta Issues; --write applies the block at once, and doctor and
// `issues metrics` report the Issues assigned by default separately.
func TestGovernanceInitProposesDefaultAndAccountOwners(t *testing.T) {
	dir := t.TempDir()
	flagDB = filepath.Join(dir, "p.db")
	flagQuiet = true
	t.Setenv("CLOUD_POSTURE_PYTHON", "/nonexistent/python")
	cfgPath := filepath.Join(dir, "cloud-posture.yaml")
	os.WriteFile(cfgPath, []byte("# lab\n"), 0o644)
	t.Cleanup(func() { flagConfig = "" })
	run(t, "-c", cfgPath, "ingest", labFile(t, "estate.findings.json"), "-o", "summary")
	out := run(t, "-c", cfgPath, "governance", "init", "--repo", dir)
	for _, bad := range []string{"owner: finance", "aws/111111111111: finance", "proposed defaults.owner \""} {
		if strings.Contains(out, bad) {
			t.Errorf("r4 #5: governance init must not propose %q from 2 of 14 tagged resources:\n%s", bad, out)
		}
	}
	for _, want := range []string{"no proposed defaults.owner", "below the 50% min_owner_share", "would assign"} {
		if !strings.Contains(out, want) {
			t.Errorf("governance init lacks %q:\n%s", want, out)
		}
	}
	run(t, "-c", cfgPath, "governance", "init", "--repo", dir, "--write")
	cfg, err := config.Load(cfgPath)
	if err != nil || cfg.Governance.Defaults.Owner != "" {
		t.Fatalf("written config: %v %+v", err, cfg.Governance.Defaults)
	}
	st := openTestStore(t)
	all, err := st.Issues(store.IssueFilter{OpenOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	byDefault := 0
	for _, is := range all {
		if is.OwnerSource == governance.SourceDefault {
			byDefault++
		}
		switch is.Provider {
		case "kubernetes", "github", "okta", "gcp":
			if is.Owner == "finance" {
				t.Errorf("r4 #5: %s Issue %s (%s) owned by finance (%s: %s)", is.Provider, is.ID, is.Title, is.OwnerSource, is.OwnerWhy)
			}
		}
	}
	doc := run(t, "-c", cfgPath, "doctor")
	if !strings.Contains(doc, "assigned by default: "+strconv.Itoa(byDefault)) {
		t.Errorf("doctor must report the Issues assigned by default (%d):\n%s", byDefault, doc)
	}
	if !strings.Contains(doc, "are unassigned") {
		t.Errorf("doctor must still warn: most lab Issues have no tag-backed owner:\n%s", doc)
	}
	met := run(t, "-c", cfgPath, "issues", "metrics")
	if !strings.Contains(met, "assigned by default: "+strconv.Itoa(byDefault)) {
		t.Errorf("issues metrics must report the Issues assigned by default (%d):\n%s", byDefault, met)
	}
}

// A clear majority still becomes the default and is reported as assigned by default.
func TestGovernanceInitMajorityDefaultReportedAsDefault(t *testing.T) {
	g := graph.New()
	for i, o := range []string{"platform", "platform", "platform", "web"} {
		g.AddNode(&graph.Node{ID: fmt.Sprintf("arn:aws:s3:::b%d", i), Type: "aws_s3_bucket", Provider: "aws", Account: "111",
			Attributes: map[string]any{"tags": map[string]any{"owner": o}}})
	}
	g.AddNode(&graph.Node{ID: "gh-repo", Type: "github_repository", Provider: "github", Account: "org"})
	p := proposeOwners(&config.Config{}, nil, g)
	if p.Default != "platform" || p.Accounts["aws/111"] != "platform" {
		t.Fatalf("3 of 4 → platform: %+v", p)
	}
	if _, ok := p.Providers["github"]; ok {
		t.Errorf("no provider owner where the provider has no tags: %+v", p.Providers)
	}
	// Tie → nothing.
	g2 := graph.New()
	for i, o := range []string{"a", "b"} {
		g2.AddNode(&graph.Node{ID: fmt.Sprintf("n%d", i), Type: "aws_s3_bucket", Provider: "aws", Account: "1", Attributes: map[string]any{"tags": map[string]any{"owner": o}}})
	}
	if p := proposeOwners(&config.Config{}, nil, g2); p.Default != "" || len(p.Accounts) != 0 {
		t.Errorf("tie must propose nothing: %+v", p)
	}
	// The share is configurable: 3 of 4 is below 0.8.
	share := 0.8
	c := &config.Config{Governance: config.Governance{Defaults: config.GovernanceDefaults{MinOwnerShare: &share}}}
	if p := proposeOwners(c, nil, g); p.Default != "" || !strings.Contains(p.DefaultWhy, "80%") {
		t.Errorf("min_owner_share 0.8: %+v", p)
	}
}

// Unassigned Issues still reach a person: governance.digest.unassigned_sink receives the
// "(unassigned)" digest; the owner digests go to the main sink.
func TestDigestUnassignedGoesToFallbackSink(t *testing.T) {
	fake := &slackFake{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b := make([]byte, 1<<20)
		n, _ := r.Body.Read(b)
		fake.mu.Lock()
		fake.posts = append(fake.posts, string(b[:n]))
		fake.mu.Unlock()
		w.Write([]byte("ok"))
	}))
	defer srv.Close()
	t.Setenv("NIMBUS_TEST_SLACK", srv.URL+"/hook")
	dir := t.TempDir()
	flagDB = filepath.Join(dir, "p.db")
	flagQuiet = true
	t.Setenv("CLOUD_POSTURE_PYTHON", "/nonexistent/python")
	cfgPath := filepath.Join(dir, "cfg.yaml")
	os.WriteFile(cfgPath, []byte("governance:\n  digest:\n    sink: slack\n    unassigned_sink: stdout\nintegrations:\n  slack:\n    url_env: NIMBUS_TEST_SLACK\n"), 0o644)
	t.Cleanup(func() { flagConfig = "" })
	run(t, "-c", cfgPath, "ingest", labFile(t, "estate.findings.json"), "-o", "summary")
	out := run(t, "-c", cfgPath, "alert", "--digest", "--since", "720h")
	if !strings.Contains(out, "Governance digest for (unassigned)") {
		t.Fatalf("the unassigned digest did not go to stdout:\n%s", out)
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if len(fake.posts) == 0 {
		t.Fatalf("owner digests not sent to slack:\n%s", out)
	}
	for _, p := range fake.posts {
		if strings.Contains(p, "(unassigned)") {
			t.Errorf("unassigned digest went to the main sink")
		}
	}
}

package cli

import (
	"database/sql"
	"strings"
	"testing"
	"time"
)

// Verification 6 (routed item 8): an Issue id from before the keyed-id migration resolves in
// `issues show`, `issues suppress` and `issues history` exactly as in `verify` and the API.
func TestIssuesCommandsResolveOldIDs(t *testing.T) {
	cfg := w6IngestLab(t)
	path := storedPathIssues(t)[0]
	const old = "0123456789abcdef0123456789abcdef"
	raw, err := sql.Open("sqlite", flagDB)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec("INSERT INTO issue_id_map (old_id, new_id) VALUES (?, ?)", old, path.ID); err != nil {
		t.Fatal(err)
	}
	raw.Close()

	show, err := runErr(t, "-c", cfg, "issues", "show", old)
	if err != nil || !strings.Contains(show, path.ID) {
		t.Errorf("issues show <old id>: %v\n%.600s", err, show)
	}
	hist, err := runErr(t, "-c", cfg, "issues", "history", old)
	if err != nil || strings.Contains(hist, "No Issue-level history") || !strings.Contains(hist, "open") {
		t.Errorf("issues history <old id> must print the path Issue's transitions: %v\n%s", err, hist)
	}
	exp := time.Now().Add(48 * time.Hour).UTC().Format("2006-01-02")
	sup, err := runErr(t, "-c", cfg, "issues", "suppress", old, "--reason", "accepted for the test", "--expires", exp)
	if err != nil || !strings.Contains(sup, "suppressed "+path.ID) {
		t.Errorf("issues suppress <old id>: %v\n%s", err, sup)
	}
}

package cli

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/store"
)

// W7-VERIFY r5 #6: MCP `verify` with from_file runs the CLI's own verify engine (one read, no
// window) over the lab and reports the same outcome `verify --from-file --attempts 1` would —
// the surviving Lambda hop for a bucket-only fix, verified-fixed when both are fixed — while the
// database stays byte-identical (no verification row, no state change).
func TestMCPVerifyFromFileUsesTheVerifyEngine(t *testing.T) {
	dir := labDB(t)
	p01 := p01Issue(t)
	fs := labCopy(t)
	labFinding(fs, "lab-W01")["status"] = "PASS"
	bucketOnly := writeFindings(t, dir, "bucket-fixed.json", fs)
	fs = labCopy(t)
	labFinding(fs, "lab-W01")["status"] = "PASS"
	labFinding(fs, "lab-W12")["status"] = "PASS"
	both := writeFindings(t, dir, "both-fixed.json", fs)
	outside := writeFindings(t, t.TempDir(), "outside.json", fs)

	before := issueRows(t)
	st := openTestStore(t)
	vsBefore, _ := st.Verifications(p01)
	st.Close()

	call := func(id int, file string) string {
		args, _ := json.Marshal(map[string]any{"issue_id": p01, "from_file": file})
		return `{"jsonrpc":"2.0","id":` + string(rune('0'+id)) + `,"method":"tools/call","params":{"name":"verify","arguments":` + string(args) + `}}`
	}
	frames := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		call(2, bucketOnly), call(3, both), call(4, outside),
	}, "\n") + "\n"
	mcpStdin = strings.NewReader(frames)
	t.Cleanup(func() { mcpStdin = nil })
	out := run(t, "mcp", "--no-redact", "--audit", filepath.Join(dir, "audit.jsonl"))
	res := map[int]string{}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		var m struct {
			ID     int             `json:"id"`
			Result json.RawMessage `json:"result"`
		}
		if json.Unmarshal([]byte(line), &m) == nil {
			res[m.ID] = string(m.Result)
		}
	}
	if r := res[2]; !strings.Contains(r, `\"result\":\"open\"`) || !strings.Contains(r, "nimbus-lab-export") || !strings.Contains(r, `\"recorded\":false`) {
		t.Errorf("bucket-only fix: want open naming the Lambda hop, unrecorded:\n%s", r)
	}
	if r := res[3]; !strings.Contains(r, `\"result\":\"`+store.VerifyFixed+`\"`) {
		t.Errorf("bucket + Lambda fixed: want %s:\n%s", store.VerifyFixed, r)
	}
	if r := res[4]; !strings.Contains(r, "outside the server's file roots") {
		t.Errorf("a file outside the roots must be refused:\n%s", r)
	}
	after := issueRows(t)
	for id, row := range before {
		if after[id] != row {
			t.Errorf("from_file changed Issue %s: %s → %s", id, row, after[id])
		}
	}
	st = openTestStore(t)
	if vs, _ := st.Verifications(p01); len(vs) != len(vsBefore) {
		t.Errorf("from_file recorded a verification (%d → %d)", len(vsBefore), len(vs))
	}
}

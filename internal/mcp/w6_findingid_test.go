package mcp

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// Verification 6 (probe zz_verify6_fporacle2.py): the sql tool returned the raw finding
// fingerprint next to the redacted account; hashing a million candidate accounts recovered the
// account in 0.7 s. Finding ids leave MCP keyed per database (store/extid.go); the probe's
// dictionary attack must recover nothing, and a raw fingerprint is no lookup oracle either.

func fpOf(src, chk, prov, acct, region, res string) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{src, chk, prov, acct, region, res, ""}, "|")))
	return hex.EncodeToString(sum[:16])
}

func TestFindingIDDictionaryAttackRecoversNothing(t *testing.T) {
	fx := newFixture(t)
	h := fx.hostiles[0]
	for _, opts := range []Options{{Scopes: []string{"all"}}, {Scopes: []string{"all"}, NoRedact: true}} {
		c := startServer(t, fx.st, opts)
		c.initialize()
		out := c.toolOK("sql", map[string]any{"query": "SELECT id, source, check_id, provider, region, resource_id FROM findings WHERE check_id = 'hostile_0'"})
		rows, _ := out["rows"].([]any)
		if len(rows) != 1 {
			t.Fatalf("rows = %v", out["rows"])
		}
		row := rows[0].([]any)
		fid := row[0].(string)
		if fid == h.ID {
			t.Errorf("no-redact=%v: the sql tool returned the raw fingerprint", opts.NoRedact)
		}
		// The probe: the account is the only unknown; brute a window around it.
		base := 222233334444
		for a := base - 500000; a < base+500000; a++ {
			if fpOf(h.Source, h.CheckID, h.Provider, fmt.Sprint(a), h.Region, h.Resource.ID) == fid {
				t.Fatalf("no-redact=%v: account %d recovered from the finding id", opts.NoRedact, a)
			}
		}
		if opts.NoRedact {
			continue
		}
		// No SQL oracle on the raw id: equality, prefix and LIKE see the keyed column.
		for _, q := range []string{
			"SELECT count(*) FROM findings WHERE id = '" + h.ID + "'",
			"SELECT count(*) FROM findings WHERE substr(id, 1, 8) = '" + h.ID[:8] + "'",
			"SELECT count(*) FROM issues WHERE finding_ids LIKE '%" + h.ID + "%'",
		} {
			o := c.toolOK("sql", map[string]any{"query": q})
			if n := o["rows"].([]any)[0].([]any)[0]; fmt.Sprint(n) != "0" {
				t.Errorf("%s = %v: the raw id is an oracle", q, n)
			}
		}
		// No tool output carries a raw digest id.
		all := map[string]any{}
		for _, name := range []string{"paths", "prioritize"} {
			all[name] = c.toolOK(name, map[string]any{"limit": 200})
		}
		all["summary"] = c.toolOK("summary", map[string]any{})
		b, _ := json.Marshal(all)
		if strings.Contains(string(b), h.ID) {
			t.Errorf("a tool output carries the raw fingerprint")
		}
		for _, p := range fx.an.Paths {
			if strings.Contains(string(b), `"`+p.ID+`"`) {
				t.Errorf("a tool output carries the raw path id %s", p.ID)
				break
			}
		}
		// The keyed id works inbound; the raw one answers exactly like an unknown id.
		if e := c.toolOK("explain", map[string]any{"id": fid}); e == nil {
			t.Errorf("explain by external id failed")
		}
		trRaw, _ := c.tool("explain", map[string]any{"id": h.ID})
		trUnknown, _ := c.tool("explain", map[string]any{"id": "0123456789abcdef0123456789abcdef"})
		if !trRaw.IsError || !trUnknown.IsError {
			t.Fatalf("raw id accepted (error %v) or unknown id accepted (%v)", trRaw.IsError, trUnknown.IsError)
		}
		norm := func(tr toolResult) string {
			return strings.NewReplacer(h.ID, "X", "0123456789abcdef0123456789abcdef", "X").Replace(tr.Content[0].Text)
		}
		if norm(trRaw) != norm(trUnknown) {
			t.Errorf("raw id and unknown id answer differently:\n%s\n%s", norm(trRaw), norm(trUnknown))
		}
		if d := c.toolOK("draft_fix", map[string]any{"finding_id": fid}); d["finding_id"] != fid {
			t.Errorf("draft_fix echoes %v, want the external id", d["finding_id"])
		}
	}
}

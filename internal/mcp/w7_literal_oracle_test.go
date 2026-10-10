package mcp

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/store"
)

// Verification 7 defect 1 (HIGH): the redacted sql tool keyed every stored digest it found in its
// output, including text the client wrote itself (a literal, a comment in a column name, a
// computed string), so `SELECT '<raw>'` came back keyed exactly when <raw> was a stored
// fingerprint: a membership oracle (account recovered in 13.8 s over 1e6 candidates). Ids are
// now keyed only inside SQLite, per column provenance (the redacting CTE over stored columns);
// nothing the query computes is post-processed through the id mapper.
func TestSQLLiteralIsNeverKeyed(t *testing.T) {
	fx := newFixture(t)
	raw := ""
	for _, f := range fx.hostiles {
		if len(f.ID) == 32 {
			raw = f.ID
			break
		}
	}
	if raw == "" {
		fs, _ := fx.st.Findings(storeFilterAll())
		for _, f := range fs {
			if len(f.ID) == 32 {
				raw = f.ID
				break
			}
		}
	}
	if raw == "" {
		t.Fatal("fixture has no digest finding id")
	}
	ext := fx.st.ExternalFindingID(raw)
	unknown := strings.Repeat("ab", 16)
	c := startServer(t, fx.st, Options{Traversal: labTraversal}) // redacted (default)
	c.initialize()
	for _, q := range []string{
		"SELECT '" + raw + "' AS a, '" + unknown + "' AS b",
		"SELECT 1 /* " + raw + " " + unknown + " */",
		"SELECT substr('x" + raw + "', 2) AS a, substr('x" + unknown + "', 2) AS b",
		"SELECT '" + raw[:16] + "' || '" + raw[16:] + "' AS a",
		"SELECT '" + raw + "' AS id, 1 AS hops",
		"SELECT '{\"x\":\"" + raw + "\"}' AS a",
	} {
		tr, r := c.tool("sql", map[string]any{"query": q})
		if r.Error != nil {
			t.Fatalf("%s: %+v", q, r.Error)
		}
		b, _ := json.Marshal(tr)
		out := string(b)
		if strings.Contains(out, ext) || strings.Contains(out, ext[:16]) {
			t.Errorf("client text came back keyed (membership oracle): %s\n%s", q, out)
		}
		if !strings.Contains(out, raw[:16]) {
			t.Errorf("the literal must come back unchanged, like an unknown value: %s\n%s", q, out)
		}
	}
	// Stored columns are still keyed inside SQLite.
	out := c.toolOK("sql", map[string]any{"query": "SELECT id FROM findings WHERE id = '" + ext + "'"})
	b, _ := json.Marshal(out)
	if !strings.Contains(string(b), ext) || strings.Contains(string(b), raw) {
		t.Errorf("stored id not keyed / raw leaked: %s", b)
	}
	// Other tools never key a digest the client sent either (explain echoes nothing keyed).
	tr, _ := c.tool("explain", map[string]any{"id": raw})
	b, _ = json.Marshal(tr)
	if strings.Contains(string(b), ext) {
		t.Errorf("explain keyed the raw id the client sent: %s", b)
	}
}

func storeFilterAll() store.Filter { return store.Filter{} }

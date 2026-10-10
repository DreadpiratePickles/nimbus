package output

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// W6-VERIFY r4 #15: a DB-less output either labels its ids as unkeyed (the file already shows
// every identifier the digest is computed from) or keys them with a run-scoped secret, so no
// redacted output can reveal a raw digest.

func TestSARIFLabelsUnkeyedFingerprints(t *testing.T) {
	f := model.Finding{Source: "prowler", CheckID: "c", CanonicalID: "C", Title: "t", Severity: model.High, Status: model.Fail, Provider: "aws", Account: "123456789012", Resource: model.Resource{ID: "arn:aws:s3:::b"}}
	f.ID = f.Fingerprint()
	doc := SARIF([]model.Finding{f})
	run := doc["runs"].([]map[string]any)[0]
	props, _ := run["properties"].(map[string]any)
	if props == nil || props["nimbus_id_scheme"] != IDSchemeUnkeyed {
		t.Fatalf("SARIF run does not label its fingerprints: %v", run["properties"])
	}
}

func TestRunKeyerHidesDigests(t *testing.T) {
	sum := sha256.Sum256([]byte("internet|arn:aws:s3:::pii|GRAPH_TRAVERSAL"))
	raw := hex.EncodeToString(sum[:16])
	a, b := NewRunKeyer(nil), NewRunKeyer(nil)
	ka := a.ID(raw)
	if ka == raw || !strings.HasPrefix(ka, "run-") || a.ID(raw) != ka {
		t.Fatalf("run-scoped id %q for %q (must differ from the digest, carry the run- label, be stable within the run)", ka, raw)
	}
	if b.ID(raw) == ka {
		t.Errorf("two runs share an id: the key is not run-scoped")
	}
	fixed := []byte("0123456789abcdef0123456789abcdef")
	if NewRunKeyer(fixed).ID(raw) != NewRunKeyer(fixed).ID(raw) {
		t.Errorf("a configured key must give stable ids across runs (alert continuity)")
	}
	if got := a.Scheme(); got != IDSchemeRunKeyed {
		t.Errorf("scheme %q", got)
	}
}

package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/integrations"
)

// V2 defect 12: alert exits non-zero when any sink had a failed delivery (not only when
// every delivery failed), after printing the per-sink summary.
func TestAlertExitsNonZeroWhenAnySinkFails(t *testing.T) {
	results := []integrations.Result{
		{Channel: "slack", FindingID: "f1", Ref: "ok"},
		{Channel: "slack", FindingID: "f2", Ref: "ok"},
		{Channel: "teams", FindingID: "f1", Err: "dial tcp: connection refused"},
		{Channel: "teams", FindingID: "f2", Err: "dial tcp: connection refused"},
	}
	var buf bytes.Buffer
	err := reportDeliveries(&buf, results)
	if err == nil {
		t.Fatalf("one sink failed completely but alert exits 0:\n%s", buf.String())
	}
	if !strings.Contains(err.Error(), "teams") {
		t.Errorf("error must name the failing sink: %v", err)
	}
	for _, want := range []string{"slack: sent 2", "teams: sent 0 · skipped 0 · failed 2"} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("summary missing %q:\n%s", want, buf.String())
		}
	}
	buf.Reset()
	if err := reportDeliveries(&buf, results[:2]); err != nil {
		t.Errorf("all deliveries succeeded: %v", err)
	}
	if err := reportDeliveries(&buf, []integrations.Result{{Channel: "slack", FindingID: "x", Skipped: true}}); err != nil {
		t.Errorf("skipped only: %v", err)
	}
}

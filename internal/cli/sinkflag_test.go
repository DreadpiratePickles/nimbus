package cli

import (
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/integrations"
)

// Item 14: `--allow-private-sinks` (global) permits sink URLs on private addresses, like
// NIMBUS_ALLOW_PRIVATE_SINKS=1; metadata/link-local addresses stay refused.
func TestAllowPrivateSinksFlag(t *testing.T) {
	integrations.SetAllowPrivateSinks(false)
	t.Cleanup(func() { integrations.SetAllowPrivateSinks(false) })
	if err := integrations.ValidateSinkURL("https://10.0.0.5/hook"); err == nil {
		t.Fatal("private sink accepted without the flag")
	}
	run(t, "--allow-private-sinks", "version")
	if err := integrations.ValidateSinkURL("https://10.0.0.5/hook"); err != nil {
		t.Fatalf("--allow-private-sinks: private sink refused: %v", err)
	}
	if err := integrations.ValidateSinkURL("http://169.254.169.254/"); err == nil {
		t.Fatal("metadata address accepted with --allow-private-sinks")
	}
}

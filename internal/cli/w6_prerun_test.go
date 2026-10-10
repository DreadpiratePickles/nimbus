package cli

import (
	"testing"

	"github.com/spf13/cobra"
)

// Coordinator item 17: the foreign (Python-built) database policy is root's own pre-run
// (root.go), and no subcommand defines a PersistentPreRun of its own — cobra would run that one
// instead and silently skip the policy.
func TestForeignDBPolicyIsRootPreRunAndNotShadowed(t *testing.T) {
	if root.PersistentPreRunE == nil {
		t.Fatal("root has no PersistentPreRunE: the foreign-DB policy is not installed")
	}
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		for _, s := range c.Commands() {
			if s.PersistentPreRun != nil || s.PersistentPreRunE != nil {
				t.Errorf("%s defines its own PersistentPreRun: it shadows root's foreign-DB policy", s.CommandPath())
			}
			walk(s)
		}
	}
	walk(root)
}

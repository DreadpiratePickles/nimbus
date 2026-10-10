package cli

import (
	"regexp"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// Delta review 2 #10 / release readiness row 11: no help text overclaims. `monitor` polls
// audit logs (minutes of delay); no command may call itself real-time.
func TestHelpTextDoesNotClaimRealTime(t *testing.T) {
	re := regexp.MustCompile(`(?i)\breal[- ]?time\b`)
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		for _, text := range []string{c.Short, c.Long, c.Example} {
			for _, m := range re.FindAllStringIndex(text, -1) {
				before := strings.ToLower(text[max(0, m[0]-4):m[0]])
				if !strings.HasSuffix(before, "not ") {
					t.Errorf("%s help claims real time: %q", c.CommandPath(), text)
				}
			}
		}
		for _, s := range c.Commands() {
			walk(s)
		}
	}
	walk(root)
}

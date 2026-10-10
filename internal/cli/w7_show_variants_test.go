package cli

import (
	"strings"
	"testing"
)

// r5 #13 / coordinator item 16: `issues show` "Hop variants" lines name each variant with the
// shared path-Issue title builder (the title every other surface prints), not the old
// "X → Y → Privilege escalation to Z" path name, and say which hops differ ("via …").
func TestIssuesShowHopVariantsUseTheSharedTitle(t *testing.T) {
	labDB(t)
	for _, id := range []string{p01Issue(t), p02Issue(t)} {
		is := issueByID(t, id)
		out := run(t, "issues", "show", id)
		i := strings.Index(out, "Hop variants (")
		if i < 0 {
			t.Fatalf("%s: no Hop variants block:\n%s", id, out)
		}
		block := out[i:]
		if j := strings.Index(block, "\n\n"); j > 0 {
			block = block[:j]
		}
		lines := strings.Split(strings.TrimSpace(block), "\n")[1:]
		if len(lines) == 0 {
			t.Fatalf("%s: empty variants block", id)
		}
		for _, l := range lines {
			if strings.HasPrefix(strings.TrimSpace(l), "…") {
				continue
			}
			if strings.Contains(l, "Privilege escalation to") || !strings.Contains(l, is.Title) || !strings.Contains(l, " via ") {
				t.Errorf("%s: variant line %q does not use the shared title %q with its hops", id, l, is.Title)
			}
		}
	}
}

// The verify outcome no longer says "PASS or absent": it says which one it re-read.
func TestVerifyOutcomeWording(t *testing.T) {
	for _, c := range []struct {
		missing bool
		want    string
	}{{false, "is now PASS (re-read)"}, {true, "confirmed deleted"}} {
		if got := fixedReason("S3_PUBLIC_BUCKET", "customer-pii", c.missing); !strings.Contains(got, c.want) || strings.Contains(got, "PASS or absent") {
			t.Errorf("missing=%v: %q", c.missing, got)
		}
	}
}

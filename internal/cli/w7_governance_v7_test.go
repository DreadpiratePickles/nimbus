package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/config"
)

// Verification 7 defect 13/14 (W7-POLISH item 9).

// min_owner_share is compared in integer basis points: 56 of 100 meets 0.56 (0.56*100 is
// 56.000000000000007 in float64, which refused it).
func TestProposeFromShareBoundaryIsExact(t *testing.T) {
	for _, c := range []struct {
		n, total int
		share    float64
		want     bool
	}{{56, 100, 0.56, true}, {55, 100, 0.56, false}, {29, 100, 0.29, true}, {57, 100, 0.57, true}, {50, 100, 0.5, true}, {49, 100, 0.5, false}} {
		counts := map[string]int{"a": c.n, "b": c.total - c.n}
		if c.total-c.n >= c.n {
			counts = map[string]int{"a": c.n}
			for i := 0; i < c.total-c.n; i++ { // spread the rest so "a" stays the strict plurality
				counts[string(rune('c'+i%20))+strings.Repeat("x", i/20)]++
			}
		}
		o, why := proposeFrom(counts, c.share)
		if (o == "a") != c.want {
			t.Errorf("%d of %d at %.4f: owner %q (%s), want proposed=%v", c.n, c.total, c.share, o, why, c.want)
		}
	}
}

// The ownership line names accounts.<name>.owner as owned and the defaults.* owners (including
// defaults.account_owners) as assigned by default — "or account owners" was ambiguous.
func TestOwnershipTextNamesTheSources(t *testing.T) {
	s := ownershipCounts{Open: 10, Owned: 5, ByDefault: 3, Unassigned: 2}.Text()
	for _, want := range []string{"accounts.<name>.owner", "assigned by default: 3 (defaults.owner / account_owners / provider_owners)", "unassigned: 2"} {
		if !strings.Contains(s, want) {
			t.Errorf("ownership line lacks %q: %s", want, s)
		}
	}
	if strings.Contains(s, "or account owners ·") {
		t.Errorf("ambiguous wording: %s", s)
	}
}

// `governance init --write` refuses a read-only config (0444) instead of replacing it through
// the rename, and leaves it untouched.
func TestGovernanceInitRefusesReadOnlyConfig(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores file modes")
	}
	dir := labDB(t)
	cfgPath := filepath.Join(dir, "c.yaml")
	body := "python:\n  enabled: false\n"
	os.WriteFile(cfgPath, []byte(body), 0o444)
	out, err := runErr(t, "-c", cfgPath, "governance", "init", "--repo", dir, "--write")
	if err == nil || !strings.Contains(out+err.Error(), "read-only") {
		t.Fatalf("a 0444 config must be refused: %v\n%s", err, out)
	}
	b, _ := os.ReadFile(cfgPath)
	fi, _ := os.Stat(cfgPath)
	if string(b) != body || fi.Mode().Perm() != 0o444 {
		t.Errorf("read-only config changed: %v %q", fi.Mode().Perm(), b)
	}
	if _, err := config.Load(cfgPath); err != nil {
		t.Error(err)
	}
}

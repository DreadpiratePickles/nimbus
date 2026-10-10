package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/risk"
)

// Verification 6 (routed item 11): the CHANGELOG "Score changes" list names the current
// score_version (2.4.0 was only under Changed).
func TestChangelogScoreListNamesCurrentScoreVersion(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "CHANGELOG.md"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	i := strings.Index(s, "### Score changes")
	if i < 0 {
		t.Fatal("CHANGELOG has no Score changes list")
	}
	list := s[i:]
	if j := strings.Index(list[3:], "\n#"); j >= 0 {
		list = list[:j+3]
	}
	if !strings.Contains(list, "**"+risk.ScoreVersion+"**") {
		t.Errorf("Score changes list lacks **%s**:\n%s", risk.ScoreVersion, list)
	}
}

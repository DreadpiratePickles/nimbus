package store

import (
	"os"
	"regexp"
	"strconv"
	"testing"
)

// The Python layer recreates findings_summary and the inventory views on every Python
// ingest; it must apply the same lifecycle filter (V2 defect 7). This keeps the copies equal.
func TestViewSQLMatchesPython(t *testing.T) {
	src, err := os.ReadFile("../../python/nimbus/store.py")
	if err != nil {
		t.Fatal(err)
	}
	for goVal, pyName := range map[string]string{activeFailSQL: "ACTIVE_FAIL_SQL", findingsSummarySQL: "FINDINGS_SUMMARY_SQL", issuesSummarySQL: "ISSUES_SUMMARY_SQL"} {
		m := regexp.MustCompile(`(?m)^` + pyName + ` = ("(?:[^"\\]|\\.)*")`).FindSubmatch(src)
		if m == nil {
			t.Fatalf("%s not found in python/nimbus/store.py", pyName)
		}
		py, err := strconv.Unquote(string(m[1]))
		if err != nil {
			t.Fatal(err)
		}
		if py != goVal {
			t.Errorf("%s drifted:\n go: %s\n py: %s", pyName, goVal, py)
		}
	}
}

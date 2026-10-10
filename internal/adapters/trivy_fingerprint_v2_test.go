package adapters

import (
	"fmt"
	"testing"
	"time"
)

func trivyDoc(vulns string) []byte {
	return []byte(fmt.Sprintf(`{"ArtifactName":"app:1","Results":[{"Target":"app:1 (java)","Class":"lang-pkgs","Type":"jar","Vulnerabilities":[%s]}]}`, vulns))
}

func trivyVuln(pkgPath, version string) string {
	return fmt.Sprintf(`{"VulnerabilityID":"CVE-2021-44228","PkgName":"org.apache.logging.log4j:log4j-core","PkgPath":%q,"InstalledVersion":%q,"FixedVersion":"2.17.1","Severity":"CRITICAL","Title":"log4shell"}`, pkgPath, version)
}

func trivyIDs(t *testing.T, data []byte) []string {
	t.Helper()
	now := time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC)
	fs, err := Trivy{}.Parse(data, Options{Now: now})
	if err != nil {
		t.Fatal(err)
	}
	Finalize(fs, Options{Now: now})
	var ids []string
	for _, f := range fs {
		ids = append(ids, f.ID)
	}
	return ids
}

// V2 defect 11a: the same CVE in two jars of one image is two findings.
func TestTrivySameCVETwoJarsAreDistinct(t *testing.T) {
	ids := trivyIDs(t, trivyDoc(trivyVuln("app/lib/a.jar", "2.14.0")+","+trivyVuln("app/lib/b.jar", "2.14.0")))
	if len(ids) != 2 || ids[0] == ids[1] {
		t.Fatalf("two jars collapsed: %v", ids)
	}
}

// V2 defect 11b: a version bump that is still vulnerable is the same finding (it must
// not show as resolved + new, losing first_seen).
func TestTrivyVersionBumpStillVulnerableKeepsFingerprint(t *testing.T) {
	before := trivyIDs(t, trivyDoc(trivyVuln("app/lib/a.jar", "2.14.0")))
	after := trivyIDs(t, trivyDoc(trivyVuln("app/lib/a.jar", "2.15.0")))
	if len(before) != 1 || len(after) != 1 || before[0] != after[0] {
		t.Fatalf("version churn changed the fingerprint: %v -> %v", before, after)
	}
}

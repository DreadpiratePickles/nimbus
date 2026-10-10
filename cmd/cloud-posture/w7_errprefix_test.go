package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// W7-POLISH r5 #13 / N5: one error prefix. Every failure — flag validation (`catalog unmapped`
// without --tool), argument validation (`verify` without an id), an unknown flag, a RunE error —
// reaches the user as exactly one "error: …" line from main, never cobra's "Error: …".
func TestErrorPrefixIsOneLowercaseLine(t *testing.T) {
	if os.Getenv("NIMBUS_W7_RUN_MAIN") == "1" {
		os.Args = append([]string{"cloud-posture"}, strings.Fields(os.Getenv("NIMBUS_W7_ARGS"))...)
		main()
		os.Exit(0)
	}
	db := t.TempDir() + "/p.db"
	for _, args := range []string{
		"catalog unmapped",
		"verify",
		"verify --id nope",
		"who-can s3:GetObject --db " + db,
		"paths --from internet --db " + db,
		"governance init --owner",
	} {
		cmd := exec.Command(os.Args[0], "-test.run=TestErrorPrefixIsOneLowercaseLine")
		cmd.Env = append(os.Environ(), "NIMBUS_W7_RUN_MAIN=1", "NIMBUS_W7_ARGS="+args, "CLOUD_POSTURE_NO_NETWORK=1", "HOME="+t.TempDir())
		cmd.Dir = t.TempDir()
		out, err := cmd.CombinedOutput()
		if err == nil {
			t.Errorf("%s: want a failure, got success:\n%s", args, out)
			continue
		}
		s := string(out)
		if strings.Contains(s, "Error:") {
			t.Errorf("%s: cobra-style \"Error:\" prefix:\n%s", args, s)
		}
		if n := strings.Count(s, "error:"); n != 1 {
			t.Errorf("%s: %d \"error:\" lines, want 1:\n%s", args, n, s)
		}
	}
}

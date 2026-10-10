package store

import (
	"os"
	"path/filepath"
	"testing"
)

// Verification 7 defect 4 (MED-LOW): fileOrigin built "file:"+path+"?mode=ro" by concatenation,
// so a '#' in the path cut it short: the probe opened (and created) the parent prefix in
// read-write mode, reported "new", and a read-only command then migrated the Python-built DB.
// The URI is now built with escaping; '#', '?', '%' and spaces all reach the real file.
func TestFileOriginEscapesThePath(t *testing.T) {
	for _, dir := range []string{"h#x", "q?mode=rw", "pct%41", "sp ace", "mix #?% x"} {
		t.Run(dir, func(t *testing.T) {
			root := t.TempDir()
			d := filepath.Join(root, dir)
			if err := os.MkdirAll(d, 0o755); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(d, "py.db")
			rawDB(t, fileURI(path, "mode=rwc"), pythonSchema)
			if _, err := os.Stat(path); err != nil {
				t.Fatalf("fixture DB not at %q: %v", path, err)
			}
			before, _ := os.ReadDir(root)
			got, err := fileOrigin(path)
			if err != nil || got != OriginPython {
				t.Fatalf("origin of a Python-built DB under %q = %q (%v)", dir, got, err)
			}
			after, _ := os.ReadDir(root)
			if len(after) != len(before) {
				t.Errorf("the probe created a stray file: %v → %v", before, after)
			}
			withPolicy(t, ForeignPolicy{Allow: false})
			if st, err := Open(path); err == nil {
				st.Close()
				t.Fatalf("a read-only open migrated the Python-built DB under %q", dir)
			}
		})
	}
}

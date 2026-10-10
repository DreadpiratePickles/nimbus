package cli

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/output"
)

// Item 15 (verify-4 LOW: convert has no size cap; a 200 MB file → 1.39 GB RSS): `convert`
// reads its input through output.ReadConvertInput, so a file over the cap is refused before
// it is parsed.
func TestConvertRefusesOversizedInput(t *testing.T) {
	p := filepath.Join(t.TempDir(), "big.json")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	const size = 200 << 20 // the verifier's 200 MB repro (> output.MaxConvertInput)
	_ = output.MaxConvertInput
	if err := f.Truncate(size); err != nil { // sparse: no disk cost
		t.Fatal(err)
	}
	f.Close()
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	out, err := runErr(t, "convert", p, "--to", "sarif")
	runtime.ReadMemStats(&after)
	// Under -race the instrumented runtime allocates far more (315 MiB measured by verification 7
	// for the same refusal), so the allocation bound only runs without it; the refusal is
	// asserted either way.
	if alloc := after.TotalAlloc - before.TotalAlloc; !raceEnabled && alloc >= size {
		t.Errorf("convert allocated %d MiB to refuse a %d MiB file; it must stop reading at the cap", alloc>>20, size>>20)
	}
	if err == nil || !strings.Contains(out+err.Error(), "MiB") {
		t.Fatalf("oversized convert input must be refused with the cap in the message: %v\n%s", err, out)
	}
}

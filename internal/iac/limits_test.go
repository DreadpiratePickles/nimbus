package iac

import (
	"errors"
	"fmt"
	"runtime"
	"runtime/debug"
	"runtime/metrics"
	"strings"
	"testing"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// Verification 2 defect 2 (D3): 70,000 nested brackets (140 KB) killed `scan --iac` with a
// non-recoverable `fatal error: stack overflow` inside the recursive hclsyntax parser.
// Pathological inputs must become an ERROR finding for the file, never a crash.

// deepBrackets is the verifier's repro (scratchpad/verify-2/so/deep.tf shape).
func deepBrackets(n int) []byte {
	return []byte("resource \"aws_security_group\" \"x\" {\n  ingress {\n    cidr_blocks = " + strings.Repeat("[", n) + strings.Repeat("]", n) + "\n  }\n}\n")
}

func pathological() map[string][]byte {
	attr := func(expr string) []byte {
		return []byte("resource \"aws_db_instance\" \"d\" {\n  publicly_accessible = " + expr + "\n}\n")
	}
	return map[string][]byte{
		"brackets_70k":            deepBrackets(70000),
		"parens_300k":             attr(strings.Repeat("(", 300000) + "true" + strings.Repeat(")", 300000)),
		"calls_200k":              attr(strings.Repeat("f(", 200000) + "1" + strings.Repeat(")", 200000)),
		"objects_200k":            attr(strings.Repeat("{a=", 200000) + "1" + strings.Repeat("}", 200000)),
		"interp_200k":             attr(strings.Repeat("\"${", 200000) + "1" + strings.Repeat("}\"", 200000)),
		"not_1m":                  attr(strings.Repeat("!", 1000000) + "true"),
		"neg_1m":                  attr(strings.Repeat("-", 1000000) + "1"),
		"ternary_400k":            attr(strings.Repeat("x?1:", 400000) + "2"),
		"ternary_lines_in_parens": attr("(\n" + strings.Repeat("x ? 1 :\n", 250000) + "2)"),
		"blocks_300k":             []byte("resource \"aws_eks_cluster\" \"x\" {\n" + strings.Repeat("a{\n", 300000) + strings.Repeat("}\n", 300000) + "}\n"),
	}
}

func TestScanHCLPathologicalNestingIsAnErrorFinding(t *testing.T) {
	now := time.Unix(0, 0)
	for name, src := range pathological() {
		fs, err := ScanHCL(src, name+".tf", now)
		if err == nil {
			t.Errorf("%s: want a parse-limit error", name)
		}
		if len(fs) != 1 || fs[0].Status != model.Error || fs[0].File != name+".tf" || !strings.Contains(fs[0].Description, "nesting") {
			t.Errorf("%s: want one ERROR finding about nesting, got %d findings %+v", name, len(fs), fs)
		}
		// The patcher has its own parse and must refuse the same input.
		if _, err := patchSource(model.Finding{CanonicalID: "RDS_PUBLIC", Resource: model.Resource{ID: "aws_db_instance.d"}}, name+".tf", src, nil); err == nil {
			t.Errorf("%s: patcher accepted pathological input", name)
		}
		if _, err := UndeclaredSymbols(src, name+".tf"); err == nil {
			t.Errorf("%s: UndeclaredSymbols accepted pathological input", name)
		}
	}
}

func TestScanTerraformPathologicalFileDoesNotStopTheScan(t *testing.T) {
	d := t.TempDir()
	writeTree(t, d, map[string]string{
		"deep.tf": string(deepBrackets(70000)),
		"ok.tf":   "resource \"aws_db_instance\" \"d\" {\n  publicly_accessible = true\n}\n",
	})
	fs, err := ScanTerraform(d, time.Unix(0, 0))
	// Verification 3 defect 2: the scan goes on, but names the file it could not examine.
	var ue *UnscannedError
	if !errors.As(err, &ue) || len(ue.Files) != 1 || ue.Files[0] != "deep.tf" {
		t.Fatalf("want an UnscannedError for deep.tf, got %v", err)
	}
	var gotErr, gotFail bool
	for _, f := range fs {
		if f.Status == model.Error && f.File == "deep.tf" {
			gotErr = true
		}
		if f.Status == model.Fail && f.CanonicalID == "RDS_PUBLIC" && f.File == "ok.tf" {
			gotFail = true
		}
	}
	if !gotErr || !gotFail {
		t.Errorf("want ERROR for deep.tf and RDS_PUBLIC FAIL for ok.tf; got %+v", fs)
	}
}

func TestReasonableNestingStillParses(t *testing.T) {
	// 100 levels is far beyond real Terraform and well under the limit.
	src := []byte("resource \"aws_db_instance\" \"d\" {\n  publicly_accessible = " + strings.Repeat("(", 100) + "true" + strings.Repeat(")", 100) + "\n  tags = { a = " + strings.Repeat("[", 100) + strings.Repeat("]", 100) + " }\n}\n")
	fs, err := ScanHCL(src, "ok.tf", time.Unix(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range fs {
		if f.CanonicalID == "RDS_PUBLIC" && f.Status != model.Fail {
			t.Errorf("RDS_PUBLIC = %s", f.Status)
		}
	}
}

func TestFileSizeLimitIsConfigurable(t *testing.T) {
	big := []byte("resource \"aws_db_instance\" \"d\" {\n  publicly_accessible = true\n}\n" + strings.Repeat("# pad\n", 1000))
	old := SetLimits(Limits{MaxFileBytes: 512, MaxDepth: DefaultMaxDepth})
	defer SetLimits(old)
	fs, err := ScanHCL(big, "big.tf", time.Unix(0, 0))
	if err == nil || len(fs) != 1 || fs[0].Status != model.Error || !strings.Contains(fs[0].Description, "size") {
		t.Fatalf("size limit: err=%v fs=%+v", err, fs)
	}
	SetLimits(old)
	if fs, err := ScanHCL(big, "big.tf", time.Unix(0, 0)); err != nil || len(fs) == 0 || fs[0].Status == model.Error {
		t.Fatalf("default limit rejected a 6 KB file: %v %+v", err, fs)
	}
}

// Verification 2 defect 9 (D5): UnifiedDiff built an n×m LCS table, so patching a 12k-line file
// used 1.33 GB and a 10 MB file ran out of memory.
func synthetic(size int) []byte {
	var b strings.Builder
	for i := 0; b.Len() < size-200; i++ {
		fmt.Fprintf(&b, "resource \"aws_s3_bucket\" \"b%d\" {\n  bucket = \"bucket-%d\"\n  acl    = \"private\"\n}\n\n", i, i)
	}
	b.WriteString("resource \"aws_db_instance\" \"target\" {\n  publicly_accessible = true\n}\n")
	return []byte(b.String())
}

// peakHeap runs fn while sampling the live heap every millisecond and returns the peak above the
// starting level, the bytes allocated in total and the elapsed time: the process CPU time where
// the platform reports it (processCPU; stable under machine load), wall-clock time otherwise.
func peakHeap(fn func()) (peak, total uint64, el time.Duration) {
	sample := []metrics.Sample{{Name: "/memory/classes/heap/objects:bytes"}}
	read := func() uint64 { metrics.Read(sample); return sample[0].Value.Uint64() }
	runtime.GC()
	base := read()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	stop, done := make(chan struct{}), make(chan uint64)
	go func() {
		var max uint64
		tk := time.NewTicker(time.Millisecond)
		defer tk.Stop()
		for {
			if v := read(); v > max {
				max = v
			}
			select {
			case <-stop:
				done <- max
				return
			case <-tk.C:
			}
		}
	}()
	st := time.Now()
	cpu0, cpuOK := processCPU()
	fn()
	el = time.Since(st)
	if cpu1, ok := processCPU(); ok && cpuOK {
		el = cpu1 - cpu0
	}
	close(stop)
	max := <-done
	runtime.ReadMemStats(&after)
	if max > base {
		peak = max - base
	}
	return peak, after.TotalAlloc - before.TotalAlloc, el
}

// TestPatchLargeFileIsLinear: a 2 MiB file patches in < 4 s of CPU with < 200 MB of live heap, and
// doubling the file size roughly doubles (not quadruples) time and allocation.
//
// Time is process CPU time (user + system, including the concurrent GC and the 1 ms heap
// sampler), not wall time: the wall-clock bound (2 s) failed whenever the machine was loaded (a
// parallel `go test ./...`; reproduced at 2.0-2.5 s wall with 40 busy processes on 10 cores, W7
// flake hunt) while the work done was unchanged: CPU time measured 0.71 s unloaded and 0.81-0.85 s
// under that load (5 runs). The 4 s CPU bound leaves ~5x headroom for slower CI runners, and a
// quadratic regression (minutes) still fails it. Where CPU time is unavailable the same bound applies to wall time. The allocation
// ratio is the deterministic linearity check; the time ratio is a backstop. Live heap is sampled with the
// GC target at 10% so the figure is live data, not uncollected garbage; under the default GOGC=100
// the process heap is up to ~2x that. The floor is the HCL library itself: hclsyntax.ParseConfig of
// the same 2 MiB file alone peaks at ~146 MB live (its token slice).
func TestPatchLargeFileIsLinear(t *testing.T) {
	f := model.Finding{CanonicalID: "RDS_PUBLIC", Resource: model.Resource{ID: "aws_db_instance.target"}}
	measure := func(size int) (peak, total uint64, el time.Duration, p *Patch) {
		src := synthetic(size)
		if len(src) > size {
			t.Fatalf("fixture %d bytes exceeds %d", len(src), size)
		}
		var err error
		_, total, el = peakHeap(func() { p, err = patchSource(f, "big.tf", src, nil) })
		if err != nil || p == nil {
			t.Fatalf("patch %d bytes: %v", size, err)
		}
		old := debug.SetGCPercent(10)
		peak, _, _ = peakHeap(func() { patchSource(f, "big.tf", src, nil) })
		debug.SetGCPercent(old)
		t.Logf("%d KiB file (%d lines): %v, live-heap peak %d MB, total allocated %d MB", size>>10, strings.Count(string(src), "\n"), el, peak>>20, total>>20)
		return peak, total, el, p
	}
	_, total1, el1, _ := measure(1 << 20)
	peak, total2, el, p := measure(2 << 20)
	if el > 4*time.Second && !raceEnabled { // -race: 3.0 s → 6.2 s (×2.04, verification 7); the ratio below still runs
		t.Errorf("2 MiB patch took %v of CPU (> 4 s)", el)
	}
	if peak > 200<<20 && !raceEnabled {
		t.Errorf("2 MiB patch live-heap peak %d MB (> 200 MB)", peak>>20)
	}
	if ratio := float64(total2) / float64(total1); ratio > 3 {
		t.Errorf("allocation grew %.1fx for 2x the input: not linear", ratio)
	}
	if ratio := float64(el) / float64(el1); ratio > 4 {
		t.Errorf("time grew %.1fx for 2x the input: not linear", ratio)
	}
	if !strings.Contains(p.Diff, "-  publicly_accessible = true") || !strings.Contains(p.Diff, "+  publicly_accessible = false") {
		t.Errorf("diff misses the change:\n%s", p.Diff[max(0, len(p.Diff)-500):])
	}
	if strings.Count(p.Diff, "\n-") != 1 || strings.Count(p.Diff, "\n+") != 2 { // the +++ header and one added line
		t.Errorf("patch touched more than the target line:\n%s", p.Diff[max(0, len(p.Diff)-800):])
	}
}

func TestUnifiedDiffWorstCaseIsBounded(t *testing.T) {
	// Every line differs: no common prefix/suffix to trim.
	var a, b strings.Builder
	for i := 0; i < 60000; i++ {
		fmt.Fprintf(&a, "a%d\n", i)
		fmt.Fprintf(&b, "b%d\n", i)
	}
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	d := UnifiedDiff("x.tf", a.String(), b.String())
	runtime.ReadMemStats(&after)
	if alloc := after.TotalAlloc - before.TotalAlloc; alloc > 200<<20 {
		t.Errorf("worst-case diff allocated %d MB", alloc>>20)
	}
	if !strings.Contains(d, "-a0") || !strings.Contains(d, "+b59999") {
		t.Errorf("diff incomplete")
	}
}

func TestUnifiedDiffSmallUnchanged(t *testing.T) {
	a := "l1\nl2\nl3\nl4\nl5\nold\nl7\n"
	b := "l1\nl2\nl3\nl4\nl5\nnew\nl7\n"
	got := UnifiedDiff("f.tf", a, b)
	want := "--- a/f.tf\n+++ b/f.tf\n l1\n l2\n l3\n@@ ... @@\n-old\n+new\n l7\n "
	if got != want {
		t.Errorf("got\n%q\nwant\n%q", got, want)
	}
}

// FuzzScanHCL seed: keep the verifier's stack-overflow input in the corpus.
func addPathologicalSeeds(f *testing.F) {
	f.Add(deepBrackets(70000))
	f.Add([]byte("resource \"aws_db_instance\" \"d\" {\n  publicly_accessible = " + strings.Repeat("!", 300000) + "true\n}\n"))
	// Verification 3 defect 1: the two crash repros at full size, and every hostile shape small
	// enough for the mutator to recombine (the guard-bound property catches an uncounted construct
	// at a depth of a few dozen).
	f.Add([]byte(hostileShapes()["splat_full_200k"]))
	f.Add([]byte(hostileShapes()["bang_nl_400k"]))
	r := strings.Repeat
	for _, small := range []string{
		"a" + r("[*]", 40), "(" + r("!\n", 40) + "true)", "(" + r("!/**/", 40) + "true)", "(" + r("-#\n", 40) + "1)",
		"a" + r("[*].b", 40), "a" + r("[*][0]", 40), "a" + r(".*", 40), "a" + r("[x]", 40), "1" + r("+1*1", 40),
		r("x?1:", 40) + "2", "(" + r("x?\n", 40) + "1" + r(":2", 40) + ")", "[for x in y : x if " + r("x ? ", 40) + "x]",
		"{for k, v in x : k => " + r("!\n", 40) + "v}", r("[for x in ", 20) + "[1]" + r(" : x]", 20), r("{a=", 40) + "1" + r("}", 40),
		r("f(", 40) + "1" + r(")", 40), r("\"${", 40) + "1" + r("}\"", 40), r("<<EOT\n${", 20) + "1" + r("}\nEOT\n", 20),
		"\"" + r("%{ if true }", 40) + "y" + r("%{ endif }", 40) + "\"", "\"" + r("%{ for x in [1] }", 40) + "y" + r("%{ endfor }", 40) + "\"",
		"(" + r("!a[*]\n", 40) + ")", r("(-", 40) + "1" + r(")", 40), "!-!-a[*][*].b[*]", "-a[*]" + r("[f(x)][*]", 20),
	} {
		f.Add([]byte(guardLocal(small)))
	}
}

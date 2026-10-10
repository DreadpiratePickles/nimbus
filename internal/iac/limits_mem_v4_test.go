package iac

import (
	"errors"
	"runtime"
	"strings"
	"testing"
)

// Verify-4 LOW: rejecting a 2 MiB pathological file allocated ~300-370 MB in the depth guard
// (a full token slice of the whole file). The guard rejects from a prefix first, so a file
// whose nesting blows up early costs a small, bounded allocation.
func pathological2MiB() map[string][]byte {
	const size = 2<<20 - 64
	fill := func(head, unit, tail string) []byte {
		n := (size - len(head) - len(tail)) / len(unit)
		return []byte(head + strings.Repeat(unit, n) + tail)
	}
	return map[string][]byte{
		"splat":    fill("locals {\n v = a", "[*]", "\n}\n"),
		"bang":     fill("locals {\n v = ", "!", "true\n}\n"),
		"bangnl":   fill("locals {\n v = (", "!\n", "true)\n}\n"),
		"brackets": fill("locals {\n v = ", "[", "\n}\n"),
		"parens":   fill("locals {\n v = ", "(", "\n}\n"),
		"chain":    fill("locals {\n v = a", ".b", "\n}\n"),
		"minus":    fill("locals {\n v = ", "-", "1\n}\n"),
		"interp":   fill("locals {\n v = \"", "${\"", "\"\n}\n"),
	}
}

func TestDepthGuardRejects2MiBWithBoundedMemory(t *testing.T) {
	for name, src := range pathological2MiB() {
		runtime.GC()
		var a, b runtime.MemStats
		runtime.ReadMemStats(&a)
		err := checkParseLimits(src, name+".tf")
		runtime.ReadMemStats(&b)
		var le *LimitError
		if !errors.As(err, &le) {
			t.Errorf("%s: not rejected: %v", name, err)
			continue
		}
		if mb := (b.TotalAlloc - a.TotalAlloc) >> 20; mb >= 200 {
			t.Errorf("%s: rejecting a %d-byte file allocated %d MB (want < 200 MB)", name, len(src), mb)
		} else {
			t.Logf("%s: rejected with %d MB allocated: %s", name, mb, le.Reason)
		}
	}
}

// The prefix pass must never change an acceptance: a file whose only violation is at its end is
// still rejected (by the full pass), and a reasonable large file is still accepted.
func TestDepthGuardPrefixPassIsOnlyAFastReject(t *testing.T) {
	var b strings.Builder
	for b.Len() < 1<<20 {
		b.WriteString("resource \"aws_s3_bucket\" \"b\" {\n  bucket = \"x\"\n  tags = { a = \"b\", c = [1, 2, 3] }\n}\n")
	}
	benign := b.String()
	if err := checkParseLimits([]byte(benign), "ok.tf"); err != nil {
		t.Fatalf("benign 1 MiB file rejected: %v", err)
	}
	deepTail := benign + "locals {\n v = " + strings.Repeat("[", 300) + strings.Repeat("]", 300) + "\n}\n"
	if err := checkParseLimits([]byte(deepTail), "tail.tf"); err == nil {
		t.Fatal("violation at the end of the file not rejected")
	}
	// a multi-line comment holding deep brackets is not code: never rejected
	commented := benign[:70<<10] + "/*\n" + strings.Repeat("(", 400) + "\n*/\n" + benign[:600<<10]
	if err := checkParseLimits([]byte(commented), "comment.tf"); err != nil {
		t.Fatalf("deep brackets inside a comment rejected: %v", err)
	}
}

func BenchmarkDepthGuardReject2MiB(b *testing.B) {
	src := pathological2MiB()["splat"]
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if checkParseLimits(src, "splat.tf") == nil {
			b.Fatal("not rejected")
		}
	}
}

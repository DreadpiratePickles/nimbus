package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNormaliseIsStableAcrossRuns(t *testing.T) {
	a := "top Issue db52148e1c0ff6758b6e35c576726f09 10.0 (cloud-posture issues show db52148e1c0ff6758b6e35c576726f09)\n" +
		"next 2c0a02b0736aaade2a2799466ea0db56  \nfirst_seen 2026-10-10T06:17:03Z · due 2026-10-17\nDatabase: /tmp/x1/.cloud-posture/posture.db\npath 1f10a63b3110bc55"
	b := strings.NewReplacer("db52148e1c0ff6758b6e35c576726f09", "0123456789abcdef0123456789abcdef",
		"2c0a02b0736aaade2a2799466ea0db56", "fedcba9876543210fedcba9876543210", "06:17:03", "09:01:44", "2026-10-17", "2026-10-24", "/tmp/x1", "/tmp/x2").Replace(a)
	na, nb := normalise(a, "/tmp/x1"), normalise(b, "/tmp/x2")
	if na != nb {
		t.Fatalf("two runs differ after normalising:\n%s\n---\n%s", na, nb)
	}
	for _, want := range []string{"<issue-id-1> 10.0 (cloud-posture issues show <issue-id-1>)", "next <issue-id-2>\n", "<timestamp>", "due <date>",
		"Database: .cloud-posture/posture.db", "path 1f10a63b3110bc55"} {
		if !strings.Contains(na, want) {
			t.Errorf("normalised output lacks %q:\n%s", want, na)
		}
	}
}

func TestHeadMarksTheCut(t *testing.T) {
	if got := head("a\nb\nc", 2); got != "a\nb\n …" {
		t.Errorf("head = %q", got)
	}
	if got := head("a\nb", 5); got != "a\nb" {
		t.Errorf("head = %q", got)
	}
}

// The whole mode against a stand-in binary: render, rewrite, -check current, -check stale.
func TestTranscriptRewriteAndCheck(t *testing.T) {
	dir := t.TempDir()
	repo := filepath.Join(dir, "repo")
	os.MkdirAll(filepath.Join(repo, "lab", "local", "out"), 0o755)
	bin := filepath.Join(dir, "cloud-posture")
	os.WriteFile(bin, []byte("#!/bin/sh\necho \"ran $1 db=$CLOUD_POSTURE_DB net=$CLOUD_POSTURE_NO_NETWORK id=0123456789abcdef0123456789abcdef\"\nfor i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14; do echo line$i; done\necho noise >&2\n"), 0o755)
	block, err := runTranscript(bin, repo)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{transcriptBegin, transcriptEnd, "```text\n$ make build\n", "$ ./bin/cloud-posture ingest lab/local/out/estate.findings.json --source native --config lab/local/cloud-posture.lab.yaml\nran ingest db=.cloud-posture/posture.db net=1 id=<issue-id-1>",
		"$ ./bin/cloud-posture plan --config lab/local/cloud-posture.lab.yaml\nran plan", "line4\n …", "--no-network"} {
		if !strings.Contains(block, want) {
			t.Errorf("block lacks %q:\n%s", want, block)
		}
	}
	if strings.Contains(block, "noise") {
		t.Error("stderr leaked into the transcript")
	}
	rd := filepath.Join(dir, "README.md")
	os.WriteFile(rd, []byte("# x\n"+transcriptBegin+" old -->\nScan complete! 9 Critical\n"+transcriptEnd+"\ntail\n"), 0o644)
	if err := applyTranscript(rd, block, true); err == nil {
		t.Fatal("-check must fail on a stale transcript")
	}
	if err := applyTranscript(rd, block, false); err != nil {
		t.Fatal(err)
	}
	if err := applyTranscript(rd, block, true); err != nil {
		t.Fatalf("-check after rewrite: %v", err)
	}
	b, _ := os.ReadFile(rd)
	if strings.Contains(string(b), "Scan complete!") || !strings.HasPrefix(string(b), "# x\n") || !strings.HasSuffix(string(b), "\ntail\n") {
		t.Fatalf("rewrite:\n%s", b)
	}
}

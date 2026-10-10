package iac

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/model"
	"github.com/DreadpiratePickles/nimbus/internal/output"
	"github.com/hashicorp/hcl/v2"
)

// ScanResult is a native Terraform scan of one IaC root.
//
// UnscannedFiles contract (Verification 3 defect 2; consumed by the CLI lifecycle):
//   - UnscannedFiles lists, root-relative with forward slashes and sorted, every .tf file under the
//     root that was not fully examined: a syntax error anywhere in the file (even when some of
//     its blocks parsed), over the size limit, over the nesting/chain limits, or unreadable.
//   - UnscannedReasons maps each of those paths to a one-line reason; the reason's first word is
//     the kind: "syntax", "size", "depth" or "read".
//   - Findings contains, for each unscanned file, exactly one ERROR finding (CanonicalID and
//     CheckID IAC_PARSE_LIMIT, Severity HIGH, File = the path above, Tags[output.TagScanGap] = the
//     kind). output.GateCount counts it at every --fail-on threshold and SARIF/PR output include
//     it. Findings from blocks of a partially parsed file are still returned.
//   - The scope (root, file) of an unscanned file was NOT observed: a lifecycle must not resolve
//     stored findings whose File is in UnscannedFiles for this root, and must not treat the root
//     as fully examined on the strength of this scan alone.
type ScanResult struct {
	Root             string            `json:"root"`
	Findings         []model.Finding   `json:"findings"`
	UnscannedFiles   []string          `json:"unscanned_files"`
	UnscannedReasons map[string]string `json:"unscanned_reasons"`
}

// UnscannedError is returned (with the full ScanResult) when any file under the root was not
// scanned. Files and Reasons are ScanResult.UnscannedFiles and UnscannedReasons.
type UnscannedError struct {
	Root    string
	Files   []string
	Reasons map[string]string
}

func (e *UnscannedError) Error() string {
	var parts []string
	for _, f := range e.Files {
		parts = append(parts, f+" ("+e.Reasons[f]+")")
	}
	return fmt.Sprintf("%d file(s) under %s not scanned: %s", len(e.Files), e.Root, strings.Join(parts, "; "))
}

const unreadableSummary = "file could not be read"

// ScanTerraformResult runs the native rules over a directory. The error is an *UnscannedError
// when some file was not scanned (the result is complete otherwise), or a parse error when the
// root yielded nothing at all.
func ScanTerraformResult(root string, now time.Time) (ScanResult, error) {
	blocks, diags := ParseTerraform(root)
	rootID := rootIdentity(root)
	gaps, reasons := gapFindings(diags, root, rootID, now)
	res := ScanResult{Root: root, Findings: append(evaluate(blocks, root, rootID, now), gaps...), UnscannedReasons: reasons}
	for f := range reasons {
		res.UnscannedFiles = append(res.UnscannedFiles, f)
	}
	sort.Strings(res.UnscannedFiles)
	if len(res.UnscannedFiles) > 0 {
		return res, &UnscannedError{Root: root, Files: res.UnscannedFiles, Reasons: reasons}
	}
	if diags.HasErrors() && len(blocks) == 0 {
		return res, fmt.Errorf("parse: %s", diags.Error())
	}
	return res, nil
}

// rootIdentity names an IaC root independently of how its path was spelled: the absolute,
// symlink-resolved, slash-separated path ("" for in-memory scans).
func rootIdentity(root string) string {
	if root == "" {
		return ""
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		abs = filepath.Clean(root)
	}
	if r, err := filepath.EvalSymlinks(abs); err == nil {
		abs = r
	}
	return filepath.ToSlash(abs)
}

// rootedID is the finding's fingerprint qualified by its IaC root (Verification 3 defect 3: the
// fingerprint alone uses the root-relative file, so stg/a.tf and prod/a.tf collided).
func rootedID(f model.Finding, rootID string) string {
	if rootID == "" {
		return f.Fingerprint()
	}
	sum := sha256.Sum256([]byte("iac-root:" + rootID + "|" + f.Fingerprint()))
	return hex.EncodeToString(sum[:16])
}

// gapKind classifies an error diagnostic: "size", "depth", "read" or "syntax".
func gapKind(d *hcl.Diagnostic) string {
	switch {
	case d.Summary == unreadableSummary:
		return "read"
	case d.Summary == parseLimitSummary && strings.Contains(d.Detail, "file size"):
		return "size"
	case d.Summary == parseLimitSummary:
		return "depth"
	}
	return "syntax"
}

var gapTitles = map[string]string{
	"size":   "IaC file not scanned: exceeds the file size limit",
	"depth":  "IaC file not scanned: exceeds parser nesting limits",
	"read":   "IaC file not scanned: could not be read",
	"syntax": "IaC file not scanned: syntax error",
}

// gapFindings turns error diagnostics into one ERROR finding per file, so a hostile, generated or
// broken file is reported (and fails the --fail-on gate, and shows in SARIF/PR output) instead of
// crashing or vanishing. reasons maps each root-relative file to "<kind>: <detail>".
func gapFindings(diags hcl.Diagnostics, root, rootID string, now time.Time) ([]model.Finding, map[string]string) {
	var out []model.Finding
	reasons := map[string]string{}
	for _, d := range diags {
		if d.Severity != hcl.DiagError || d.Subject == nil || d.Subject.Filename == "" {
			continue
		}
		rel := d.Subject.Filename
		if root != "" {
			if r, err := filepath.Rel(root, rel); err == nil && r != "" && !strings.HasPrefix(r, "..") {
				rel = r
			}
		}
		rel = filepath.ToSlash(rel)
		if _, seen := reasons[rel]; seen {
			continue // one finding per file: the first error explains it
		}
		kind := gapKind(d)
		detail := d.Detail
		if kind == "syntax" {
			detail = fmt.Sprintf("line %d: %s: %s", d.Subject.Start.Line, d.Summary, d.Detail)
		}
		reasons[rel] = kind + ": " + detail
		f := model.Finding{
			Source: "nimbus-iac", CheckID: "IAC_PARSE_LIMIT", CanonicalID: "IAC_PARSE_LIMIT", Title: gapTitles[kind],
			Description: detail, Severity: model.High, Status: model.Error, Provider: model.ProviderIaC, Account: "iac", File: rel, LineStart: 1,
			Resource: model.Resource{ID: rel, Type: "file", Name: rel, Attributes: map[string]any{"file": rel}},
			Tags:     map[string]string{"framework": "terraform", output.TagScanGap: kind},
		}
		f.ID = rootedID(f, rootID)
		f.Finalize(now)
		f.Status = model.Error
		out = append(out, f)
	}
	return out, reasons
}

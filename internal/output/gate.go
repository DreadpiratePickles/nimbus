package output

import "github.com/DreadpiratePickles/nimbus/internal/model"

// TagScanGap marks a finding that reports something the scan could not examine (an IaC file that
// did not parse, or exceeded the size or nesting limits; the value says why). Such a finding has
// Status ERROR; it is not a misconfiguration, but whatever the unexamined input contains is
// unknown, so it fails closed: it blocks every --fail-on threshold and is rendered in SARIF, JSON
// and PR output (Verification 3 defect 2).
const TagScanGap = "scan_gap"

// IsScanGap reports whether f marks input the scan could not examine.
func IsScanGap(f model.Finding) bool { return f.Tags[TagScanGap] != "" }

// GateBlocks reports whether f fails a --fail-on sev gate: an open (FAIL) finding at or above
// sev, or any scan gap whatever its severity. An empty sev disables the gate.
func GateBlocks(f model.Finding, sev string) bool {
	if sev == "" {
		return false
	}
	if IsScanGap(f) {
		return true
	}
	return f.Status == model.Fail && f.Severity.Rank() >= model.ParseSeverity(sev).Rank()
}

// GateCount is the number of findings that fail a --fail-on sev gate (see GateBlocks).
func GateCount(fs []model.Finding, sev string) int {
	n := 0
	for _, f := range fs {
		if GateBlocks(f, sev) {
			n++
		}
	}
	return n
}

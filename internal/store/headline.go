package store

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// Headline is the one set of header numbers every surface prints (W5-ISSUES item 2, r3 #4):
// ingest / scan summaries, `scan --diff`, `plan`, GET /api/summary ("headline"), the dashboard
// risk panel and the MCP summary resource. The unit is the Issue: attack-path Issues (one per
// entry → anchor → rule; hop variants are evidence) and finding Issues (single + combination, one
// per check × resource). "Critical" is always the Issue's severity: the band of a path Issue's
// score, the analysis verdict of a finding Issue — never a raw scanner severity or a hop
// variant. Open means open | reopened; the closure sub-states are counted apart.
type Headline struct {
	Unit string `json:"unit"` // always "issues"

	Issues   int `json:"issues"`   // open Issues of every produced kind (PathIssues + FindingIssues)
	Critical int `json:"critical"` // open Issues whose severity is CRITICAL (PathCritical + FindingCritical)

	PathIssues   int            `json:"path_issues"`   // open attack-path Issues
	PathVariants int            `json:"path_variants"` // hop variants behind them (distinct hop lists)
	PathCritical int            `json:"path_critical"` // open path Issues in band Critical
	PathByBand   map[string]int `json:"path_by_band"`

	FindingIssues   int `json:"finding_issues"`   // open single + combination Issues
	FindingCritical int `json:"finding_critical"` // of which CRITICAL
	Combinations    int `json:"combinations"`     // open toxic-combination Issues (part of FindingIssues)

	BySeverity map[string]int `json:"by_severity"` // open Issues of every kind by severity
	ByProvider map[string]int `json:"by_provider"` // open Issues of every kind by provider

	// OpenFindings are the failing scanner results behind the Issues (evidence, not a headline unit).
	OpenFindings int `json:"open_findings"`

	PendingVerification int `json:"pending_verification"`
	VerifiedFixed       int `json:"verified_fixed"`
	Resolved            int `json:"resolved"`
	Suppressed          int `json:"suppressed"`
	RegressedOpen       int `json:"regressed_open"` // open Issues that had been verified_fixed
}

// Headline computes the header numbers from the stored Issues and findings.
func (s *Store) Headline() (*Headline, error) {
	h := &Headline{Unit: "issues", PathByBand: map[string]int{}, BySeverity: map[string]int{}, ByProvider: map[string]int{}}
	rows, err := s.db.Query(`SELECT kind, state, severity, COALESCE(band,''), COALESCE(provider,''), COALESCE(secondary_keys,''), COALESCE(regressed_after_verify,0) FROM issues`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var kind, state, sev, band, prov, keys string
		var regressed bool
		if err := rows.Scan(&kind, &state, &sev, &band, &prov, &keys, &regressed); err != nil {
			return nil, err
		}
		if kind != model.IssuePath && kind != model.IssueSingle && kind != model.IssueCombination {
			continue // reserved kinds are not produced
		}
		switch state {
		case model.StatePendingVerification:
			h.PendingVerification++
			continue
		case model.StateVerifiedFixed:
			h.VerifiedFixed++
			continue
		case model.StateResolved:
			h.Resolved++
			continue
		case model.StateSuppressed:
			h.Suppressed++
			continue
		}
		if !model.IsActive(state) {
			continue
		}
		crit := sev == string(model.Critical)
		h.Issues++
		h.BySeverity[sev]++
		h.ByProvider[prov]++
		if regressed {
			h.RegressedOpen++
		}
		if crit {
			h.Critical++
		}
		if kind == model.IssuePath {
			h.PathIssues++
			h.PathByBand[band]++
			var ks []string
			if json.Unmarshal([]byte(keys), &ks) == nil && len(ks) > 0 {
				h.PathVariants += len(ks)
			} else {
				h.PathVariants++
			}
			if crit {
				h.PathCritical++
			}
			continue
		}
		h.FindingIssues++
		if kind == model.IssueCombination {
			h.Combinations++
		}
		if crit {
			h.FindingCritical++
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := s.db.QueryRow("SELECT COUNT(*) FROM findings WHERE status = 'FAIL' AND state IN ('open','reopened')").Scan(&h.OpenFindings); err != nil {
		return nil, err
	}
	return h, nil
}

func plural(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
}

// Text is the one-line headline every text surface prints:
// "83 open Issues: 19 attack path Issues (22 hop variants) + 64 finding Issues; 12 critical (2 path, 10 finding)".
func (h *Headline) Text() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s: %s (%s) + %s; %d critical (%d path, %d finding)",
		plural(h.Issues, "open Issue", "open Issues"), plural(h.PathIssues, "attack path Issue", "attack path Issues"),
		plural(h.PathVariants, "hop variant", "hop variants"), plural(h.FindingIssues, "finding Issue", "finding Issues"),
		h.Critical, h.PathCritical, h.FindingCritical)
	return b.String()
}

// ClosureText summarises the closed and pending Issues ("" when there are none).
func (h *Headline) ClosureText() string {
	var parts []string
	for _, x := range []struct {
		n    int
		what string
	}{{h.PendingVerification, "pending verification"}, {h.VerifiedFixed, "verified fixed"}, {h.Resolved, "resolved"}, {h.Suppressed, "suppressed"}, {h.RegressedOpen, "regressed after verify (open)"}} {
		if x.n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", x.n, x.what))
		}
	}
	return strings.Join(parts, ", ")
}

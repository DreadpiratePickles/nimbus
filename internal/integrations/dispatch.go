package integrations

import (
	"context"
	"fmt"
	"path"
	"strings"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/model"
	"github.com/DreadpiratePickles/nimbus/internal/store"
)

// Closer is implemented by sinks that can resolve a previously-created ticket/alert when the
// finding passes again (GitHub issue close, PagerDuty resolve, Jira transition).
type Closer interface {
	Close(ctx context.Context, f model.Finding, ref string) error
}

// Rule is a notification rule: which findings a sink receives (Datadog-style, one rule covers many checks).
type Rule struct {
	MinSeverity      model.Severity
	Providers        []string
	Accounts         []string
	CanonicalIDs     []string // glob patterns, e.g. "S3_*"
	Weaknesses       []string
	OnlyOnAttackPath bool
}

func (r Rule) Matches(f model.Finding, onPath bool) bool {
	if r.MinSeverity != "" && f.Severity.Rank() < r.MinSeverity.Rank() {
		return false
	}
	if len(r.Providers) > 0 && !containsFold(r.Providers, f.Provider) {
		return false
	}
	if len(r.Accounts) > 0 && !containsFold(r.Accounts, f.Account) && !containsFold(r.Accounts, f.Tags["account_label"]) {
		return false
	}
	if len(r.CanonicalIDs) > 0 {
		ok := false
		for _, p := range r.CanonicalIDs {
			if m, _ := path.Match(strings.ToUpper(p), f.CanonicalID); m {
				ok = true
			}
		}
		if !ok {
			return false
		}
	}
	if len(r.Weaknesses) > 0 {
		ok := false
		for _, w := range r.Weaknesses {
			if f.HasWeakness(w) {
				ok = true
			}
		}
		if !ok {
			return false
		}
	}
	if r.OnlyOnAttackPath && !onPath {
		return false
	}
	return true
}

// Suppression mutes a finding/check/resource until it expires (never forever by default).
type Suppression struct {
	FindingID   string    `json:"finding_id,omitempty"`
	CanonicalID string    `json:"canonical_id,omitempty"`
	ResourceID  string    `json:"resource_id,omitempty"` // glob
	Reason      string    `json:"reason"`
	ExpiresAt   time.Time `json:"expires_at"`
}

func (s Suppression) Matches(f model.Finding, now time.Time) bool {
	if !s.ExpiresAt.IsZero() && now.After(s.ExpiresAt) {
		return false
	}
	if s.FindingID != "" && s.FindingID != f.ID {
		return false
	}
	if s.CanonicalID != "" && !strings.EqualFold(s.CanonicalID, f.CanonicalID) {
		return false
	}
	if s.ResourceID != "" {
		if m, _ := path.Match(s.ResourceID, f.Resource.ID); !m && s.ResourceID != f.Resource.ID {
			return false
		}
	}
	return s.FindingID != "" || s.CanonicalID != "" || s.ResourceID != ""
}

type Target struct {
	Sink Sink
	Rule Rule
}

type Options struct {
	Force        bool
	DryRun       bool
	Suppressions []Suppression
	AutoClose    bool
	Now          time.Time
}

// Dispatch sends each FAIL finding to every matching sink once (deduplicated via the store),
// and when AutoClose is on, closes tickets for findings that now PASS.
func Dispatch(ctx context.Context, st *store.Store, targets []Target, findings []model.Finding, paths []model.AttackPath, opts Options) []Result {
	now := opts.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	byFinding := map[string][]model.AttackPath{}
	for _, p := range paths {
		for _, id := range p.FindingIDs {
			byFinding[id] = append(byFinding[id], p)
		}
	}
	var results []Result
	for _, f := range findings {
		if f.Status == model.Pass && opts.AutoClose {
			for _, t := range targets {
				c, ok := t.Sink.(Closer)
				if !ok {
					continue
				}
				if ref, done := st.Alerted(f.ID, t.Sink.Name()); done && ref != "" && !strings.HasPrefix(ref, "closed:") {
					r := Result{Channel: t.Sink.Name(), FindingID: f.ID, Ref: ref}
					if opts.DryRun {
						r.Skipped = true
					} else if err := c.Close(ctx, f, ref); err != nil {
						r.Err = err.Error()
					} else {
						st.MarkAlerted(f.ID, t.Sink.Name(), "closed:"+ref)
						r.Ref = "closed:" + ref
					}
					results = append(results, r)
				}
			}
			continue
		}
		if f.Status != model.Fail {
			continue
		}
		suppressed := false
		for _, s := range opts.Suppressions {
			if s.Matches(f, now) {
				suppressed = true
				results = append(results, Result{Channel: "suppressed", FindingID: f.ID, Ref: s.Reason, Skipped: true})
				break
			}
		}
		if suppressed {
			continue
		}
		onPath := len(byFinding[f.ID]) > 0
		for _, t := range targets {
			if !t.Rule.Matches(f, onPath) {
				continue
			}
			r := Result{Channel: t.Sink.Name(), FindingID: f.ID}
			if !opts.Force {
				if ref, done := st.Alerted(f.ID, t.Sink.Name()); done && !strings.HasPrefix(ref, "closed:") {
					r.Ref, r.Skipped = ref, true
					results = append(results, r)
					continue
				}
			}
			if opts.DryRun {
				r.Ref, r.Skipped = "dry-run", true
				results = append(results, r)
				continue
			}
			ref, err := t.Sink.Deliver(ctx, f, byFinding[f.ID])
			if err != nil {
				r.Err = err.Error()
			} else {
				r.Ref = ref
				if err := st.MarkAlerted(f.ID, t.Sink.Name(), ref); err != nil {
					r.Err = fmt.Sprintf("delivered but could not record: %v", err)
				}
			}
			results = append(results, r)
		}
	}
	return results
}

func containsFold(list []string, v string) bool {
	for _, x := range list {
		if strings.EqualFold(x, v) {
			return true
		}
	}
	return false
}

package core

import (
	"strings"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/catalog"
	"github.com/DreadpiratePickles/nimbus/internal/graph"
	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// Check describes one evaluated control on one resource. CheckID is the
// Prowler alias from catalog.yaml (or the Steampipe alias for Okta checks).
type Check struct {
	CheckID      string
	Provider     string
	Account      string
	AccountLabel string
	Region       string
	Resource     model.Resource
	Pass         bool
	// Detail is the human explanation of the evaluated state (becomes Description).
	Detail string
	// Severity overrides the catalog default when set.
	Severity model.Severity
	// AliasSource is the catalog alias namespace for CheckID; default "prowler" then "steampipe".
	AliasSource string
}

// Finding builds a finalized, catalog-enriched finding with Source "nimbus".
func (c Check) Finding(now time.Time) model.Finding {
	f := model.Finding{
		Source:      Source,
		CheckID:     c.CheckID,
		Provider:    c.Provider,
		Account:     c.Account,
		Region:      c.Region,
		Resource:    c.Resource,
		Description: c.Detail,
		Severity:    c.Severity,
		Status:      model.Fail,
	}
	if c.Pass {
		f.Status = model.Pass
	}
	if c.AccountLabel != "" && c.AccountLabel != c.Account {
		f.Tags = map[string]string{"account_label": c.AccountLabel}
	}
	if e, ok := LookupCheck(c.AliasSource, c.CheckID); ok {
		f.CanonicalID = e.ID
		f.Title = e.Title
		if f.Severity == "" {
			f.Severity = e.Severity
		}
		if f.Resource.Type == "" {
			f.Resource.Type = e.ResourceType
		}
		f.Weaknesses = append([]string(nil), e.Weaknesses...)
		for fw, ctrls := range e.Compliance {
			f.AddCompliance(fw, ctrls...)
		}
		if len(e.Remediation) > 0 {
			f.Remediation = "cloud-posture fix --finding " + e.ID + " (templates: " + strings.Join(e.Remediation, ", ") + ")"
		}
	}
	if f.Title == "" {
		f.Title = strings.ReplaceAll(c.CheckID, "_", " ")
	}
	f.Finalize(now)
	return f
}

// LookupCheck resolves a native alias in the embedded catalog. With an empty source
// it tries the prowler namespace, then steampipe.
func LookupCheck(source, checkID string) (*catalog.Entry, bool) {
	cat := catalog.Default()
	if source != "" {
		return cat.Lookup(source, checkID)
	}
	for _, s := range []string{"prowler", "steampipe"} {
		if e, ok := cat.Lookup(s, checkID); ok {
			return e, true
		}
	}
	return nil, false
}

// AttachFinding marks the graph node behind a FAIL finding with its weaknesses and
// finding ID without disturbing the node's type, class or context fields.
func AttachFinding(g *graph.Graph, f model.Finding) {
	if f.Status != model.Fail || f.Resource.ID == "" {
		return
	}
	n := &graph.Node{ID: f.Resource.ID, Type: f.Resource.Type, Name: f.Resource.Name, Provider: f.Provider, Account: f.Account, Region: f.Region,
		Weaknesses: append([]string(nil), f.Weaknesses...), FindingIDs: []string{f.ID}}
	if ex, ok := g.Node(f.Resource.ID); ok {
		n.Type, n.Class, n.Name = ex.Type, ex.Class, ex.Name
	}
	g.AddNode(n)
}

// AttachFindings applies AttachFinding to each finding.
func AttachFindings(g *graph.Graph, fs []model.Finding) {
	for _, f := range fs {
		AttachFinding(g, f)
	}
}

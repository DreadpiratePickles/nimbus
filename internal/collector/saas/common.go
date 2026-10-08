// Package saas implements REST collectors for SaaS control planes: GitHub
// organizations, Okta tenants and Microsoft 365 (Entra ID via Microsoft Graph).
package saas

import (
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/collector/core"
	"github.com/DreadpiratePickles/nimbus/internal/graph"
	"github.com/DreadpiratePickles/nimbus/internal/model"
)

func nowFn(f func() time.Time) time.Time {
	if f != nil {
		return f()
	}
	return time.Now().UTC()
}

// emit builds the finding, records it and attaches FAIL findings to the graph.
func emit(acc *core.Acc, g *graph.Graph, now time.Time, c core.Check) model.Finding {
	f := c.Finding(now)
	acc.Finding(f)
	core.AttachFinding(g, f)
	return f
}

// Package core holds the contracts and helpers shared by every nimbus collector:
// account specs, cost signals, the Collector interface, finding construction with
// catalog enrichment, graph node helpers, credential loading and a paginating REST
// client. Provider implementations live in sibling packages (aws, azure, gcp,
// kubernetes, saas); package collector re-exports these types and wires RunAll.
package core

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/DreadpiratePickles/nimbus/internal/graph"
	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// Source is the Finding.Source used by every native collector finding.
const Source = "nimbus"

// AccountSpec describes one cloud account / subscription / project / cluster / SaaS org to collect.
type AccountSpec struct {
	Name           string
	Provider       string
	Profile        string
	RoleARN        string
	Regions        []string
	SubscriptionID string
	TenantID       string
	ProjectID      string
	KubeContext    string
	Org            string
	Domain         string
	// TokenEnv overrides the environment variable a REST collector reads its token from.
	TokenEnv string
}

// Label is the human name of the account (Name, else the provider-specific identifier).
func (s AccountSpec) Label() string {
	for _, v := range []string{s.Name, s.SubscriptionID, s.ProjectID, s.KubeContext, s.Org, s.Domain, s.Profile} {
		if v != "" {
			return v
		}
	}
	return s.Provider
}

// Cost signal kinds.
const (
	KindUnattachedVolume  = "unattached_volume"
	KindUnassociatedIP    = "unassociated_ip"
	KindStoppedInstance   = "stopped_instance"
	KindIdleInstance      = "idle_instance"
	KindOversizedInstance = "oversized_instance"
	KindPublicEgress      = "public_egress"
	// KindServiceSpend carries Cost Explorer last-30-day spend per service (informational).
	KindServiceSpend = "service_spend"
)

// CostSignal is a raw cost observation; internal/cost prices and aggregates them.
type CostSignal struct {
	Provider, Account, Region, ResourceID, ResourceType, Kind string
	SizeGB                                                    float64
	InstanceType                                              string
	AvgCPU                                                    float64
	MonthlySpend                                              float64
	Attributes                                                map[string]any
}

// Result is everything one collection produced. Errors are partial failures; the
// collection still returns whatever it gathered.
type Result struct {
	Findings []model.Finding
	Cost     []CostSignal
	Runs     []model.ToolRun
	Errors   []error
	// Warnings are non-fatal conditions (missing permissions for optional APIs).
	Warnings []string
}

// Merge appends other into r.
func (r *Result) Merge(other Result) {
	r.Findings = append(r.Findings, other.Findings...)
	r.Cost = append(r.Cost, other.Cost...)
	r.Runs = append(r.Runs, other.Runs...)
	r.Errors = append(r.Errors, other.Errors...)
	r.Warnings = append(r.Warnings, other.Warnings...)
}

// Err joins all partial errors (nil when there were none).
func (r Result) Err() error { return errors.Join(r.Errors...) }

// Collector gathers inventory, findings, graph nodes/edges and cost signals for one account.
type Collector interface {
	Name() string
	Provider() string
	Collect(ctx context.Context, spec AccountSpec, g *graph.Graph) (Result, error)
}

// Acc is a goroutine-safe Result accumulator used by parallel service collectors.
type Acc struct {
	mu sync.Mutex
	r  Result
}

func (a *Acc) Finding(fs ...model.Finding) {
	a.mu.Lock()
	a.r.Findings = append(a.r.Findings, fs...)
	a.mu.Unlock()
}

func (a *Acc) Cost(cs ...CostSignal) {
	a.mu.Lock()
	a.r.Cost = append(a.r.Cost, cs...)
	a.mu.Unlock()
}

// Error records a partial failure, labelled with the service / scope that produced it.
func (a *Acc) Error(scope string, err error) {
	if err == nil {
		return
	}
	a.mu.Lock()
	a.r.Errors = append(a.r.Errors, fmt.Errorf("%s: %w", scope, err))
	a.mu.Unlock()
}

func (a *Acc) Warn(format string, args ...any) {
	a.mu.Lock()
	a.r.Warnings = append(a.r.Warnings, fmt.Sprintf(format, args...))
	a.mu.Unlock()
}

func (a *Acc) Run(r model.ToolRun) {
	a.mu.Lock()
	a.r.Runs = append(a.r.Runs, r)
	a.mu.Unlock()
}

// Result returns a copy of the accumulated result.
func (a *Acc) Result() Result {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := a.r
	out.Findings = append([]model.Finding(nil), a.r.Findings...)
	out.Cost = append([]CostSignal(nil), a.r.Cost...)
	out.Runs = append([]model.ToolRun(nil), a.r.Runs...)
	out.Errors = append([]error(nil), a.r.Errors...)
	out.Warnings = append([]string(nil), a.r.Warnings...)
	return out
}

// Package collector runs nimbus's agentless collectors (AWS, Azure, GCP, Kubernetes,
// GitHub, Okta, Microsoft 365) across many accounts in parallel and merges their
// security graphs, findings and cost signals. Shared contracts live in
// internal/collector/core and are re-exported here as aliases.
package collector

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"

	awscol "github.com/DreadpiratePickles/nimbus/internal/collector/aws"
	"github.com/DreadpiratePickles/nimbus/internal/collector/azure"
	"github.com/DreadpiratePickles/nimbus/internal/collector/core"
	"github.com/DreadpiratePickles/nimbus/internal/collector/gcp"
	"github.com/DreadpiratePickles/nimbus/internal/collector/k8s"
	"github.com/DreadpiratePickles/nimbus/internal/collector/saas"
	"github.com/DreadpiratePickles/nimbus/internal/graph"
	"github.com/DreadpiratePickles/nimbus/internal/model"
)

type (
	AccountSpec = core.AccountSpec
	CostSignal  = core.CostSignal
	Result      = core.Result
	Collector   = core.Collector
)

// Cost signal kinds.
const (
	KindUnattachedVolume  = core.KindUnattachedVolume
	KindUnassociatedIP    = core.KindUnassociatedIP
	KindStoppedInstance   = core.KindStoppedInstance
	KindIdleInstance      = core.KindIdleInstance
	KindOversizedInstance = core.KindOversizedInstance
	KindPublicEgress      = core.KindPublicEgress
	KindServiceSpend      = core.KindServiceSpend
)

var factories = map[string]func() Collector{
	model.ProviderAWS:        func() Collector { return awscol.New() },
	model.ProviderAzure:      func() Collector { return azure.New() },
	model.ProviderGCP:        func() Collector { return gcp.New() },
	model.ProviderKubernetes: func() Collector { return k8s.New() },
	model.ProviderGitHub:     func() Collector { return saas.NewGitHub() },
	model.ProviderOkta:       func() Collector { return saas.NewOkta() },
	model.ProviderM365:       func() Collector { return saas.NewM365() },
}

// ForProvider returns a fresh collector for a provider name (aliases such as
// "k8s", "gh", "microsoft365" are normalized).
func ForProvider(provider string) (Collector, bool) {
	f, ok := factories[model.NormalizeProvider(provider)]
	if !ok {
		return nil, false
	}
	return f(), true
}

// Providers lists the providers with a native collector.
func Providers() []string {
	out := make([]string, 0, len(factories))
	for p := range factories {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// Options tunes RunAll.
type Options struct {
	// Concurrency bounds accounts collected at once (default 4). Each collector
	// bounds its own region / service fan-out.
	Concurrency int
	// AccountTimeout caps one account's collection (0 = no limit beyond ctx).
	AccountTimeout time.Duration
	// Collectors overrides ForProvider by normalized provider name (tests, plugins).
	Collectors map[string]Collector
	// OnAccount is called after each account completes (progress reporting).
	OnAccount func(spec AccountSpec, res Result, err error)
}

// RunAll collects every account in parallel (bounded), merges the per-account
// graphs and results, and never aborts on a partial failure: account-level errors
// become Result.Errors and a failed ToolRun.
func RunAll(ctx context.Context, specs []AccountSpec, opts Options) (*graph.Graph, Result) {
	limit := opts.Concurrency
	if limit <= 0 {
		limit = 4
	}
	master := graph.New()
	var (
		mu  sync.Mutex
		out Result
	)
	var eg errgroup.Group
	eg.SetLimit(limit)
	for _, spec := range specs {
		eg.Go(func() error {
			res, g, err := runOne(ctx, spec, opts)
			mu.Lock()
			defer mu.Unlock()
			if g != nil {
				master.Merge(g)
			}
			out.Merge(res)
			if opts.OnAccount != nil {
				opts.OnAccount(spec, res, err)
			}
			return nil
		})
	}
	_ = eg.Wait()
	sort.SliceStable(out.Findings, func(i, j int) bool { return out.Findings[i].ID < out.Findings[j].ID })
	return master, out
}

func runOne(ctx context.Context, spec AccountSpec, opts Options) (res Result, g *graph.Graph, err error) {
	provider := model.NormalizeProvider(spec.Provider)
	label := spec.Label()
	c, ok := opts.Collectors[provider]
	if !ok {
		c, ok = ForProvider(provider)
	}
	if !ok {
		err = fmt.Errorf("account %s: no collector for provider %q", label, spec.Provider)
		return Result{Errors: []error{err}, Runs: []model.ToolRun{{Tool: "nimbus-" + provider, Account: label, Status: "skipped", Message: err.Error()}}}, nil, err
	}
	if opts.AccountTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, opts.AccountTimeout)
		defer cancel()
	}
	g = graph.New()
	func() {
		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("account %s: collector %s panicked: %v", label, c.Name(), r)
			}
		}()
		res, err = c.Collect(ctx, spec, g)
	}()
	if err != nil {
		res.Errors = append(res.Errors, err)
	}
	if len(res.Runs) == 0 {
		run := model.ToolRun{Tool: "nimbus-" + c.Name(), Account: label, Status: "ok", Findings: len(res.Findings)}
		switch {
		case err != nil:
			run.Status, run.Message = "failed", err.Error()
		case len(res.Errors) > 0:
			run.Message = fmt.Sprintf("%d partial errors: %s", len(res.Errors), summarize(res.Errors))
		}
		res.Runs = append(res.Runs, run)
	}
	return res, g, err
}

func summarize(errs []error) string {
	var parts []string
	for i, e := range errs {
		if i == 3 {
			parts = append(parts, fmt.Sprintf("... and %d more", len(errs)-3))
			break
		}
		parts = append(parts, e.Error())
	}
	return strings.Join(parts, "; ")
}

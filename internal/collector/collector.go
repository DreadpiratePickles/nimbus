// Package collector runs nimbus's agentless collectors (AWS, Azure, GCP, Kubernetes,
// GitHub, Okta, Microsoft 365) across many accounts in parallel and merges their
// security graphs, findings and cost signals. Shared contracts live in
// internal/collector/core and are re-exported here as aliases.
package collector

import (
	"context"
	"errors"
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
	AccountSpec  = core.AccountSpec
	CostSignal   = core.CostSignal
	Result       = core.Result
	Collector    = core.Collector
	CollectError = core.CollectError
)

// DefaultAccountTimeout caps one account's collection when Options.AccountTimeout is 0.
const DefaultAccountTimeout = 10 * time.Minute

// defaultTimeoutGrace is how long a collector may keep running after its deadline to
// return partial results before RunAll abandons it.
const defaultTimeoutGrace = 30 * time.Second

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
	// AccountTimeout caps one account's collection (0 = DefaultAccountTimeout, 10m;
	// negative = no limit beyond ctx). On expiry the account records a CollectError
	// {API: "account", Reason: "timeout"} and a ToolRun with status "timeout"; a
	// parent-context cancel records Reason/status "canceled".
	AccountTimeout time.Duration
	// TimeoutGrace is how long a collector that ignores its context may run past the
	// deadline before it is abandoned (default 30s).
	TimeoutGrace time.Duration
	// TrustedCIDRs (config trusted_cidrs) are copied into every AccountSpec that has
	// none, so collectors label trusted-only exposure.
	TrustedCIDRs []string
	// Collectors overrides ForProvider by normalized provider name (tests, plugins).
	Collectors map[string]Collector
	// OnAccount is called after each account completes (progress reporting).
	OnAccount func(spec AccountSpec, res Result, err error)
}

// DefaultConcurrency is how many accounts RunAll collects at once when unset.
const DefaultConcurrency = 4

// RunAll collects every account in parallel (bounded), merges the per-account
// graphs and results, and never aborts on a partial failure: account-level errors
// become Result.Errors and a failed ToolRun.
func RunAll(ctx context.Context, specs []AccountSpec, opts Options) (*graph.Graph, Result) {
	limit := opts.Concurrency
	if limit <= 0 {
		limit = DefaultConcurrency
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

func (o Options) accountTimeout() time.Duration {
	switch {
	case o.AccountTimeout < 0:
		return 0
	case o.AccountTimeout == 0:
		return DefaultAccountTimeout
	}
	return o.AccountTimeout
}

func runOne(ctx context.Context, spec AccountSpec, opts Options) (res Result, g *graph.Graph, err error) {
	provider := model.NormalizeProvider(spec.Provider)
	label := spec.Label()
	if len(spec.TrustedCIDRs) == 0 && len(opts.TrustedCIDRs) > 0 {
		spec.TrustedCIDRs = append([]string(nil), opts.TrustedCIDRs...)
	}
	c, ok := opts.Collectors[provider]
	if !ok {
		c, ok = ForProvider(provider)
	}
	if !ok {
		err = fmt.Errorf("account %s: no collector for provider %q", label, spec.Provider)
		ce := &core.CollectError{Provider: provider, Account: label, API: "collector", Reason: "unsupported_provider", Message: err.Error(), Err: err}
		return Result{Errors: []error{ce}, Runs: []model.ToolRun{{Tool: "nimbus-" + provider, Account: label, Status: "skipped", Message: err.Error()}}}, nil, err
	}
	var timeout time.Duration
	if timeout = opts.accountTimeout(); timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	grace := opts.TimeoutGrace
	if grace <= 0 {
		grace = defaultTimeoutGrace
	}
	cg := graph.New() // the collector's private graph; never shared with an abandoned goroutine
	type outcome struct {
		res Result
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		var o outcome
		defer func() {
			if r := recover(); r != nil {
				o.err = fmt.Errorf("account %s: collector %s panicked: %v", label, c.Name(), r)
			}
			done <- o
		}()
		o.res, o.err = c.Collect(ctx, spec, cg)
	}()
	abandoned := false
	var ctxErr error // the account context's state when the collector returned (or was abandoned)
	select {
	case o := <-done:
		res, err, ctxErr = o.res, o.err, ctx.Err()
	case <-ctx.Done():
		select {
		case o := <-done:
			res, err = o.res, o.err
		case <-time.After(grace):
			// The collector ignores its context: abandon it (its private graph and
			// results are dropped) so one stuck account cannot hang the scan.
			abandoned = true
		}
		ctxErr = ctx.Err()
	}
	if !abandoned {
		g = cg
	}
	// A run whose context ended (account deadline or parent cancel) is incomplete no
	// matter what the collector returned: a ctx-honouring collector typically returns
	// partial results and a nil error. Record it as timeout / canceled, never ok.
	interrupted := ""
	switch {
	case errors.Is(ctxErr, context.DeadlineExceeded):
		interrupted = core.ReasonTimeout
		if timeout > 0 {
			err = fmt.Errorf("account %s: collection exceeded %s: %w", label, timeout, context.DeadlineExceeded)
		} else {
			err = fmt.Errorf("account %s: collection deadline exceeded: %w", label, context.DeadlineExceeded)
		}
		res.Errors = append(res.Errors, &core.CollectError{API: "account", Reason: core.ReasonTimeout, Message: err.Error(), Err: err})
	case errors.Is(ctxErr, context.Canceled):
		interrupted = core.ReasonCanceled
		err = fmt.Errorf("account %s: collection canceled: %w", label, context.Canceled)
		res.Errors = append(res.Errors, &core.CollectError{API: "account", Reason: core.ReasonCanceled, Message: err.Error(), Err: err})
	case err != nil:
		res.Errors = append(res.Errors, err)
	}
	res.Errors = core.AttributeErrors(res.Errors, provider, label)
	if len(res.Runs) == 0 {
		run := model.ToolRun{Tool: "nimbus-" + c.Name(), Account: label, Status: "ok", Findings: len(res.Findings)}
		switch {
		case interrupted != "":
			run.Status, run.Message = interrupted, err.Error()
		case err != nil:
			run.Status, run.Message = "failed", err.Error()
		case len(res.Errors) > 0:
			run.Message = fmt.Sprintf("%d partial errors: %s", len(res.Errors), summarize(res.Errors))
		}
		res.Runs = append(res.Runs, run)
	} else if interrupted != "" {
		for i := range res.Runs {
			if res.Runs[i].Status == "ok" {
				res.Runs[i].Status, res.Runs[i].Message = interrupted, err.Error()
			}
		}
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

package collector

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/collector/core"
	"github.com/DreadpiratePickles/nimbus/internal/graph"
	"github.com/DreadpiratePickles/nimbus/internal/model"
)

type fakeCollector struct {
	provider string
	mode     string // ok | partial | fatal | panic | slow
	inFlight *int32
	maxSeen  *int32
}

func (f *fakeCollector) Name() string     { return f.provider }
func (f *fakeCollector) Provider() string { return f.provider }

func (f *fakeCollector) Collect(ctx context.Context, spec AccountSpec, g *graph.Graph) (Result, error) {
	if f.inFlight != nil {
		n := atomic.AddInt32(f.inFlight, 1)
		defer atomic.AddInt32(f.inFlight, -1)
		for {
			m := atomic.LoadInt32(f.maxSeen)
			if n <= m || atomic.CompareAndSwapInt32(f.maxSeen, m, n) {
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	switch f.mode {
	case "fatal":
		return Result{}, errors.New("no credentials")
	case "panic":
		panic("boom")
	case "slow":
		<-ctx.Done()
		return Result{}, ctx.Err()
	}
	id := "res-" + spec.Name
	core.AddResource(g, core.Res{Provider: f.provider, Account: spec.Name, Resource: model.Resource{ID: id, Type: "aws_s3_bucket", Name: id}})
	f1 := core.Check{CheckID: "s3_bucket_public_access", Provider: f.provider, Account: spec.Name, Resource: model.Resource{ID: id, Type: "aws_s3_bucket"}}.Finding(time.Now())
	res := Result{Findings: []model.Finding{f1}, Cost: []CostSignal{{Kind: KindUnattachedVolume, ResourceID: id}}}
	if f.mode == "partial" {
		res.Errors = []error{errors.New("rds: throttled")}
	}
	return res, nil
}

func TestRunAll(t *testing.T) {
	specs := []AccountSpec{
		{Name: "a1", Provider: "aws"},
		{Name: "a2", Provider: "amazon"},
		{Name: "z1", Provider: "azure"},
		{Name: "g1", Provider: "gcp"},
		{Name: "k1", Provider: "k8s"},
		{Name: "x1", Provider: "nonsense"},
	}
	opts := Options{Collectors: map[string]Collector{
		"aws":        &fakeCollector{provider: "aws", mode: "ok"},
		"azure":      &fakeCollector{provider: "azure", mode: "partial"},
		"gcp":        &fakeCollector{provider: "gcp", mode: "fatal"},
		"kubernetes": &fakeCollector{provider: "kubernetes", mode: "panic"},
	}}
	var calls int32
	opts.OnAccount = func(AccountSpec, Result, error) { atomic.AddInt32(&calls, 1) }
	g, res := RunAll(context.Background(), specs, opts)

	if calls != int32(len(specs)) {
		t.Errorf("OnAccount calls = %d", calls)
	}
	if len(res.Findings) != 3 {
		t.Errorf("findings = %d, want 3 (a1, a2, z1)", len(res.Findings))
	}
	if len(res.Cost) != 3 {
		t.Errorf("cost = %d", len(res.Cost))
	}
	// partial (1) + fatal (1) + panic (1) + unknown provider (1)
	if len(res.Errors) != 4 {
		t.Errorf("errors = %v", res.Errors)
	}
	status := map[string]string{}
	for _, r := range res.Runs {
		status[r.Account] = r.Status
	}
	want := map[string]string{"a1": "ok", "a2": "ok", "z1": "ok", "g1": "failed", "k1": "failed", "x1": "skipped"}
	for k, v := range want {
		if status[k] != v {
			t.Errorf("run %s status = %q, want %q", k, status[k], v)
		}
	}
	for _, id := range []string{"res-a1", "res-a2", "res-z1"} {
		if _, ok := g.Node(id); !ok {
			t.Errorf("merged graph missing %s", id)
		}
	}
	if _, ok := g.Node(core.AccountNodeID("aws", "a1")); !ok {
		t.Error("account node missing")
	}
}

func TestRunAllBoundedConcurrency(t *testing.T) {
	var inFlight, maxSeen int32
	fc := &fakeCollector{provider: "aws", mode: "ok", inFlight: &inFlight, maxSeen: &maxSeen}
	var specs []AccountSpec
	for i := 0; i < 12; i++ {
		specs = append(specs, AccountSpec{Name: string(rune('a' + i)), Provider: "aws"})
	}
	_, res := RunAll(context.Background(), specs, Options{Concurrency: 3, Collectors: map[string]Collector{"aws": fc}})
	if maxSeen > 3 || maxSeen < 2 {
		t.Errorf("max in flight = %d, want <=3", maxSeen)
	}
	if len(res.Findings) != 12 {
		t.Errorf("findings = %d", len(res.Findings))
	}
}

func TestRunAllAccountTimeout(t *testing.T) {
	_, res := RunAll(context.Background(), []AccountSpec{{Name: "s", Provider: "aws"}}, Options{AccountTimeout: 20 * time.Millisecond,
		Collectors: map[string]Collector{"aws": &fakeCollector{provider: "aws", mode: "slow"}}})
	if len(res.Errors) != 1 || !errors.Is(res.Errors[0], context.DeadlineExceeded) {
		t.Fatalf("errors = %v", res.Errors)
	}
}

func TestForProvider(t *testing.T) {
	cases := map[string]string{"aws": "aws", "Azure": "azure", "google": "gcp", "k8s": "kubernetes", "gh": "github", "okta": "okta", "office365": "m365"}
	for in, want := range cases {
		c, ok := ForProvider(in)
		if !ok || c.Provider() != want {
			t.Errorf("ForProvider(%q) = %v %v", in, c, ok)
		}
	}
	if _, ok := ForProvider("oci"); ok {
		t.Error("oci has no native collector")
	}
	if len(Providers()) != 7 {
		t.Errorf("providers = %v", Providers())
	}
}

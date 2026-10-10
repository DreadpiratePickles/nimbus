package cli

import (
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/collector"
	"github.com/DreadpiratePickles/nimbus/internal/config"
)

// V2 defect 12: an unset scan.parallel uses the collector default (4), not 1.
func TestCollectorConcurrencyDefault(t *testing.T) {
	old := collectorHook
	collectorHook = nil
	t.Cleanup(func() { collectorHook = old })
	cfg := &config.Config{}
	if got := collectorOptions(cfg, nil).Concurrency; got != collector.DefaultConcurrency {
		t.Fatalf("unset scan.parallel → concurrency %d, want %d", got, collector.DefaultConcurrency)
	}
	cfg.Scan.Parallel = 2
	if got := collectorOptions(cfg, nil).Concurrency; got != 2 {
		t.Fatalf("scan.parallel 2 → %d", got)
	}
	cfg.Scan.Parallel = -3
	if got := collectorOptions(cfg, nil).Concurrency; got != collector.DefaultConcurrency {
		t.Fatalf("negative scan.parallel → %d, want the default", got)
	}
}

package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/collector"
	"github.com/DreadpiratePickles/nimbus/internal/config"
	"github.com/DreadpiratePickles/nimbus/internal/cost"
	"github.com/DreadpiratePickles/nimbus/internal/integrations"
	"github.com/DreadpiratePickles/nimbus/internal/model"
	"github.com/DreadpiratePickles/nimbus/internal/monitor"
	"github.com/DreadpiratePickles/nimbus/internal/output"
	"github.com/DreadpiratePickles/nimbus/internal/server"
	"github.com/DreadpiratePickles/nimbus/internal/store"
	"github.com/spf13/cobra"
)

var serveFlags struct {
	addr         string
	copilot      string
	scanInterval time.Duration
	monitor      bool
	monInterval  time.Duration
	token        string
}

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Live dashboard + JSON API + WebSocket updates; optional scheduled scans and change monitoring",
	Example: `  cloud-posture serve                                  # http://localhost:8080
  cloud-posture serve --scan-interval 24h --monitor    # continuous compliance + real-time change detection
  cloud-posture serve --copilot http://localhost:8081  # wire the Python copilot (nimbus serve --port 8081)`,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := signalContext()
		defer cancel()
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		st, err := openStore()
		if err != nil {
			return err
		}
		defer st.Close()
		srv := server.New(st, func() ([]byte, error) {
			res, st2, err := loadResult(ctx, cfg)
			if err != nil {
				return nil, err
			}
			st2.Close()
			return renderDashboard(res, "live", serveFlags.copilot)
		})
		srv.Logf = logf
		srv.Token = serveFlags.token
		if len(cfg.Accounts) > 0 {
			srv.Rescan = func(c context.Context) error {
				scanFlags.out = "summary"
				scanFlags.accounts = nil
				return runScan(scanCmd, nil)
			}
		}
		go srv.WatchDB(ctx, st.Path(), 2*time.Second)
		if serveFlags.scanInterval > 0 && srv.Rescan != nil {
			go srv.Schedule(ctx, serveFlags.scanInterval, srv.Rescan)
		}
		if serveFlags.monitor {
			go runMonitorLoop(ctx, cfg, serveFlags.monInterval, func(ev monitor.Event) {
				srv.Broadcast(server.Event{Type: "monitor_event", Payload: map[string]any{"title": ev.Title, "severity": ev.Severity, "resource": ev.ResourceID, "actor": ev.Actor}})
			}, true)
		}
		fmt.Printf("cloud-posture dashboard: http://%s  (API: /api/*, live: /ws)\n", displayAddr(serveFlags.addr))
		return srv.ListenAndServe(ctx, serveFlags.addr)
	},
}

func displayAddr(a string) string {
	if len(a) > 0 && a[0] == ':' {
		return "localhost" + a
	}
	return a
}

// ---------------------------------------------------------------- monitor

var monitorFlags struct {
	interval time.Duration
	once     bool
	alert    bool
	json     bool
}

var monitorCmd = &cobra.Command{
	Use:   "monitor",
	Short: "Real-time change detection from CloudTrail, Azure Activity Log and GCP audit logs; alerts on risky changes",
	Example: `  cloud-posture monitor --interval 60s --alert
  cloud-posture monitor --once --json`,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := signalContext()
		defer cancel()
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		if monitorFlags.once {
			m := monitor.New(specsFromConfig(cfg), filepath.Join(".cloud-posture", "monitor-checkpoint.json"))
			events, err := m.Poll(ctx)
			if err != nil {
				logf("monitor: %v", err)
			}
			if monitorFlags.json {
				return output.JSON(os.Stdout, events)
			}
			for _, ev := range events {
				printEvent(ev)
			}
			if len(events) == 0 {
				fmt.Println("no security-relevant changes since the last checkpoint")
			}
			return nil
		}
		return runMonitorLoop(ctx, cfg, monitorFlags.interval, func(ev monitor.Event) { printEvent(ev) }, monitorFlags.alert)
	},
}

func printEvent(ev monitor.Event) {
	fmt.Printf("%s [%s] %s — %s by %s on %s (%s/%s)\n", ev.Time.Format(time.RFC3339), ev.Severity, ev.Title, ev.EventName, ev.Actor, ev.ResourceID, ev.Provider, ev.Account)
}

func specsFromConfig(cfg *config.Config) []collector.AccountSpec { return accountSpecs(cfg) }

func accountSpecs(cfg *config.Config) []collector.AccountSpec {
	var specs []collector.AccountSpec
	for _, a := range cfg.Accounts {
		specs = append(specs, collector.AccountSpec{Name: a.Name, Provider: a.Provider, Profile: a.Profile, RoleARN: a.RoleARN, Regions: a.Regions, SubscriptionID: a.SubscriptionID, TenantID: a.TenantID, ProjectID: a.ProjectID, KubeContext: a.KubeContext, Org: a.Org, Domain: a.Domain, TokenEnv: a.TokenEnv})
	}
	return specs
}

func runMonitorLoop(ctx context.Context, cfg *config.Config, interval time.Duration, onEvent func(monitor.Event), alert bool) error {
	specs := accountSpecs(cfg)
	if len(specs) == 0 {
		return fmt.Errorf("no accounts configured for monitoring")
	}
	m := monitor.New(specs, filepath.Join(".cloud-posture", "monitor-checkpoint.json"))
	ch := make(chan monitor.Event, 64)
	go func() {
		if err := m.Run(ctx, interval, ch); err != nil && ctx.Err() == nil {
			logf("monitor stopped: %v", err)
		}
		close(ch)
	}()
	var st *store.Store
	var targets []integrations.Target
	if alert {
		if s, err := openStore(); err == nil {
			st = s
			defer s.Close()
			targets = sinksFromConfig(cfg, nil)
		}
	}
	logf("monitoring %d account(s) every %s", len(specs), interval)
	for ev := range ch {
		onEvent(ev)
		if st != nil {
			f := ev.ToFinding()
			st.UpsertFindings([]model.Finding{f})
			if len(targets) > 0 {
				integrations.Dispatch(ctx, st, targets, []model.Finding{f}, nil, integrations.Options{})
			}
		}
	}
	return nil
}

// ---------------------------------------------------------------- cost

var costFlags struct {
	json       bool
	breachCost float64
}

var costCmd = &cobra.Command{
	Use:   "cost",
	Short: "Cost optimization + security: zombie resources, rightsizing, security-driven savings and breach-risk ROI",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		data, err := os.ReadFile(filepath.Join(".cloud-posture", "cost-signals.json"))
		if err != nil {
			return fmt.Errorf("no cost signals yet — run `cloud-posture scan --accounts …` with the native collectors first")
		}
		var signals []collector.CostSignal
		if err := json.Unmarshal(data, &signals); err != nil {
			return err
		}
		res, st, err := loadResult(cmd.Context(), cfg)
		if err != nil {
			return err
		}
		defer st.Close()
		rep := cost.Analyze(signals, res.Graph, res.Paths, cost.Options{Findings: res.Findings, BreachCostUSD: costFlags.breachCost})
		if costFlags.json {
			b, err := rep.JSON()
			if err != nil {
				return err
			}
			os.Stdout.Write(b)
			return nil
		}
		fmt.Print(rep.Text())
		return nil
	},
}

func init() {
	serveCmd.Flags().StringVar(&serveFlags.addr, "addr", ":8080", "listen address")
	serveCmd.Flags().StringVar(&serveFlags.copilot, "copilot", "", "URL of the Python intelligence API for the copilot panel")
	serveCmd.Flags().DurationVar(&serveFlags.scanInterval, "scan-interval", 0, "re-scan configured accounts on this interval (continuous compliance)")
	serveCmd.Flags().BoolVar(&serveFlags.monitor, "monitor", false, "run change detection and push events to the dashboard")
	serveCmd.Flags().DurationVar(&serveFlags.monInterval, "monitor-interval", 2*time.Minute, "monitor poll interval")
	serveCmd.Flags().StringVar(&serveFlags.token, "token", os.Getenv("CLOUD_POSTURE_TOKEN"), "bearer token required for POST /api/scan")
	monitorCmd.Flags().DurationVar(&monitorFlags.interval, "interval", 2*time.Minute, "poll interval")
	monitorCmd.Flags().BoolVar(&monitorFlags.once, "once", false, "poll once and exit")
	monitorCmd.Flags().BoolVar(&monitorFlags.alert, "alert", false, "dispatch events to configured integrations")
	monitorCmd.Flags().BoolVar(&monitorFlags.json, "json", false, "JSON output (with --once)")
	costCmd.Flags().BoolVar(&costFlags.json, "json", false, "JSON output")
	costCmd.Flags().Float64Var(&costFlags.breachCost, "breach-cost", 0, "average breach cost in USD for ROI (default IBM 2024: 4.88M)")
	root.AddCommand(serveCmd, monitorCmd, costCmd)
}

package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/collector"
	"github.com/DreadpiratePickles/nimbus/internal/config"
	"github.com/DreadpiratePickles/nimbus/internal/cost"
	"github.com/DreadpiratePickles/nimbus/internal/integrations"
	"github.com/DreadpiratePickles/nimbus/internal/model"
	"github.com/DreadpiratePickles/nimbus/internal/monitor"
	"github.com/DreadpiratePickles/nimbus/internal/output"
	"github.com/DreadpiratePickles/nimbus/internal/risk"
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
	corsOrigins  []string
	allowedHosts []string
	queryTimeout time.Duration
	mcp          bool
	mcpScopes    []string
	mcpTokens    []string
}

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Live dashboard + JSON API + WebSocket updates; optional scheduled scans and change monitoring",
	Example: `  cloud-posture serve                                  # http://127.0.0.1:8080 (loopback only)
  CLOUD_POSTURE_TOKEN=… cloud-posture serve --addr 0.0.0.0:8080 --allowed-host posture.corp.example
                                                       # remote access: token required; open /?token=… once in the browser
  cloud-posture serve --scan-interval 24h --monitor    # continuous compliance + change detection by polling audit logs
  cloud-posture serve --copilot http://localhost:8081  # wire the Python copilot (nimbus serve --port 8081)
  NIMBUS_MCP_READER=… cloud-posture serve --mcp --mcp-token NIMBUS_MCP_READER=read
                                                       # MCP over streamable HTTP at /mcp (bearer token, scoped tools)`,
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
		token, err := serveToken(cmd.Flags().Changed("token"))
		if err != nil {
			return err
		}
		srv.Token = token
		srv.RiskOptions = func() risk.Options { return riskOptions(ctx, cfg) }
		srv.Traversal = storedTraversal(cfg, st)
		srv.AllowedHosts = serveFlags.allowedHosts
		srv.QueryTimeout = serveFlags.queryTimeout
		if err := server.ValidateBind(serveFlags.addr, srv.Token); err != nil {
			return err
		}
		if err := mountMCP(srv, st, cfg); err != nil {
			return err
		}
		srv.CORSOrigins = serveFlags.corsOrigins
		srv.CopilotURL = serveFlags.copilot
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

// serveToken resolves --token / $CLOUD_POSTURE_TOKEN. Surrounding whitespace is trimmed
// (a pasted " abc " would otherwise never match "Bearer abc" and lock the operator out);
// a whitespace-only value is refused: it would unlock a non-loopback bind while
// protecting nothing.
func serveToken(flagSet bool) (string, error) {
	tok, src := serveFlags.token, "--token"
	if !flagSet {
		tok, src = os.Getenv("CLOUD_POSTURE_TOKEN"), "CLOUD_POSTURE_TOKEN"
	}
	if tok != "" && strings.TrimSpace(tok) == "" {
		return "", fmt.Errorf("%s is empty or whitespace only; set a real secret (e.g. openssl rand -hex 32) or omit it on a loopback address", src)
	}
	if flagSet && tok == "" {
		return "", fmt.Errorf("--token is empty; set a real secret or omit the flag")
	}
	return strings.TrimSpace(tok), nil
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
	Short: "Change detection by polling CloudTrail, Azure Activity Log and GCP audit logs (minutes of delay, not real time); alerts on risky changes",
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
			m := monitor.New(specsFromConfig(cfg), filepath.Join(stateDir(), "monitor-checkpoint.json"))
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
	m := monitor.New(specs, filepath.Join(stateDir(), "monitor-checkpoint.json"))
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
		data, err := os.ReadFile(filepath.Join(stateDir(), "cost-signals.json"))
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
	serveCmd.Flags().StringVar(&serveFlags.addr, "addr", "127.0.0.1:8080", "listen address; a non-loopback address requires a token")
	serveCmd.Flags().StringVar(&serveFlags.copilot, "copilot", "", "URL of the Python intelligence API for the copilot panel")
	serveCmd.Flags().BoolVar(&serveFlags.mcp, "mcp", false, "also serve MCP over streamable HTTP at /mcp (bearer token required; stdio `cloud-posture mcp` stays the default)")
	serveCmd.Flags().StringSliceVar(&serveFlags.mcpScopes, "mcp-scope", nil, "MCP tool scopes of the --token (default read)")
	serveCmd.Flags().StringArrayVar(&serveFlags.mcpTokens, "mcp-token", nil, "an extra MCP bearer token: ENV_VAR=scope[,scope] (the token is read from ENV_VAR; repeatable)")
	serveCmd.Flags().DurationVar(&serveFlags.scanInterval, "scan-interval", 0, "re-scan configured accounts on this interval (continuous compliance)")
	serveCmd.Flags().BoolVar(&serveFlags.monitor, "monitor", false, "run change detection and push events to the dashboard")
	serveCmd.Flags().DurationVar(&serveFlags.monInterval, "monitor-interval", 2*time.Minute, "monitor poll interval")
	serveCmd.Flags().StringArrayVar(&serveFlags.corsOrigins, "cors-origin", nil, "extra browser origin (scheme://host:port) allowed to call the API; repeatable (the server's own host is always allowed)")
	// The default is resolved at run time so the secret never appears in --help.
	serveCmd.Flags().StringVar(&serveFlags.token, "token", "", "bearer token required on /, /ws and /api/* (default from $CLOUD_POSTURE_TOKEN)")
	serveCmd.Flags().StringArrayVar(&serveFlags.allowedHosts, "allowed-host", nil, "extra Host header name accepted (DNS-rebinding protection); repeatable. The bound host, localhost, 127.0.0.1 and [::1] are always accepted")
	serveCmd.Flags().DurationVar(&serveFlags.queryTimeout, "query-timeout", server.DefaultQueryTimeout, "per-request limit for POST /api/query")
	monitorCmd.Flags().DurationVar(&monitorFlags.interval, "interval", 2*time.Minute, "poll interval")
	monitorCmd.Flags().BoolVar(&monitorFlags.once, "once", false, "poll once and exit")
	monitorCmd.Flags().BoolVar(&monitorFlags.alert, "alert", false, "dispatch events to configured integrations")
	monitorCmd.Flags().BoolVar(&monitorFlags.json, "json", false, "JSON output (with --once)")
	costCmd.Flags().BoolVar(&costFlags.json, "json", false, "JSON output")
	costCmd.Flags().Float64Var(&costFlags.breachCost, "breach-cost", 0, "average breach cost in USD for ROI (default IBM 2024: 4.88M)")
	root.AddCommand(serveCmd, monitorCmd, costCmd)
}

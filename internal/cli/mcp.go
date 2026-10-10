package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/DreadpiratePickles/nimbus/internal/mcp"
	"github.com/DreadpiratePickles/nimbus/internal/query"
	"github.com/DreadpiratePickles/nimbus/internal/risk"
	"github.com/spf13/cobra"
)

// mcpStdin replaces os.Stdin for `cloud-posture mcp` (tests).
var mcpStdin io.Reader

var mcpFlags struct {
	scopes   []string
	noRedact bool
	audit    string
}

// mcpCmd serves the read-only MCP tools (internal/mcp) over stdio: JSON-RPC frames on stdin
// and stdout only; logs go to stderr so a client's protocol stream is never polluted.
var mcpCmd = &cobra.Command{
	Use:   "mcp",
	Short: "Serve the read-only MCP tools over stdio (default scope read: sql, schema, paths, issue, explain, coverage, who_can, prioritize, verify, summary)",
	Long: `Starts a Model Context Protocol server on stdin/stdout for an AI client (Claude Desktop, Cursor,
VS Code). Every tool is read-only. The default scope is "read": the change-shaped tools
(simulate_fix, draft_fix) are listed only with --scope fix or --scope all. "verify" reports what
` + "`cloud-posture verify`" + ` would re-check and the stored verification state; it never re-collects
or changes an Issue. Results are wrapped as untrusted data; account ids, ARN accounts, GCP projects,
AWS resource ids (sg-, rtb-, acl-, i-, ...), IPs and tag values are redacted to per-session
placeholders unless --no-redact; every call is appended to a JSONL audit file (default beside the
database). See docs/data-flow.md.`,
	Example: `  cloud-posture mcp                          # read scope (default), redacted
  cloud-posture mcp --scope read,fix         # also simulate_fix / draft_fix
  cloud-posture mcp --scope all              # every tool
  cloud-posture mcp --audit ~/.nimbus/mcp-audit.jsonl
  # Claude Desktop: {"command": "cloud-posture", "args": ["mcp"]}`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if _, err := mcp.ParseScopes(mcpFlags.scopes); err != nil {
			return err
		}
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		st, err := openStore()
		if err != nil {
			return err
		}
		defer st.Close()
		if _, err := query.EnsureAllViews(st); err != nil {
			return fmt.Errorf("mcp: views: %w", err)
		}
		ctx := cmd.Context()
		if ctx == nil {
			ctx = context.Background()
		}
		in := mcpStdin
		if in == nil {
			in = os.Stdin
		}
		fmt.Fprintf(os.Stderr, "nimbus mcp: serving %s over stdio (scope %s, redaction %s)\n", st.Path(),
			firstNonEmpty(strings.Join(mcpFlags.scopes, ","), mcp.DefaultScope), map[bool]string{true: "off", false: "on"}[mcpFlags.noRedact])
		return mcp.Serve(ctx, st, mcp.Options{
			In: in, Out: os.Stdout,
			Scopes: mcpFlags.scopes, NoRedact: mcpFlags.noRedact, AuditPath: mcpFlags.audit,
			Traversal:   storedTraversal(cfg, st),
			RiskOptions: func() risk.Options { return riskOptions(ctx, cfg) },
			Version:     Version,
		})
	},
}

func init() {
	f := mcpCmd.Flags()
	f.StringSliceVar(&mcpFlags.scopes, "scope", nil, "tool scopes to expose ("+strings.Join(mcp.KnownScopes(), "|")+"; default: read, i.e. every tool except simulate_fix and draft_fix)")
	f.BoolVar(&mcpFlags.noRedact, "no-redact", false, "send account ids, ARNs, IPs and tag values unredacted to the client")
	f.StringVar(&mcpFlags.audit, "audit", "", "JSONL audit file (default: mcp-audit.jsonl beside the database)")
	root.AddCommand(mcpCmd)
}

package cli

// `serve --mcp` (W7-VERIFY r5 #14): the MCP streamable HTTP transport at /mcp. Tokens: the
// serve --token (scopes --mcp-scope, default read) and any number of --mcp-token ENV_VAR=scopes,
// each read from that environment variable (secrets never on the command line or in logs).

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/DreadpiratePickles/nimbus/internal/config"
	"github.com/DreadpiratePickles/nimbus/internal/mcp"
	"github.com/DreadpiratePickles/nimbus/internal/risk"
	"github.com/DreadpiratePickles/nimbus/internal/server"
	"github.com/DreadpiratePickles/nimbus/internal/store"
)

func mountMCP(srv *server.Server, st *store.Store, cfg *config.Config) error {
	if !serveFlags.mcp {
		return nil
	}
	if _, err := mcp.ParseScopes(serveFlags.mcpScopes); err != nil {
		return fmt.Errorf("--mcp-scope: %w", err)
	}
	var toks []server.MCPToken
	for _, spec := range serveFlags.mcpTokens {
		name, scopes, err := mcp.ParseTokenScopes(spec)
		if err != nil {
			return fmt.Errorf("--mcp-token %q: %w", spec, err)
		}
		v := strings.TrimSpace(os.Getenv(name))
		if v == "" {
			return fmt.Errorf("--mcp-token: environment variable %s is empty or unset", name)
		}
		if len(v) < 16 {
			return fmt.Errorf("--mcp-token: the token in %s is shorter than 16 characters", name)
		}
		toks = append(toks, server.MCPToken{Name: name, Token: v, Scopes: scopes})
	}
	o := mcp.Options{Version: Version, Traversal: storedTraversal(cfg, st)}
	if cfg != nil {
		o.RiskOptions = func() risk.Options { return riskOptions(context.Background(), cfg) }
	}
	h, err := mcp.NewHTTPHandler(st, mcp.HTTPOptions{Options: o})
	if err != nil {
		return err
	}
	srv.MCP, srv.MCPTokens, srv.MCPScopes = h, toks, serveFlags.mcpScopes
	return nil
}

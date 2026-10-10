package cli

import (
	"strings"
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/server"
)

// W7-VERIFY r5 #14: `serve --mcp` mounts the HTTP transport; --mcp-token NAME_ENV=scopes reads
// each token from the environment (never from the command line) with its own scopes; --mcp-scope
// sets the scopes of the --token. Without --mcp nothing is mounted.
func TestServeMountsMCPWithTokenScopes(t *testing.T) {
	labDB(t)
	st := openTestStore(t)
	srv := server.New(st, nil)
	resetServeMCPFlags := func() { serveFlags.mcp, serveFlags.mcpScopes, serveFlags.mcpTokens = false, nil, nil }
	defer resetServeMCPFlags()

	if err := mountMCP(srv, st, nil); err != nil || srv.MCP != nil {
		t.Fatalf("without --mcp: %v mounted=%v", err, srv.MCP != nil)
	}
	serveFlags.mcp = true
	serveFlags.mcpTokens = []string{"NIMBUS_MCP_READER=read", "NIMBUS_MCP_FIXER=read,fix"}
	t.Setenv("NIMBUS_MCP_READER", "r-secret-0123456789")
	t.Setenv("NIMBUS_MCP_FIXER", "")
	if err := mountMCP(srv, st, nil); err == nil || !strings.Contains(err.Error(), "NIMBUS_MCP_FIXER") || strings.Contains(err.Error(), "r-secret") {
		t.Fatalf("an empty token env must be an error naming the variable, not a value: %v", err)
	}
	t.Setenv("NIMBUS_MCP_FIXER", "f-secret-0123456789")
	serveFlags.mcpScopes = []string{"nonsense"}
	if err := mountMCP(srv, st, nil); err == nil || !strings.Contains(err.Error(), "nonsense") {
		t.Fatalf("an unknown --mcp-scope must be refused: %v", err)
	}
	serveFlags.mcpScopes = []string{"summary"}
	if err := mountMCP(srv, st, nil); err != nil {
		t.Fatal(err)
	}
	if srv.MCP == nil || len(srv.MCPTokens) != 2 || srv.MCPTokens[1].Name != "NIMBUS_MCP_FIXER" || srv.MCPTokens[1].Token != "f-secret-0123456789" ||
		strings.Join(srv.MCPTokens[1].Scopes, ",") != "read,fix" || strings.Join(srv.MCPScopes, ",") != "summary" {
		t.Fatalf("mounted tokens = %+v scopes %v", srv.MCPTokens, srv.MCPScopes)
	}
	serveFlags.mcpTokens = []string{"no-equals"}
	if err := mountMCP(srv, st, nil); err == nil {
		t.Errorf("a malformed --mcp-token must be refused")
	}
}

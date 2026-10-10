package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/DreadpiratePickles/nimbus/internal/graph"
)

var whoCanFlags struct {
	json  bool
	depth int
}

// whoCanCmd answers "who can <action> <resource>" from the stored graph with the IAM evaluator
// (graph.WhoCan): direct principals and principals that reach one through can_assume chains.
var whoCanCmd = &cobra.Command{
	Use:   "who-can <action> <resource>",
	Short: "List the principals that can perform an action on a resource (directly or by assuming roles)",
	Long: `who-can evaluates the action against every AWS principal's collected policies (identity,
permission boundary, SCPs, the resource's own policy) and walks can_assume chains backwards
(depth <= --depth). When the resource is anonymously readable (a Principal * policy without an
organisation condition, a public ACL, an auth-less URL) "anonymous (internet)" is listed first.
Each line names the statement that grants it and the confidence (verified |
inferred | hint, docs/iam/evaluator.md).

<resource> is an ARN / node id, or a resource name that exactly one node in the graph has (the
MCP who_can tool resolves names with the same rule, graph.ResolveNodeName); the header then names the resolved id.

  cloud-posture who-can s3:GetObject arn:aws:s3:::customer-pii/*
  cloud-posture who-can s3:GetObject customer-pii`,
	Args: cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		st, err := openStore()
		if err != nil {
			return err
		}
		defer st.Close()
		g, err := graphFromStore(st)
		if err != nil {
			return err
		}
		resource, err := graph.ResolveNodeName(g, args[1])
		if err != nil {
			return err
		}
		res := graph.WhoCan(g, args[0], resource, whoCanFlags.depth)
		if whoCanFlags.json {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			if res == nil {
				res = []graph.WhoCanResult{}
			}
			return enc.Encode(res)
		}
		on := args[1]
		if resource != args[1] {
			on += " (" + resource + ")"
		}
		if len(res) == 0 {
			fmt.Printf("No principal can %s on %s (in the collected graph).\n", args[0], on)
			return nil
		}
		fmt.Printf("%d principal(s) can %s on %s:\n", len(res), args[0], on)
		for _, r := range res {
			if r.Holder == "*" { // anonymous / org-wide (graph.AnonymousPrincipal, delta r2 #5): listed first
				fmt.Printf("  %-70s %-9s %s\n      because %s\n", r.Principal, r.Confidence, r.Decision, r.Because)
				continue
			}
			how := "direct"
			if len(r.Via) > 0 {
				how = "via " + strings.Join(r.Via, " -> ")
			}
			stmt := r.Statement
			if stmt == "" {
				stmt = "(declared relationship)"
			}
			fmt.Printf("  %-70s %-9s %s\n      %s; statement %s\n", r.Principal, r.Confidence, how, r.Decision, stmt)
		}
		return nil
	},
}

func init() {
	whoCanCmd.Flags().BoolVar(&whoCanFlags.json, "json", false, "JSON output")
	whoCanCmd.Flags().IntVar(&whoCanFlags.depth, "depth", 4, "maximum can_assume chain length")
}

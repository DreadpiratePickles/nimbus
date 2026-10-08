package cli

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/DreadpiratePickles/nimbus/internal/attackpath"
	"github.com/DreadpiratePickles/nimbus/internal/graph"
	"github.com/DreadpiratePickles/nimbus/internal/neo4j"
	"github.com/DreadpiratePickles/nimbus/internal/output"
	"github.com/DreadpiratePickles/nimbus/internal/store"
	"github.com/spf13/cobra"
)

var pathFlags struct {
	format string
	fixes  bool
	blast  string
	limit  int
}

var pathsCmd = &cobra.Command{
	Use:   "paths",
	Short: "Attack paths: multi-hop chains from entry points to crown jewels, choke points and break-the-path fixes",
	Example: `  cloud-posture paths
  cloud-posture paths --fixes                 # recommendations that break paths vs. lower risk, and the min fix set
  cloud-posture paths --format mermaid > paths.md
  cloud-posture paths --blast-radius arn:aws:iam::123:role/web-admin-role`,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		res, st, err := loadResult(context.Background(), cfg)
		if err != nil {
			return err
		}
		defer st.Close()
		if pathFlags.blast != "" {
			reach, sens := attackpath.BlastRadius(res.Graph, pathFlags.blast, 6, nil)
			if pathFlags.format == "json" {
				return output.JSON(os.Stdout, map[string]any{"node": pathFlags.blast, "reachable": reach, "sensitive": sens})
			}
			fmt.Printf("Blast radius of %s: %d resources reachable, %d sensitive\n", pathFlags.blast, len(reach), len(sens))
			for _, s := range sens {
				fmt.Println("  ◆", s)
			}
			for _, r := range reach {
				fmt.Println("  ·", r)
			}
			return nil
		}
		paths := res.Paths
		if pathFlags.limit > 0 && len(paths) > pathFlags.limit {
			paths = paths[:pathFlags.limit]
		}
		switch pathFlags.format {
		case "json":
			if pathFlags.fixes {
				return output.JSON(os.Stdout, res.Analysis)
			}
			return output.JSON(os.Stdout, paths)
		case "mermaid":
			fmt.Print(attackpath.Mermaid(paths))
			return nil
		case "dot":
			fmt.Print(attackpath.DOT(paths))
			return nil
		}
		if len(paths) == 0 {
			fmt.Println("No attack paths. Run `cloud-posture scan` with accounts (native collectors build the graph) or ingest more scanner output.")
			return nil
		}
		fmt.Printf("%d attack paths (%d entry points, %d crown jewels)\n\n", len(res.Paths), len(res.Analysis.EntryPoints), len(res.Analysis.Targets))
		for i, p := range paths {
			fmt.Printf("%2d. [%s %.1f] %s → %s\n", i+1, p.Severity, p.Score, p.Name, p.Impact)
			for _, s := range p.Steps {
				fmt.Printf("      %d. %s\n", s.Stage, firstNonEmpty(s.Summary, s.Title))
			}
			if len(p.Mitre) > 0 {
				fmt.Printf("      MITRE: %s\n", strings.Join(p.Mitre, ", "))
			}
		}
		if pathFlags.fixes {
			an := res.Analysis
			fmt.Println("\nChoke points:")
			for i, c := range an.ChokePoints {
				if i >= 5 {
					break
				}
				fmt.Printf("  %s (%s) — on %d paths\n", c.Name, c.Type, c.Paths)
			}
			fmt.Println("\nRecommendations (break the path):")
			for i, f := range an.BreakFixes {
				if i >= 8 {
					break
				}
				fmt.Printf("  - %s on %s → removes %d path(s), %.1f risk\n      %s\n", strings.ToLower(strings.ReplaceAll(f.Weakness, "_", " ")), f.Name, len(f.Breaks), f.ScoreRemoved, f.Command)
			}
			fmt.Println("\nAdditional (lower risk only):")
			for i, f := range an.ReduceFixes {
				if i >= 5 {
					break
				}
				fmt.Printf("  - %s on %s → affects %d path(s)\n", strings.ToLower(strings.ReplaceAll(f.Weakness, "_", " ")), f.Name, len(f.Reduces))
			}
			fmt.Printf("\nCheapest fix set (%.0f%% of attack-path risk):\n", an.MinFixCoverage)
			for i, f := range an.MinFixSet {
				fmt.Printf("  %d. %s on %s — %s\n", i+1, strings.ToLower(strings.ReplaceAll(f.Weakness, "_", " ")), f.Name, f.Command)
			}
		}
		return nil
	},
}

var graphFlags struct {
	format              string
	out                 string
	uri, user, password string
	database            string
	cleanup             bool
}

var graphCmd = &cobra.Command{Use: "graph", Short: "Export or push the security graph (JSON, Cypher, Mermaid, Neo4j)"}

var graphExportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export the graph as json|cypher|mermaid|dot",
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
		var out string
		switch graphFlags.format {
		case "cypher":
			out = g.Cypher()
		case "mermaid":
			out = graphMermaid(g)
		case "dot":
			out = graphDOT(g)
		default:
			w := os.Stdout
			if graphFlags.out != "" {
				f, err := os.Create(graphFlags.out)
				if err != nil {
					return err
				}
				defer f.Close()
				w = f
			}
			return output.JSON(w, g.JSON())
		}
		if graphFlags.out != "" {
			return os.WriteFile(graphFlags.out, []byte(out), 0o644)
		}
		fmt.Print(out)
		return nil
	},
}

var graphPushCmd = &cobra.Command{
	Use:   "push",
	Short: "Push the graph to Neo4j with Cartography-style labels (AWSAccount, EC2Instance, S3Bucket, IAMRole…)",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		st, err := openStore()
		if err != nil {
			return err
		}
		defer st.Close()
		g, err := graphFromStore(st)
		if err != nil {
			return err
		}
		uri := firstNonEmpty(graphFlags.uri, cfg.Neo4j.URI, os.Getenv(firstNonEmpty(cfg.Neo4j.URIEnv, "NEO4J_URI")))
		user := firstNonEmpty(graphFlags.user, cfg.Neo4j.User, os.Getenv(firstNonEmpty(cfg.Neo4j.UserEnv, "NEO4J_USER")), "neo4j")
		pass := firstNonEmpty(graphFlags.password, cfg.Neo4j.Password, os.Getenv(firstNonEmpty(cfg.Neo4j.PasswordEnv, "NEO4J_PASSWORD")))
		if uri == "" {
			return fmt.Errorf("neo4j URI required (--uri, config neo4j.uri or NEO4J_URI)")
		}
		stats, err := neo4j.Push(context.Background(), neo4j.Config{URI: uri, Username: user, Password: pass, Database: firstNonEmpty(graphFlags.database, cfg.Neo4j.Database), Cleanup: graphFlags.cleanup}, g)
		if err != nil {
			return err
		}
		return output.JSON(os.Stdout, stats)
	},
}

func init() {
	pathsCmd.Flags().StringVarP(&pathFlags.format, "format", "f", "text", "text|json|mermaid|dot")
	pathsCmd.Flags().BoolVar(&pathFlags.fixes, "fixes", false, "show choke points and break-the-path recommendations")
	pathsCmd.Flags().StringVar(&pathFlags.blast, "blast-radius", "", "show what a compromised node can reach")
	pathsCmd.Flags().IntVar(&pathFlags.limit, "limit", 25, "paths to print (0 = all)")
	graphExportCmd.Flags().StringVarP(&graphFlags.format, "format", "f", "json", "json|cypher|mermaid|dot")
	graphExportCmd.Flags().StringVar(&graphFlags.out, "out", "", "write to file")
	graphPushCmd.Flags().StringVar(&graphFlags.uri, "uri", "", "bolt://host:7687")
	graphPushCmd.Flags().StringVar(&graphFlags.user, "user", "", "neo4j user")
	graphPushCmd.Flags().StringVar(&graphFlags.password, "password", "", "neo4j password (prefer NEO4J_PASSWORD)")
	graphPushCmd.Flags().StringVar(&graphFlags.database, "database", "", "neo4j database")
	graphPushCmd.Flags().BoolVar(&graphFlags.cleanup, "cleanup", false, "delete stale nodes of the pushed accounts")
	graphCmd.AddCommand(graphExportCmd, graphPushCmd)
	root.AddCommand(pathsCmd, graphCmd)
}

func graphFromStore(st *store.Store) (*graph.Graph, error) {
	g, err := loadGraph(st)
	if err != nil {
		return nil, err
	}
	if g.Len() <= 1 {
		fs, _ := st.Findings(store.Filter{})
		g.AttachFindings(fs)
	}
	return g, nil
}

func graphMermaid(g *graph.Graph) string {
	var b strings.Builder
	b.WriteString("flowchart LR\n")
	ids := map[string]string{}
	for i, n := range g.Nodes() {
		id := fmt.Sprintf("n%d", i)
		ids[n.ID] = id
		label := strings.ReplaceAll(n.Name, "\"", "'")
		if len(n.Weaknesses) > 0 {
			label += "<br/>⚠ " + strings.Join(n.Weaknesses, ", ")
		}
		fmt.Fprintf(&b, "  %s[\"%s\"]\n", id, label)
	}
	for _, e := range g.Edges() {
		fmt.Fprintf(&b, "  %s -->|%s| %s\n", ids[e.From], e.Kind, ids[e.To])
	}
	return b.String()
}

func graphDOT(g *graph.Graph) string {
	var b strings.Builder
	b.WriteString("digraph security_graph {\n  rankdir=LR;\n  node [shape=box, style=rounded, fontsize=10];\n")
	for _, n := range g.Nodes() {
		color := "black"
		if len(n.Weaknesses) > 0 {
			color = "red"
		}
		if n.Sensitive {
			color = "purple"
		}
		fmt.Fprintf(&b, "  \"%s\" [label=\"%s\\n%s\", color=%s];\n", n.ID, strings.ReplaceAll(n.Name, "\"", "'"), n.Type, color)
	}
	for _, e := range g.Edges() {
		fmt.Fprintf(&b, "  \"%s\" -> \"%s\" [label=\"%s\", fontsize=8];\n", e.From, e.To, e.Kind)
	}
	b.WriteString("}\n")
	return b.String()
}

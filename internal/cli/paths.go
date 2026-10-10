package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/DreadpiratePickles/nimbus/internal/attackpath"
	"github.com/DreadpiratePickles/nimbus/internal/config"
	"github.com/DreadpiratePickles/nimbus/internal/graph"
	"github.com/DreadpiratePickles/nimbus/internal/model"
	"github.com/DreadpiratePickles/nimbus/internal/neo4j"
	"github.com/DreadpiratePickles/nimbus/internal/output"
	"github.com/DreadpiratePickles/nimbus/internal/store"
	"github.com/spf13/cobra"
)

var pathFlags struct {
	format     string
	fixes      bool
	blast      string
	limit      int
	deadEnds   bool
	noDeadEnds bool
	choke      string
	explain    bool
	exposures  bool
	variants   bool
	grouped    bool
	from       string
	to         string
	through    string
	maxHops    int
}

var pathsCmd = &cobra.Command{
	Use:   "paths",
	Short: "Attack paths: multi-hop chains from entry points to crown jewels, choke points and break-the-path fixes",
	Example: `  cloud-posture paths
  cloud-posture paths --fixes                 # recommendations that break paths vs. lower risk, and the min fix set
  cloud-posture paths --format mermaid > paths.md
  cloud-posture paths --blast-radius arn:aws:iam::123:role/web-admin-role
  cloud-posture paths --explain               # per-hop "because" for every step
  cloud-posture paths --all-variants          # every hop variant, not one row per path Issue
  cloud-posture paths --dead-ends             # findings that reach no crown jewel
  cloud-posture paths --choke <node-id>       # paths through one choke point and how many removing it closes
  cloud-posture paths --from internet --to type:aws_s3_bucket --through type:aws_iam_role --max-hops 5
                                              # graph query: every attack-step path between two node sets`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if pathFlags.deadEnds && pathFlags.noDeadEnds {
			return fmt.Errorf("--dead-ends and --no-dead-ends are mutually exclusive")
		}
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		res, st, err := loadResult(context.Background(), cfg)
		if err != nil {
			return err
		}
		defer st.Close()
		if pathFlags.from != "" || pathFlags.to != "" || pathFlags.through != "" || cmd.Flags().Changed("max-hops") {
			return runPathQuery(os.Stdout, cfg, res)
		}
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
		if pathFlags.choke != "" {
			return printChoke(os.Stdout, res, pathFlags.choke, pathFlags.format)
		}
		if pathFlags.deadEnds {
			return printDeadEnds(os.Stdout, res, pathFlags.format)
		}
		if pathFlags.noDeadEnds && res.Analysis != nil {
			res.Analysis.DeadEnds = attackpath.DeadEnds{IDs: []string{}}
			res.Analysis.ReachesCrownJewel = nil
		}
		paths := res.Paths
		groups := res.Analysis.Grouped() // one row per path Issue (engine round 2)
		// One title and one order with `issues`, the dashboard and the API (W6-POLISH, r4 #4).
		view := newPathIssueView(st, res.Graph)
		view.SortGroups(groups)
		if pathFlags.format == "" || pathFlags.format == "table" || pathFlags.format == "text" {
			if pathFlags.variants {
				paths = append([]model.AttackPath(nil), paths...)
				view.SortPaths(paths)
			} else {
				// One row per path Issue (entry, impact anchor, rule): the SG-entry and
				// instance-entry variants of one problem are one row (delta shortfall #11).
				paths = paths[:0:0]
				for _, g := range groups {
					paths = append(paths, g.Best)
				}
			}
		}
		if pathFlags.limit > 0 && len(paths) > pathFlags.limit {
			paths = paths[:pathFlags.limit]
		}
		switch pathFlags.format {
		case "json":
			if pathFlags.fixes {
				return output.JSON(os.Stdout, res.Analysis)
			}
			if pathFlags.exposures {
				return output.JSON(os.Stdout, exposuresJSON(res))
			}
			if pathFlags.grouped {
				return output.JSON(os.Stdout, pathIssuesJSON(view, groups, pathFlags.limit))
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
			printSuppressed(os.Stdout, res.Analysis)
			printExposures(os.Stdout, res.Analysis, pathFlags.exposures)
			return nil
		}
		if pathFlags.variants {
			fmt.Printf("%d attack paths (%d entry points, %d crown jewels)\n\n", len(res.Paths), len(res.Analysis.EntryPoints), len(res.Analysis.Targets))
		} else {
			fmt.Printf("%d attack path Issue(s) from %d hop variant(s) (%d entry points, %d crown jewels); --all-variants lists every variant\n\n",
				len(groups), len(res.Paths), len(res.Analysis.EntryPoints), len(res.Analysis.Targets))
		}
		variantsOf := map[string]int{}
		for _, g := range groups {
			variantsOf[g.Best.ID] = len(g.Paths)
		}
		for i, p := range paths {
			more := ""
			if n := variantsOf[p.ID]; !pathFlags.variants && n > 1 {
				more = fmt.Sprintf("  (+%d more hop variant(s))", n-1)
			}
			fmt.Printf("%2d. [%s %.1f] %s%s\n", i+1, p.Severity, p.Score, view.Row(p), more)
			for _, s := range p.Steps {
				fmt.Printf("      %d. %s\n", s.Stage, firstNonEmpty(s.Summary, s.Title))
				if pathFlags.explain {
					fmt.Printf("         because: %s\n", firstNonEmpty(s.Because, "(no reason recorded for this hop)"))
				}
			}
			if len(p.Mitre) > 0 {
				fmt.Printf("      MITRE: %s\n", strings.Join(p.Mitre, ", "))
			}
			if id := view.IssueID(p); !pathFlags.variants && view.pos != nil {
				if _, stored := view.pos[id]; stored { // r4 E12: the id the next command needs
					fmt.Printf("      Issue %s · cloud-posture issues show %s\n", id, id)
				}
			}
		}
		printSuppressed(os.Stdout, res.Analysis)
		printExposures(os.Stdout, res.Analysis, pathFlags.exposures)
		if !pathFlags.noDeadEnds && res.Analysis != nil {
			fmt.Printf("\nDead ends: %d finding-bearing resource(s) reach no crown jewel (--dead-ends lists them, --no-dead-ends hides this)\n", res.Analysis.DeadEnds.Count)
		}
		if pathFlags.fixes {
			an := res.Analysis
			fmt.Println("\nChoke points:")
			for i, c := range an.ChokePoints {
				if i >= 5 {
					break
				}
				fmt.Printf("  %s (%s) — on %d paths, removing it closes %d  [paths --choke %s]\n", c.Name, c.Type, c.Paths, c.ClosesN, c.NodeID)
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
			fmt.Printf("\nCheapest fix set (%.0f%% of attack-path risk; min_fix_exact=%v min_fix_verified=%v):\n", an.MinFixCoverage, an.MinFixExact, an.MinFixVerified)
			for i, f := range an.MinFixSet {
				fmt.Printf("  %d. %s on %s — %s\n", i+1, strings.ToLower(strings.ReplaceAll(f.Weakness, "_", " ")), f.Name, f.Command)
			}
		}
		return nil
	},
}

// runPathQuery answers `paths --from/--to/--through/--max-hops` on the stored graph with the
// engine's per-hop because (delta r3 #8, matrix IG6).
func runPathQuery(w io.Writer, cfg *config.Config, res *scanResult) error {
	if pathFlags.from == "" || pathFlags.to == "" {
		return fmt.Errorf("a path query needs both --from and --to (internet, type:<type>, class:<class>, a node id or name)")
	}
	q := attackpath.PathQuery{From: pathFlags.from, To: pathFlags.to, Through: pathFlags.through, MaxHops: pathFlags.maxHops}
	qr, err := attackpath.Query(res.Graph, traversalOptionsFor(cfg, res.Graph, res.Findings), q)
	if err != nil {
		return err
	}
	paths := qr.Paths
	if pathFlags.limit > 0 && len(paths) > pathFlags.limit {
		paths = paths[:pathFlags.limit]
	}
	view := newPathIssueView(nil, res.Graph)
	switch pathFlags.format {
	case "json":
		qr.Paths = paths
		return output.JSON(w, qr)
	case "mermaid":
		fmt.Fprint(w, attackpath.Mermaid(paths))
		return nil
	case "dot":
		fmt.Fprint(w, attackpath.DOT(paths))
		return nil
	}
	via := ""
	if q.Through != "" {
		via = " through " + q.Through
	}
	fmt.Fprintf(w, "%d path(s) from %s to %s%s (max %d hops; %d start node(s), %d end node(s))",
		len(qr.Paths), q.From, q.To, via, qr.Query.MaxHops, qr.FromNodes, qr.ToNodes)
	if len(paths) < len(qr.Paths) {
		fmt.Fprintf(w, "; showing %d (--limit 0 for all)", len(paths))
	}
	fmt.Fprintln(w)
	if qr.Truncated {
		fmt.Fprintln(w, "  (search truncated: narrow --from/--to or lower --max-hops)")
	}
	for i, p := range paths {
		fmt.Fprintf(w, "\n%2d. [%s %.1f] %s\n", i+1, p.Severity, p.Score, view.Row(p))
		for _, s := range p.Steps {
			fmt.Fprintf(w, "      %d. %s\n         because: %s\n", s.Stage, firstNonEmpty(s.Summary, s.Title), firstNonEmpty(s.Because, "(no reason recorded for this hop)"))
		}
	}
	if len(paths) == 0 {
		fmt.Fprintln(w, "  no hop sequence the engine scores as an attack step connects them")
	}
	return nil
}

// printSuppressed lists internet exposure analysis refused as an entry (every source inside
// trusted_cidrs, or private) with the reason, so a missing path is explained, not silent.
func printSuppressed(w io.Writer, an *attackpath.Analysis) {
	if an == nil || len(an.Suppressed) == 0 {
		return
	}
	trusted := 0
	for _, s := range an.Suppressed {
		if s.Exposure == "trusted" {
			trusted++
		}
	}
	fmt.Fprintf(w, "\nsuppressed (trusted): %d", trusted)
	if other := len(an.Suppressed) - trusted; other > 0 {
		fmt.Fprintf(w, ", suppressed (private): %d", other)
	}
	fmt.Fprintln(w)
	for _, s := range an.Suppressed {
		fmt.Fprintf(w, "  - %s [%s %s]: %s\n", firstNonEmpty(s.Name, s.NodeID), s.Exposure, strings.Join(s.CIDRs, ", "), s.Reason)
	}
}

// printExposures prints how many internet-reachable resources are exposures, not attack
// paths (planning decision 1: no impact target behind them), and lists them with list=true.
func printExposures(w io.Writer, an *attackpath.Analysis, list bool) {
	if an == nil {
		return
	}
	fmt.Fprintf(w, "\nExposures (not attack paths): %d", len(an.Exposures))
	if !list {
		if len(an.Exposures) > 0 {
			fmt.Fprint(w, " (--exposures lists them)")
		}
		fmt.Fprintln(w)
		return
	}
	fmt.Fprintln(w)
	for _, e := range an.Exposures {
		fmt.Fprintf(w, "  - %s [%s %s]: %s\n", firstNonEmpty(e.Name, e.NodeID), e.Width, e.Type, firstNonEmpty(e.Because, "internet-reachable; no impact target behind it"))
	}
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
		if cmd.Flags().Changed("password") {
			return fmt.Errorf("--password was removed: secrets on the command line leak via ps and shell history; set NEO4J_PASSWORD (or neo4j.password_env in the config)")
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
		g, err := graphFromStore(st)
		if err != nil {
			return err
		}
		uri := firstNonEmpty(graphFlags.uri, cfg.Neo4j.URI, os.Getenv(firstNonEmpty(cfg.Neo4j.URIEnv, "NEO4J_URI")))
		user := firstNonEmpty(graphFlags.user, cfg.Neo4j.User, os.Getenv(firstNonEmpty(cfg.Neo4j.UserEnv, "NEO4J_USER")), "neo4j")
		pass := firstNonEmpty(cfg.Neo4j.Password, os.Getenv(firstNonEmpty(cfg.Neo4j.PasswordEnv, "NEO4J_PASSWORD")))
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

// pathIssueJSON is one path Issue as the engine's analysis groups it (`paths --format json
// --grouped`): computed from the traversal, not read back from the issues table, so a parity
// check against stored Issues compares two independent sources (Verification 6).
type pathIssueJSON struct {
	IssueID  string         `json:"issue_id"`
	Title    string         `json:"title"`
	Entry    string         `json:"entry"`
	Anchor   string         `json:"anchor"`
	Rule     string         `json:"rule"`
	Score    float64        `json:"score"`
	Band     string         `json:"band"`
	Severity model.Severity `json:"severity"`
	Variants int            `json:"variants"` // hop variants behind the Issue (≥ 1)
	BestID   string         `json:"best_id"`
	PathIDs  []string       `json:"path_ids"`
}

func pathIssuesJSON(view *pathIssueView, groups []attackpath.PathGroup, limit int) []pathIssueJSON {
	out := make([]pathIssueJSON, 0, len(groups))
	for _, g := range groups {
		if limit > 0 && len(out) == limit {
			break
		}
		out = append(out, pathIssueJSON{IssueID: view.IssueID(g.Best), Title: view.Title(g.Best), Entry: g.Entry, Anchor: g.Anchor, Rule: g.Rule,
			Score: g.Score, Band: g.Band, Severity: g.Severity, Variants: len(g.Paths), BestID: g.Best.ID, PathIDs: g.PathIDs})
	}
	return out
}

func init() {
	pathsCmd.Flags().StringVarP(&pathFlags.format, "format", "f", "text", "text|json|mermaid|dot")
	pathsCmd.Flags().BoolVar(&pathFlags.fixes, "fixes", false, "show choke points and break-the-path recommendations")
	pathsCmd.Flags().BoolVar(&pathFlags.exposures, "exposures", false, "list the internet exposures that are not attack paths (no impact target behind them)")
	pathsCmd.Flags().StringVar(&pathFlags.blast, "blast-radius", "", "show what a compromised node can reach")
	pathsCmd.Flags().IntVar(&pathFlags.limit, "limit", 25, "paths to print (0 = all)")
	pathsCmd.Flags().BoolVar(&pathFlags.deadEnds, "dead-ends", false, "list finding-bearing resources that reach no crown jewel (dead ends)")
	pathsCmd.Flags().BoolVar(&pathFlags.noDeadEnds, "no-dead-ends", false, "hide the dead-end summary (and drop dead_ends from --fixes JSON)")
	pathsCmd.Flags().StringVar(&pathFlags.choke, "choke", "", "drill into one choke point (node id or name): the paths through it and how many removing it closes")
	pathsCmd.Flags().BoolVar(&pathFlags.variants, "all-variants", false, "text: list every hop variant instead of one row per path Issue (JSON always lists every variant)")
	pathsCmd.Flags().BoolVar(&pathFlags.grouped, "grouped", false, "with --format json: one object per path Issue (issue_id, title, entry, anchor, rule, score, band, variants) from the engine's analysis")
	pathsCmd.Flags().StringVar(&pathFlags.from, "from", "", "graph query start: internet, type:<node type>, class:<class>, a node id or exact name (comma-separated list)")
	pathsCmd.Flags().StringVar(&pathFlags.to, "to", "", "graph query end (same selector forms as --from)")
	pathsCmd.Flags().StringVar(&pathFlags.through, "through", "", "graph query: only paths that pass through one of these nodes (same selector forms)")
	pathsCmd.Flags().IntVar(&pathFlags.maxHops, "max-hops", 6, "graph query: maximum hops (1-10)")
	pathsCmd.Flags().BoolVar(&pathFlags.explain, "explain", false, "print the per-hop \"because\" (rule, statement, binding or role) under every step")
	graphExportCmd.Flags().StringVarP(&graphFlags.format, "format", "f", "json", "json|cypher|mermaid|dot")
	graphExportCmd.Flags().StringVar(&graphFlags.out, "out", "", "write to file")
	graphPushCmd.Flags().StringVar(&graphFlags.uri, "uri", "", "bolt://host:7687")
	graphPushCmd.Flags().StringVar(&graphFlags.user, "user", "", "neo4j user")
	// --password was removed (secrets in argv leak via ps and shell history); it stays defined,
	// hidden, only to fail with a pointer to NEO4J_PASSWORD.
	graphPushCmd.Flags().StringVar(&graphFlags.password, "password", "", "removed: use NEO4J_PASSWORD")
	graphPushCmd.Flags().MarkHidden("password")
	graphPushCmd.Flags().StringVar(&graphFlags.database, "database", "", "neo4j database")
	graphPushCmd.Flags().BoolVar(&graphFlags.cleanup, "cleanup", false, "delete stale nodes of the pushed accounts")
	graphCmd.AddCommand(graphExportCmd, graphPushCmd)
	root.AddCommand(pathsCmd, graphCmd)
}

// printDeadEnds lists finding-bearing resources on no complete path to a crown jewel (O11).
func printDeadEnds(w io.Writer, res *scanResult, format string) error {
	an := res.Analysis
	if an == nil {
		an = &attackpath.Analysis{}
	}
	dead := an.FilterFindings(res.Findings, false)
	if format == "json" {
		return output.JSON(w, map[string]any{"dead_ends": an.DeadEnds, "findings": len(dead)})
	}
	fmt.Fprintf(w, "Dead ends: %d finding-bearing resource(s) reach no crown jewel (%d finding(s)); fix them after the paths.\n", an.DeadEnds.Count, len(dead))
	byRes := map[string]int{}
	for _, f := range dead {
		byRes[f.Resource.ID]++
	}
	for _, id := range an.DeadEnds.IDs {
		fmt.Fprintf(w, "  · %s (%d finding(s))\n", id, byRes[id])
	}
	return nil
}

// printChoke drills into one choke point: the complete paths through it (PathIDs) and how many
// disappear when it is removed and the traversal re-run (ClosesN).
func printChoke(w io.Writer, res *scanResult, node, format string) error {
	if res.Analysis == nil {
		return fmt.Errorf("no attack-path analysis")
	}
	var cp *attackpath.ChokePoint
	for i := range res.Analysis.ChokePoints {
		c := &res.Analysis.ChokePoints[i]
		if c.NodeID == node {
			cp = c
			break
		}
		if cp == nil && strings.EqualFold(c.Name, node) {
			cp = c
		}
	}
	cp = withRuleChains(cp, res.Paths, node)
	if cp == nil {
		return fmt.Errorf("%q is not a choke point (see `cloud-posture paths --fixes`)", node)
	}
	byID := map[string]model.AttackPath{}
	for _, p := range res.Paths {
		byID[p.ID] = p
	}
	if format == "json" {
		var ps []model.AttackPath
		for _, id := range cp.PathIDs {
			if p, ok := byID[id]; ok {
				ps = append(ps, p)
			}
		}
		return output.JSON(w, map[string]any{"choke_point": cp, "paths": ps})
	}
	fmt.Fprintf(w, "Choke point %s (%s, %s): on %d path(s); removing it closes %d\n", cp.Name, cp.Type, cp.NodeID, cp.Paths, cp.ClosesN)
	if len(cp.Weaknesses) > 0 {
		fmt.Fprintf(w, "  weaknesses: %s\n", strings.Join(cp.Weaknesses, ", "))
	}
	for _, id := range cp.PathIDs {
		p, ok := byID[id]
		if !ok {
			fmt.Fprintf(w, "  - %s\n", id)
			continue
		}
		fmt.Fprintf(w, "  - %s [%s %.1f] %s\n", id, p.Severity, p.Score, newPathIssueView(nil, res.Graph).Row(p))
	}
	return nil
}

// withRuleChains adds the rule-chain paths (res.Paths beyond the traversal's) that pass
// through the node at a non-final step to a copy of cp: Analysis.ChokePoints only counts
// traversal paths, while `paths` lists both. Removing the node breaks such a chain, so it
// also counts toward ClosesN. A node only rule chains pass through yields a new entry; nil
// when no path passes through it.
func withRuleChains(cp *attackpath.ChokePoint, paths []model.AttackPath, node string) *attackpath.ChokePoint {
	var out attackpath.ChokePoint
	if cp != nil {
		out = *cp
		out.PathIDs = append([]string(nil), cp.PathIDs...)
	}
	matches := func(r string) bool {
		if cp != nil {
			return r == cp.NodeID || (cp.Name != "" && strings.EqualFold(r, cp.Name))
		}
		return r == node || strings.EqualFold(r, node)
	}
	have := map[string]bool{}
	for _, id := range out.PathIDs {
		have[id] = true
	}
	added := 0
	for _, p := range paths {
		if have[p.ID] {
			continue
		}
		for i, st := range p.Steps {
			if i < len(p.Steps)-1 && matches(st.Resource) {
				out.PathIDs = append(out.PathIDs, p.ID)
				out.ScoreSum += p.Score
				have[p.ID] = true
				added++
				break
			}
		}
	}
	if cp == nil && added == 0 {
		return nil
	}
	if cp == nil {
		out.NodeID, out.Name = node, node
	}
	out.Paths += added
	out.ClosesN += added
	return &out
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

// ---------------------------------------------------------------------------
// risk: author and dry-run path rules (competitive delta r3 #9; matrix AP4, ID2).
// `risk list` prints the embedded privesc library with ids and credits; `risk test <rule.yaml>`
// validates one rule, runs its own tests block, then dry-runs it against the stored snapshot
// (loadConfig + loadResult, the same loader paths uses) WITHOUT writing to the store.

var riskFlags struct {
	format   string
	rulesDir string
}

var riskCmd = &cobra.Command{
	Use:   "risk",
	Short: "Path-rule library: author, validate and dry-run privilege-escalation path rules",
}

var riskListCmd = &cobra.Command{
	Use:   "list",
	Short: "List the path-rule library (ids, titles, confidence and credits)",
	RunE: func(cmd *cobra.Command, args []string) error {
		rules, err := riskLibrary()
		if err != nil {
			return err
		}
		counts := riskMatchCounts(rules) // nil without a stored snapshot
		if riskFlags.format == "json" {
			type row struct {
				attackpath.PathRule
				SourceKind string                    `json:"source_kind"` // library | custom
				Matches    *attackpath.PathRuleCount `json:"matches,omitempty"`
			}
			out := make([]row, 0, len(rules))
			for _, r := range rules {
				rw := row{PathRule: r, SourceKind: ruleSourceKind(r)}
				if c, ok := counts[r.ID]; ok {
					rw.Matches = &c
				}
				out = append(out, rw)
			}
			return output.JSON(os.Stdout, out)
		}
		nCustom := 0
		for _, r := range rules {
			if ruleSourceKind(r) == "custom" {
				nCustom++
			}
		}
		src := fmt.Sprintf("%d library + %d custom", len(rules)-nCustom, nCustom)
		if counts != nil {
			fmt.Printf("%d path rules, %s (matches: a dry run on the stored snapshot, no writes; verified matches an entry reaches are path Issues):\n", len(rules), src)
		} else {
			fmt.Printf("%d path rules, %s (no stored snapshot: run ingest or scan to see match counts):\n", len(rules), src)
		}
		for _, r := range rules {
			if ruleSourceKind(r) == "custom" {
				m := ""
				if c, ok := counts[r.ID]; ok {
					m = fmt.Sprintf("  matches %d (%d verified)", c.Total, c.Verified)
				}
				fmt.Printf("  %-52s %-10s %-8s %s%s  [custom: %s]\n", r.ID, r.Confidence, "custom", r.Title, m, r.Source)
				continue
			}
			credit := ""
			if r.Credit != nil {
				credit = fmt.Sprintf("  [%s %s: %s]", r.Credit.Source, r.Credit.Licence, r.Credit.UpstreamID)
			}
			m := ""
			if c, ok := counts[r.ID]; ok {
				m = fmt.Sprintf("  matches %d (%d verified)", c.Total, c.Verified)
			}
			fmt.Printf("  %-52s %-10s %-8s %s%s%s\n", r.ID, r.Confidence, "library", r.Title, m, credit)
		}
		return nil
	},
}

var riskTestCmd = &cobra.Command{
	Use:   "test <rule.yaml>",
	Short: "Validate a path rule, run its own tests, then dry-run it against the stored snapshot (no writes)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		rule, err := attackpath.LoadPathRuleFile(args[0])
		if err != nil {
			return err
		}
		testErr := attackpath.RunPathRuleTests(rule)

		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		res, st, err := loadResult(context.Background(), cfg)
		if err != nil {
			return err
		}
		defer st.Close()
		matches := attackpath.MatchPathRule(res.Graph, rule)

		if riskFlags.format == "json" {
			doc := map[string]any{
				"rule":       rule.ID,
				"title":      rule.Title,
				"confidence": rule.Confidence,
				"credit":     rule.Credit,
				"tests_pass": testErr == nil,
				"matches":    matches,
			}
			if testErr != nil {
				doc["tests_error"] = testErr.Error()
			}
			return output.JSON(os.Stdout, doc)
		}
		fmt.Printf("Rule %s — %s\n", rule.ID, rule.Title)
		if testErr != nil {
			fmt.Printf("  own tests: FAIL — %v\n", testErr)
		} else {
			fmt.Printf("  own tests: pass\n")
		}
		if rule.Credit != nil {
			fmt.Printf("  credit: %s (%s) %s\n", rule.Credit.Source, rule.Credit.Licence, rule.Credit.UpstreamID)
		}
		fmt.Printf("  dry run against the stored snapshot (no writes): %d match(es)\n", len(matches))
		for _, m := range matches {
			fmt.Printf("  • %s → %s  [%s]\n", m.Anchor, m.Target, m.Confidence)
			for _, b := range m.Because {
				fmt.Printf("      because: %s\n", b)
			}
		}
		if testErr != nil {
			return fmt.Errorf("rule %s failed its own tests", rule.ID)
		}
		return nil
	},
}

// riskLibrary returns the embedded library, plus user rules from --rules-dir (or ./rules/paths
// when present), validated together so duplicate ids across sources are caught.
// riskMatchCounts dry-runs every rule on the stored graph (attackpath.PathRuleMatchCounts); nil
// when there is no database yet (never creates one).
func riskMatchCounts(rules []attackpath.PathRule) map[string]attackpath.PathRuleCount {
	if _, err := os.Stat(firstNonEmpty(flagDB, store.DefaultPath())); err != nil {
		return nil
	}
	cfg, err := loadConfig()
	if err != nil {
		return nil
	}
	res, st, err := loadResult(context.Background(), cfg)
	if err != nil {
		return nil
	}
	st.Close()
	return attackpath.PathRuleMatchCounts(res.Graph, rules)
}

// riskLibrary returns the embedded library plus the customer rules traversal would use: config
// path_rules.dirs, the root --rules-dir, and risk's own --rules-dir (or ./rules/paths when
// present), each validated with `risk test` semantics (attackpath.LoadCustomPathRules, the loader
// traversal uses). Rejected files are printed as warnings and never listed (W7-POLISH item 15).
func riskLibrary() ([]attackpath.PathRule, error) {
	rules, err := attackpath.LibraryPathRules()
	if err != nil {
		return nil, err
	}
	var dirs []string
	if cfg, err := loadConfig(); err == nil {
		dirs = append(dirs, cfg.PathRuleDirs()...)
	}
	dirs = append(dirs, flagRulesDirs...)
	dir := riskFlags.rulesDir
	if dir == "" && len(dirs) == 0 {
		if _, statErr := os.Stat(filepath.Join("rules", "paths")); statErr == nil {
			dir = filepath.Join("rules", "paths")
		}
	}
	if dir != "" {
		dirs = append(dirs, dir)
	}
	if len(dirs) == 0 {
		return rules, nil
	}
	custom, rejected := attackpath.LoadCustomPathRules(dirs, rules)
	for _, r := range rejected {
		fmt.Fprintln(root.ErrOrStderr(), "warning: "+r.String())
	}
	return append(rules, custom...), nil
}

// ruleSourceKind is "custom" for a customer rule (a rules directory), "library" otherwise.
func ruleSourceKind(r attackpath.PathRule) string {
	if attackpath.IsCustomRule(r) {
		return "custom"
	}
	return "library"
}

func init() {
	riskListCmd.Flags().StringVarP(&riskFlags.format, "format", "f", "text", "text|json")
	riskListCmd.Flags().StringVar(&riskFlags.rulesDir, "rules-dir", "", "also load user path rules from this directory (default: ./rules/paths when present)")
	riskTestCmd.Flags().StringVarP(&riskFlags.format, "format", "f", "text", "text|json")
	riskCmd.AddCommand(riskListCmd, riskTestCmd)
	root.AddCommand(riskCmd)
}

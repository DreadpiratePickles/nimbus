package cli

// `pr-comment --plan-json` (P1-PLANDIFF D3): the plan-time attack-path diff as a sticky pull-request
// comment, optional SARIF for the opened paths, and an exit code when the PR opens a path.
//
// Topology disclosure (plan v3 §5.3): with --redact (default auto: on unless the event payload says
// the repository is private) the comment carries counts, hop types, short hashes, scores, toxic
// tags and fix template ids only: no resource names, ids, ARNs, accounts or addresses of the cloud
// estate. Every cloud- or plan-controlled string that does reach the comment goes through md(),
// which turns Markdown / HTML control characters and @-mentions into inert HTML entities, so a
// resource named "](javascript:…)" or "<!-- nimbus-plan-diff -->" cannot inject links, markup,
// mentions or a spoofed sticky marker.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"text/template"
	"time"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"

	"github.com/DreadpiratePickles/nimbus/internal/attackpath"
	"github.com/DreadpiratePickles/nimbus/internal/gitops"
	"github.com/DreadpiratePickles/nimbus/internal/graph"
	"github.com/DreadpiratePickles/nimbus/internal/iac"
	"github.com/DreadpiratePickles/nimbus/internal/model"
	"github.com/DreadpiratePickles/nimbus/internal/output"
	"github.com/DreadpiratePickles/nimbus/internal/pathdiff"
	"github.com/DreadpiratePickles/nimbus/internal/risk"
	"github.com/DreadpiratePickles/nimbus/internal/store"
	"github.com/spf13/cobra"
)

// exitOpened is the exit code of `pr-comment --fail-on-opened` when the plan opens a path
// (2 is the scan gate; 3 keeps the two distinguishable in CI logs).
const exitOpened = 3

var exitFn = os.Exit

var planCommentFlags struct {
	planJSON     string
	live         string
	redact       string
	maxPaths     int
	sarif        string
	sarifURI     string
	failOnOpened bool
	openedOnly   bool
	trusted      []string
	jsonOut      string
	botLogin     string
	maxBytes     int
	iacRoot      string
	reviewSugs   bool
}

func init() {
	f := prCommentCmd.Flags()
	f.StringVar(&planCommentFlags.planJSON, "plan-json", "", "`terraform show -json` / `tofu show -json` output of a saved plan: comment the attack paths the PR opens / closes")
	f.StringVar(&planCommentFlags.live, "live", "auto", "use the scan DB's graph as the live graph: auto (when the DB exists) | on | off (plan-only, confidence hint)")
	f.StringVar(&planCommentFlags.redact, "redact", "auto", "topology redaction: auto (on unless the event says the repository is private) | on | off")
	f.IntVar(&planCommentFlags.maxPaths, "max-paths", 10, "max paths listed per section (counts and footer always cover all)")
	f.StringVar(&planCommentFlags.sarif, "sarif", "", "write the opened paths as SARIF 2.1.0 results to this file")
	f.StringVar(&planCommentFlags.sarifURI, "sarif-uri", "main.tf", "artifact URI the SARIF results point at (the Terraform root's main file)")
	f.BoolVar(&planCommentFlags.failOnOpened, "fail-on-opened", false, "exit 3 when the plan opens an attack path or escalates one into High/Critical (unless --opened-only); lowered paths never trip it")
	f.BoolVar(&planCommentFlags.openedOnly, "opened-only", false, "with --fail-on-opened: gate on opened paths only; escalations are still reported but do not exit 3")
	f.StringSliceVar(&planCommentFlags.trusted, "trusted-cidr", nil, "extra trusted CIDRs (added to config trusted_cidrs)")
	f.StringVar(&planCommentFlags.jsonOut, "diff-json", "", "also write the diff result as JSON to this file (contains topology: never upload it from a public repo)")
	f.StringVar(&planCommentFlags.botLogin, "bot-login", "", "only edit a sticky comment authored by this login (default: the token's own identity from GitHub /user; github-actions[bot] for the Actions GITHUB_TOKEN). A comment by anyone else is never edited, even if it starts with the marker")
	f.IntVar(&planCommentFlags.maxBytes, "plan-max-bytes", iac.DefaultPlanMaxBytes, "reject plan JSON larger than this")
	f.StringVar(&planCommentFlags.iacRoot, "iac", "", "Terraform root (repository-relative) to build GitHub suggestion blocks from: a single-hunk fix of an opened / escalated path becomes a one-click suggestion; multi-hunk or unpatchable fixes keep the fix: hint (empty: off)")
	f.BoolVar(&planCommentFlags.reviewSugs, "review-suggestions", true, "with --iac and --repo/--pr: also post each suggestion once as a review comment on its lines, where GitHub offers \"Commit suggestion\"")
}

// runPlanComment is `pr-comment --plan-json`.
func runPlanComment(cmd *cobra.Command) error {
	fh, err := os.Open(planCommentFlags.planJSON)
	if err != nil {
		return err
	}
	plan, err := iac.ReadPlanJSON(fh, iac.PlanLimits{MaxBytes: planCommentFlags.maxBytes})
	fh.Close()
	if err != nil {
		return fmt.Errorf("plan %s: %w", planCommentFlags.planJSON, err)
	}
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	live, err := planLiveGraph()
	if err != nil {
		return err
	}
	o := pathdiff.Options{Traversal: traversalOptions(cfg, live)}
	if live != nil {
		if st, err := openStore(); err == nil {
			fs, _ := st.Findings(store.Filter{Status: "FAIL"})
			st.Close()
			o.Traversal.NodeCVEs = attackpath.CVEIndex(fs)
		}
	}
	o.Traversal.TrustedCIDRs = append(o.Traversal.TrustedCIDRs, planCommentFlags.trusted...)
	res := pathdiff.Diff(live, nil, plan, o)
	redact := redactFor(planCommentFlags.redact)
	var sugs []planSuggestion
	if planCommentFlags.iacRoot != "" {
		sugs = planSuggestions(res, planCommentFlags.iacRoot, planCommentFlags.maxPaths)
	}
	body := renderPlanComment(res, commentOptions{Redact: redact, MaxPaths: planCommentFlags.maxPaths, Suggestions: sugs})
	// DB-less outputs (W6-VERIFY handoff, r4 #15): redacted ones carry run-keyed path Issue ids
	// (NIMBUS_ID_KEY keeps them stable across runs), never the raw digest of a redacted name;
	// unredacted ones keep the digest and say id_scheme "unkeyed".
	pub := res
	if redact {
		keyer, err := output.RunKeyerFromKey(os.Getenv("NIMBUS_ID_KEY"))
		if err != nil {
			return err
		}
		pub = res.WithKeyedIDs(keyer)
	}
	if planCommentFlags.jsonOut != "" {
		b, _ := json.MarshalIndent(pub, "", "  ")
		if err := os.WriteFile(planCommentFlags.jsonOut, b, 0o600); err != nil {
			return err
		}
	}
	if planCommentFlags.sarif != "" {
		b, _ := json.MarshalIndent(pathsSARIF(pub, redact, planCommentFlags.sarifURI), "", "  ")
		if err := os.WriteFile(planCommentFlags.sarif, b, 0o644); err != nil {
			return err
		}
	}
	var postErr error
	if prFlags.repo == "" || prFlags.pr == 0 {
		fmt.Print(body)
	} else {
		ctx := cmd.Context()
		if ctx == nil {
			ctx = context.Background()
		}
		act, err := gitops.StickyComment(ctx, gitops.StickyOptions{BaseURL: os.Getenv("GITHUB_API_URL"), OwnerRepo: prFlags.repo, PR: prFlags.pr, Token: os.Getenv("GITHUB_TOKEN"),
			Marker: gitops.PlanDiffMarker, BotLogin: planCommentFlags.botLogin}, body)
		var apiErr *gitops.APIError
		if errors.As(err, &apiErr) && !apiErr.Permission() {
			// verify-5 H1: GitHub refused the comment itself (422 too long, 5xx): the PR shows
			// no plan diff, so the step fails (after the gate below) instead of exiting 0.
			postErr = fmt.Errorf("plan-diff comment not posted: %w", err)
			fmt.Fprintf(os.Stderr, "✗ %v\n", postErr)
		} else if err != nil {
			// A fork PR's token is read-only: report, do not hide the gate result behind it.
			fmt.Fprintf(os.Stderr, "warning: plan-diff comment not posted: %v\n", err)
		} else {
			fmt.Printf("✓ %s plan-diff comment on %s#%d (opens %d / escalates %d / lowers %d / closes %d)\n", act, prFlags.repo, prFlags.pr, len(res.Opened), len(escalatedPaths(res)), len(res.Lowered()), len(res.Closed))
		}
		if len(sugs) > 0 && planCommentFlags.reviewSugs {
			n, err := postReviewSuggestions(ctx, reviewTarget{APIURL: os.Getenv("GITHUB_API_URL"), OwnerRepo: prFlags.repo, PR: prFlags.pr, Token: os.Getenv("GITHUB_TOKEN"), IaCRoot: planCommentFlags.iacRoot}, sugs)
			if err != nil {
				fmt.Fprintf(os.Stderr, "warning: suggestion review comments: %v\n", err)
			} else if n > 0 {
				fmt.Printf("✓ posted %d suggestion review comment(s) on %s#%d\n", n, prFlags.repo, prFlags.pr)
			}
		}
	}
	if planCommentFlags.failOnOpened && res.GateTripped(planCommentFlags.openedOnly) {
		if planCommentFlags.openedOnly {
			fmt.Fprintf(os.Stderr, "✗ this change opens %d attack path(s)\n", len(res.Opened))
		} else {
			fmt.Fprintf(os.Stderr, "✗ this change opens %d and escalates %d attack path(s)\n", len(res.Opened), len(escalatedPaths(res)))
		}
		exitFn(exitOpened)
	}
	return postErr
}

// planLiveGraph loads the scan DB's graph (nil for plan-only mode).
func planLiveGraph() (*graph.Graph, error) {
	mode := strings.ToLower(planCommentFlags.live)
	if mode == "off" || mode == "false" {
		return nil, nil
	}
	path := firstNonEmpty(flagDB, store.DefaultPath())
	if _, err := os.Stat(path); err != nil {
		if mode == "on" || mode == "true" {
			return nil, fmt.Errorf("--live on: no scan DB at %s", path)
		}
		return nil, nil
	}
	st, err := openStore()
	if err != nil {
		return nil, err
	}
	defer st.Close()
	g, err := loadGraph(st)
	if err != nil {
		return nil, err
	}
	if g.Len() <= 1 {
		if fs, err := st.Findings(store.Filter{}); err == nil {
			g.AttachFindings(fs)
		}
	}
	if g.Len() <= 1 && mode != "on" && mode != "true" {
		return nil, nil
	}
	return g, nil
}

// redactFor resolves --redact: auto redacts unless the GitHub event payload says the
// repository is private (unknown visibility redacts).
func redactFor(mode string) bool {
	switch strings.ToLower(mode) {
	case "off", "false", "no":
		return false
	case "on", "true", "yes":
		return true
	}
	p := os.Getenv("GITHUB_EVENT_PATH")
	if p == "" {
		return true
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return true
	}
	var ev struct {
		Repository struct {
			Private *bool `json:"private"`
		} `json:"repository"`
	}
	if json.Unmarshal(b, &ev) != nil || ev.Repository.Private == nil {
		return true
	}
	return !*ev.Repository.Private
}

// ---------------------------------------------------------------- rendering

type commentOptions struct {
	Redact      bool
	MaxPaths    int
	Suggestions []planSuggestion
	Notes       []string // trusted notes (budget trimming); shown even when redacted
}

var mdEntities = map[rune]string{
	'&': "&amp;", '<': "&lt;", '>': "&gt;", '@': "&#64;", '`': "&#96;", '[': "&#91;", ']': "&#93;", '(': "&#40;", ')': "&#41;",
	'*': "&#42;", '#': "&#35;", '|': "&#124;", '~': "&#126;", '!': "&#33;", '\\': "&#92;", ':': "&#58;",
}

// md makes an untrusted string inert in GitHub Markdown: control characters become spaces and
// every Markdown / HTML control character (and @ mentions) an HTML entity. Length is capped.
func md(s string) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		if n >= 300 {
			b.WriteString("…")
			break
		}
		n++
		switch {
		case r < 0x20 || r == 0x7f || r == 0x2028 || r == 0x2029 || r == 0x85:
			b.WriteByte(' ')
		case mdEntities[r] != "":
			b.WriteString(mdEntities[r])
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

var (
	safeToken   = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,80}$`)
	safeCommand = regexp.MustCompile(`^cloud-posture fix --finding [A-Z0-9_]{1,80} --generate-terraform$`)
)

func shortHash(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:2])
}

type pathView struct {
	N          int
	Path       string // already escaped / redacted
	Score      string
	Tags       string
	Why        string
	Fix        string
	FixCommand string
	Suggested  bool // a one-click suggestion below replaces the CLI hint
}

type commentView struct {
	Opened, Closed   int
	Escalated        int
	EscalatedPaths   []string
	Lowered          int
	LoweredPaths     []string
	Suggestions      []suggestionView
	Redacted         bool
	Mode, Confidence string
	Note             string
	OpenedPaths      []pathView
	ClosedPaths      []pathView
	MoreOpened       int
	MoreClosed       int
	Changed          []string
	MoreChanged      int
	Rerouted         int
	ExposuresOpened  int
	ExposuresClosed  int
	Notes            []string
	Marker           string
}

func hopLabel(h pathdiff.HopRef, redact bool) string {
	if redact {
		return md(h.Type) + " &#91;" + shortHash(h.ID) + "&#93;"
	}
	return "**" + md(h.Name) + "** &#40;" + md(h.Type) + "&#41;"
}

func pathLine(p pathdiff.PathRef, redact bool) string {
	parts := []string{}
	if p.Entry == "internet" {
		parts = append(parts, "Internet")
	}
	for _, h := range p.Hops {
		l := hopLabel(h, redact)
		if h.Relation != "entry" {
			l = "&#40;" + md(h.Relation) + "&#41; " + l
		}
		parts = append(parts, l)
	}
	return strings.Join(parts, " → ")
}

func viewOf(p pathdiff.PathRef, i int, redact bool) pathView {
	v := pathView{N: i + 1, Path: pathLine(p, redact), Score: fmt.Sprintf("%.1f", p.Score)}
	tags := []string{md(p.Band)}
	if p.ToxicCombination != "" {
		tags = append(tags, md(p.ToxicCombination))
	}
	tags = append(tags, "confidence "+md(string(p.Confidence)))
	v.Tags = strings.Join(tags, " · ")
	if p.ChangedHop >= 0 && p.ChangedHop < len(p.Hops) {
		h := p.Hops[p.ChangedHop]
		if redact {
			v.Why = fmt.Sprintf("changed hop %d &#40;%s → %s&#41;", p.ChangedHop+1, md(h.Relation), md(h.Type))
		} else {
			v.Why = fmt.Sprintf("changed hop %d &#40;%s&#41;: %s", p.ChangedHop+1, md(h.Relation), md(p.Why))
		}
		if p.ChangedBy != "" && !strings.HasPrefix(p.ChangedBy, "live ") && (redact || !strings.Contains(p.Why, p.ChangedBy)) {
			v.Why += " — planned by " + md(p.ChangedBy)
		}
	}
	// Fix template ids and commands come from the catalog (trusted); refuse anything else.
	if p.FixTemplate != "" && safeToken.MatchString(p.FixTemplate) && safeCommand.MatchString(p.FixCommand) {
		v.Fix, v.FixCommand = p.FixTemplate, p.FixCommand
	}
	return v
}

var planCommentTmpl = template.Must(template.New("plan").Parse(`{{.Marker}}
## 🛡️ nimbus plan diff: this PR opens {{.Opened}} / escalates {{.Escalated}} / lowers {{.Lowered}} / closes {{.Closed}} attack paths

Mode **{{.Mode}}** · confidence **{{.Confidence}}**{{if .Note}} — {{.Note}}{{end}}{{if .Redacted}}
_Topology redacted (public repository): hop types and short hashes only; run with ` + "`--redact off`" + ` in a private repository for resource names._{{end}}
{{if .OpenedPaths}}
### Opened ({{.Opened}})
{{range .OpenedPaths}}{{.N}}. {{.Path}} — score {{.Score}} &#40;{{.Tags}}&#41;
{{if .Why}}   - why: {{.Why}}
{{end}}{{if .Suggested}}   - fix: one-click suggestion below &#40;template ` + "`{{.Fix}}`" + `&#41;
{{else if .Fix}}   - fix: template ` + "`{{.Fix}}`" + ` — ` + "`{{.FixCommand}}`" + `
{{end}}{{end}}{{if .MoreOpened}}
…and {{.MoreOpened}} more opened path(s) not listed (--max-paths).
{{end}}{{end}}{{if .EscalatedPaths}}
### Escalated to High/Critical ({{.Escalated}})
{{range .EscalatedPaths}}- {{.}}
{{end}}{{end}}{{if .LoweredPaths}}
### Lowered ({{.Lowered}})
{{range .LoweredPaths}}- {{.}}
{{end}}{{end}}{{if .ClosedPaths}}
### Closed ({{.Closed}})
{{range .ClosedPaths}}{{.N}}. {{.Path}} — score {{.Score}} &#40;{{.Tags}}&#41;
{{if .Why}}   - why: {{.Why}}
{{end}}{{end}}{{if .MoreClosed}}
…and {{.MoreClosed}} more closed path(s) not listed (--max-paths).
{{end}}{{end}}{{if .Changed}}
### Score changes
{{range .Changed}}- {{.}}
{{end}}{{if .MoreChanged}}- …and {{.MoreChanged}} more
{{end}}{{end}}{{if or .Rerouted .ExposuresOpened .ExposuresClosed}}
Rerouted paths (same entry and target, new hops): {{.Rerouted}} · internet exposures (not paths) opened {{.ExposuresOpened}} / closed {{.ExposuresClosed}}
{{end}}{{if .Suggestions}}
### Suggested changes ({{len .Suggestions}})
_One block per hunk of the deterministic patcher's fix for the PR's Terraform. With ` + "`--repo`/`--pr`" + ` each block is also posted as a review comment on its lines, where GitHub offers **Commit suggestion**; commit every part of one fix together._
{{range .Suggestions}}
**{{.Canonical}}** on {{.Where}} — confidence **{{.Label}}**{{if .Part}} · {{.Part}}{{end}} — {{.Explanation}} &#40;patch confidence {{.Confidence}}, {{.Check}}&#41;

{{.Block}}
{{end}}{{end}}{{range .Notes}}
> note: {{.}}{{end}}

---
<sub>Generated by cloud-posture pr-comment --plan-json. Paths are keyed by entry → target, so middle-hop churn is not counted as new.</sub>

nimbus-opens-paths: {{.Opened}}
nimbus-escalates-paths: {{.Escalated}}
nimbus-lowers-paths: {{.Lowered}}
nimbus-closes-paths: {{.Closed}}
`))

// renderPlanComment renders the diff (the sticky marker is added by gitops.StickyComment) within
// commentMaxChars (verify-5 H1: GitHub refuses a longer body, which would drop the whole plan
// diff): past the budget the suggestions are dropped, then the path lists shortened, each with
// a visible note; the headline counts and the footer always stay exact.
func renderPlanComment(r pathdiff.Result, o commentOptions) string {
	body := renderPlanCommentOnce(r, o)
	if len([]rune(body)) <= commentMaxChars {
		return body
	}
	if len(o.Suggestions) > 0 {
		o.Notes = append(o.Notes, fmt.Sprintf("%d suggested change(s) omitted: the comment would exceed GitHub's 65,536-character limit; run cloud-posture fix locally", len(o.Suggestions)))
		o.Suggestions = nil
		if body = renderPlanCommentOnce(r, o); len([]rune(body)) <= commentMaxChars {
			return body
		}
	}
	if o.MaxPaths <= 0 {
		o.MaxPaths = 10
	}
	notes := o.Notes
	for o.MaxPaths > 1 {
		o.MaxPaths /= 2
		o.Notes = append(append([]string{}, notes...), fmt.Sprintf("path lists shortened to %d per section to stay under GitHub's comment limit; counts and footer cover all paths", o.MaxPaths))
		if body = renderPlanCommentOnce(r, o); len([]rune(body)) <= commentMaxChars {
			return body
		}
	}
	return body
}

func renderPlanCommentOnce(r pathdiff.Result, o commentOptions) string {
	if o.MaxPaths <= 0 {
		o.MaxPaths = 10
	}
	v := commentView{Opened: len(r.Opened), Closed: len(r.Closed), Redacted: o.Redact, Mode: md(r.Mode), Confidence: md(string(r.Confidence)),
		Rerouted: r.Rerouted, ExposuresOpened: len(r.ExposuresOpened), ExposuresClosed: len(r.ExposuresClosed)}
	if !o.Redact {
		v.Note = md(r.ConfidenceNote)
		for _, n := range r.Notes {
			v.Notes = append(v.Notes, md(n))
		}
	}
	for _, n := range o.Notes {
		v.Notes = append(v.Notes, md(n))
	}
	suggested := map[string]bool{}
	for _, s := range o.Suggestions {
		suggested[s.IssueID] = true
		if sv, ok := s.view(); ok {
			v.Suggestions = append(v.Suggestions, sv)
		}
	}
	for i, p := range r.Opened {
		if i >= o.MaxPaths {
			v.MoreOpened = len(r.Opened) - o.MaxPaths
			break
		}
		pv := viewOf(p, i, o.Redact)
		pv.Suggested = pv.Fix != "" && suggested[p.IssueID]
		v.OpenedPaths = append(v.OpenedPaths, pv)
	}
	for i, p := range r.Closed {
		if i >= o.MaxPaths {
			v.MoreClosed = len(r.Closed) - o.MaxPaths
			break
		}
		cv := viewOf(p, i, o.Redact)
		cv.Fix, cv.FixCommand = "", ""
		v.ClosedPaths = append(v.ClosedPaths, cv)
	}
	esc := escalatedPaths(r)
	v.Escalated = len(esc)
	for i, c := range esc {
		if i >= o.MaxPaths {
			v.EscalatedPaths = append(v.EscalatedPaths, fmt.Sprintf("…and %d more", len(esc)-o.MaxPaths))
			break
		}
		v.EscalatedPaths = append(v.EscalatedPaths, fmt.Sprintf("%s: %.1f → %.1f &#40;%s → %s&#41;", pathLine(c.Path, o.Redact), c.Before, c.After, risk.BandFor(c.Before), risk.BandFor(c.After)))
	}
	low := r.Lowered()
	v.Lowered = len(low)
	for i, c := range low {
		if i >= o.MaxPaths {
			v.LoweredPaths = append(v.LoweredPaths, fmt.Sprintf("…and %d more", len(low)-o.MaxPaths))
			break
		}
		v.LoweredPaths = append(v.LoweredPaths, fmt.Sprintf("%s: %.1f → %.1f &#40;%s → %s&#41;", pathLine(c.Path, o.Redact), c.Before, c.After, risk.BandFor(c.Before), risk.BandFor(c.After)))
	}
	for i, c := range r.ChangedScore {
		if i >= o.MaxPaths {
			v.MoreChanged = len(r.ChangedScore) - o.MaxPaths
			break
		}
		v.Changed = append(v.Changed, fmt.Sprintf("%s: %.1f → %.1f", pathLine(c.Path, o.Redact), c.Before, c.After))
	}
	var b strings.Builder
	if err := planCommentTmpl.Execute(&b, v); err != nil {
		return "nimbus plan diff: render error\n\nnimbus-opens-paths: " + fmt.Sprint(len(r.Opened)) + "\nnimbus-escalates-paths: " + fmt.Sprint(len(esc)) + "\nnimbus-lowers-paths: " + fmt.Sprint(len(low)) + "\nnimbus-closes-paths: " + fmt.Sprint(len(r.Closed)) + "\n"
	}
	return strings.TrimLeft(b.String(), "\n")
}

// ---------------------------------------------------------------- SARIF

const sarifMaxResults = 25000 // GitHub code scanning's per-run cap

// pathsSARIF is a SARIF 2.1.0 log with one result per opened path.
func pathsSARIF(r pathdiff.Result, redact bool, uri string) map[string]any {
	results := []any{}
	for i, p := range r.Opened {
		if i >= sarifMaxResults {
			break
		}
		level := "warning"
		if p.Score >= 7 {
			level = "error"
		}
		var hops []string
		for _, h := range p.Hops {
			if redact {
				hops = append(hops, h.Type+" ["+shortHash(h.ID)+"]")
			} else {
				hops = append(hops, h.Name+" ("+h.Type+")")
			}
		}
		if p.Entry == "internet" {
			hops = append([]string{"Internet"}, hops...)
		}
		msg := fmt.Sprintf("This change opens an attack path (score %.1f, %s): %s.", p.Score, p.Band, strings.Join(hops, " → "))
		if p.ToxicCombination != "" {
			msg += " Toxic combination: " + p.ToxicCombination + "."
		}
		if p.FixCommand != "" {
			msg += " Fix: " + p.FixCommand
		}
		props := map[string]any{"issue_id": p.IssueID, "score": p.Score, "confidence": string(p.Confidence), "toxic_combination": p.ToxicCombination, "fix_template": p.FixTemplate}
		if !redact {
			props["changed_by"] = p.ChangedBy
		}
		results = append(results, map[string]any{
			"ruleId": "NIMBUS_PATH_OPENED", "level": level, "message": map[string]any{"text": msg},
			"partialFingerprints": map[string]any{"nimbusPathIssue/v1": p.IssueID},
			"locations":           []any{map[string]any{"physicalLocation": map[string]any{"artifactLocation": map[string]any{"uri": uri}, "region": map[string]any{"startLine": 1}}}},
			"properties":          props,
		})
	}
	return map[string]any{
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"version": "2.1.0",
		"runs": []any{map[string]any{
			"tool": map[string]any{"driver": map[string]any{"name": "nimbus-plan-diff", "informationUri": "https://github.com/DreadpiratePickles/nimbus",
				"rules": []any{map[string]any{"id": "NIMBUS_PATH_OPENED", "name": "AttackPathOpened",
					"shortDescription": map[string]any{"text": "The planned change opens an attack path from an entry point to an impact target"},
					"helpUri":          "https://github.com/DreadpiratePickles/nimbus/blob/main/docs/plan-diff.md"}}}},
			"results": results,
			// What issue_id / nimbusPathIssue/v1 are (internal/output ids.go).
			"properties": map[string]any{"nimbus_id_scheme": firstNonEmpty(r.IDScheme, output.IDSchemeUnkeyed)},
		}},
	}
}

// ---------------------------------------------------------------- suggestions (shortfall #14)

// suggestionMaxLines caps a suggestion's hunk on either side: a reviewable one-click change.
const suggestionMaxLines = 40

// planSuggestion is a single-hunk fix for the path Issue IssueID: lines Start..End
// (1-based, inclusive) of File (relative to the --iac root) become Lines.
type planSuggestion struct {
	IssueID     string
	File        string
	Start, End  int
	Lines       []string
	Canonical   string
	Explanation string
	Confidence  float64
	Verified    bool // the re-scan proved the finding gone; false: not statically provable (e.g. a variable)
	Part, Of    int  // hunk Part of Of for one fix (multi-hunk patches: commit them together)
	NewVars     []string
}

type suggestionView struct {
	Canonical, Where, Explanation, Confidence, Label, Check, Block, Part string
}

// Suggestion size bounds (verify-5 H1): GitHub refuses a comment body over 65,536 characters,
// which would drop the whole plan-diff comment. A suggestion is a reviewable change: a line
// longer than suggestionMaxLineLen or content over suggestionMaxBytes keeps the CLI fix hint.
const (
	suggestionMaxLineLen = 500
	suggestionMaxBytes   = 8 << 10
	// commentMaxChars is the body budget below GitHub's 65,536-character limit (the sticky
	// marker and a margin are added on top).
	commentMaxChars = 60000
)

// confidenceLabel is the reviewer-facing label of a suggestion: high only when the re-scan
// proved the fix and the patch is deterministic; low below 0.6 patch confidence.
func (s planSuggestion) confidenceLabel() string {
	switch {
	case s.Verified && s.Confidence >= 0.9:
		return "high"
	case s.Confidence >= 0.6:
		return "medium"
	default:
		return "low"
	}
}

// content is the suggestion's replacement text, verbatim (it is code to commit, never escaped).
func (s planSuggestion) content() string { return strings.Join(s.Lines, "\n") }

// block is the ```suggestion code block; its fence outlasts every backtick run in the content
// (pathdiff.Fence), so repository-controlled text cannot close it and inject Markdown.
func (s planSuggestion) block() string {
	c := s.content()
	f := pathdiff.Fence(c)
	return f + "suggestion\n" + c + "\n" + f
}

func (s planSuggestion) where() string {
	if s.Start == s.End {
		return fmt.Sprintf("%s line %d", md(filepath.ToSlash(s.File)), s.Start)
	}
	return fmt.Sprintf("%s lines %d–%d", md(filepath.ToSlash(s.File)), s.Start, s.End)
}

func (s planSuggestion) view() (suggestionView, bool) {
	if !safeToken.MatchString(s.Canonical) || s.Start < 1 || s.End < s.Start || len(s.Lines) == 0 || !suggestionSizeOK(s.Lines) {
		return suggestionView{}, false
	}
	check := map[bool]string{true: "re-scan verified", false: "re-scan unverified: review the values"}[s.Verified]
	if len(s.NewVars) > 0 {
		check += "; declares variable " + md(strings.Join(s.NewVars, ", ")) + ": set it before plan"
	}
	v := suggestionView{Canonical: s.Canonical, Where: s.where(), Explanation: md(s.Explanation), Label: s.confidenceLabel(),
		Confidence: fmt.Sprintf("%.1f", s.Confidence), Check: check, Block: s.block()}
	if s.Of > 1 {
		v.Part = fmt.Sprintf("part %d of %d of one fix: commit all %d together (Add suggestion to batch)", s.Part, s.Of, s.Of)
	}
	return v, true
}

func suggestionSizeOK(lines []string) bool {
	n := 0
	for _, l := range lines {
		if len(l) > suggestionMaxLineLen {
			return false
		}
		n += len(l) + 1
	}
	return n <= suggestionMaxBytes
}

// patchParses reports whether the patched file is valid HCL: a suggestion the re-scan could
// not parse is never offered.
func patchParses(file, after string) bool {
	_, diags := hclsyntax.ParseConfig([]byte(after), file, hcl.InitialPos)
	return !diags.HasErrors()
}

// planSuggestions builds one-click suggestions for the opened and escalated paths: the plan
// address that changed the path (ChangedBy) and its fix (FixCanonical) are matched to a finding
// of the native Terraform scan of root, patched with iac.PatchTerraformWith, and kept only when
// the patch is not disproven (verifyPatchResult re-scans it: "not fixed" is dropped, "unverified"
// is shown as such), does not widen access, needs no appended variable block or shared-module
// change, and is one hunk. Anything else keeps the `fix:` hint.
func planSuggestions(r pathdiff.Result, root string, max int) []planSuggestion {
	sr, _ := iac.ScanTerraformResult(root, time.Now()) // an unscanned file yields no finding to patch
	var cands []pathdiff.PathRef
	cands = append(cands, r.Opened...)
	for _, c := range escalatedPaths(r) {
		cands = append(cands, c.Path)
	}
	var out []planSuggestion
	seen := map[string]bool{}
	for _, p := range cands {
		if len(out) >= max {
			break
		}
		ss, ok := suggestFor(p, sr.Findings, root)
		if !ok {
			continue
		}
		key := fmt.Sprintf("%s:%d:%d", ss[0].File, ss[0].Start, ss[0].End)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, ss...)
	}
	return out
}

// suggestFor patches the finding behind p's changed hop and returns one suggestion per hunk of
// the patch (a rewritten rule plus an appended variable block is two hunks, each its own
// review comment, labelled "part i of n"). It refuses (false) when the patch is ambiguous,
// widens access, touches a shared module, is disproven by the re-scan, does not parse, or has
// a hunk over the size bounds: never a partial fix.
func suggestFor(p pathdiff.PathRef, fs []model.Finding, root string) ([]planSuggestion, bool) {
	if p.FixCanonical == "" || p.ChangedBy == "" || strings.HasPrefix(p.ChangedBy, "live ") {
		return nil, false
	}
	var got [][]planSuggestion
	for _, f := range fs {
		if f.CanonicalID != p.FixCanonical || f.Status != model.Fail || f.File == "" || shortAddress(f.Resource.ID) != shortAddress(p.ChangedBy) {
			continue
		}
		if _, err := gitops.SafeJoin(root, f.File); err != nil {
			continue
		}
		// The full plan address lets the patcher refuse a same-named block in another module.
		f.Resource.ID = p.ChangedBy
		pt, err := iac.PatchTerraformWith(f, root, iac.PatchOptions{})
		if err != nil || pt == nil || pt.WidensAccess || len(pt.Callers) > 1 {
			continue
		}
		if !patchParses(f.File, pt.After) {
			continue
		}
		v := verifyPatchResult(f, *pt)
		if v.Verdict == verdictNotFixed {
			continue
		}
		hs, ok := pathdiff.Hunks(pt.Before, pt.After, suggestionMaxLines)
		if !ok || pathdiff.ApplyHunks(pt.Before, hs) != pt.After {
			continue
		}
		var ss []planSuggestion
		for i, h := range hs {
			if !suggestionSizeOK(h.Lines) {
				ss = nil
				break
			}
			ss = append(ss, planSuggestion{IssueID: p.IssueID, File: f.File, Start: h.Start, End: h.End, Lines: h.Lines,
				Canonical: pt.CanonicalID, Explanation: pt.Explanation, Confidence: pt.Confidence, Verified: v.Verdict == verdictVerified,
				Part: i + 1, Of: len(hs), NewVars: pt.DeclaredVariables})
		}
		if len(ss) > 0 {
			got = append(got, ss)
		}
	}
	if len(got) != 1 { // none, or ambiguous: never guess
		return nil, false
	}
	return got[0], true
}

// reviewTarget addresses the pull request the suggestions are posted to as review comments.
type reviewTarget struct {
	APIURL    string // default https://api.github.com ($GITHUB_API_URL on GHES)
	HTTP      *http.Client
	OwnerRepo string
	PR        int
	Token     string
	IaCRoot   string // --iac, relative to the repository root (the working directory)
}

var headSHA = regexp.MustCompile(`^[0-9a-f]{40}$`)

// postReviewSuggestions posts each suggestion as a pull-request review comment on its lines
// (start_line..line, side RIGHT, on the PR head commit), where GitHub renders "Commit
// suggestion". Each comment carries a hidden marker hashed from its anchor and content; a
// suggestion already present is not posted again. It returns the number posted.
func postReviewSuggestions(ctx context.Context, t reviewTarget, sugs []planSuggestion) (int, error) {
	if !ownerRepoOK(t.OwnerRepo) || t.PR <= 0 {
		return 0, fmt.Errorf("invalid repository %q or pull request %d", t.OwnerRepo, t.PR)
	}
	base := strings.TrimRight(firstNonEmpty(t.APIURL, "https://api.github.com"), "/")
	hc := t.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	do := func(method, u string, payload any, into any) (int, error) {
		var rd io.Reader
		if payload != nil {
			b, _ := json.Marshal(payload)
			rd = bytes.NewReader(b)
		}
		req, err := http.NewRequestWithContext(ctx, method, u, rd)
		if err != nil {
			return 0, err
		}
		req.Header.Set("Authorization", "Bearer "+t.Token)
		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
		if payload != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := hc.Do(req)
		if err != nil {
			return 0, err
		}
		defer resp.Body.Close()
		if into != nil && resp.StatusCode < 300 {
			if err := json.NewDecoder(io.LimitReader(resp.Body, 32<<20)).Decode(into); err != nil {
				return resp.StatusCode, err
			}
		}
		return resp.StatusCode, nil
	}
	sha := eventHeadSHA()
	if sha == "" {
		var pr struct {
			Head struct {
				SHA string `json:"sha"`
			} `json:"head"`
		}
		if code, err := do(http.MethodGet, fmt.Sprintf("%s/repos/%s/pulls/%d", base, t.OwnerRepo, t.PR), nil, &pr); err != nil || code >= 300 {
			return 0, fmt.Errorf("pull request head: GitHub API %d %v", code, err)
		}
		sha = pr.Head.SHA
	}
	if !headSHA.MatchString(sha) {
		return 0, fmt.Errorf("pull request head commit unknown")
	}
	existing := map[string]bool{}
	for page := 1; page <= 10; page++ {
		var cs []struct {
			Body string `json:"body"`
		}
		code, err := do(http.MethodGet, fmt.Sprintf("%s/repos/%s/pulls/%d/comments?per_page=100&page=%d", base, t.OwnerRepo, t.PR, page), nil, &cs)
		if err != nil || code >= 300 {
			return 0, fmt.Errorf("list review comments: GitHub API %d %v", code, err)
		}
		for _, c := range cs {
			if m := reviewMarkerRe.FindStringSubmatch(c.Body); m != nil {
				existing[m[1]] = true
			}
		}
		if len(cs) < 100 {
			break
		}
	}
	posted := 0
	for _, s := range sugs {
		sv, ok := s.view()
		if !ok {
			continue
		}
		path, ok := repoPath(t.IaCRoot, s.File)
		if !ok {
			continue
		}
		h := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%d\x00%d\x00%s", path, s.Start, s.End, s.content())))
		id := hex.EncodeToString(h[:8])
		if existing[id] {
			continue
		}
		part := ""
		if sv.Part != "" {
			part = " · " + sv.Part
		}
		body := fmt.Sprintf("<!-- nimbus-suggestion:%s -->\n**nimbus** · %s — confidence **%s**%s — %s &#40;patch confidence %s, %s&#41;. This fix is for an attack path this PR opens or escalates.\n\n%s\n",
			id, sv.Canonical, sv.Label, part, sv.Explanation, sv.Confidence, sv.Check, sv.Block)
		payload := map[string]any{"body": body, "commit_id": sha, "path": path, "line": s.End, "side": "RIGHT"}
		if s.Start < s.End {
			payload["start_line"], payload["start_side"] = s.Start, "RIGHT"
		}
		code, err := do(http.MethodPost, fmt.Sprintf("%s/repos/%s/pulls/%d/comments", base, t.OwnerRepo, t.PR), payload, nil)
		if err != nil {
			return posted, err
		}
		if code >= 300 {
			// 422: the lines are not part of the PR diff; the sticky comment still carries the block.
			fmt.Fprintf(os.Stderr, "warning: suggestion on %s:%d not posted as a review comment (GitHub API %d; lines outside the PR diff?)\n", path, s.End, code)
			continue
		}
		existing[id] = true
		posted++
	}
	return posted, nil
}

var reviewMarkerRe = regexp.MustCompile(`^<!-- nimbus-suggestion:([0-9a-f]{16}) -->`)

var ownerRepoPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9_.-]+$`)

func ownerRepoOK(s string) bool { return ownerRepoPattern.MatchString(s) && !strings.Contains(s, "..") }

// repoPath is the repository-relative path of file (relative to the --iac root) for the review
// API; a root or file outside the working directory is refused.
func repoPath(root, file string) (string, bool) {
	p := filepath.Join(root, file)
	if filepath.IsAbs(p) {
		wd, err := os.Getwd()
		if err != nil {
			return "", false
		}
		if p, err = filepath.Rel(wd, p); err != nil {
			return "", false
		}
	}
	p = filepath.ToSlash(filepath.Clean(p))
	if p == "." || p == ".." || strings.HasPrefix(p, "../") || strings.HasPrefix(p, "/") {
		return "", false
	}
	return p, true
}

// eventHeadSHA is the pull request head commit from $GITHUB_EVENT_PATH ("" when unknown).
func eventHeadSHA() string {
	p := os.Getenv("GITHUB_EVENT_PATH")
	if p == "" {
		return ""
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	var ev struct {
		PullRequest struct {
			Head struct {
				SHA string `json:"sha"`
			} `json:"head"`
		} `json:"pull_request"`
	}
	if json.Unmarshal(b, &ev) != nil {
		return ""
	}
	return ev.PullRequest.Head.SHA
}

// Package query runs SQL over the local posture database (zero-ETL: findings-derived
// inventory, compliance and attack-path views) and transparently proxies queries that
// reference Steampipe tables to a running Steampipe service.
package query

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/store"
)

type Result struct {
	Columns []string `json:"columns"`
	Rows    [][]any  `json:"rows"`
	Engine  string   `json:"engine"` // local | steampipe
	// Truncated is set when the row cap cut the result short.
	Truncated bool `json:"truncated,omitempty"`
}

var tableRe = regexp.MustCompile(`(?i)\b(?:from|join)\s+([a-zA-Z_][a-zA-Z0-9_.]*)`)

// Tables lists table names referenced by a query.
func Tables(sqlText string) []string {
	var out []string
	for _, m := range tableRe.FindAllStringSubmatch(sqlText, -1) {
		out = append(out, m[1])
	}
	return out
}

// IsReadOnly reports whether sqlText passes the lexical read-only check (one SELECT/WITH
// statement, no ATTACH/DETACH/PRAGMA, no sqlite_*/pragma_* references). Run additionally
// enforces read-only execution in the engine; see store.QueryReadOnly.
func IsReadOnly(sqlText string) bool { return store.CheckReadOnlySQL(sqlText) == nil }

// Options bound a local query; zero values use the store defaults.
type Options struct {
	Timeout time.Duration
	MaxRows int
}

// Run executes against the local DB; when the query references tables the local DB does not
// have and Steampipe is installed, it is proxied to `steampipe query`.
func Run(ctx context.Context, st *store.Store, sqlText string, forceEngine string) (*Result, error) {
	return RunWith(ctx, st, sqlText, forceEngine, Options{})
}

// RunWith is Run with explicit limits.
func RunWith(ctx context.Context, st *store.Store, sqlText string, forceEngine string, opts Options) (*Result, error) {
	if err := store.CheckReadOnlySQL(sqlText); err != nil {
		return nil, err
	}
	if _, err := EnsureAllViews(st); err != nil {
		return nil, err
	}
	useSteampipe := forceEngine == "steampipe"
	if forceEngine == "" {
		for _, t := range Tables(sqlText) {
			if !st.TableExists(t) {
				if _, err := exec.LookPath("steampipe"); err == nil {
					useSteampipe = true
				}
				break
			}
		}
	}
	if useSteampipe {
		return runSteampipe(ctx, sqlText)
	}
	res, err := st.QueryReadOnly(ctx, sqlText, store.ReadOnlyOptions{Timeout: opts.Timeout, MaxRows: opts.MaxRows})
	if err != nil {
		return nil, err
	}
	return &Result{Columns: res.Columns, Rows: res.Rows, Engine: "local", Truncated: res.Truncated}, nil
}

func runSteampipe(ctx context.Context, sqlText string) (*Result, error) {
	cmd := exec.CommandContext(ctx, "steampipe", "query", sqlText, "--output", "json")
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("steampipe: %s", strings.TrimSpace(string(ee.Stderr)))
		}
		return nil, err
	}
	var rows []map[string]any
	if err := json.Unmarshal(out, &rows); err != nil {
		// steampipe >= 0.20 wraps rows: {"rows":[...]}
		var wrapped struct {
			Rows []map[string]any `json:"rows"`
		}
		if err2 := json.Unmarshal(out, &wrapped); err2 != nil {
			return nil, fmt.Errorf("parse steampipe output: %w", err)
		}
		rows = wrapped.Rows
	}
	res := &Result{Engine: "steampipe"}
	if len(rows) == 0 {
		return res, nil
	}
	for k := range rows[0] {
		res.Columns = append(res.Columns, k)
	}
	for _, r := range rows {
		row := make([]any, len(res.Columns))
		for i, c := range res.Columns {
			row[i] = r[c]
		}
		res.Rows = append(res.Rows, row)
	}
	return res, nil
}

// frameworks that get their own view, mirroring the Python compliance packs.
var frameworkViews = []string{"cis_aws", "cis_azure", "cis_gcp", "cis_k8s", "cis_github", "nist_800_53", "pci_dss", "hipaa", "gdpr", "soc2", "iso_27001"}

// EnsureAllViews (re)creates inventory, compliance and attack-path views.
func EnsureAllViews(st *store.Store) ([]string, error) {
	st.LockViews()
	defer st.UnlockViews()
	views, err := st.EnsureViews()
	if err != nil {
		return nil, err
	}
	db := st.DB()
	stmts := []string{
		`DROP VIEW IF EXISTS attack_path_summary`,
		`CREATE VIEW attack_path_summary AS
		 SELECT id, rule_id, name,
		   json_extract(doc, '$.steps[0].resource') AS entry_point,
		   json_extract(doc, '$.steps[0].weakness') AS entry_type,
		   json_extract(doc, '$.steps[' || (json_array_length(json_extract(doc, '$.steps')) - 1) || '].resource') AS target,
		   json_extract(doc, '$.steps[' || (json_array_length(json_extract(doc, '$.steps')) - 1) || '].weakness') AS target_type,
		   json_array_length(json_extract(doc, '$.steps')) AS path_length,
		   score, severity, provider, account,
		   json_extract(doc, '$.impact') AS impact,
		   json_extract(doc, '$.narrative') AS narrative
		 FROM attack_paths`,
		`DROP VIEW IF EXISTS finding_compliance`,
		`CREATE VIEW finding_compliance AS
		 SELECT f.id AS finding_id, f.provider, f.account, f.status, f.severity, f.title, f.resource_name, f.description,
		   fw.key AS framework, ctl.value AS control_id
		 FROM findings f, json_each(f.compliance) AS fw, json_each(fw.value) AS ctl`,
		`DROP VIEW IF EXISTS compliance_controls`,
		`CREATE VIEW compliance_controls AS
		 SELECT framework, control_id, MIN(title) AS title, provider, account,
		   CASE WHEN SUM(status = 'FAIL') > 0 THEN 'FAIL' WHEN SUM(status = 'PASS') > 0 THEN 'PASS' ELSE 'NOT_ASSESSED' END AS status,
		   SUM(status = 'FAIL') AS failed, SUM(status = 'PASS') AS passed,
		   GROUP_CONCAT(CASE WHEN status = 'FAIL' THEN resource_name END, ', ') AS reason
		 FROM finding_compliance GROUP BY framework, control_id, provider, account`,
	}
	for _, fw := range frameworkViews {
		name := fw
		if strings.HasPrefix(fw, "cis_") {
			name = fw + "_benchmark"
		}
		stmts = append(stmts,
			"DROP VIEW IF EXISTS "+name,
			fmt.Sprintf(`CREATE VIEW %s AS SELECT control_id, title, provider, account, status, failed, passed, reason FROM compliance_controls WHERE framework = '%s'`, name, fw),
		)
		views = append(views, name)
	}
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			return nil, fmt.Errorf("view: %w (%s)", err, firstLine(s))
		}
	}
	return append(views, "attack_path_summary", "finding_compliance", "compliance_controls", "graph_nodes", "graph_edges", "findings", "resources", "attack_paths", "scans"), nil
}

func firstLine(s string) string {
	if i := strings.Index(s, "\n"); i > 0 {
		return s[:i]
	}
	return s
}

// Schema returns a compact description of tables/views and columns for copilots and --describe.
// It lists exactly what untrusted SQL may read (store.QueryableTables), so /api/schema is the
// read-only query allowlist.
func Schema(st *store.Store) (map[string][]string, error) {
	if _, err := EnsureAllViews(st); err != nil {
		return nil, err
	}
	names, err := st.QueryableTables()
	if err != nil {
		return nil, err
	}
	out := map[string][]string{}
	for _, n := range names {
		crow, err := st.DB().Query("SELECT name FROM pragma_table_info(?)", n)
		if err != nil {
			continue
		}
		for crow.Next() {
			var c string
			crow.Scan(&c)
			out[n] = append(out[n], c)
		}
		crow.Close()
	}
	return out, nil
}

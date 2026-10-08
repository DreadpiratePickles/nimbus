// Package neo4j pushes the nimbus security graph into Neo4j using Cartography-style
// labels and relationship types (AWSAccount -[:RESOURCE]-> EC2Instance, ...).
// Every node also carries the :Resource label, which holds the unique id constraint.
// Writes are batched UNWIND ... MERGE statements stamped with a lastupdated tag so a
// sync can optionally clean up stale nodes and relationships afterwards.
package neo4j

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/DreadpiratePickles/nimbus/internal/graph"
	driver "github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

// DefaultBatchSize is the number of rows per UNWIND statement.
const DefaultBatchSize = 500

// Config is the connection and sync configuration.
type Config struct {
	URI, Username, Password, Database string
	BatchSize                         int
	// Cleanup deletes nodes/relationships of the pushed accounts that were not
	// refreshed by this sync (Cartography's update-tag cleanup).
	Cleanup bool
}

// Stats summarises a push.
type Stats struct {
	Nodes         int            `json:"nodes"`
	Relationships int            `json:"relationships"`
	Batches       int            `json:"batches"`
	Labels        map[string]int `json:"labels"`
	RelTypes      map[string]int `json:"rel_types"`
}

// Statement is one parameterised Cypher statement.
type Statement struct {
	Cypher string
	Params map[string]any
}

// Runner executes one write statement; Push uses the official driver, tests a fake.
type Runner interface {
	Run(ctx context.Context, cypher string, params map[string]any) error
}

var typeLabels = map[string]string{
	"aws_account":                  "AWSAccount",
	"azure_subscription":           "AzureSubscription",
	"azure_account":                "AzureSubscription",
	"gcp_project":                  "GCPProject",
	"gcp_account":                  "GCPProject",
	"aws_instance":                 "EC2Instance",
	"aws_s3_bucket":                "S3Bucket",
	"aws_iam_role":                 "IAMRole",
	"aws_iam_user":                 "IAMUser",
	"aws_iam_policy":               "IAMPolicy",
	"aws_security_group":           "SecurityGroup",
	"aws_db_instance":              "RDSInstance",
	"aws_lambda_function":          "LambdaFunction",
	"aws_eks_cluster":              "EKSCluster",
	"aws_ebs_volume":               "EBSVolume",
	"azure_virtual_machine":        "AzureVM",
	"azure_storage_account":        "AzureStorageAccount",
	"azure_network_security_group": "AzureNSG",
	"azure_sql_server":             "AzureSQLServer",
	"azure_key_vault":              "KeyVault",
	"gcp_compute_instance":         "GCEInstance",
	"gcp_storage_bucket":           "GCSBucket",
	"gcp_compute_firewall":         "GCPFirewall",
	"gcp_sql_database_instance":    "CloudSQLInstance",
	"k8s_pod":                      "KubernetesPod",
	"k8s_namespace":                "KubernetesNamespace",
	"k8s_service_account":          "KubernetesServiceAccount",
	"k8s_cluster_role_binding":     "ClusterRoleBinding",
	"github_repository":            "GitHubRepository",
	"github_organization":          "GitHubOrganization",
	"okta_user":                    "OktaUser",
	"internet":                     "Internet",
}

var kindRels = map[string]string{
	graph.EdgeContains:        "RESOURCE",
	graph.EdgeAttachedTo:      "ATTACHED_TO",
	graph.EdgeCanAssume:       "STS_ASSUME_ROLE_ALLOWS",
	graph.EdgeHasPolicy:       "POLICY",
	graph.EdgeGrantsAccessTo:  "GRANTS_ACCESS_TO",
	graph.EdgeAllowsTrafficTo: "ALLOWS_TRAFFIC_TO",
	graph.EdgeExposes:         "EXPOSED_TO_INTERNET",
	graph.EdgeRunsAs:          "RUNS_AS",
	graph.EdgeBoundTo:         "BOUND_TO",
	graph.EdgeMemberOf:        "MEMBER_OF",
	graph.EdgeTrusts:          "TRUSTS",
	graph.EdgeRunsOn:          "RUNS_ON",
	graph.EdgeStoresDataIn:    "STORES_DATA_IN",
}

// LabelFor returns the primary (Cartography-style) label of a node: a fixed label
// for known resource types, otherwise the CamelCased graph class.
func LabelFor(n *graph.Node) string {
	if n == nil {
		return "Resource"
	}
	if n.ID == graph.InternetNodeID || n.Class == graph.ClassInternet {
		return "Internet"
	}
	if l, ok := typeLabels[strings.ToLower(n.Type)]; ok {
		return l
	}
	class := n.Class
	if class == "" {
		class = graph.ClassFor(n.Type)
	}
	if l := camel(class); l != "" {
		return l
	}
	return "Resource"
}

// Labels returns every label for a node: its primary label plus :Resource.
func Labels(n *graph.Node) []string {
	l := LabelFor(n)
	if l == "Resource" {
		return []string{"Resource"}
	}
	return []string{l, "Resource"}
}

// RelFor maps a graph edge onto a Neo4j relationship type.
func RelFor(e *graph.Edge, g *graph.Graph) string {
	if e == nil {
		return "RELATED_TO"
	}
	if e.Kind == graph.EdgeAttachedTo && g != nil {
		if to, ok := g.Node(e.To); ok && isSecurityGroup(to) {
			return "MEMBER_OF_SECURITY_GROUP"
		}
	}
	if r, ok := kindRels[e.Kind]; ok {
		return r
	}
	return sanitizeRel(e.Kind)
}

func isSecurityGroup(n *graph.Node) bool {
	t := strings.ToLower(n.Type)
	return strings.Contains(t, "security_group") || strings.Contains(t, "securitygroup") || strings.Contains(t, "nsg") || strings.Contains(t, "firewall")
}

func sanitizeRel(kind string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(kind) {
		if (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteRune('_')
		}
	}
	s := strings.Trim(b.String(), "_")
	if s == "" {
		return "RELATED_TO"
	}
	if s[0] >= '0' && s[0] <= '9' {
		s = "R_" + s
	}
	return s
}

func camel(s string) string {
	var b strings.Builder
	up := true
	for _, r := range s {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			up = true
			continue
		}
		if b.Len() == 0 && unicode.IsDigit(r) {
			b.WriteString("N")
		}
		if up {
			b.WriteRune(unicode.ToUpper(r))
			up = false
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// NodeProps returns the Neo4j-safe property map of a node.
func NodeProps(n *graph.Node) map[string]any {
	props := map[string]any{}
	for k, v := range n.Attributes {
		key := propKey(k)
		if key == "" {
			continue
		}
		if fv, ok := flatten(v); ok {
			props[key] = fv
		}
	}
	props["id"] = n.ID
	props["type"] = n.Type
	props["class"] = n.Class
	props["name"] = n.Name
	props["provider"] = n.Provider
	props["account"] = n.Account
	props["region"] = n.Region
	props["sensitive"] = n.Sensitive
	props["criticality"] = n.Criticality
	props["owner"] = n.Owner
	props["weaknesses"] = nonNil(n.Weaknesses)
	props["finding_ids"] = nonNil(n.FindingIDs)
	props["cve_count"] = int64(n.CVECount)
	props["monthly_cost"] = n.MonthlyCost
	props["modified_at"] = n.ModifiedAt
	return props
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func propKey(k string) string {
	var b strings.Builder
	for _, r := range k {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteRune('_')
		}
	}
	return b.String()
}

// flatten converts a value into a Neo4j property: primitives and homogeneous
// primitive lists pass through, everything else becomes a JSON string.
func flatten(v any) (any, bool) {
	switch x := v.(type) {
	case nil:
		return nil, false
	case string, bool, int64, float64:
		return x, true
	case int:
		return int64(x), true
	case int32:
		return int64(x), true
	case uint32:
		return int64(x), true
	case float32:
		return float64(x), true
	case time.Time:
		return x.UTC().Format(time.RFC3339), true
	case []string:
		return x, true
	case []int64, []float64, []bool:
		return x, true
	case []any:
		if strs, ok := allStrings(x); ok {
			return strs, true
		}
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return rv.Int(), true
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return int64(rv.Uint()), true
	case reflect.Float32, reflect.Float64:
		return rv.Float(), true
	case reflect.String:
		return rv.String(), true
	case reflect.Bool:
		return rv.Bool(), true
	}
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprint(v), true
	}
	return string(b), true
}

func allStrings(xs []any) ([]string, bool) {
	out := make([]string, 0, len(xs))
	for _, x := range xs {
		s, ok := x.(string)
		if !ok {
			return nil, false
		}
		out = append(out, s)
	}
	return out, true
}

func edgeProps(e *graph.Edge) map[string]any {
	props := map[string]any{"kind": e.Kind}
	for k, v := range e.Attr {
		key := propKey(k)
		if key == "" {
			continue
		}
		if fv, ok := flatten(v); ok {
			props[key] = fv
		}
	}
	return props
}

// Statements renders the graph as constraint statements followed by batched node
// MERGEs grouped by label and relationship MERGEs grouped by type. Each batch has
// a "rows" parameter; Push adds "update_tag".
func Statements(g *graph.Graph, batchSize int) []Statement {
	if batchSize <= 0 {
		batchSize = DefaultBatchSize
	}
	nodes := g.Nodes()
	byLabel := map[string][]map[string]any{}
	for _, n := range nodes {
		l := LabelFor(n)
		byLabel[l] = append(byLabel[l], map[string]any{"id": n.ID, "props": NodeProps(n)})
	}
	labels := sortedKeys(byLabel)

	stmts := []Statement{{Cypher: "CREATE CONSTRAINT resource_id IF NOT EXISTS FOR (n:Resource) REQUIRE n.id IS UNIQUE"}}
	for _, l := range labels {
		if l == "Resource" {
			continue
		}
		stmts = append(stmts, Statement{Cypher: fmt.Sprintf("CREATE INDEX %s_id IF NOT EXISTS FOR (n:%s) ON (n.id)", strings.ToLower(l), l)})
	}
	for _, l := range labels {
		set := "SET n += row.props, n.lastupdated = $update_tag"
		if l != "Resource" {
			set = fmt.Sprintf("SET n:%s, n += row.props, n.lastupdated = $update_tag", l)
		}
		cy := "UNWIND $rows AS row MERGE (n:Resource {id: row.id}) " + set
		for _, rows := range chunk(byLabel[l], batchSize) {
			stmts = append(stmts, Statement{Cypher: cy, Params: map[string]any{"rows": rows, "label": l}})
		}
	}

	byRel := map[string][]map[string]any{}
	for _, e := range g.Edges() {
		r := RelFor(e, g)
		byRel[r] = append(byRel[r], map[string]any{"from": e.From, "to": e.To, "props": edgeProps(e)})
	}
	for _, r := range sortedKeys(byRel) {
		cy := fmt.Sprintf("UNWIND $rows AS row MATCH (a:Resource {id: row.from}), (b:Resource {id: row.to}) MERGE (a)-[r:%s]->(b) SET r += row.props, r.lastupdated = $update_tag", r)
		for _, rows := range chunk(byRel[r], batchSize) {
			stmts = append(stmts, Statement{Cypher: cy, Params: map[string]any{"rows": rows, "rel": r}})
		}
	}
	return stmts
}

// CleanupStatements delete stale relationships and nodes belonging to the given
// accounts that were not touched by the sync carrying $update_tag.
func CleanupStatements(accounts []string) []Statement {
	if len(accounts) == 0 {
		return nil
	}
	p := map[string]any{"accounts": accounts}
	return []Statement{
		{Cypher: "MATCH (a:Resource)-[r]->(:Resource) WHERE a.account IN $accounts AND r.lastupdated <> $update_tag DELETE r", Params: p},
		{Cypher: "MATCH (n:Resource) WHERE n.account IN $accounts AND n.lastupdated <> $update_tag DETACH DELETE n", Params: p},
	}
}

func chunk(rows []map[string]any, n int) [][]map[string]any {
	var out [][]map[string]any
	for i := 0; i < len(rows); i += n {
		end := min(i+n, len(rows))
		out = append(out, rows[i:end])
	}
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// PushWith writes the graph through r. Statements are executed in order; the first
// failure aborts the push (later batches may reference earlier nodes).
func PushWith(ctx context.Context, r Runner, g *graph.Graph, cfg Config) (Stats, error) {
	return pushWith(ctx, r, g, cfg, time.Now().Unix())
}

func pushWith(ctx context.Context, r Runner, g *graph.Graph, cfg Config, tag int64) (Stats, error) {
	st := Stats{Labels: map[string]int{}, RelTypes: map[string]int{}}
	if g == nil {
		return st, errors.New("neo4j: nil graph")
	}
	stmts := Statements(g, cfg.BatchSize)
	if cfg.Cleanup {
		accts := map[string]bool{}
		for _, n := range g.Nodes() {
			if n.Account != "" {
				accts[n.Account] = true
			}
		}
		stmts = append(stmts, CleanupStatements(sortedKeys(accts))...)
	}
	for i, s := range stmts {
		if err := ctx.Err(); err != nil {
			return st, err
		}
		params := map[string]any{"update_tag": tag}
		var rows []map[string]any
		for k, v := range s.Params {
			if k == "label" || k == "rel" {
				continue
			}
			params[k] = v
		}
		if rv, ok := s.Params["rows"].([]map[string]any); ok {
			rows = rv
			// The driver needs []any for list parameters.
			anyRows := make([]any, len(rv))
			for j := range rv {
				anyRows[j] = rv[j]
			}
			params["rows"] = anyRows
		}
		if err := r.Run(ctx, s.Cypher, params); err != nil {
			return st, fmt.Errorf("neo4j statement %d (%s): %w", i, firstLine(s.Cypher), err)
		}
		if rows == nil {
			continue
		}
		st.Batches++
		if l, ok := s.Params["label"].(string); ok {
			st.Nodes += len(rows)
			st.Labels[l] += len(rows)
		}
		if rel, ok := s.Params["rel"].(string); ok {
			st.Relationships += len(rows)
			st.RelTypes[rel] += len(rows)
		}
	}
	return st, nil
}

func firstLine(s string) string {
	if len(s) > 80 {
		return s[:80] + "..."
	}
	return s
}

// driverRunner executes statements with the official driver.
type driverRunner struct {
	drv driver.DriverWithContext
	db  string
}

func (d *driverRunner) Run(ctx context.Context, cypher string, params map[string]any) error {
	opts := []driver.ExecuteQueryConfigurationOption{driver.ExecuteQueryWithWritersRouting()}
	if d.db != "" {
		opts = append(opts, driver.ExecuteQueryWithDatabase(d.db))
	}
	_, err := driver.ExecuteQuery(ctx, d.drv, cypher, params, driver.EagerResultTransformer, opts...)
	return err
}

// Push connects to Neo4j and syncs the graph.
func Push(ctx context.Context, cfg Config, g *graph.Graph) (Stats, error) {
	if cfg.URI == "" {
		return Stats{}, errors.New("neo4j: URI required (e.g. neo4j://localhost:7687)")
	}
	auth := driver.NoAuth()
	if cfg.Username != "" {
		auth = driver.BasicAuth(cfg.Username, cfg.Password, "")
	}
	drv, err := driver.NewDriverWithContext(cfg.URI, auth)
	if err != nil {
		return Stats{}, fmt.Errorf("neo4j: %w", err)
	}
	defer drv.Close(ctx)
	if err := drv.VerifyConnectivity(ctx); err != nil {
		return Stats{}, fmt.Errorf("neo4j connectivity: %w", err)
	}
	return PushWith(ctx, &driverRunner{drv: drv, db: cfg.Database}, g, cfg)
}

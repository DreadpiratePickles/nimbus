// Package graph is the in-memory security graph: every cloud resource is a node,
// relationships (attached_to, can_assume, allows_traffic_to, member_of, contains,
// reads_from, exposes) are typed edges. Findings attach weaknesses to nodes.
// The graph persists to SQLite (graph_nodes/graph_edges) and exports to Neo4j Cypher.
package graph

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// Edge kinds. Keep these stable: attack-path traversal and the dashboard key off them.
const (
	EdgeAttachedTo      = "attached_to"       // instance -> security group / role / volume
	EdgeCanAssume       = "can_assume"        // principal -> role
	EdgeAllowsTrafficTo = "allows_traffic_to" // internet / sg -> instance / db
	EdgeMemberOf        = "member_of"         // user -> group, pod -> namespace
	EdgeContains        = "contains"          // account -> resource, vpc -> subnet
	EdgeHasPolicy       = "has_policy"        // role/user/group -> policy
	EdgeGrantsAccessTo  = "grants_access_to"  // policy -> resource (s3, secrets, rds)
	EdgeExposes         = "exposes"           // internet -> public resource
	EdgeRunsAs          = "runs_as"           // pod -> service account, instance -> instance profile
	EdgeBoundTo         = "bound_to"          // service account -> cluster role
	EdgeStoresDataIn    = "stores_data_in"    // app -> bucket/db
	EdgeTrusts          = "trusts"            // role -> external account
	EdgeRunsOn          = "runs_on"           // pod -> node, container -> image
)

// Node classes drive entry-point / target detection.
const (
	ClassInternet  = "internet"
	ClassCompute   = "compute"   // ec2, vm, gce, pod, lambda, function
	ClassNetwork   = "network"   // sg, nsg, firewall, vpc, subnet, lb
	ClassIdentity  = "identity"  // user, role, service account, group, policy
	ClassDataStore = "datastore" // s3, blob, gcs, rds, sql, dynamodb, secrets
	ClassCluster   = "cluster"   // eks, aks, gke, k8s namespace
	ClassSaaS      = "saas"      // repo, org, tenant
	ClassAccount   = "account"
	ClassImage     = "image"
)

const InternetNodeID = "internet"

type Node struct {
	ID         string         `json:"id"`
	Type       string         `json:"type"`  // aws_instance, aws_s3_bucket, k8s_pod...
	Class      string         `json:"class"` // see Class* constants
	Name       string         `json:"name"`
	Provider   string         `json:"provider"`
	Account    string         `json:"account"`
	Region     string         `json:"region,omitempty"`
	Attributes map[string]any `json:"attributes,omitempty"`
	Weaknesses []string       `json:"weaknesses,omitempty"`
	FindingIDs []string       `json:"finding_ids,omitempty"`
	// Context used by risk scoring (filled by collectors / heuristics).
	Sensitive   bool    `json:"sensitive,omitempty"`   // crown jewel: PII, secrets, prod DB
	Criticality string  `json:"criticality,omitempty"` // production | staging | dev | unknown
	Owner       string  `json:"owner,omitempty"`
	ModifiedAt  string  `json:"modified_at,omitempty"` // RFC3339 when known
	CVECount    int     `json:"cve_count,omitempty"`
	MonthlyCost float64 `json:"monthly_cost,omitempty"`

	// Guessed: the type is not in the registry (registry.go), or the node is an edge
	// placeholder whose type was guessed from its id; Class came from a heuristic.
	Guessed bool `json:"guessed,omitempty"`

	placeholder bool // created by AddEdge; type/class are guesses until the resource arrives

	// owners: every (provider, account) pair any source reported for this node. Provider and
	// Account are a deterministic function of the set (pickOwner), never of arrival order
	// (verify-4 D4: path Issue provider/account flipped with ingest order).
	owners map[[2]string]bool
}

type Edge struct {
	From string         `json:"from"`
	To   string         `json:"to"`
	Kind string         `json:"kind"`
	Attr map[string]any `json:"attr,omitempty"`
}

type Graph struct {
	mu    sync.RWMutex
	nodes map[string]*Node
	out   map[string][]*Edge
	in    map[string][]*Edge
}

func New() *Graph {
	g := &Graph{nodes: map[string]*Node{}, out: map[string][]*Edge{}, in: map[string][]*Edge{}}
	g.AddNode(&Node{ID: InternetNodeID, Type: "internet", Class: ClassInternet, Name: "Internet", Provider: "any"})
	return g
}

// AddNode merges attributes when the node already exists.
func (g *Graph) AddNode(n *Node) *Node {
	g.mu.Lock()
	defer g.mu.Unlock()
	if n.ID == "" {
		return nil
	}
	if n.Class == "" {
		n.Class = ClassFor(n.Type)
	}
	if !n.placeholder {
		n.Guessed = !Registered(n.Type)
	}
	if n.Name == "" {
		n.Name = n.ID
	}
	if ex, ok := g.nodes[n.ID]; ok {
		if ex.Attributes == nil {
			ex.Attributes = map[string]any{}
		}
		for k, v := range n.Attributes {
			ex.Attributes[k] = v
		}
		if ex.placeholder && n.Type != "" {
			// ex was an edge placeholder: the real resource's type and class win.
			ex.Type, ex.Class, ex.placeholder, ex.Guessed = n.Type, n.Class, false, n.Guessed
		} else if ex.Type == "" && n.Type != "" {
			ex.Type, ex.Guessed = n.Type, n.Guessed
		}
		if ex.Class == "" || ex.Class == ClassAccount && n.Class != "" {
			ex.Class = n.Class
		}
		if n.Name != n.ID {
			ex.Name = n.Name
		}
		if n.Region != "" {
			ex.Region = n.Region
		}
		ex.mergeOwner(n.Provider, n.Account)
		if n.Sensitive {
			ex.Sensitive = true
		}
		if n.Criticality != "" {
			ex.Criticality = n.Criticality
		}
		if n.Owner != "" {
			ex.Owner = n.Owner
		}
		if n.ModifiedAt != "" {
			ex.ModifiedAt = n.ModifiedAt
		}
		if n.CVECount > ex.CVECount {
			ex.CVECount = n.CVECount
		}
		if n.MonthlyCost > 0 {
			ex.MonthlyCost = n.MonthlyCost
		}
		for _, w := range n.Weaknesses {
			ex.addWeakness(w)
		}
		ex.FindingIDs = appendUnique(ex.FindingIDs, n.FindingIDs...)
		return ex
	}
	n.owners = nil
	n.mergeOwner(n.Provider, n.Account)
	g.nodes[n.ID] = n
	return n
}

// mergeOwner records a reported (provider, account) pair and re-derives Provider / Account
// from every pair seen (order-independent; see pickOwner).
func (n *Node) mergeOwner(provider, account string) {
	if n.owners == nil {
		n.owners = map[[2]string]bool{}
	}
	for _, p := range [][2]string{{n.Provider, n.Account}, {provider, account}} {
		if p[0] != "" || p[1] != "" {
			n.owners[p] = true
		}
	}
	if len(n.owners) > 0 {
		n.Provider, n.Account = pickOwner(n.ID, n.owners)
	}
}

// pickOwner chooses a node's provider and account from the pairs reported for it, with a
// stable tie-break: the provider / account the resource id itself names (an ARN's partition
// and account, a GCP project, an Azure subscription) wins; otherwise the lexicographically
// smallest non-empty value. The account is chosen among pairs of the chosen provider (or of
// no provider). "any" (the internet node) is used only when nothing else is known.
func pickOwner(id string, pairs map[[2]string]bool) (string, string) {
	hp, ha := OwnerFromID(id)
	provider := ""
	for p := range pairs {
		v := p[0]
		if v == "" || v == "any" && provider != "" {
			continue
		}
		switch {
		case provider == "", provider == "any":
			provider = v
		case hp != "" && v == hp:
			provider = v
		case hp != "" && provider == hp:
		case v < provider:
			provider = v
		}
	}
	account := ""
	for p := range pairs {
		v := p[1]
		if v == "" || p[0] != "" && p[0] != provider {
			continue
		}
		switch {
		case account == "":
			account = v
		case ha != "" && v == ha:
			account = v
		case ha != "" && account == ha:
		case v < account:
			account = v
		}
	}
	return provider, account
}

// OwnerFromID returns the provider and account a resource id names, when it names one:
// arn:<partition>:<svc>:<region>:<account>:… → aws/<account>; //….googleapis.com/projects/<p>/…
// → gcp/<p>; /subscriptions/<s>/… → azure/<s>. Otherwise "", "".
func OwnerFromID(id string) (provider, account string) {
	switch {
	case strings.HasPrefix(id, "arn:aws"):
		parts := strings.SplitN(id, ":", 6)
		if len(parts) >= 5 {
			return "aws", parts[4]
		}
		return "aws", ""
	case strings.HasPrefix(id, "//") && strings.Contains(id, ".googleapis.com/"):
		if i := strings.Index(id, "/projects/"); i >= 0 {
			rest := id[i+len("/projects/"):]
			if j := strings.IndexByte(rest, '/'); j >= 0 {
				rest = rest[:j]
			}
			return "gcp", rest
		}
		return "gcp", ""
	case strings.HasPrefix(strings.ToLower(id), "/subscriptions/"):
		rest := id[len("/subscriptions/"):]
		if j := strings.IndexByte(rest, '/'); j >= 0 {
			rest = rest[:j]
		}
		return "azure", rest
	}
	return "", ""
}

func (n *Node) addWeakness(w string) {
	for _, x := range n.Weaknesses {
		if x == w {
			return
		}
	}
	n.Weaknesses = append(n.Weaknesses, w)
}

func (n *Node) HasWeakness(w string) bool {
	for _, x := range n.Weaknesses {
		if x == w {
			return true
		}
	}
	return false
}

func (g *Graph) AddEdge(from, to, kind string, attr map[string]any) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if from == "" || to == "" || from == to {
		return
	}
	for _, e := range g.out[from] {
		if e.To == to && e.Kind == kind {
			return
		}
	}
	// Auto-create placeholder nodes so references to not-yet-collected resources still link.
	for _, id := range []string{from, to} {
		if _, ok := g.nodes[id]; !ok {
			g.nodes[id] = &Node{ID: id, Name: lastSegment(id), Type: GuessType(id), Class: ClassFor(GuessType(id)), Guessed: true, placeholder: true}
		}
	}
	// Every edge says why it exists (O4). The caller's map is copied, never mutated.
	cp := make(map[string]any, len(attr)+1)
	for k, v := range attr {
		cp[k] = v
	}
	if b, _ := cp["because"].(string); b == "" {
		cp["because"] = DescribeEdge(g.nodes[from], g.nodes[to], kind, attr)
	}
	e := &Edge{From: from, To: to, Kind: kind, Attr: cp}
	g.out[from] = append(g.out[from], e)
	g.in[to] = append(g.in[to], e)
}

// Clone deep-copies nodes (weakness and finding slices included) and edges, so callers can
// apply what-if fixes without touching the original.
func (g *Graph) Clone() *Graph {
	g.mu.RLock()
	defer g.mu.RUnlock()
	c := &Graph{nodes: make(map[string]*Node, len(g.nodes)), out: make(map[string][]*Edge, len(g.out)), in: make(map[string][]*Edge, len(g.in))}
	for id, n := range g.nodes {
		nn := *n
		nn.Weaknesses = append([]string(nil), n.Weaknesses...)
		nn.FindingIDs = append([]string(nil), n.FindingIDs...)
		if n.owners != nil {
			nn.owners = make(map[[2]string]bool, len(n.owners))
			for k := range n.owners {
				nn.owners[k] = true
			}
		}
		c.nodes[id] = &nn
	}
	for from, es := range g.out {
		for _, e := range es {
			ne := &Edge{From: e.From, To: e.To, Kind: e.Kind, Attr: e.Attr}
			c.out[from] = append(c.out[from], ne)
			c.in[e.To] = append(c.in[e.To], ne)
		}
	}
	return c
}

// RemoveEdge deletes the edge from→to of the given kind; it reports whether one existed.
func (g *Graph) RemoveEdge(from, to, kind string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	found := false
	keep := g.out[from][:0:0]
	for _, e := range g.out[from] {
		if e.To == to && e.Kind == kind {
			found = true
			continue
		}
		keep = append(keep, e)
	}
	g.out[from] = keep
	keepIn := g.in[to][:0:0]
	for _, e := range g.in[to] {
		if e.From == from && e.Kind == kind {
			continue
		}
		keepIn = append(keepIn, e)
	}
	g.in[to] = keepIn
	return found
}

// RemoveNode deletes a node and every edge touching it.
func (g *Graph) RemoveNode(id string) {
	for _, e := range append(append([]*Edge{}, g.Out(id)...), g.In(id)...) {
		g.RemoveEdge(e.From, e.To, e.Kind)
	}
	g.mu.Lock()
	delete(g.nodes, id)
	delete(g.out, id)
	delete(g.in, id)
	g.mu.Unlock()
}

// RemoveWeakness drops one weakness from a node (a what-if fix); it reports whether it was present.
func (g *Graph) RemoveWeakness(id, w string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	n, ok := g.nodes[id]
	if !ok {
		return false
	}
	for i, x := range n.Weaknesses {
		if x == w {
			n.Weaknesses = append(append([]string(nil), n.Weaknesses[:i]...), n.Weaknesses[i+1:]...)
			return true
		}
	}
	return false
}

func (g *Graph) Node(id string) (*Node, bool) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	n, ok := g.nodes[id]
	return n, ok
}

func (g *Graph) Nodes() []*Node {
	g.mu.RLock()
	defer g.mu.RUnlock()
	out := make([]*Node, 0, len(g.nodes))
	for _, n := range g.nodes {
		out = append(out, n)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (g *Graph) Edges() []*Edge {
	g.mu.RLock()
	defer g.mu.RUnlock()
	var out []*Edge
	for _, es := range g.out {
		out = append(out, es...)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].From != out[j].From {
			return out[i].From < out[j].From
		}
		if out[i].To != out[j].To {
			return out[i].To < out[j].To
		}
		return out[i].Kind < out[j].Kind
	})
	return out
}

func (g *Graph) Out(id string) []*Edge { g.mu.RLock(); defer g.mu.RUnlock(); return g.out[id] }
func (g *Graph) In(id string) []*Edge  { g.mu.RLock(); defer g.mu.RUnlock(); return g.in[id] }
func (g *Graph) Len() int              { g.mu.RLock(); defer g.mu.RUnlock(); return len(g.nodes) }

// Merge copies another graph in (used to combine per-provider collector results).
func (g *Graph) Merge(other *Graph) {
	for _, n := range other.Nodes() {
		c := *n
		g.AddNode(&c)
	}
	for _, e := range other.Edges() {
		g.AddEdge(e.From, e.To, e.Kind, e.Attr)
	}
}

// AttachFindings adds weaknesses to the nodes findings point at, creating nodes for
// resources only known through scanner output, and wires account containment,
// internet exposure and relationship hints from Resource.Related.
func (g *Graph) AttachFindings(findings []model.Finding) {
	for _, f := range findings {
		if f.Resource.ID == "" {
			continue
		}
		n := &Node{ID: f.Resource.ID, Type: f.Resource.Type, Name: f.Resource.Name, Provider: f.Provider, Account: f.Account, Region: f.Region, Attributes: map[string]any{}}
		for k, v := range f.Resource.Attributes {
			n.Attributes[k] = v
		}
		n.Sensitive = looksSensitive(f.Resource.Name, f.Resource.Type, f.Resource.Attributes)
		n.Criticality = criticalityOf(f.Resource.Name, f.Account, f.Resource.Attributes, f.Tags)
		n.Owner = ownerOf(f.Resource.Attributes)
		if f.Status == model.Fail {
			n.Weaknesses = append(n.Weaknesses, f.Weaknesses...)
			n.FindingIDs = []string{f.ID}
			if f.CanonicalID == "CVE_VULNERABILITY" {
				n.CVECount = 1
			}
		}
		node := g.AddNode(n)
		if f.Status == model.Fail && f.CanonicalID == "CVE_VULNERABILITY" {
			node.CVECount++ // AddNode merged; count every CVE finding
		}
		acct := accountNodeID(f.Provider, f.Account)
		if f.Account != "" {
			g.AddNode(&Node{ID: acct, Type: f.Provider + "_account", Class: ClassAccount, Name: f.Account, Provider: f.Provider, Account: f.Account})
			g.AddEdge(acct, node.ID, EdgeContains, map[string]any{"because": fmt.Sprintf("finding %s reports %s in %s account %s", f.CanonicalID, node.Name, f.Provider, f.Account), "finding_id": f.ID})
		}
		if f.Status == model.Fail {
			for _, w := range f.Weaknesses {
				if w == "PUBLIC_NETWORK_EXPOSURE" || w == "PUBLIC_DATA_STORE" {
					attr := map[string]any{"via": f.CanonicalID, "check_id": f.CheckID, "finding_id": f.ID, "weakness": w,
						"because": fmt.Sprintf("finding %s (%s) reports %s on %s", f.CanonicalID, f.Title, w, node.Name)}
					// Exposure width input (O10): the public sources the scanner saw. Width
					// against trusted_cidrs is decided at analysis time (attackpath).
					if cidrs := exposureCIDRs(f.Resource.Attributes); len(cidrs) > 0 {
						attr["exposure_cidrs"] = cidrs
						attr["because"] = attr["because"].(string) + " from " + strings.Join(cidrs, ", ")
					}
					if ex, _ := f.Resource.Attributes["exposure"].(string); ex != "" {
						attr["exposure"] = ex
					}
					g.AddEdge(InternetNodeID, node.ID, EdgeExposes, attr)
				}
			}
		}
		typed := g.attachRelations(f, node)
		for _, r := range f.Resource.Related {
			if typed[r] {
				continue
			}
			g.AddEdge(node.ID, r, EdgeAttachedTo, map[string]any{"hint": true, "finding_id": f.ID,
				"because": fmt.Sprintf("finding %s lists %s as related to %s (scanner hint, attachment not verified)", f.CanonicalID, r, node.Name)})
		}
	}
	// Permission-bearing edges from the IAM evaluator (permissions.go); idempotent.
	g.EvaluatePermissions()
	// Effective internet reachability on every internet edge / exposed node (reachability.go,
	// P2-REACH); idempotent.
	g.AnnotateReachability()
}

func accountNodeID(provider, account string) string { return provider + ":account:" + account }

// Neighbors returns adjacent node IDs in both directions (optionally filtered by edge kinds).
func (g *Graph) Neighbors(id string, kinds ...string) []string {
	allow := map[string]bool{}
	for _, k := range kinds {
		allow[k] = true
	}
	var out []string
	for _, e := range g.Out(id) {
		if len(allow) == 0 || allow[e.Kind] {
			out = append(out, e.To)
		}
	}
	for _, e := range g.In(id) {
		if len(allow) == 0 || allow[e.Kind] {
			out = append(out, e.From)
		}
	}
	return out
}

// Cypher exports the graph as Neo4j CREATE statements.
func (g *Graph) Cypher() string {
	var b strings.Builder
	b.WriteString("// Generated by cloud-posture graph export --format cypher\n")
	b.WriteString("CREATE CONSTRAINT resource_id IF NOT EXISTS FOR (n:Resource) REQUIRE n.id IS UNIQUE;\n")
	for _, n := range g.Nodes() {
		props := map[string]any{"id": n.ID, "type": n.Type, "class": n.Class, "name": n.Name, "provider": n.Provider, "account": n.Account, "region": n.Region,
			"weaknesses": n.Weaknesses, "sensitive": n.Sensitive, "criticality": n.Criticality, "owner": n.Owner, "cve_count": n.CVECount}
		pj, _ := json.Marshal(props)
		label := strings.Title(strings.ReplaceAll(n.Class, "_", ""))
		fmt.Fprintf(&b, "MERGE (n:Resource:%s {id: %s}) SET n += %s;\n", label, jsonString(n.ID), cypherMap(pj))
	}
	for _, e := range g.Edges() {
		fmt.Fprintf(&b, "MATCH (a:Resource {id: %s}), (b:Resource {id: %s}) MERGE (a)-[:%s]->(b);\n", jsonString(e.From), jsonString(e.To), strings.ToUpper(e.Kind))
	}
	return b.String()
}

// JSON is the shape consumed by the dashboard (Cytoscape elements).
func (g *Graph) JSON() map[string]any {
	return map[string]any{"nodes": g.Nodes(), "edges": g.Edges()}
}

func jsonString(s string) string { b, _ := json.Marshal(s); return string(b) }

// cypherMap converts a JSON object into Cypher map syntax (keys unquoted).
func cypherMap(j []byte) string {
	var m map[string]json.RawMessage
	_ = json.Unmarshal(j, &m)
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+": "+string(m[k]))
	}
	return "{" + strings.Join(parts, ", ") + "}"
}

func lastSegment(s string) string {
	s = strings.TrimRight(s, "/")
	if i := strings.LastIndexAny(s, "/:"); i >= 0 && i < len(s)-1 {
		return s[i+1:]
	}
	return s
}

// classByType pins types whose names would otherwise hit the wrong substring rule
// (a service account is an identity and a storage account a data store, not an account).
var classByType = map[string]string{
	"internet":                 ClassInternet,
	"k8s_service_account":      ClassIdentity,
	"gcp_service_account":      ClassIdentity,
	"serviceaccount":           ClassIdentity,
	"azure_storage_account":    ClassDataStore,
	"aws_account":              ClassAccount,
	"gcp_project":              ClassAccount,
	"azure_subscription":       ClassAccount,
	"k8s_cluster_account":      ClassAccount,
	"m365_tenant":              ClassAccount,
	"okta_tenant":              ClassAccount,
	"github_account":           ClassAccount,
	"k8s_cluster_role":         ClassIdentity,
	"k8s_cluster_role_binding": ClassIdentity,
	"k8s_role":                 ClassIdentity,
}

// legacyClassFor is the pre-registry heuristic: an explicit type table first, then substring
// rules in which service/storage accounts are matched before the generic "account" rule.
// ClassFor (registry.go) falls back to it only for unregistered types.
func legacyClassFor(t string) string {
	l := strings.ToLower(t)
	if c, ok := classByType[l]; ok {
		return c
	}
	switch {
	case strings.Contains(l, "service_account") || strings.Contains(l, "serviceaccount") || strings.Contains(l, "service-account"):
		return ClassIdentity
	case strings.Contains(l, "storage_account") || strings.Contains(l, "storageaccount"):
		return ClassDataStore
	case strings.Contains(l, "account") || strings.Contains(l, "subscription") || strings.Contains(l, "project") || strings.Contains(l, "tenant"):
		return ClassAccount
	case strings.Contains(l, "bucket") || strings.Contains(l, "s3") || strings.Contains(l, "storage") || strings.Contains(l, "blob") || strings.Contains(l, "rds") || strings.Contains(l, "db_") || strings.Contains(l, "sql") || strings.Contains(l, "database") || strings.Contains(l, "dynamo") || strings.Contains(l, "secret") || strings.Contains(l, "kms") || strings.Contains(l, "keyvault") || strings.Contains(l, "key_vault") || strings.Contains(l, "volume") || strings.Contains(l, "disk") || strings.Contains(l, "snapshot"):
		return ClassDataStore
	case strings.Contains(l, "iam") || strings.Contains(l, "role") || strings.Contains(l, "policy") || strings.Contains(l, "user") || strings.Contains(l, "group") && !strings.Contains(l, "security") || strings.Contains(l, "service_account") || strings.Contains(l, "serviceaccount") || strings.Contains(l, "principal") || strings.Contains(l, "binding") || strings.Contains(l, "access_key"):
		return ClassIdentity
	case strings.Contains(l, "security_group") || strings.Contains(l, "securitygroup") || strings.Contains(l, "nsg") || strings.Contains(l, "firewall") || strings.Contains(l, "vpc") || strings.Contains(l, "subnet") || strings.Contains(l, "network") || strings.Contains(l, "load_balancer") || strings.Contains(l, "lb") || strings.Contains(l, "gateway") || strings.Contains(l, "eip") || strings.Contains(l, "address"):
		return ClassNetwork
	case strings.Contains(l, "eks") || strings.Contains(l, "aks") || strings.Contains(l, "gke") || strings.Contains(l, "cluster") || strings.Contains(l, "namespace"):
		return ClassCluster
	case strings.Contains(l, "image") || strings.Contains(l, "container_image"):
		return ClassImage
	case strings.Contains(l, "repo") || strings.Contains(l, "org") || strings.Contains(l, "github") || strings.Contains(l, "okta") || strings.Contains(l, "m365") || strings.Contains(l, "sharepoint"):
		return ClassSaaS
	case strings.Contains(l, "instance") || strings.Contains(l, "vm") || strings.Contains(l, "pod") || strings.Contains(l, "deployment") || strings.Contains(l, "lambda") || strings.Contains(l, "function") || strings.Contains(l, "compute") || strings.Contains(l, "container") || strings.Contains(l, "node"):
		return ClassCompute
	}
	return ClassCompute
}

// GuessType infers a resource type from an identifier (ARNs, k8s paths, Azure resource IDs).
func GuessType(id string) string {
	l := strings.ToLower(id)
	switch {
	case strings.HasPrefix(l, "arn:aws:s3:::"):
		return "aws_s3_bucket"
	case strings.HasPrefix(l, "arn:aws:iam::") && strings.Contains(l, ":role/"):
		return "aws_iam_role"
	case strings.HasPrefix(l, "arn:aws:iam::") && strings.Contains(l, ":policy/"):
		return "aws_iam_policy"
	case strings.HasPrefix(l, "arn:aws:iam::") && strings.Contains(l, ":user/"):
		return "aws_iam_user"
	case strings.HasPrefix(l, "arn:aws:iam::") && strings.Contains(l, ":instance-profile/"):
		return "aws_iam_instance_profile"
	case strings.HasPrefix(l, "arn:aws:ec2:") && strings.Contains(l, ":security-group/"), strings.HasPrefix(l, "sg-"):
		return "aws_security_group"
	case strings.HasPrefix(l, "arn:aws:ec2:") && strings.Contains(l, ":instance/"), strings.HasPrefix(l, "i-"):
		return "aws_instance"
	case strings.HasPrefix(l, "arn:aws:ec2:") && strings.Contains(l, ":volume/"), strings.HasPrefix(l, "vol-"):
		return "aws_ebs_volume"
	case strings.HasPrefix(l, "arn:aws:ec2:") && strings.Contains(l, ":vpc/"), strings.HasPrefix(l, "vpc-"):
		return "aws_vpc"
	case strings.HasPrefix(l, "subnet-"):
		return "aws_subnet"
	case strings.HasPrefix(l, "arn:aws:rds:"):
		return "aws_db_instance"
	case strings.HasPrefix(l, "arn:aws:lambda:"):
		return "aws_lambda_function"
	case strings.HasPrefix(l, "arn:aws:eks:"):
		return "aws_eks_cluster"
	case strings.HasPrefix(l, "arn:aws:secretsmanager:"):
		return "aws_secretsmanager_secret"
	case strings.Contains(l, "/providers/microsoft.storage/"):
		return "azure_storage_account"
	case strings.Contains(l, "/providers/microsoft.network/networksecuritygroups/"):
		return "azure_network_security_group"
	case strings.Contains(l, "/providers/microsoft.compute/virtualmachines/"):
		return "azure_virtual_machine"
	case strings.Contains(l, "/providers/microsoft.sql/"):
		return "azure_sql_server"
	case strings.Contains(l, "/providers/microsoft.keyvault/"):
		return "azure_key_vault"
	case strings.Contains(l, "/providers/microsoft.compute/disks/"):
		return "azure_managed_disk"
	case strings.HasPrefix(l, "//storage.googleapis.com/") || strings.HasPrefix(l, "gs://"):
		return "gcp_storage_bucket"
	case strings.Contains(l, "/instances/") && strings.Contains(l, "compute"):
		return "gcp_compute_instance"
	case strings.Contains(l, "/firewalls/"):
		return "gcp_compute_firewall"
	case strings.HasPrefix(l, "namespace/") || strings.HasPrefix(l, "ns/"):
		return "k8s_namespace"
	case strings.Contains(l, "/pod/") || strings.HasPrefix(l, "pod/"):
		return "k8s_pod"
	case strings.Contains(l, "iam.googleapis.com/") || strings.HasSuffix(l, ".gserviceaccount.com"):
		return "gcp_service_account"
	case strings.Contains(l, "clusterrolebinding/"):
		return "k8s_cluster_role_binding"
	case strings.Contains(l, "clusterrole/"):
		return "k8s_cluster_role"
	case strings.Contains(l, "serviceaccount"):
		return "k8s_service_account"
	}
	return ""
}

var sensitiveHints = []string{"pii", "customer", "prod", "payment", "card", "billing", "finance", "secret", "credential", "backup", "medical", "health", "patient", "hr", "salary", "ssn", "password", "token", "vault", "db", "database", "sql", "rds", "warehouse", "analytics"}

func looksSensitive(name, typ string, attrs map[string]any) bool {
	l := strings.ToLower(name)
	c := ClassFor(typ)
	if c == ClassDataStore {
		for _, h := range sensitiveHints {
			if strings.Contains(l, h) {
				return true
			}
		}
		if strings.Contains(strings.ToLower(typ), "secret") || strings.Contains(strings.ToLower(typ), "rds") || strings.Contains(strings.ToLower(typ), "sql") || strings.Contains(strings.ToLower(typ), "db_instance") {
			return true
		}
	}
	if attrs != nil {
		for _, k := range []string{"data_classification", "DataClassification", "classification"} {
			if v, ok := attrs[k].(string); ok {
				v = strings.ToLower(v)
				if v == "pii" || v == "confidential" || v == "restricted" || v == "phi" || v == "pci" {
					return true
				}
			}
		}
		if tags, ok := attrs["tags"].(map[string]any); ok {
			for k, v := range tags {
				lk := strings.ToLower(k)
				lv := strings.ToLower(fmt.Sprint(v))
				if strings.Contains(lk, "classification") || strings.Contains(lk, "sensitivity") {
					if lv == "pii" || lv == "confidential" || lv == "restricted" || lv == "high" || lv == "phi" || lv == "pci" {
						return true
					}
				}
			}
		}
	}
	return false
}

func criticalityOf(name, account string, attrs map[string]any, tags map[string]string) string {
	l := strings.ToLower(name + " " + account)
	if attrs != nil {
		if t, ok := attrs["tags"].(map[string]any); ok {
			for k, v := range t {
				lk := strings.ToLower(k)
				if lk == "environment" || lk == "env" || lk == "stage" || lk == "tier" {
					l += " " + strings.ToLower(fmt.Sprint(v))
				}
			}
		}
	}
	for k, v := range tags {
		if k == "account_label" || k == "environment" {
			l += " " + strings.ToLower(v)
		}
	}
	switch {
	case strings.Contains(l, "prod") || strings.Contains(l, "live") || strings.Contains(l, "prd"):
		return "production"
	case strings.Contains(l, "stag") || strings.Contains(l, "uat") || strings.Contains(l, "preprod"):
		return "staging"
	case strings.Contains(l, "dev") || strings.Contains(l, "test") || strings.Contains(l, "sandbox") || strings.Contains(l, "lab"):
		return "dev"
	}
	return "unknown"
}

func ownerOf(attrs map[string]any) string {
	if attrs == nil {
		return ""
	}
	if t, ok := attrs["tags"].(map[string]any); ok {
		for k, v := range t {
			lk := strings.ToLower(k)
			if lk == "owner" || lk == "team" || lk == "contact" || lk == "created_by" || lk == "createdby" {
				return fmt.Sprint(v)
			}
		}
	}
	for _, k := range []string{"owner", "Owner", "team"} {
		if v, ok := attrs[k].(string); ok {
			return v
		}
	}
	return ""
}

func appendUnique(list []string, vals ...string) []string {
	seen := map[string]bool{}
	for _, x := range list {
		seen[x] = true
	}
	for _, v := range vals {
		if v != "" && !seen[v] {
			seen[v] = true
			list = append(list, v)
		}
	}
	return list
}

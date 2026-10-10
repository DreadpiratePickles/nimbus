package iac

// Plan ingest (P1-PLANDIFF D1): `terraform show -json <planfile>` / `tofu show -json` → resource
// changes (create / update / delete / replace / no-op) with before / after values, mapped to the
// native resources, weaknesses and typed relations the attack-path graph is built from.
//
// The plan is UNTRUSTED input (plan v3 §5.3: a fork PR can supply it). ParsePlanJSON therefore
//
//   - rejects input over a size cap (DefaultPlanMaxBytes, 20 MiB) before decoding,
//   - rejects nesting deeper than a depth cap (DefaultPlanMaxDepth) with an iterative byte scan
//     before any recursive decoder sees it (a 70,000-deep array is an error, not a crash),
//   - caps the number of resource changes,
//   - never reads a file or runs a command: module sources, `file` attributes and provisioner
//     commands inside the plan are data and are ignored; expressions are never evaluated (only
//     their `references` lists are read, to link resources whose ids are unknown until apply),
//   - copies only the attributes the mapping rules need (no whole value maps), and skips any
//     attribute the plan marks sensitive.
//
// The mapping follows the HCL scanner's rules (scan.go) on decoded values: world-open security
// group ingress, IMDSv1, `*:*` IAM policies, public S3 ACL / policy, Lambda function URL auth NONE,
// public EKS endpoint, publicly accessible RDS; plus what the graph needs: instance → role through
// the instance profile, attached security groups, cross-account and GitHub OIDC role trusts.

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/DreadpiratePickles/nimbus/internal/collector/saas"
	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// Plan JSON limits.
const (
	DefaultPlanMaxBytes     = 20 << 20 // 20 MiB
	DefaultPlanMaxDepth     = 128
	DefaultPlanMaxResources = 50000
)

// PlanLimits bounds what ParsePlanJSON accepts. Zero fields mean the defaults.
type PlanLimits struct {
	MaxBytes     int
	MaxDepth     int
	MaxResources int
}

func (l PlanLimits) withDefaults() PlanLimits {
	if l.MaxBytes <= 0 {
		l.MaxBytes = DefaultPlanMaxBytes
	}
	if l.MaxDepth <= 0 {
		l.MaxDepth = DefaultPlanMaxDepth
	}
	if l.MaxResources <= 0 {
		l.MaxResources = DefaultPlanMaxResources
	}
	return l
}

// PlanLimitError reports a plan that was not decoded because it exceeds a limit.
type PlanLimitError struct{ Reason string }

func (e *PlanLimitError) Error() string { return "plan JSON rejected: " + e.Reason }

// PlanAction is the normalised change action.
type PlanAction string

const (
	PlanCreate  PlanAction = "create"
	PlanUpdate  PlanAction = "update"
	PlanDelete  PlanAction = "delete"
	PlanReplace PlanAction = "replace"
	PlanNoOp    PlanAction = "no-op"
)

// ResourceChange is one managed resource in the plan.
type ResourceChange struct {
	Address string     `json:"address"`
	Module  string     `json:"module,omitempty"`
	Type    string     `json:"type"`
	Name    string     `json:"name"`
	Action  PlanAction `json:"action"`
	// Before / After are the decoded values (nil when the side does not exist).
	Before map[string]any `json:"-"`
	After  map[string]any `json:"-"`
	// AfterUnknown marks after values known only after apply; *Sensitive mark sensitive values.
	AfterUnknown    any `json:"-"`
	BeforeSensitive any `json:"-"`
	AfterSensitive  any `json:"-"`
}

// Plan is a parsed plan.
type Plan struct {
	FormatVersion    string           `json:"format_version"`
	TerraformVersion string           `json:"terraform_version"`
	Errored          bool             `json:"errored"`
	Changes          []ResourceChange `json:"changes"`
	// refs: base address (no index) → attribute → referenced base addresses (configuration).
	refs map[string]map[string][]string
}

// Side selects the before or after state of a plan.
type Side int

const (
	SideBefore Side = iota
	SideAfter
)

func (s Side) String() string {
	if s == SideBefore {
		return "before"
	}
	return "after"
}

// Reach says whether a resource can be reached from the internet at all (public IP / flag).
type Reach int

const (
	ReachUnknown Reach = iota
	ReachYes
	ReachNo
)

// IngressRule is one ingress rule of a security group.
type IngressRule struct {
	CIDRs    []string `json:"cidrs"`
	FromPort int      `json:"from_port"`
	ToPort   int      `json:"to_port"`
	Protocol string   `json:"protocol"`
	Source   string   `json:"source"` // plan address that declares the rule
}

// Open reports a rule whose sources include the whole internet.
func (r IngressRule) Open() bool {
	for _, c := range r.CIDRs {
		if c == "0.0.0.0/0" || c == "::/0" {
			return true
		}
	}
	return false
}

// Ports renders the rule's ports ("tcp/22", "tcp/0-65535", "all").
func (r IngressRule) Ports() string {
	p := strings.ToLower(r.Protocol)
	if p == "-1" || p == "all" {
		return "all ports"
	}
	if p == "" {
		p = "tcp"
	}
	if r.FromPort == r.ToPort {
		return fmt.Sprintf("%s/%d", p, r.FromPort)
	}
	return fmt.Sprintf("%s/%d-%d", p, r.FromPort, r.ToPort)
}

// OpenIngress returns the world-open rules (nil when none).
func OpenIngress(rs []IngressRule) []IngressRule {
	var out []IngressRule
	for _, r := range rs {
		if r.Open() {
			out = append(out, r)
		}
	}
	return out
}

// PlanCheck is one failing native check on a mapped resource.
type PlanCheck struct {
	CanonicalID string         `json:"canonical_id"`
	CheckID     string         `json:"check_id"`
	Title       string         `json:"title"`
	Severity    model.Severity `json:"severity"`
	Weakness    string         `json:"weakness"`
	Detail      string         `json:"detail"`
	Source      string         `json:"source"` // plan address whose values triggered it
}

// PlanResource is one graph node as one side of the plan describes it.
type PlanResource struct {
	Address string     `json:"address,omitempty"` // empty for a stub (a live resource a plan resource modifies)
	Type    string     `json:"type"`
	Name    string     `json:"name"`
	Action  PlanAction `json:"action,omitempty"`
	// ID is the graph node id: the ARN or id when the plan knows it, "tf:<address>" for a
	// resource whose id is known only after apply, "name:<type>/<name>" for a reference by name
	// to a resource outside the plan (resolved against the live graph by the caller).
	ID       string `json:"id"`
	Provider string `json:"provider"`
	Account  string `json:"account,omitempty"`
	Region   string `json:"region,omitempty"`
	// Partial: a stub whose other properties live outside the plan.
	Partial         bool              `json:"partial,omitempty"`
	Attributes      map[string]any    `json:"attributes,omitempty"`
	Weaknesses      []string          `json:"weaknesses,omitempty"`
	Checks          []PlanCheck       `json:"checks,omitempty"`
	Relations       []model.Relation  `json:"relations,omitempty"`
	Ingress         []IngressRule     `json:"ingress,omitempty"`
	SecurityGroups  []string          `json:"security_groups,omitempty"`
	PublicReachable Reach             `json:"public_reachable,omitempty"`
	OIDCSubjects    []string          `json:"oidc_subjects,omitempty"`
	Unknown         []string          `json:"unknown,omitempty"`
	Sources         map[string]string `json:"-"` // contributing address → why
}

// ---------------------------------------------------------------- parsing

// ReadPlanJSON reads at most lim.MaxBytes+1 bytes from r and parses them.
func ReadPlanJSON(r io.Reader, lim PlanLimits) (*Plan, error) {
	lim = lim.withDefaults()
	data, err := io.ReadAll(io.LimitReader(r, int64(lim.MaxBytes)+1))
	if err != nil {
		return nil, err
	}
	return ParsePlanJSON(data, lim)
}

type rawChange struct {
	Address       string `json:"address"`
	ModuleAddress string `json:"module_address"`
	Mode          string `json:"mode"`
	Type          string `json:"type"`
	Name          string `json:"name"`
	Change        struct {
		Actions         []string `json:"actions"`
		Before          any      `json:"before"`
		After           any      `json:"after"`
		AfterUnknown    any      `json:"after_unknown"`
		BeforeSensitive any      `json:"before_sensitive"`
		AfterSensitive  any      `json:"after_sensitive"`
	} `json:"change"`
}

type rawModule struct {
	Resources []struct {
		Address     string                     `json:"address"`
		Mode        string                     `json:"mode"`
		Expressions map[string]json.RawMessage `json:"expressions"`
	} `json:"resources"`
	ModuleCalls map[string]struct {
		Module *rawModule `json:"module"`
	} `json:"module_calls"`
}

type rawPlan struct {
	FormatVersion    string      `json:"format_version"`
	TerraformVersion string      `json:"terraform_version"`
	Errored          bool        `json:"errored"`
	ResourceChanges  []rawChange `json:"resource_changes"`
	Configuration    *struct {
		RootModule *rawModule `json:"root_module"`
	} `json:"configuration"`
}

// ParsePlanJSON parses `terraform show -json` output under the limits.
func ParsePlanJSON(data []byte, lim PlanLimits) (*Plan, error) {
	lim = lim.withDefaults()
	if len(data) > lim.MaxBytes {
		return nil, &PlanLimitError{Reason: fmt.Sprintf("size %d bytes exceeds the %d-byte limit", len(data), lim.MaxBytes)}
	}
	if d := jsonDepth(data, lim.MaxDepth); d > lim.MaxDepth {
		return nil, &PlanLimitError{Reason: fmt.Sprintf("nesting depth exceeds the limit of %d", lim.MaxDepth)}
	}
	var raw rawPlan
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("plan JSON: %w", err)
	}
	if len(raw.ResourceChanges) > lim.MaxResources {
		return nil, &PlanLimitError{Reason: fmt.Sprintf("%d resource changes exceed the limit of %d", len(raw.ResourceChanges), lim.MaxResources)}
	}
	p := &Plan{FormatVersion: raw.FormatVersion, TerraformVersion: raw.TerraformVersion, Errored: raw.Errored, refs: map[string]map[string][]string{}}
	for _, rc := range raw.ResourceChanges {
		if rc.Mode != "" && rc.Mode != "managed" {
			continue // data sources are reads, not changes
		}
		if rc.Address == "" || rc.Type == "" {
			continue
		}
		act, ok := normalizeActions(rc.Change.Actions)
		if !ok {
			continue
		}
		before, _ := rc.Change.Before.(map[string]any)
		after, _ := rc.Change.After.(map[string]any)
		p.Changes = append(p.Changes, ResourceChange{Address: rc.Address, Module: rc.ModuleAddress, Type: rc.Type, Name: rc.Name, Action: act,
			Before: before, After: after, AfterUnknown: rc.Change.AfterUnknown, BeforeSensitive: rc.Change.BeforeSensitive, AfterSensitive: rc.Change.AfterSensitive})
	}
	sort.SliceStable(p.Changes, func(i, j int) bool { return p.Changes[i].Address < p.Changes[j].Address })
	if raw.Configuration != nil && raw.Configuration.RootModule != nil {
		p.collectRefs(raw.Configuration.RootModule, "", 0)
	}
	return p, nil
}

func normalizeActions(a []string) (PlanAction, bool) {
	switch {
	case len(a) == 1 && a[0] == "create":
		return PlanCreate, true
	case len(a) == 1 && a[0] == "update":
		return PlanUpdate, true
	case len(a) == 1 && a[0] == "delete":
		return PlanDelete, true
	case len(a) == 1 && a[0] == "no-op":
		return PlanNoOp, true
	case len(a) == 2 && (a[0] == "delete" && a[1] == "create" || a[0] == "create" && a[1] == "delete"):
		return PlanReplace, true
	}
	return "", false // read, forget, unknown
}

// jsonDepth is the maximum array/object nesting of data, scanning bytes iteratively (strings
// and escapes respected). It stops counting once stop is exceeded.
func jsonDepth(data []byte, stop int) int {
	depth, max := 0, 0
	inStr, esc := false, false
	for _, c := range data {
		if inStr {
			switch {
			case esc:
				esc = false
			case c == '\\':
				esc = true
			case c == '"':
				inStr = false
			}
			continue
		}
		switch c {
		case '"':
			inStr = true
		case '[', '{':
			depth++
			if depth > max {
				max = depth
				if max > stop {
					return max
				}
			}
		case ']', '}':
			depth--
		}
	}
	return max
}

const maxModuleDepth = 64

// collectRefs records, for every configured resource, the resources its expressions reference
// (module-qualified). Nothing is evaluated.
func (p *Plan) collectRefs(m *rawModule, prefix string, depth int) {
	if m == nil || depth > maxModuleDepth {
		return
	}
	for _, r := range m.Resources {
		if r.Mode != "" && r.Mode != "managed" {
			continue
		}
		base := prefix + r.Address
		for attr, raw := range r.Expressions {
			var v any
			if json.Unmarshal(raw, &v) != nil {
				continue
			}
			var refs []string
			walkRefs(v, func(ref string) {
				if a := refAddress(prefix, ref); a != "" {
					refs = append(refs, a)
				}
			})
			if len(refs) > 0 {
				if p.refs[base] == nil {
					p.refs[base] = map[string][]string{}
				}
				p.refs[base][attr] = uniqStrings(append(p.refs[base][attr], refs...))
			}
		}
	}
	names := make([]string, 0, len(m.ModuleCalls))
	for n := range m.ModuleCalls {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		p.collectRefs(m.ModuleCalls[n].Module, prefix+"module."+n+".", depth+1)
	}
}

// walkRefs calls fn for every string in a "references" list anywhere under v (iteratively).
func walkRefs(v any, fn func(string)) {
	stack := []any{v}
	for len(stack) > 0 && len(stack) < 100000 {
		x := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		switch t := x.(type) {
		case map[string]any:
			for k, e := range t {
				if k == "references" {
					if l, ok := e.([]any); ok {
						for _, s := range l {
							if str, ok := s.(string); ok {
								fn(str)
							}
						}
					}
					continue
				}
				stack = append(stack, e)
			}
		case []any:
			stack = append(stack, t...)
		}
	}
}

// refAddress turns a reference ("aws_security_group.ssh.id") into the module-qualified resource
// address ("module.web.aws_security_group.ssh"); "" for vars, locals, data sources, modules.
func refAddress(prefix, ref string) string {
	for _, skip := range []string{"var.", "local.", "data.", "module.", "each.", "count.", "path.", "self.", "terraform."} {
		if strings.HasPrefix(ref, skip) {
			return ""
		}
	}
	parts := strings.SplitN(ref, ".", 3)
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return ""
	}
	name := parts[1]
	if i := strings.IndexByte(name, '['); i >= 0 {
		name = name[:i]
	}
	return prefix + parts[0] + "." + name
}

func baseAddr(addr string) string { return indexSuffix.ReplaceAllString(addr, "") }

// ---------------------------------------------------------------- mapping

type planIndex struct {
	side    Side
	changes []*ResourceChange
	byAddr  map[string]*ResourceChange
	ids     map[string]string // address → node id
	byKey   map[string]string // "<type>|<identifier>" → address
}

func (c *ResourceChange) values(side Side) map[string]any {
	if side == SideBefore {
		if c.Action == PlanCreate {
			return nil
		}
		return c.Before
	}
	if c.Action == PlanDelete {
		return nil
	}
	return c.After
}

func (p *Plan) index(side Side) *planIndex {
	ix := &planIndex{side: side, byAddr: map[string]*ResourceChange{}, ids: map[string]string{}, byKey: map[string]string{}}
	for i := range p.Changes {
		c := &p.Changes[i]
		ix.ids[c.Address] = p.nodeID(c)
		if c.values(side) == nil {
			continue
		}
		ix.changes = append(ix.changes, c)
		ix.byAddr[c.Address] = c
		v := c.values(side)
		for _, k := range []string{"arn", "id", "name", "bucket", "function_name", "identifier"} {
			if s := str(v, k); s != "" && !c.sensitive(side, k) {
				ix.byKey[c.Type+"|"+s] = c.Address
			}
		}
	}
	return ix
}

// nodeID is stable across both sides: a known ARN (before first, so a replace keeps its id),
// then a type-specific natural id, then "tf:<address>".
func (p *Plan) nodeID(c *ResourceChange) string {
	for _, v := range []map[string]any{c.Before, c.After} {
		if s := str(v, "arn"); s != "" {
			return s
		}
	}
	for _, v := range []map[string]any{c.Before, c.After} {
		switch c.Type {
		case "aws_s3_bucket":
			if b := str(v, "bucket"); b != "" {
				return "arn:aws:s3:::" + b
			}
		case "aws_security_group", "aws_instance":
			if id := str(v, "id"); id != "" {
				return id
			}
		}
	}
	return "tf:" + c.Address
}

func (c *ResourceChange) sensitive(side Side, attr string) bool {
	s := c.AfterSensitive
	if side == SideBefore {
		s = c.BeforeSensitive
	}
	switch t := s.(type) {
	case bool:
		return t
	case map[string]any:
		b, _ := t[attr].(bool)
		return b
	}
	return false
}

func (c *ResourceChange) unknown(side Side, attr string) bool {
	if side == SideBefore {
		return false
	}
	m, _ := c.AfterUnknown.(map[string]any)
	switch t := m[attr].(type) {
	case bool:
		return t
	case []any, map[string]any:
		return true // partly unknown
	}
	return false
}

// resolve maps identifier values of attribute attr (pointing at resources of type typ) to node
// ids: a resource in the plan, else the value itself when it is an id / ARN, else a
// "name:<type>/<value>" reference. Unknown values fall back to configuration references.
func (p *Plan) resolve(ix *planIndex, c *ResourceChange, attr, typ string, vals []string) []string {
	var out []string
	for _, s := range vals {
		if s == "" {
			continue
		}
		if a, ok := ix.byKey[typ+"|"+s]; ok {
			out = append(out, ix.ids[a])
			continue
		}
		if looksLikeID(s) {
			out = append(out, s)
			continue
		}
		out = append(out, "name:"+typ+"/"+s)
	}
	if len(out) == 0 && c.unknown(ix.side, attr) {
		for _, a := range p.refs[baseAddr(c.Address)][attr] {
			for _, cand := range ix.changes {
				if baseAddr(cand.Address) == a && cand.Type == typ {
					out = append(out, ix.ids[cand.Address])
				}
			}
		}
	}
	return uniqStrings(out)
}

func looksLikeID(s string) bool {
	return strings.HasPrefix(s, "arn:") || strings.HasPrefix(s, "sg-") || strings.HasPrefix(s, "i-")
}

type builder struct {
	order []string
	res   map[string]*PlanResource
}

func (b *builder) get(id, typ string) *PlanResource {
	if r, ok := b.res[id]; ok {
		if r.Type == "" {
			r.Type = typ
		}
		return r
	}
	r := &PlanResource{ID: id, Type: typ, Name: lastSegment(id), Provider: providerOfType(typ), Partial: true, Attributes: map[string]any{}, Sources: map[string]string{}}
	r.Account, r.Region = arnAccountRegion(id)
	b.res[id] = r
	b.order = append(b.order, id)
	return r
}

func (b *builder) primary(c *ResourceChange, id string) *PlanResource {
	r := b.get(id, c.Type)
	r.Address, r.Type, r.Name, r.Action, r.Partial = c.Address, c.Type, c.Name, c.Action, false
	r.Attributes["address"] = c.Address
	return r
}

func (r *PlanResource) weak(ch PlanCheck) {
	r.Checks = append(r.Checks, ch)
	if ch.Weakness != "" && !contains(r.Weaknesses, ch.Weakness) {
		r.Weaknesses = append(r.Weaknesses, ch.Weakness)
	}
}

func (r *PlanResource) rel(kind, to string, attr map[string]any) {
	if to == "" || to == r.ID {
		return
	}
	for _, x := range r.Relations {
		if x.Kind == kind && x.ID == to {
			return
		}
	}
	r.Relations = append(r.Relations, model.Relation{ID: to, Kind: kind, Attr: attr})
}

// Resources maps one side of the plan to graph resources (sorted by id). Deterministic.
func (p *Plan) Resources(side Side) []PlanResource {
	if p == nil {
		return nil
	}
	ix := p.index(side)
	b := &builder{res: map[string]*PlanResource{}}
	// Pass 1: resources that are graph nodes.
	for _, c := range ix.changes {
		v := c.values(side)
		id := ix.ids[c.Address]
		switch c.Type {
		case "aws_security_group":
			r := b.primary(c, id)
			r.Name = firstNonEmptyStr(str(v, "name"), c.Name)
			for _, in := range maps(v["ingress"]) {
				r.Ingress = append(r.Ingress, ingressRule(in, c.Address))
			}
			if c.unknown(side, "ingress") {
				r.Unknown = append(r.Unknown, "ingress")
			}
		case "aws_instance":
			r := b.primary(c, id)
			r.Name = firstNonEmptyStr(tagName(v), c.Name)
			r.SecurityGroups = append(p.resolve(ix, c, "vpc_security_group_ids", "aws_security_group", strs(v["vpc_security_group_ids"])),
				p.resolve(ix, c, "security_groups", "aws_security_group", strs(v["security_groups"]))...)
			r.SecurityGroups = uniqStrings(r.SecurityGroups)
			r.PublicReachable = instanceReach(c, side, v)
			if ip := str(v, "public_ip"); ip != "" {
				r.Attributes["public_ip"] = ip
			}
			mo := maps(v["metadata_options"])
			tokens := ""
			if len(mo) > 0 {
				tokens = str(mo[0], "http_tokens")
			}
			switch {
			case len(mo) > 0 && tokens == "" && c.unknown(side, "metadata_options"):
				r.Unknown = append(r.Unknown, "metadata_options.http_tokens")
			case tokens != "required":
				r.Attributes["metadata_http_tokens"] = firstNonEmptyStr(tokens, "optional")
				r.weak(PlanCheck{CanonicalID: "EC2_IMDSV1", CheckID: "NIMBUS_PLAN_IMDSV1", Title: "EC2 instance allows IMDSv1", Severity: model.High, Weakness: "IMDSV1_ENABLED",
					Detail: "metadata_options.http_tokens is not \"required\"", Source: c.Address})
			default:
				r.Attributes["metadata_http_tokens"] = tokens
			}
			for _, prof := range p.resolve(ix, c, "iam_instance_profile", "aws_iam_instance_profile", strs(v["iam_instance_profile"])) {
				role := ""
				if a, ok := ix.byKey["aws_iam_instance_profile|"+strings.TrimPrefix(prof, "name:aws_iam_instance_profile/")]; ok {
					role = p.profileRole(ix, ix.byAddr[a])
				} else {
					for _, cand := range ix.changes {
						if cand.Type == "aws_iam_instance_profile" && ix.ids[cand.Address] == prof {
							role = p.profileRole(ix, cand)
						}
					}
				}
				if role != "" {
					r.rel("runs_as", role, map[string]any{"via": "instance profile " + lastSegment(prof), "source": "plan"})
				} else {
					r.rel("runs_as", prof, map[string]any{"via": "instance profile", "source": "plan"})
				}
			}
		case "aws_db_instance", "aws_rds_cluster_instance":
			r := b.primary(c, id)
			r.Name = firstNonEmptyStr(str(v, "identifier"), c.Name)
			r.SecurityGroups = p.resolve(ix, c, "vpc_security_group_ids", "aws_security_group", strs(v["vpc_security_group_ids"]))
			pub, known := boolean(v, "publicly_accessible")
			switch {
			case known && pub:
				r.PublicReachable = ReachYes
				r.weak(PlanCheck{CanonicalID: "RDS_PUBLIC", CheckID: "NIMBUS_PLAN_RDS_PUBLIC", Title: "RDS instance publicly accessible", Severity: model.Critical, Weakness: "PUBLIC_NETWORK_EXPOSURE",
					Detail: "publicly_accessible = true", Source: c.Address})
			case known:
				r.PublicReachable = ReachNo
			}
			if enc, known := boolean(v, "storage_encrypted"); known && !enc && c.Type == "aws_db_instance" {
				r.weak(PlanCheck{CanonicalID: "RDS_UNENCRYPTED", CheckID: "NIMBUS_PLAN_RDS_ENC", Title: "RDS storage not encrypted", Severity: model.High, Weakness: "UNENCRYPTED_AT_REST",
					Detail: "storage_encrypted = false", Source: c.Address})
			}
		case "aws_iam_role":
			r := b.primary(c, id)
			r.Name = firstNonEmptyStr(str(v, "name"), c.Name)
			if !c.sensitive(side, "assume_role_policy") {
				p.mapTrust(r, c, str(v, "assume_role_policy"))
			}
			for _, a := range strs(v["managed_policy_arns"]) {
				addPolicy(r, a, c.Address)
			}
			for _, in := range maps(v["inline_policy"]) {
				if adminDoc(str(in, "policy")) {
					adminCheck(r, "inline policy "+str(in, "name"), c.Address)
				}
			}
		case "aws_iam_policy":
			r := b.primary(c, id)
			r.Name = firstNonEmptyStr(str(v, "name"), c.Name)
			if adminDoc(str(v, "policy")) {
				r.weak(PlanCheck{CanonicalID: "IAM_ADMIN_POLICY", CheckID: "NIMBUS_PLAN_IAM_STAR", Title: "IAM policy allows *:*", Severity: model.High, Weakness: "OVERPRIVILEGED_IDENTITY",
					Detail: "statement allows Action \"*\" on Resource \"*\"", Source: c.Address})
			}
		case "aws_s3_bucket":
			r := b.primary(c, id)
			r.Name = firstNonEmptyStr(str(v, "bucket"), c.Name)
			publicACL(r, str(v, "acl"), c.Address)
			if pol := str(v, "policy"); pol != "" {
				bucketPolicy(r, pol, c.Address)
			}
		case "aws_lambda_function":
			r := b.primary(c, id)
			r.Name = firstNonEmptyStr(str(v, "function_name"), c.Name)
			for _, role := range p.resolve(ix, c, "role", "aws_iam_role", strs(v["role"])) {
				r.rel("runs_as", role, map[string]any{"via": "execution role", "source": "plan"})
			}
		case "aws_eks_cluster":
			r := b.primary(c, id)
			r.Name = firstNonEmptyStr(str(v, "name"), c.Name)
			for _, vc := range maps(v["vpc_config"]) {
				pub, known := boolean(vc, "endpoint_public_access")
				if known && !pub {
					continue
				}
				cidrs := strs(vc["public_access_cidrs"])
				if len(cidrs) == 0 {
					cidrs = []string{"0.0.0.0/0"} // provider default
				}
				r.Attributes["exposure_cidrs"] = cidrs
				r.Attributes["endpoint_public_access"] = true
				r.weak(PlanCheck{CanonicalID: "EKS_PUBLIC_ENDPOINT", CheckID: "NIMBUS_PLAN_EKS_PUBLIC", Title: "EKS endpoint public", Severity: model.High, Weakness: "PUBLIC_NETWORK_EXPOSURE",
					Detail: "endpoint_public_access from " + strings.Join(cidrs, ", "), Source: c.Address})
			}
		}
	}
	// Pass 2: resources that modify other nodes.
	for _, c := range ix.changes {
		v := c.values(side)
		switch c.Type {
		case "aws_security_group_rule", "aws_vpc_security_group_ingress_rule":
			if t := str(v, "type"); c.Type == "aws_security_group_rule" && t != "" && t != "ingress" {
				continue
			}
			for _, sg := range p.resolve(ix, c, "security_group_id", "aws_security_group", strs(v["security_group_id"])) {
				r := b.get(sg, "aws_security_group")
				r.Ingress = append(r.Ingress, ingressRule(v, c.Address))
				r.Sources[c.Address] = "ingress rule"
			}
		case "aws_iam_role_policy_attachment", "aws_iam_role_policy":
			for _, role := range p.resolve(ix, c, "role", "aws_iam_role", strs(v["role"])) {
				r := b.get(role, "aws_iam_role")
				if c.Type == "aws_iam_role_policy" {
					if adminDoc(str(v, "policy")) {
						adminCheck(r, "inline policy "+firstNonEmptyStr(str(v, "name"), c.Name), c.Address)
					}
					continue
				}
				pa := str(v, "policy_arn")
				if a, ok := ix.byKey["aws_iam_policy|"+pa]; ok && adminDoc(str(ix.byAddr[a].values(side), "policy")) {
					adminCheck(r, "attached policy "+lastSegment(pa), c.Address)
				}
				for _, pol := range p.resolve(ix, c, "policy_arn", "aws_iam_policy", strs(v["policy_arn"])) {
					if strings.HasPrefix(pol, "tf:") {
						if pc := changeByID(ix, pol); pc != nil && adminDoc(str(pc.values(side), "policy")) {
							adminCheck(r, "attached policy "+pc.Name, c.Address)
						}
						continue
					}
					addPolicy(r, pol, c.Address)
				}
			}
		case "aws_s3_bucket_policy", "aws_s3_bucket_acl", "aws_s3_bucket_public_access_block":
			for _, bk := range p.resolve(ix, c, "bucket", "aws_s3_bucket", strs(v["bucket"])) {
				if strings.HasPrefix(bk, "name:") {
					bk = "arn:aws:s3:::" + strings.TrimPrefix(bk, "name:aws_s3_bucket/")
				}
				r := b.get(bk, "aws_s3_bucket")
				switch c.Type {
				case "aws_s3_bucket_policy":
					bucketPolicy(r, str(v, "policy"), c.Address)
				case "aws_s3_bucket_acl":
					publicACL(r, str(v, "acl"), c.Address)
				default:
					on := true
					for _, k := range []string{"block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"} {
						if b, known := boolean(v, k); !known || !b {
							on = false
						}
					}
					r.Attributes["public_access_block"] = on
				}
			}
		case "aws_lambda_function_url":
			for _, fn := range p.resolve(ix, c, "function_name", "aws_lambda_function", strs(v["function_name"])) {
				r := b.get(fn, "aws_lambda_function")
				auth := str(v, "authorization_type")
				if auth == "" {
					continue
				}
				r.Attributes["function_url_auth_type"] = auth
				if strings.EqualFold(auth, "NONE") {
					r.weak(PlanCheck{CanonicalID: "LAMBDA_PUBLIC", CheckID: "NIMBUS_PLAN_LAMBDA_URL", Title: "Lambda function URL allows unauthenticated invocation", Severity: model.High,
						Weakness: "PUBLIC_NETWORK_EXPOSURE", Detail: "function URL authorization_type = NONE", Source: c.Address})
				}
			}
		}
	}
	// Finalise.
	out := make([]PlanResource, 0, len(b.order))
	for _, id := range b.order {
		r := b.res[id]
		if r.Type == "aws_s3_bucket" {
			if on, _ := r.Attributes["public_access_block"].(bool); on {
				r.dropWeakness("PUBLIC_DATA_STORE")
			}
		}
		if r.Type == "aws_security_group" {
			r.Attributes["ingress"] = ingressAttr(r.Ingress)
			if open := OpenIngress(r.Ingress); len(open) > 0 {
				var cidrs, ports []string
				for _, o := range open {
					cidrs = append(cidrs, o.CIDRs...)
					ports = append(ports, o.Ports())
				}
				r.Attributes["exposure_cidrs"] = uniqStrings(cidrs)
				canon := "EC2_SG_OPEN_SSH"
				switch {
				case open[0].Ports() == "all ports" || open[0].FromPort == 0 && open[0].ToPort >= 65535:
					canon = "EC2_SG_OPEN_ALL"
				case open[0].FromPort <= 3389 && open[0].ToPort >= 3389 && !(open[0].FromPort <= 22 && open[0].ToPort >= 22):
					canon = "EC2_SG_OPEN_RDP"
				}
				r.weak(PlanCheck{CanonicalID: canon, CheckID: "NIMBUS_PLAN_SG_OPEN", Title: "Security group ingress open to the world", Severity: model.High, Weakness: "PUBLIC_NETWORK_EXPOSURE",
					Detail: "ingress " + strings.Join(uniqStrings(ports), ", ") + " from " + strings.Join(uniqStrings(cidrs), ", "), Source: open[0].Source})
			}
		}
		sort.Strings(r.Weaknesses)
		sort.Strings(r.Unknown)
		out = append(out, *r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func changeByID(ix *planIndex, id string) *ResourceChange {
	for _, c := range ix.changes {
		if ix.ids[c.Address] == id {
			return c
		}
	}
	return nil
}

func (r *PlanResource) dropWeakness(w string) {
	var keep []string
	for _, x := range r.Weaknesses {
		if x != w {
			keep = append(keep, x)
		}
	}
	r.Weaknesses = keep
	var checks []PlanCheck
	for _, c := range r.Checks {
		if c.Weakness != w {
			checks = append(checks, c)
		}
	}
	r.Checks = checks
}

// profileRole is the node id of the role an instance profile in the plan holds ("" if none).
func (p *Plan) profileRole(ix *planIndex, prof *ResourceChange) string {
	if prof == nil {
		return ""
	}
	roles := p.resolve(ix, prof, "role", "aws_iam_role", strs(prof.values(ix.side)["role"]))
	if len(roles) == 0 {
		return ""
	}
	return roles[0]
}

func instanceReach(c *ResourceChange, side Side, v map[string]any) Reach {
	if ip := str(v, "public_ip"); ip != "" {
		return ReachYes
	}
	pub, known := boolean(v, "associate_public_ip_address")
	switch {
	case known && pub:
		return ReachYes
	case known && !pub && !c.unknown(side, "public_ip"):
		return ReachNo
	}
	return ReachUnknown
}

// mapTrust reads a role trust policy: GitHub OIDC subjects, and principals outside the account.
func (p *Plan) mapTrust(r *PlanResource, c *ResourceChange, doc string) {
	if doc == "" {
		return
	}
	var pol map[string]any
	if json.Unmarshal([]byte(doc), &pol) != nil {
		return
	}
	r.Attributes["trust_policy"] = pol
	if tr, ok := saas.GitHubOIDCTrust(pol); ok {
		subs := append([]string(nil), tr.Subjects...)
		if tr.NoSubject {
			subs = append(subs, "")
		}
		r.OIDCSubjects = subs
		r.Attributes["oidc_subjects"] = subs
		cls := tr.Class()
		r.Attributes["oidc_subject_class"] = cls
		if cls == saas.OIDCSubjectWildcard {
			// Any repository (on GitHub, or in an organisation) can assume the role: an external
			// principal in the P14 sense.
			r.Attributes["trust_principals"] = []string{"oidc-provider/" + saas.GitHubOIDCHost}
			r.weak(PlanCheck{CanonicalID: "IAM_CROSS_ACCOUNT_TRUST", CheckID: "NIMBUS_PLAN_OIDC_WILDCARD", Title: "Role trusts GitHub OIDC tokens of any repository", Severity: model.High,
				Weakness: "CROSS_ACCOUNT_TRUST", Detail: "GitHub OIDC trust with a wildcard subject", Source: c.Address})
		}
	}
	acct, _ := arnAccountRegion(r.ID)
	var ext []string
	stmts, _ := pol["Statement"].([]any)
	if one, ok := pol["Statement"].(map[string]any); ok {
		stmts = []any{one}
	}
	for _, s := range stmts {
		st, _ := s.(map[string]any)
		if st == nil || str(st, "Effect") != "Allow" {
			continue
		}
		var prs []string
		switch pr := st["Principal"].(type) {
		case string:
			prs = []string{pr}
		case map[string]any:
			prs = strs(pr["AWS"])
		}
		for _, x := range prs {
			a, _ := arnAccountRegion(x)
			if x == "*" || (len(x) == 12 && x != acct) || (a != "" && a != acct) {
				ext = append(ext, x)
			}
		}
	}
	if len(ext) > 0 {
		r.Attributes["trust_principals"] = uniqStrings(ext)
		r.weak(PlanCheck{CanonicalID: "IAM_CROSS_ACCOUNT_TRUST", CheckID: "NIMBUS_PLAN_ROLE_XACCT", Title: "Role assumable by principals in another account", Severity: model.High,
			Weakness: "CROSS_ACCOUNT_TRUST", Detail: "trusts " + strings.Join(uniqStrings(ext), ", "), Source: c.Address})
	}
}

func addPolicy(r *PlanResource, arn, src string) {
	ps, _ := r.Attributes["attached_policies"].([]string)
	r.Attributes["attached_policies"] = uniqStrings(append(ps, arn))
	if strings.HasSuffix(strings.ToLower(arn), "/administratoraccess") {
		adminCheck(r, "attached policy AdministratorAccess", src)
	}
}

func adminCheck(r *PlanResource, what, src string) {
	for _, c := range r.Checks {
		if c.CanonicalID == "IAM_ADMIN_POLICY" {
			return
		}
	}
	r.weak(PlanCheck{CanonicalID: "IAM_ADMIN_POLICY", CheckID: "NIMBUS_PLAN_IAM_ADMIN", Title: "IAM role has administrative permissions", Severity: model.High,
		Weakness: "OVERPRIVILEGED_IDENTITY", Detail: what + " allows *:*", Source: src})
}

// adminDoc reports an IAM policy document with an Allow of Action * on Resource *.
func adminDoc(doc string) bool {
	if doc == "" {
		return false
	}
	var d map[string]any
	if json.Unmarshal([]byte(doc), &d) != nil {
		return false
	}
	stmts, _ := d["Statement"].([]any)
	if one, ok := d["Statement"].(map[string]any); ok {
		stmts = []any{one}
	}
	for _, s := range stmts {
		st, _ := s.(map[string]any)
		if st != nil && st["Effect"] == "Allow" && hasStar(st["Action"]) && hasStar(st["Resource"]) {
			return true
		}
	}
	return false
}

func publicACL(r *PlanResource, acl, src string) {
	if acl == "public-read" || acl == "public-read-write" || acl == "authenticated-read" {
		r.Attributes["acl"] = acl
		r.weak(PlanCheck{CanonicalID: "S3_PUBLIC_BUCKET", CheckID: "NIMBUS_PLAN_S3_ACL", Title: "S3 bucket ACL grants public access", Severity: model.High, Weakness: "PUBLIC_DATA_STORE",
			Detail: "acl = " + acl, Source: src})
	}
}

// bucketPolicy marks a bucket public when an Allow statement has Principal * (or AWS *) and no
// condition that limits it to an organisation, account or network.
func bucketPolicy(r *PlanResource, doc, src string) {
	var d map[string]any
	if json.Unmarshal([]byte(doc), &d) != nil {
		return
	}
	r.Attributes["bucket_policy"] = doc
	stmts, _ := d["Statement"].([]any)
	if one, ok := d["Statement"].(map[string]any); ok {
		stmts = []any{one}
	}
	for _, s := range stmts {
		st, _ := s.(map[string]any)
		if st == nil || st["Effect"] != "Allow" {
			continue
		}
		star := false
		switch pr := st["Principal"].(type) {
		case string:
			star = pr == "*"
		case map[string]any:
			star = hasStar(pr["AWS"])
		}
		if !star || limitingCondition(st["Condition"]) {
			continue
		}
		r.Attributes["bucket_policy_principal"] = "*"
		r.weak(PlanCheck{CanonicalID: "S3_PUBLIC_BUCKET", CheckID: "NIMBUS_PLAN_S3_POLICY", Title: "S3 bucket policy allows anyone", Severity: model.High, Weakness: "PUBLIC_DATA_STORE",
			Detail: "bucket policy Allow with Principal *", Source: src})
		return
	}
}

var limitingKeys = []string{"aws:principalorgid", "aws:principalorgpaths", "aws:principalaccount", "aws:sourcevpc", "aws:sourcevpce", "aws:sourceaccount", "aws:sourceip"}

func limitingCondition(c any) bool {
	m, _ := c.(map[string]any)
	for _, kv := range m {
		km, _ := kv.(map[string]any)
		for k := range km {
			for _, l := range limitingKeys {
				if strings.EqualFold(k, l) {
					return true
				}
			}
		}
	}
	return false
}

func ingressRule(m map[string]any, src string) IngressRule {
	r := IngressRule{Source: src, FromPort: num(m, "from_port"), ToPort: num(m, "to_port"), Protocol: firstNonEmptyStr(str(m, "protocol"), str(m, "ip_protocol"))}
	r.CIDRs = append(strs(m["cidr_blocks"]), strs(m["ipv6_cidr_blocks"])...)
	for _, k := range []string{"cidr_ipv4", "cidr_ipv6"} {
		if s := str(m, k); s != "" {
			r.CIDRs = append(r.CIDRs, s)
		}
	}
	return r
}

func ingressAttr(rs []IngressRule) []any {
	out := []any{}
	for _, r := range rs {
		for _, c := range r.CIDRs {
			out = append(out, map[string]any{"cidr": c, "from_port": r.FromPort, "to_port": r.ToPort, "protocol": r.Protocol, "source": r.Source})
		}
	}
	return out
}

// Findings turns the resource into native findings: one FAIL per check (with its weakness) and,
// when there is no check, one PASS inventory record. The first finding carries the relations.
func (r PlanResource) Findings() []model.Finding {
	attrs := make(map[string]any, len(r.Attributes))
	for k, v := range r.Attributes {
		attrs[k] = v
	}
	base := func(id string) model.Finding {
		return model.Finding{ID: id, Source: "nimbus-plan", Provider: r.Provider, Account: r.Account, Region: r.Region,
			Resource: model.Resource{ID: r.ID, Type: r.Type, Name: r.Name, Attributes: attrs}, Tags: map[string]string{"framework": "terraform-plan"}}
	}
	var out []model.Finding
	for _, c := range r.Checks {
		f := base("plan:" + r.ID + ":" + c.CheckID + ":" + c.Weakness)
		f.CheckID, f.CanonicalID, f.Title, f.Description, f.Severity, f.Status = c.CheckID, c.CanonicalID, c.Title, c.Detail, c.Severity, model.Fail
		if c.Weakness != "" {
			f.Weaknesses = []string{c.Weakness}
		}
		f.File = c.Source
		out = append(out, f)
	}
	if len(out) == 0 {
		f := base("plan:" + r.ID + ":inventory")
		f.CheckID, f.Title, f.Status, f.Severity = "NIMBUS_PLAN_INVENTORY", "planned resource", model.Pass, model.Info
		out = append(out, f)
	}
	out[0].Resource.Relations = append([]model.Relation(nil), r.Relations...)
	for _, rel := range r.Relations {
		out[0].Resource.Related = append(out[0].Resource.Related, rel.ID)
	}
	return out
}

// ---------------------------------------------------------------- value helpers (type-safe on hostile input)

func str(m map[string]any, k string) string {
	if m == nil {
		return ""
	}
	s, _ := m[k].(string)
	return s
}

func strs(v any) []string {
	switch t := v.(type) {
	case string:
		if t == "" {
			return nil
		}
		return []string{t}
	case []any:
		var out []string
		for _, e := range t {
			if s, ok := e.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func toStringList(v any) []string {
	if l, ok := v.([]string); ok {
		return l
	}
	return strs(v)
}

func maps(v any) []map[string]any {
	l, _ := v.([]any)
	var out []map[string]any
	for _, e := range l {
		if m, ok := e.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

func boolean(m map[string]any, k string) (bool, bool) {
	if m == nil {
		return false, false
	}
	b, ok := m[k].(bool)
	return b, ok
}

func num(m map[string]any, k string) int {
	if f, ok := m[k].(float64); ok && f >= -1 && f <= 65535 {
		return int(f)
	}
	return 0
}

func tagName(v map[string]any) string {
	t, _ := v["tags"].(map[string]any)
	s, _ := t["Name"].(string)
	return s
}

func firstNonEmptyStr(vs ...string) string {
	for _, v := range vs {
		if v != "" {
			return v
		}
	}
	return ""
}

func uniqStrings(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func lastSegment(s string) string {
	s = strings.TrimRight(s, "/")
	if i := strings.LastIndexAny(s, "/:"); i >= 0 && i < len(s)-1 {
		return s[i+1:]
	}
	return s
}

// arnAccountRegion returns the account and region fields of an ARN ("" when not an ARN).
func arnAccountRegion(id string) (account, region string) {
	if !strings.HasPrefix(id, "arn:") {
		return "", ""
	}
	parts := strings.SplitN(id, ":", 6)
	if len(parts) < 6 {
		return "", ""
	}
	return parts[4], parts[3]
}

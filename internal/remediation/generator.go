// Package remediation renders Infrastructure-as-Code fixes for canonical findings.
// Templates are Go text/template files named <canonical-slug>.<format-ext>:
//
//	.tf        Terraform (1.5+ import blocks adopt existing resources; least-change edits only)
//	.cfn.yaml  CloudFormation
//	.k8s.yaml  Kubernetes strategic-merge patch (or a full manifest when it has apiVersion:)
//	.bicep     Bicep
//
// Every template has a sidecar <template>.meta.yaml (see Metadata: actions required, validation
// query, mitigation, effort, confidence, rollback, breaks_function). Generated commands always
// start with a plan / change set / what-if / server dry-run; nothing auto-approves.
package remediation

import (
	"bytes"
	"embed"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strings"
	"text/template"

	"github.com/DreadpiratePickles/nimbus/internal/catalog"
	"github.com/DreadpiratePickles/nimbus/internal/model"
)

//go:embed templates/*
var templateFS embed.FS

type Format string

const (
	Terraform      Format = "terraform"
	CloudFormation Format = "cloudformation"
	Kubernetes     Format = "kubernetes"
	Bicep          Format = "bicep"
)

var formatExt = map[Format]string{Terraform: ".tf", CloudFormation: ".cfn.yaml", Kubernetes: ".k8s.yaml", Bicep: ".bicep"}

func ParseFormat(s string) (Format, error) {
	switch strings.ToLower(s) {
	case "terraform", "tf", "hcl":
		return Terraform, nil
	case "cloudformation", "cfn":
		return CloudFormation, nil
	case "kubernetes", "k8s", "kubectl":
		return Kubernetes, nil
	case "bicep", "arm":
		return Bicep, nil
	}
	return "", fmt.Errorf("unknown format %q (terraform|cloudformation|bicep|kubernetes)", s)
}

type Fix struct {
	Finding     model.Finding `json:"finding"`
	CanonicalID string        `json:"canonical_id"`
	Format      Format        `json:"format"`
	FileName    string        `json:"file_name"`
	Content     string        `json:"content"`
	// Apply is the first command to run. It never applies a change by itself: it produces a
	// plan / change set / what-if / server dry-run for review (Steps lists the full sequence).
	Apply    string    `json:"apply"`
	Steps    []string  `json:"steps"`
	Generic  bool      `json:"generic"`
	Template string    `json:"template,omitempty"`
	Metadata *Metadata `json:"metadata,omitempty"` // nil for generic stubs
}

// ctx is the data a template renders. Name, ID, ShortID, Region, Account, Namespace and every
// top-level string in Attr are pre-escaped for the template's format (HCL string, Bicep string,
// single-line YAML), so templates may embed them inside quotes; lists go through hcllist.
type ctx struct {
	F         model.Finding
	Slug      string
	Name      string
	ID        string
	ShortID   string // last path/colon segment of ID (sg-123 from an ARN)
	Region    string
	Account   string
	Attr      map[string]any
	Namespace string
	Kind      string
	Ports     []int
	// Service / ServiceFrom / Workload: a fix that patches the Service selecting the finding's
	// pod (k8sservice.go): the Service name ("" when unresolved), where it was resolved from,
	// and the pod's own name.
	Service, ServiceFrom, Workload string
	// Raw holds the same values unescaped. Templates use them only through `sh` (shq), in
	// copy-paste command lines of the form `# CLI: <command>` / `// CLI: <command>`, with every
	// value bound to its flag (`--name={{ sh .Raw.Name }}`), behind a prefix (`gs://`), or after
	// `--` (Verification 3 defect 6).
	Raw rawValues
}

// rawValues are the finding's identifiers before format escaping (see ctx.Raw).
type rawValues struct {
	Name, ID, ShortID, Region, Account, Namespace, Kind, Service string
}

var slugRe = regexp.MustCompile(`[^a-z0-9_]+`)

func slugify(s string) string {
	s = strings.ToLower(s)
	s = slugRe.ReplaceAllString(s, "_")
	s = strings.Trim(s, "_")
	if s == "" {
		s = "resource"
	}
	if s[0] >= '0' && s[0] <= '9' {
		s = "r_" + s
	}
	if len(s) > 48 {
		s = s[:48]
	}
	return s
}

// extraTemplates wires templates to canonical IDs whose catalog entry lists none yet (W5, delta
// r3 #10: the fixes on the lab's top attack paths were generic stubs). They apply only while the
// catalog entry lists no template of its own; once it does, the catalog's list wins.
var extraTemplates = map[string][]string{
	"LAMBDA_PUBLIC":         {"lambda_function_url_auth.tf"},
	"GH_BRANCH_UNPROTECTED": {"gh_branch_protection.tf"},
}

// templatesFor lists the template files of a canonical ID: the catalog entry's remediation list,
// or extraTemplates when that list is empty.
func templatesFor(canonicalID string) []string {
	if e, ok := catalog.Default().Get(canonicalID); ok && len(e.Remediation) > 0 {
		return e.Remediation
	}
	return extraTemplates[canonicalID]
}

// Formats lists the IaC formats that have a template for the canonical ID.
func Formats(canonicalID string) []Format {
	var out []Format
	for _, name := range templatesFor(canonicalID) {
		for f, ext := range formatExt {
			if strings.HasSuffix(name, ext) {
				out = append(out, f)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Generate renders a fix. When no template exists for the canonical ID, a generic
// annotated stub carrying the scanner's own remediation guidance is produced.
func Generate(f model.Finding, format Format) (*Fix, error) {
	ctx := buildCtx(f, format)
	var tplName string
	for _, name := range templatesFor(f.CanonicalID) {
		if strings.HasSuffix(name, formatExt[format]) {
			tplName = name
		}
	}
	fix := &Fix{Finding: f, CanonicalID: f.CanonicalID, Format: format}
	if tplName == "" {
		fix.Generic = true
		fix.Content = genericStub(f, format)
		fix.FileName = fmt.Sprintf("%s_%s%s", strings.ToLower(f.CanonicalID), ctx.Slug, formatExt[format])
		fix.Apply, fix.Steps = applySteps(format, fix.FileName, ctx, false)
		return fix, nil
	}
	raw, err := fs.ReadFile(templateFS, path.Join("templates", tplName))
	if err != nil {
		return nil, err
	}
	tpl, err := template.New(tplName).Funcs(funcs).Parse(string(raw))
	if err != nil {
		return nil, fmt.Errorf("template %s: %w", tplName, err)
	}
	var buf bytes.Buffer
	if err := tpl.Execute(&buf, ctx); err != nil {
		return nil, fmt.Errorf("render %s: %w", tplName, err)
	}
	meta, err := renderMetadata(tplName, ctx)
	if err != nil {
		return nil, err
	}
	fix.Template = tplName
	fix.Metadata = meta
	fix.Content = header(f, format) + buf.String()
	fix.FileName = fmt.Sprintf("%s_%s%s", strings.ToLower(f.CanonicalID), ctx.Slug, formatExt[format])
	fix.Apply, fix.Steps = applySteps(format, fix.FileName, ctx, isManifest(buf.String()))
	return fix, nil
}

var funcs = template.FuncMap{
	"slug": slugify, "lower": strings.ToLower, "upper": strings.ToUpper, "join": strings.Join,
	"default": func(def string, v any) any {
		if v == nil || v == "" {
			return def
		}
		return v
	},
	"hclstr": func(v any) string { return `"` + hclEscape(fmt.Sprint(v)) + `"` },
	// sh single-quotes a raw value for a copy-paste shell command line (shQuote, which shq uses
	// for Apply/Steps); in templates it always quotes, so no value is ever read by the shell.
	"sh": func(v any) string { return shQuote(fmt.Sprint(v)) },
	// shq quotes a raw value only when it holds shell-unsafe characters (DNS-1123 names pass as is).
	"shq":     func(v any) string { return shq(fmt.Sprint(v)) },
	"hcllist": hclList,
	// accountids extracts the 12-digit AWS account IDs from principal ARNs / bare IDs.
	"accountids": accountIDs,
	"sqlstr":     func(v any) string { return "'" + strings.ReplaceAll(fmt.Sprint(v), "'", "''") + "'" },
	"dnslabel": func(s string, max int) string {
		s = strings.Trim(strings.ReplaceAll(slugify(s), "_", "-"), "-")
		if len(s) > max {
			s = strings.TrimRight(s[:max], "-")
		}
		return s
	},
}

// hclEscape escapes s for use inside a double-quoted HCL string (no interpolation).
func hclEscape(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`, "\r", `\r`, "\t", `\t`, "${", "$${", "%{", "%%{")
	return r.Replace(s)
}

// bicepEscape escapes s for use inside a single-quoted Bicep string.
func bicepEscape(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `'`, `\'`, "\n", `\n`, "\r", `\r`, "\t", `\t`, "${", `\${`)
	return r.Replace(s)
}

// yamlLine makes s safe to embed in a single-line plain YAML scalar or comment: control
// characters become spaces, flow/quote indicators become '_', and ": " / " #" (which end a plain
// scalar) are broken up. Real cloud identifiers (ARNs, bucket, K8s names) pass through unchanged.
func yamlLine(s string) string {
	s = strings.Map(func(r rune) rune {
		switch {
		case isLineBreakish(r):
			return ' '
		case strings.ContainsRune("{}[]&!|>'\"%`", r):
			return '_'
		}
		return r
	}, s)
	return strings.NewReplacer(": ", ":_", " #", " _").Replace(s)
}

var shellSafe = regexp.MustCompile(`^[A-Za-z0-9._:/@+,][A-Za-z0-9._:/@+=,-]*$`)

// shq single-quotes s for a POSIX shell unless it is made only of safe characters (and does not
// start with '-'), so a copy-pasted command cannot run anything embedded in a resource name. It
// keeps s on one line. Quoting does not stop a value from being read as an option: callers bind
// values to their flag with '=' or place them after `--`.
func shq(s string) string {
	if shellSafe.MatchString(s) {
		return s
	}
	return shQuote(s)
}

// shQuote always single-quotes s (on one line) for a POSIX shell.
func shQuote(s string) string {
	return "'" + strings.ReplaceAll(oneLine(s), "'", `'"'"'`) + "'"
}

// oneLine keeps s on one line (for comments): control characters, and the Unicode line breaks
// YAML also honours (NEL, LS, PS), become spaces.
func oneLine(s string) string {
	return strings.Map(func(r rune) rune {
		if isLineBreakish(r) {
			return ' '
		}
		return r
	}, s)
}

func isLineBreakish(r rune) bool {
	return r < 0x20 || r == 0x7f || r == 0x85 || r == 0x2028 || r == 0x2029
}

func escaperFor(format Format) func(string) string {
	switch format {
	case Terraform:
		return hclEscape
	case Bicep:
		return bicepEscape
	}
	return yamlLine
}

var accountIDRe = regexp.MustCompile(`^(?:arn:aws[a-z-]*:iam::)?([0-9]{12})(?::|$)`)

// accountIDs returns the distinct AWS account IDs named by a list of principals (ARNs such as
// arn:aws:iam::123456789012:root, or bare 12-digit IDs), in order; other entries are skipped.
func accountIDs(v any) []string {
	var items []string
	switch t := v.(type) {
	case []string:
		items = t
	case []any:
		for _, x := range t {
			if s, ok := x.(string); ok {
				items = append(items, s)
			}
		}
	case string:
		items = []string{t}
	}
	var out []string
	seen := map[string]bool{}
	for _, s := range items {
		if m := accountIDRe.FindStringSubmatch(strings.TrimSpace(s)); m != nil && !seen[m[1]] {
			seen[m[1]] = true
			out = append(out, m[1])
		}
	}
	return out
}

// hclList renders a list of strings ([]string or []any) as an HCL list literal.
func hclList(v any) string {
	var items []string
	switch t := v.(type) {
	case []string:
		items = t
	case []any:
		for _, x := range t {
			items = append(items, fmt.Sprint(x))
		}
	case string:
		items = []string{t}
	}
	q := make([]string, len(items))
	for i, s := range items {
		q[i] = `"` + hclEscape(s) + `"`
	}
	return "[" + strings.Join(q, ", ") + "]"
}

// serviceApplySteps patches the Service that selects the pod (k8sservice.go); unresolved, it
// lists the namespace's LoadBalancer Services and patches "$SERVICE". Never the pod.
func serviceApplySteps(c ctx, flags string) (string, []string) {
	if c.Raw.Service != "" {
		target := "-- service " + shq(c.Raw.Service)
		dry := fmt.Sprintf("kubectl patch %s --dry-run=server --output=yaml %s", flags, target)
		return dry, []string{
			dry,
			fmt.Sprintf("Review the rendered Service %s (it selects pod %s; resolved from the %s): only the internal-load-balancer annotations and loadBalancerSourceRanges may change.", c.Raw.Service, c.Workload, c.ServiceFrom),
			fmt.Sprintf("kubectl patch %s %s", flags, target),
		}
	}
	list := fmt.Sprintf("kubectl get services --namespace=%s --field-selector=spec.type=LoadBalancer --output=wide", shq(c.Raw.Namespace))
	target := `-- service "$SERVICE"`
	dry := fmt.Sprintf("kubectl patch %s --dry-run=server --output=yaml %s   # set SERVICE first: %s", flags, target, list)
	return dry, []string{
		dry,
		fmt.Sprintf("SERVICE is the LoadBalancer Service whose selector matches pod %s (listed by: %s); the pod itself is never patched. Review the rendered Service: only the internal-load-balancer annotations and loadBalancerSourceRanges may change.", c.Workload, list),
		fmt.Sprintf("kubectl patch %s %s", flags, target),
	}
}

func isManifest(content string) bool {
	return strings.Contains("\n"+content, "\napiVersion:")
}

func buildCtx(f model.Finding, format Format) ctx {
	name := f.Resource.Name
	if name == "" {
		name = f.Resource.ID
	}
	// ARNs: use the trailing path element as the human name.
	if strings.HasPrefix(f.Resource.ID, "arn:") && (name == f.Resource.ID || name == "") {
		name = f.Resource.ID[strings.LastIndexAny(f.Resource.ID, ":/")+1:]
	}
	short := f.Resource.ID[strings.LastIndexAny(f.Resource.ID, ":/")+1:]
	esc := escaperFor(format)
	c := ctx{F: f, Slug: slugify(name), Name: esc(name), ID: esc(f.Resource.ID), ShortID: esc(short), Region: esc(f.Region), Account: esc(f.Account), Attr: map[string]any{},
		Raw: rawValues{Name: name, ID: f.Resource.ID, ShortID: short, Region: f.Region, Account: f.Account, Namespace: "default", Kind: "Deployment"}}
	if ns, ok := f.Resource.Attributes["namespace"].(string); ok && ns != "" {
		c.Raw.Namespace = ns
	}
	if k, ok := f.Resource.Attributes["kind"].(string); ok && k != "" {
		c.Raw.Kind = k
	}
	for k, v := range f.Resource.Attributes {
		if s, ok := v.(string); ok {
			v = esc(s)
		}
		c.Attr[k] = v
	}
	if ns, ok := c.Attr["namespace"].(string); ok {
		c.Namespace = ns
	}
	if c.Namespace == "" {
		c.Namespace = "default"
	}
	c.Kind = "Deployment"
	if k, ok := c.Attr["kind"].(string); ok && k != "" {
		c.Kind = k
	} else if strings.Contains(strings.ToLower(f.Resource.Type), "pod") && !strings.Contains(strings.ToLower(f.Resource.ID), "deployment") {
		c.Kind = "Pod"
		c.Raw.Kind = "Pod"
	}
	if serviceTargetedCanonical[f.CanonicalID] && format == Kubernetes {
		// The fix patches the Service that selects the pod, never the pod (W7-ENGINE r5 #7).
		c.Workload = c.Name
		c.Kind, c.Raw.Kind = "Service", "Service"
		if ns, name, from := serviceOf(f); name != "" {
			c.Service, c.Raw.Service, c.ServiceFrom = esc(name), name, from
			c.Name, c.Raw.Name, c.Slug = esc(name), name, slugify(name)
			if ns != "" {
				c.Namespace, c.Raw.Namespace = esc(ns), ns
			}
		}
	}
	switch f.CanonicalID {
	case "EC2_SG_OPEN_SSH", "AZ_NSG_OPEN_SSH", "GCP_FIREWALL_OPEN_SSH", "OCI_SECLIST_OPEN_SSH":
		c.Ports = []int{22}
	case "EC2_SG_OPEN_RDP", "AZ_NSG_OPEN_RDP", "GCP_FIREWALL_OPEN_RDP":
		c.Ports = []int{3389}
	case "EC2_SG_OPEN_HTTP":
		c.Ports = []int{80}
	case "EC2_INSTANCE_PORT_EXPOSED":
		// The port is in the check id (Prowler ec2_instance_port_<proto>_exposed_to_internet).
		c.Ports = []int{22}
		for proto, port := range map[string]int{"_rdp_": 3389, "_https_": 443, "_http_": 80, "_telnet_": 23, "_ftp_": 21} {
			if strings.Contains(strings.ToLower(f.CheckID), proto) {
				c.Ports = []int{port}
			}
		}
	default:
		c.Ports = []int{22, 3389}
	}
	return c
}

func header(f model.Finding, format Format) string {
	c := "# "
	if format == Bicep {
		c = "// "
	}
	one := oneLine // comments must stay on one line
	review := "Review before applying: run the plan/what-if/dry-run in `apply`, confirm only the intended resource changes."
	return fmt.Sprintf("%sGenerated by cloud-posture fix\n%sFinding: %s (%s) via %s\n%sResource: %s\n%sAccount: %s  Region: %s\n%s%s\n\n",
		c, c, one(f.CanonicalID), one(string(f.Severity)), one(f.Source), c, one(f.Resource.ID), c, one(f.Account), one(f.Region), c, review)
}

func genericStub(f model.Finding, format Format) string {
	text := f.Remediation
	if text == "" {
		text = "No tool-provided guidance. Review the finding and apply the vendor hardening recommendation."
	}
	var b strings.Builder
	b.WriteString(header(f, format))
	c := "# "
	if format == Bicep {
		c = "// "
	}
	b.WriteString(c + "No typed template exists yet for this check; guidance from the scanner follows.\n")
	for _, line := range strings.Split(text, "\n") {
		b.WriteString(c + oneLine(line) + "\n")
	}
	switch format {
	case Terraform:
		fmt.Fprintf(&b, "\n# TODO: encode the fix for %s as Terraform.\n", oneLine(f.Resource.ID))
	case CloudFormation:
		fmt.Fprintf(&b, "\nAWSTemplateFormatVersion: '2010-09-09'\nDescription: TODO remediation for %s\nResources: {}\n", yamlLine(f.CanonicalID))
	case Kubernetes:
		fmt.Fprintf(&b, "\n# Set KIND, NAMESPACE and PATCH (a JSON merge patch), then:\n# CLI: kubectl patch --namespace=\"$NAMESPACE\" --type=merge --patch=\"$PATCH\" --dry-run=server --output=yaml -- \"$KIND\" %s   # review, then re-run without --dry-run\n", shq(f.Resource.Name))
	case Bicep:
		fmt.Fprintf(&b, "\n// TODO: encode the fix for %s as Bicep.\n", oneLine(f.Resource.ID))
	}
	return b.String()
}

// applySteps returns the first command (always a plan / change set / what-if / server dry-run,
// never an apply) and the full plan → review → apply sequence. No step ever auto-approves.
func applySteps(format Format, file string, c ctx, manifest bool) (string, []string) {
	switch format {
	case Terraform:
		plan := "terraform init && terraform plan -out=nimbus-fix.tfplan"
		return plan, []string{
			plan,
			"Review the plan: only the resources named in " + file + " may change; stop on any destroy/replace you did not expect.",
			"terraform apply nimbus-fix.tfplan   # applies exactly the reviewed plan",
		}
	case CloudFormation:
		stack := "cloud-posture-" + strings.ReplaceAll(c.Slug, "_", "-")
		create := fmt.Sprintf("aws cloudformation deploy --template-file=%s --stack-name=%s --capabilities CAPABILITY_NAMED_IAM --no-execute-changeset", shq(file), shq(stack))
		return create, []string{
			create,
			fmt.Sprintf("aws cloudformation describe-change-set --stack-name=%s --change-set-name <name printed above>   # review: no Remove/Replacement you did not expect", shq(stack)),
			fmt.Sprintf("aws cloudformation execute-change-set --stack-name=%s --change-set-name <name>", shq(stack)),
		}
	case Kubernetes:
		// Values are bound to their flag with `=` and the positional kind/name follow `--`, so a
		// name such as `--server=https://evil` or `-n kube-system` can never become an option
		// (Verification 2 defect 6); shq keeps shell metacharacters inert.
		if manifest {
			diff := fmt.Sprintf("kubectl diff --filename=%s", shq(file))
			return diff, []string{diff, "Review the diff (and test in a non-production namespace first).", fmt.Sprintf("kubectl apply --filename=%s", shq(file))}
		}
		flags := fmt.Sprintf("--namespace=%s --type=strategic --patch-file=%s", shq(c.Namespace), shq(file))
		if serviceTargetedCanonical[c.F.CanonicalID] {
			return serviceApplySteps(c, flags)
		}
		target := fmt.Sprintf("-- %s %s", shq(strings.ToLower(c.Kind)), shq(c.F.Resource.Name))
		dry := fmt.Sprintf("kubectl patch %s --dry-run=server --output=yaml %s", flags, target)
		return dry, []string{
			dry,
			"Review the rendered object; check the container name in the patch matches the workload.",
			fmt.Sprintf("kubectl patch %s %s", flags, target),
		}
	case Bicep:
		rg := "<resource-group>"
		if v, ok := c.Attr["resource_group"].(string); ok && v != "" {
			rg = shq(c.F.Resource.Attributes["resource_group"].(string))
		}
		whatIf := fmt.Sprintf("az deployment group what-if --resource-group=%s --template-file=%s", rg, shq(file))
		return whatIf, []string{
			whatIf,
			"Review the what-if: a full PUT resets properties the template does not set; stop on any Delete or unexpected Modify.",
			fmt.Sprintf("az deployment group create --resource-group=%s --template-file=%s --mode Incremental --confirm-with-what-if", rg, shq(file)),
		}
	}
	return "", nil
}

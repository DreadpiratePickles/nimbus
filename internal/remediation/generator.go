// Package remediation renders Infrastructure-as-Code fixes for canonical findings.
// Templates are Go text/template files named <canonical-slug>.<format-ext>:
//   .tf        Terraform (uses 1.5+ import blocks so `terraform apply` adopts existing resources)
//   .cfn.yaml  CloudFormation
//   .k8s.yaml  Kubernetes strategic-merge patch applied with `kubectl patch`
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
	Apply       string        `json:"apply"` // the one command that applies it
	Generic     bool          `json:"generic"`
}

type ctx struct {
	F           model.Finding
	Slug        string
	Name        string
	ID          string
	Region      string
	Account     string
	Attr        map[string]any
	Namespace   string
	Kind        string
	Ports       []int
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

// Formats lists the IaC formats that have a template for the canonical ID.
func Formats(canonicalID string) []Format {
	e, ok := catalog.Default().Get(canonicalID)
	if !ok {
		return nil
	}
	var out []Format
	for _, name := range e.Remediation {
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
	e, _ := catalog.Default().Get(f.CanonicalID)
	ctx := buildCtx(f)
	var tplName string
	if e != nil {
		for _, name := range e.Remediation {
			if strings.HasSuffix(name, formatExt[format]) {
				tplName = name
			}
		}
	}
	fix := &Fix{Finding: f, CanonicalID: f.CanonicalID, Format: format}
	if tplName == "" {
		fix.Generic = true
		fix.Content = genericStub(f, format)
		fix.FileName = fmt.Sprintf("%s_%s%s", strings.ToLower(f.CanonicalID), ctx.Slug, formatExt[format])
		fix.Apply = applyCommand(format, fix.FileName, ctx)
		return fix, nil
	}
	raw, err := fs.ReadFile(templateFS, path.Join("templates", tplName))
	if err != nil {
		return nil, err
	}
	tpl, err := template.New(tplName).Funcs(template.FuncMap{
		"slug": slugify, "lower": strings.ToLower, "upper": strings.ToUpper, "join": strings.Join,
		"default": func(def string, v any) any {
			if v == nil || v == "" {
				return def
			}
			return v
		},
	}).Parse(string(raw))
	if err != nil {
		return nil, fmt.Errorf("template %s: %w", tplName, err)
	}
	var buf bytes.Buffer
	if err := tpl.Execute(&buf, ctx); err != nil {
		return nil, fmt.Errorf("render %s: %w", tplName, err)
	}
	fix.Content = header(f, format) + buf.String()
	fix.FileName = fmt.Sprintf("%s_%s%s", strings.ToLower(f.CanonicalID), ctx.Slug, formatExt[format])
	fix.Apply = applyCommand(format, fix.FileName, ctx)
	return fix, nil
}

func buildCtx(f model.Finding) ctx {
	name := f.Resource.Name
	if name == "" {
		name = f.Resource.ID
	}
	// ARNs: use the trailing path element as the human name.
	if strings.HasPrefix(f.Resource.ID, "arn:") && (name == f.Resource.ID || name == "") {
		name = f.Resource.ID[strings.LastIndexAny(f.Resource.ID, ":/")+1:]
	}
	c := ctx{F: f, Slug: slugify(name), Name: name, ID: f.Resource.ID, Region: f.Region, Account: f.Account, Attr: f.Resource.Attributes}
	if c.Attr == nil {
		c.Attr = map[string]any{}
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
	}
	switch f.CanonicalID {
	case "EC2_SG_OPEN_SSH", "AZ_NSG_OPEN_SSH", "GCP_FIREWALL_OPEN_SSH", "OCI_SECLIST_OPEN_SSH":
		c.Ports = []int{22}
	case "EC2_SG_OPEN_RDP", "AZ_NSG_OPEN_RDP", "GCP_FIREWALL_OPEN_RDP":
		c.Ports = []int{3389}
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
	return fmt.Sprintf("%sGenerated by cloud-posture fix\n%sFinding: %s (%s) via %s\n%sResource: %s\n%sAccount: %s  Region: %s\n\n",
		c, c, f.CanonicalID, f.Severity, f.Source, c, f.Resource.ID, c, f.Account, f.Region)
}

func genericStub(f model.Finding, format Format) string {
	text := f.Remediation
	if text == "" {
		text = "No tool-provided guidance. Review the finding and apply the vendor hardening recommendation."
	}
	var b strings.Builder
	b.WriteString(header(f, format))
	b.WriteString("# No typed template exists yet for this check; guidance from the scanner follows.\n")
	for _, line := range strings.Split(text, "\n") {
		b.WriteString("# " + line + "\n")
	}
	switch format {
	case Terraform:
		fmt.Fprintf(&b, "\n# TODO: encode the fix for %s as Terraform.\n", f.Resource.ID)
	case CloudFormation:
		fmt.Fprintf(&b, "\nAWSTemplateFormatVersion: '2010-09-09'\nDescription: TODO remediation for %s\nResources: {}\n", f.CanonicalID)
	case Kubernetes:
		fmt.Fprintf(&b, "\n# kubectl patch <kind> %s -n <ns> --type merge -p '<patch>'\n", f.Resource.Name)
	case Bicep:
		fmt.Fprintf(&b, "\n// TODO: encode the fix for %s as Bicep.\n", f.Resource.ID)
	}
	return b.String()
}

func applyCommand(format Format, file string, c ctx) string {
	switch format {
	case Terraform:
		return "terraform init && terraform apply -auto-approve"
	case CloudFormation:
		return fmt.Sprintf("aws cloudformation deploy --template-file %s --stack-name cloud-posture-%s --capabilities CAPABILITY_NAMED_IAM", file, c.Slug)
	case Kubernetes:
		return fmt.Sprintf("kubectl patch %s %s -n %s --type strategic --patch-file %s", strings.ToLower(c.Kind), c.Name, c.Namespace, file)
	case Bicep:
		rg := "<resource-group>"
		if v, ok := c.Attr["resource_group"].(string); ok && v != "" {
			rg = v
		}
		return fmt.Sprintf("az deployment group create --resource-group %s --template-file %s --mode Incremental", rg, file)
	}
	return ""
}

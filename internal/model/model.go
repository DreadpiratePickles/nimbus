// Package model defines the unified finding schema every adapter normalizes into.
// The JSON shape of Finding is the contract shared with the Python SDK and plugins.
package model

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"
)

type Severity string

const (
	Critical Severity = "CRITICAL"
	High     Severity = "HIGH"
	Medium   Severity = "MEDIUM"
	Low      Severity = "LOW"
	Info     Severity = "INFO"
)

var severityRank = map[Severity]int{Critical: 5, High: 4, Medium: 3, Low: 2, Info: 1}

func (s Severity) Rank() int { return severityRank[s] }

// ParseSeverity accepts the many spellings tools use (critical, Danger, warning, 9.8...).
func ParseSeverity(raw string) Severity {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "critical", "crit", "danger", "5", "error":
		return Critical
	case "high", "4", "warning", "warn":
		return High
	case "medium", "med", "moderate", "3":
		return Medium
	case "low", "2", "minor":
		return Low
	case "info", "informational", "1", "note", "none", "unknown", "":
		return Info
	}
	return Info
}

type Status string

const (
	Fail  Status = "FAIL"
	Pass  Status = "PASS"
	Skip  Status = "SKIP"
	Error Status = "ERROR"
)

func ParseStatus(raw string) Status {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "fail", "failed", "alarm", "open", "new", "danger", "warning":
		return Fail
	case "pass", "passed", "ok", "success", "resolved":
		return Pass
	case "skip", "skipped", "manual", "muted", "suppressed", "info":
		return Skip
	}
	return Error
}

// Provider values are lower-case and stable; "iac" marks findings on code rather than live resources.
const (
	ProviderAWS        = "aws"
	ProviderAzure      = "azure"
	ProviderGCP        = "gcp"
	ProviderOCI        = "oci"
	ProviderKubernetes = "kubernetes"
	ProviderGitHub     = "github"
	ProviderM365       = "m365"
	ProviderOkta       = "okta"
	ProviderIaC        = "iac"
	ProviderUnknown    = "unknown"
)

func NormalizeProvider(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "aws", "amazon":
		return ProviderAWS
	case "azure", "azurerm", "az", "microsoft":
		return ProviderAzure
	case "gcp", "google", "googlecloud", "google cloud":
		return ProviderGCP
	case "oci", "oracle":
		return ProviderOCI
	case "kubernetes", "k8s", "helm", "kustomize":
		return ProviderKubernetes
	case "github", "gh":
		return ProviderGitHub
	case "m365", "microsoft365", "office365", "o365":
		return ProviderM365
	case "okta":
		return ProviderOkta
	case "terraform", "cloudformation", "iac", "dockerfile", "bicep", "arm":
		return ProviderIaC
	}
	return ProviderUnknown
}

type Resource struct {
	ID         string         `json:"id"`
	Type       string         `json:"type"`
	Name       string         `json:"name"`
	Attributes map[string]any `json:"attributes,omitempty"`
	// Related lists IDs of resources this one is attached to (instance -> role, pod -> service account).
	Related []string `json:"related,omitempty"`
}

type Finding struct {
	ID          string              `json:"id"`
	Source      string              `json:"source"`
	CheckID     string              `json:"check_id"`
	CanonicalID string              `json:"canonical_id"`
	Title       string              `json:"title"`
	Description string              `json:"description,omitempty"`
	Severity    Severity            `json:"severity"`
	Status      Status              `json:"status"`
	Provider    string              `json:"provider"`
	Account     string              `json:"account"`
	Region      string              `json:"region,omitempty"`
	Resource    Resource            `json:"resource"`
	File        string              `json:"file,omitempty"`
	LineStart   int                 `json:"line_start,omitempty"`
	LineEnd     int                 `json:"line_end,omitempty"`
	Remediation string              `json:"remediation,omitempty"`
	Weaknesses  []string            `json:"weaknesses,omitempty"`
	Compliance  map[string][]string `json:"compliance,omitempty"`
	Tags        map[string]string   `json:"tags,omitempty"`
	ScanID      string              `json:"scan_id,omitempty"`
	FirstSeen   time.Time           `json:"first_seen"`
	LastSeen    time.Time           `json:"last_seen"`
	Raw         json.RawMessage     `json:"raw,omitempty"`
}

// Fingerprint is stable across scans for the same check on the same resource.
func (f *Finding) Fingerprint() string {
	key := strings.Join([]string{f.Source, f.CheckID, f.Provider, f.Account, f.Region, f.Resource.ID, f.File}, "|")
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:16])
}

func (f *Finding) Finalize(now time.Time) {
	if f.Provider == "" {
		f.Provider = ProviderUnknown
	}
	if f.Severity == "" {
		f.Severity = Info
	}
	if f.Status == "" {
		f.Status = Fail
	}
	if f.Resource.Name == "" {
		f.Resource.Name = f.Resource.ID
	}
	if f.CanonicalID == "" {
		f.CanonicalID = strings.ToUpper(f.Source) + ":" + f.CheckID
	}
	if f.ID == "" {
		f.ID = f.Fingerprint()
	}
	if f.FirstSeen.IsZero() {
		f.FirstSeen = now
	}
	f.LastSeen = now
}

func (f *Finding) HasWeakness(w string) bool {
	for _, x := range f.Weaknesses {
		if x == w {
			return true
		}
	}
	return false
}

func (f *Finding) AddCompliance(framework string, controls ...string) {
	if f.Compliance == nil {
		f.Compliance = map[string][]string{}
	}
	seen := map[string]bool{}
	for _, c := range f.Compliance[framework] {
		seen[c] = true
	}
	for _, c := range controls {
		if c == "" || seen[c] {
			continue
		}
		seen[c] = true
		f.Compliance[framework] = append(f.Compliance[framework], c)
	}
}

// AttackPath is a chain of findings that together enable a breach scenario.
type AttackPath struct {
	ID         string   `json:"id"`
	RuleID     string   `json:"rule_id"`
	Name       string   `json:"name"`
	Impact     string   `json:"impact"`
	Mitre      []string `json:"mitre,omitempty"`
	Provider   string   `json:"provider"`
	Account    string   `json:"account"`
	Score      float64  `json:"score"`
	Severity   Severity `json:"severity"`
	Steps      []Step   `json:"steps"`
	Narrative  string   `json:"narrative"`
	FindingIDs []string `json:"finding_ids"`
}

type Step struct {
	Stage     int    `json:"stage"`
	FindingID string `json:"finding_id"`
	Weakness  string `json:"weakness"`
	Relation  string `json:"relation"`
	Resource  string `json:"resource"`
	Title     string `json:"title"`
	Summary   string `json:"summary"`
}

type ScanSummary struct {
	ScanID      string           `json:"scan_id"`
	StartedAt   time.Time        `json:"started_at"`
	FinishedAt  time.Time        `json:"finished_at"`
	Accounts    []string         `json:"accounts"`
	Tools       []ToolRun        `json:"tools"`
	Total       int              `json:"total"`
	Failed      int              `json:"failed"`
	BySeverity  map[Severity]int `json:"by_severity"`
	ByProvider  map[string]int   `json:"by_provider"`
	AttackPaths int              `json:"attack_paths"`
}

type ToolRun struct {
	Tool     string `json:"tool"`
	Account  string `json:"account"`
	Status   string `json:"status"` // ok | skipped | failed
	Message  string `json:"message,omitempty"`
	Findings int    `json:"findings"`
	Output   string `json:"output,omitempty"`
}

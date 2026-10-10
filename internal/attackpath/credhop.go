package attackpath

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/DreadpiratePickles/nimbus/internal/graph"
)

// Credential hop: a workload (compute) → the identity it runs as (runs_as / attached_to).
// Planning decision (Track B2 item 5): the hop needs a way to make the workload hand over its
// credentials.
//
//	IMDSv1 on an internet-exposed instance                      1.0  SSRF reads the role credentials
//	mounted service-account token on an exposed pod             0.8  a file-read bug (LFI) is enough
//	exposed and running vulnerable software                     CVE gate (cvegate.go): KEV 0.9,
//	                                                                 EPSS ≥ 0.5 0.6, ≥ 0.1 0.3, else 0.1;
//	                                                                 no ids / no data 0.3 (hint)
//	remote-login port (SSH/RDP/WinRM) open to the internet       0.5  credential attack on a known service
//	publicly invocable serverless function (no auth)             0.5  the attacker drives the function's own use of its role
//	anything else (or not internet-exposed)                      0.1  unknown code execution required
//
// The highest applicable value wins. 0.1 keeps such paths below MinLikelihood, so disabling
// IMDSv1 on a non-vulnerable exposed web instance breaks the path. AI agent runtimes are priced
// by agentHop instead.
func credentialHop(g *graph.Graph, o *TraversalOptions, from *graph.Node) stepEval {
	trusted := o.trusted()
	width := nodeExposure(g, from, trusted)
	best := stepEval{exploitability: 0.1, label: "workload identity usable only after unknown code execution on " + from.Name}
	take := func(p float64, w, label string) {
		if p > best.exploitability {
			best = on(stepEval{exploitability: p, weakness: w, label: label}, from)
		}
	}
	takeHint := func(p float64, w, label string, hint bool) {
		if p > best.exploitability {
			best = on(stepEval{exploitability: p, weakness: w, label: label, hint: hint}, from)
		}
	}
	if width == "" {
		if from.HasWeakness("IMDSV1_ENABLED") {
			best.label += " (IMDSv1 is enabled but the instance is not reachable from the internet)"
		}
		return best
	}
	// Width is priced on the internet hop already; here it only matters that the workload is
	// reachable at all (narrow or wide).
	factor := 1.0
	if from.HasWeakness("IMDSV1_ENABLED") {
		take(1.0*factor, "IMDSV1_ENABLED", "role credentials stolen via IMDSv1 (SSRF on an internet-exposed instance)")
	}
	if from.HasWeakness("SERVICE_ACCOUNT_TOKEN") {
		take(0.8*factor, "SERVICE_ACCOUNT_TOKEN", "mounted service account token readable through a file-read bug on an exposed pod")
	}
	if cg := gateCVE(from, o); cg.applies {
		w := "UNPATCHED"
		if !from.HasWeakness(w) {
			w = "PUBLIC_NETWORK_EXPOSURE"
		}
		takeHint(cg.p*factor, w, "remote code execution through a vulnerability ("+cg.label+"), then credential theft", cg.hint)
	}
	if port := managementPort(g, from, trusted); port != "" {
		take(0.5*factor, "PUBLIC_NETWORK_EXPOSURE", fmt.Sprintf("remote-login service (%s) open to the internet: credential attack, then the workload identity", port))
	}
	if serverless(from) {
		take(0.5*factor, "PUBLIC_NETWORK_EXPOSURE", "unauthenticated invocation drives the function's own use of its role")
	}
	return best
}

// AI agent runtime → the role it runs as (competitive delta IG9 / lab P18; SCC "agents are
// attack-path nodes"). An agent turns its input into tool calls made with its role, so who can
// reach that input decides the hop:
//
//	public / unauthenticated invoke surface, or tool access driven by     0.7  prompt injection steers
//	untrusted input (internet exposure, invoked_by / untrusted_input,          the role's permissions
//	publicly_invocable, auth_type NONE)
//	anything else (internal, authenticated callers only)                    0.3
const (
	AgentUntrustedInput = 0.7
	AgentOtherInput     = 0.3
)

// agentType reports an AI agent runtime (Bedrock agents, generic ai_agent types).
func agentType(n *graph.Node) bool {
	if n == nil {
		return false
	}
	t := strings.ToLower(n.Type)
	return (strings.Contains(t, "bedrock") && strings.Contains(t, "agent")) || strings.Contains(t, "ai_agent") || strings.Contains(t, "agent_runtime")
}

func agentHop(g *graph.Graph, o *TraversalOptions, from *graph.Node) stepEval {
	why := ""
	if g != nil && nodeExposure(g, from, o.trusted()) != "" {
		why = "invocable from the internet"
	}
	a := from.Attributes
	if why == "" {
		for _, k := range []string{"publicly_invocable", "public_invoke", "unauthenticated", "untrusted_input"} {
			if v, _ := a[k].(bool); v {
				why = k + "=true"
				break
			}
		}
	}
	if why == "" {
		for _, k := range []string{"auth_type", "invoke_auth_type"} {
			if v, _ := a[k].(string); strings.EqualFold(strings.TrimSpace(v), "NONE") {
				why = k + " NONE"
			}
		}
	}
	if why == "" {
		if v, _ := a["invoked_by"].(string); v != "" {
			lv := strings.ToLower(v)
			if strings.Contains(lv, "unauthenticated") || strings.Contains(lv, "public") || strings.Contains(lv, "anonymous") || strings.Contains(lv, "authtype none") {
				why = "invoked by " + v
			}
		}
	}
	if why != "" {
		ev := stepEval{exploitability: AgentUntrustedInput, label: "prompt injection through untrusted input (" + why + ") drives the agent's own use of its role"}
		if from.HasWeakness("PUBLIC_NETWORK_EXPOSURE") {
			ev.weakness = "PUBLIC_NETWORK_EXPOSURE"
		}
		return on(ev, from)
	}
	return stepEval{exploitability: AgentOtherInput, label: "agent tools reachable only from internal / authenticated input on " + from.Name}
}

func serverless(n *graph.Node) bool { return serverlessType(strings.ToLower(n.Type)) }

var (
	mgmtWord   = regexp.MustCompile(`(?i)\b(ssh|rdp|winrm|remote desktop)\b|_ssh_|_rdp_|open_ssh|open_rdp`)
	mgmtPortRe = regexp.MustCompile(`(^|[^0-9.])(22|3389|5985|5986)([^0-9.]|$)`)
	allPorts   = regexp.MustCompile(`(?i)all ports|any port|0-65535|"-1"|protocol:-1|protocol=-1|to_port=65535|\ball\b`)
)

// managementPort names the remote-login exposure of n ("ssh", "rdp", "all ports") from the
// evidence on its internet edges and on the exposed network controls in front of it.
func managementPort(g *graph.Graph, n *graph.Node, trusted []string) string {
	var texts []string
	for _, e := range g.In(n.ID) {
		switch {
		case e.From == graph.InternetNodeID:
			if w, _, _ := exposureAt(g, e, trusted); suppressedWidth(w) {
				continue
			}
			texts = append(texts, edgeText(e))
		case e.Kind == graph.EdgeAllowsTrafficTo:
			src, ok := g.Node(e.From)
			if !ok || src.Class != graph.ClassNetwork || nodeExposure(g, src, trusted) == "" {
				continue
			}
			texts = append(texts, edgeText(e), fmt.Sprint(src.Attributes))
			for _, in := range g.In(src.ID) {
				if in.From == graph.InternetNodeID {
					texts = append(texts, edgeText(in))
				}
			}
		}
	}
	all := strings.Join(texts, " | ")
	switch {
	case mgmtWord.MatchString(all):
		m := strings.ToLower(mgmtWord.FindString(all))
		if strings.Contains(m, "rdp") || strings.Contains(m, "remote desktop") {
			return "rdp"
		}
		if strings.Contains(m, "winrm") {
			return "winrm"
		}
		return "ssh"
	case mgmtPortRe.MatchString(portText(texts)):
		return "port " + strings.Trim(mgmtPortRe.FindString(portText(texts)), " :,[]{}\"'")
	case allPorts.MatchString(portText(texts)):
		return "all ports"
	}
	return ""
}

func edgeText(e *graph.Edge) string {
	var parts []string
	for _, k := range []string{"ports", "internet_ports", "via", "check_id", "because", "security_groups"} {
		if v, ok := e.Attr[k]; ok && v != nil {
			parts = append(parts, k+"="+fmt.Sprint(v))
		}
	}
	return strings.Join(parts, " ")
}

// portText keeps only port-bearing fragments so IP addresses do not look like ports.
func portText(texts []string) string {
	var b strings.Builder
	for _, t := range texts {
		for _, f := range strings.FieldsFunc(t, func(r rune) bool { return r == ' ' || r == '|' }) {
			l := strings.ToLower(f)
			if strings.Contains(l, "port") || strings.Contains(l, "tcp") || strings.Contains(l, "udp") || strings.Contains(l, "protocol") || strings.Contains(l, "allowed") {
				b.WriteString(f)
				b.WriteString(" ")
			}
		}
	}
	return b.String()
}

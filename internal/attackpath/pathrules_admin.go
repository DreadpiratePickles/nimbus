package attackpath

import (
	"strconv"
	"strings"

	"github.com/DreadpiratePickles/nimbus/internal/graph"
	"github.com/DreadpiratePickles/nimbus/internal/iam"
)

// fullAdminProbe: actions of unrelated services a full administrator is allowed on "*". A
// principal allowed every one is admin for the path rules; one escalation action on "*" (the
// grant a rule looks for) or an Allow NotAction iam:* is not.
var fullAdminProbe = []string{
	"iam:CreateUser", "iam:PutRolePolicy", "iam:PassRole", "s3:GetObject", "ec2:RunInstances",
	"lambda:CreateFunction", "kms:Decrypt", "sts:AssumeRole", "ssm:SendCommand", "organizations:ListAccounts",
}

func fullAdmin(g *graph.Graph, principal string) bool {
	for _, act := range fullAdminProbe {
		if g.EvaluatePrincipalAction(principal, act, "*").Effect != iam.Allow {
			return false
		}
	}
	return true
}

var mfaKeys = map[string]bool{"aws:multifactorauthpresent": true, "aws:multifactorauthage": true}

// mfaOnlyDeny reports whether the denying statement (graph ActionDecision.DeniedBy, "<layer>
// <policy id>#<sid|index>") is conditioned only on the MFA keys (Deny + BoolIfExists
// aws:MultiFactorAuthPresent false, or an MFA age bound): it binds sessions without MFA only.
// The policy document is resolved as the graph collects it (a policy node's policy_document,
// the principal's inline_policy_document / inline_policy_documents).
func mfaOnlyDeny(g *graph.Graph, deniedBy string) (string, bool) {
	ref := deniedBy
	if i := strings.IndexByte(ref, ' '); i >= 0 {
		ref = ref[i+1:]
	}
	ref = strings.TrimSuffix(ref, "?")
	h := strings.LastIndexByte(ref, '#')
	if h < 0 {
		return "", false
	}
	pid, sid := ref[:h], ref[h+1:]
	var doc any
	if n, ok := g.Node(pid); ok && n.Attributes != nil && n.Attributes["policy_document"] != nil {
		doc = n.Attributes["policy_document"]
	} else if i := strings.Index(pid, "/inline-policy"); i >= 0 {
		n, ok := g.Node(pid[:i])
		if !ok {
			return "", false
		}
		rest := strings.TrimPrefix(pid[i+len("/inline-policy"):], "/")
		switch docs := n.Attributes["inline_policy_documents"].(type) {
		case map[string]any:
			doc = docs[rest]
		case []any:
			if k, err := strconv.Atoi(rest); err == nil && k >= 0 && k < len(docs) {
				doc = docs[k]
			}
		}
		if rest == "" {
			doc = n.Attributes["inline_policy_document"]
		}
	}
	if doc == nil {
		return "", false
	}
	pol, err := iam.ParseAny(doc)
	if err != nil {
		return "", false
	}
	for i, st := range pol.Statement {
		if st.Sid != sid && strconv.Itoa(i) != sid {
			continue
		}
		if !strings.EqualFold(st.Effect, "Deny") || len(st.Condition) == 0 {
			return "", false
		}
		for op, keys := range st.Condition {
			for k, vals := range keys {
				if !mfaKeys[strings.ToLower(k)] {
					return "", false
				}
				if strings.EqualFold(k, "aws:MultiFactorAuthPresent") {
					lop := strings.ToLower(op)
					if !strings.HasPrefix(lop, "bool") || len(vals) != 1 || !strings.EqualFold(vals[0], "false") {
						return "", false
					}
				}
			}
		}
		return "Deny " + ref + " applies when aws:MultiFactorAuthPresent is false", true
	}
	return "", false
}

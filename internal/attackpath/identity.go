package attackpath

import (
	"fmt"

	"github.com/DreadpiratePickles/nimbus/internal/graph"
	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// Identity-entry floor (engine round 2; competitive delta 2026-10-09 shortfall #12; docs/scoring.md
// "Path score"). The toxic-combination floor covers internet exposure → admin and the CI-entry
// floor covers pipeline poisoning → admin. Three identity chains are the same impact policy and
// are what Wiz and Cartography show first, yet multiplied down to 1.4–6.0 before round 2:
//
//	idp-entry       the entry is a federated IdP user (Okta / Entra / …) whose credential is
//	                usable (status ACTIVE, account_enabled) and is not protected by MFA (NO_MFA /
//	                WEAK_AUTH entry), and its groups federate into an admin role (lab P15)
//	external-trust  the entry is a role that an external account can assume without an
//	                ExternalId (CROSS_ACCOUNT_TRUST entry, likelihood ≥ 0.7: a foreign root 0.8,
//	                another foreign principal 0.7) and the path chains into an admin role (P20)
//	privesc         the path crosses a privilege-escalation edge (can_assume with a `technique`
//	                attribute from the IAM evaluator, e.g. iam:PassRole+ec2:RunInstances, priced
//	                EscalationLikelihood = 0.8) from a usable identity entry into an admin role (P13)
//
// Such a path gets likelihood max(likelihood, 0.7) before priority, so it scores ≥ 7 at priority
// 10, and its last step carries toxic_combination = idp-entry | external-trust | privesc with the
// reason. Like the other floors it never applies to a hint entry (credential usability unknown),
// to an internet entry (the toxic floor decides those), to a target that is not admin-level (or a
// configured crown jewel tier ≥ 3), or below MinLikelihood: it lifts reported paths and never
// creates one, so removing the MFA exemption, the trust or the PassRole grant still breaks it.
const (
	ToxicIdPEntry        = "idp-entry"
	ToxicExternalTrust   = "external-trust"
	ToxicPrivesc         = "privesc"
	EscalationLikelihood = 0.8
)

func applyIdentityFloor(g *graph.Graph, lik float64, entry *graph.Node, steps []model.Step, target *graph.Node, jewels []JewelRule) (float64, string, string) {
	if entry == nil || target == nil || len(steps) == 0 || steps[0].Relation != "entry" || entry.ID == graph.InternetNodeID {
		return lik, "", ""
	}
	first := steps[0]
	if c, _ := first.Evidence["confidence"].(string); c == string(model.ConfidenceHint) {
		return lik, "", ""
	}
	admin := adminLevel(target)
	if admin == "" {
		if lvl := configuredJewel(target, jewels); lvl >= 3 {
			admin = fmt.Sprintf("configured crown jewel tier %d", lvl)
		}
	}
	if admin == "" {
		return lik, "", ""
	}
	weaks := map[string]bool{}
	for _, w := range toStrings(first.Evidence["entry_weaknesses"]) {
		weaks[w] = true
	}
	if w, _ := first.Evidence["weakness"].(string); w != "" {
		weaks[w] = true
	}
	entryLik, _ := first.Evidence["likelihood"].(float64)

	kind, reason := "", ""
	// A cross-account entry protected by ExternalId / SourceIdentity (ProtectedTrustEntry) is not
	// a usable identity entry for any floor (verify-4 D2): only its own likelihood counts.
	if w, _ := first.Evidence["weakness"].(string); w == "CROSS_ACCOUNT_TRUST" && entryLik < 0.7 {
		return lik, "", ""
	}
	for _, s := range steps[1:] {
		if tech, _ := s.Evidence[graph.AttrTechnique].(string); tech != "" && s.Relation == graph.EdgeCanAssume {
			kind = ToxicPrivesc
			reason = fmt.Sprintf("%s escalates to %s (%s) by %s", entry.Name, target.Name, admin, tech)
			break
		}
	}
	if kind == "" && idpUser(entry) && (weaks["NO_MFA"] || weaks["WEAK_AUTH"]) {
		kind = ToxicIdPEntry
		reason = fmt.Sprintf("federated IdP user %s (credential usable: %s, MFA not enforced) federates into %s (%s)", entry.Name, idpUsable(entry), target.Name, admin)
	}
	if kind == "" && weaks["CROSS_ACCOUNT_TRUST"] && entryLik >= 0.7 && len(steps) > 1 {
		kind = ToxicExternalTrust
		reason = fmt.Sprintf("external principals assume %s without an ExternalId and chain into %s (%s)", entry.Name, target.Name, admin)
	}
	if kind == "" {
		return lik, "", ""
	}
	if lik < ToxicFloor {
		reason += fmt.Sprintf("; likelihood floored %.2f → %.2f", lik, ToxicFloor)
		lik = ToxicFloor
	}
	return lik, kind, reason
}

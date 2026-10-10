package attackpath

import (
	"fmt"
	"path"
	"strings"

	"github.com/DreadpiratePickles/nimbus/internal/collector/core"
	"github.com/DreadpiratePickles/nimbus/internal/collector/saas"
	"github.com/DreadpiratePickles/nimbus/internal/graph"
	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// Toxic-combination floor (Track B3 item 3, planning decision; docs/scoring.md "Path score",
// docs/benchmark.md "Toxic-combination floor"). It mirrors Wiz "toxic combinations" and
// Tenable's "toxic cloud trilogy": public exposure that leads to admin rights or sensitive data
// is critical even when the per-hop likelihood table multiplies down to a modest number.
//
// Rule. A graph-traversal path whose entry hop is WIDE internet exposure and whose target is
//
//	admin-level  an identity / RBAC binding carrying OVERPRIVILEGED_IDENTITY or CLUSTER_ADMIN,
//	             a project / subscription / account admin role (AdministratorAccess, roles/owner,
//	             roles/editor, Owner / Contributor / User Access Administrator at subscription or
//	             management-group scope, cluster-admin role_ref), or a configured crown jewel at
//	             level very_high / high (TraversalOptions.CrownJewels criticality >= 3)
//	sensitive    a data store marked sensitive
//
// gets likelihood max(likelihood, 0.7) before priority is applied, and its last step carries
// evidence toxic_combination = "exposed+admin" | "exposed+sensitive" plus a one-line reason in
// `because`. It does not apply to narrow / trusted / private exposure, to an entry behind an
// authenticating load balancer (auth-lb, P1-ENGINE noise round decision 3), to non-internet entries,
// to rule chains (no likelihood; weak_link chains included), or to targets that are neither
// admin-level nor sensitive, and it never rescues a path below MinLikelihood: the floor lifts
// reported paths, it does not create them, so removing a weakness still breaks the path.
const (
	ToxicFloor     = 0.7
	ToxicAdmin     = "exposed+admin"
	ToxicSensitive = "exposed+sensitive"
)

// ToxicCombination returns the path's toxic-combination tag ("" when none).
func ToxicCombination(p model.AttackPath) string {
	if len(p.Steps) == 0 {
		return ""
	}
	s, _ := p.Steps[len(p.Steps)-1].Evidence["toxic_combination"].(string)
	return s
}

// toxicCombination classifies a path ending at target whose entry hop had width entryWidth.
func toxicCombination(entryWidth string, target *graph.Node, jewels []JewelRule) (kind, reason string) {
	if entryWidth != core.ExposureWide || target == nil {
		return "", ""
	}
	if target.Class == graph.ClassDataStore {
		if sensitiveData(target) {
			return ToxicSensitive, "wide internet exposure reaches sensitive data store " + target.Name
		}
		if lvl := configuredJewel(target, jewels); lvl >= 3 {
			return ToxicSensitive, fmt.Sprintf("wide internet exposure reaches %s, a configured crown jewel (tier %d)", target.Name, lvl)
		}
		return "", ""
	}
	if why := adminLevel(target); why != "" {
		return ToxicAdmin, "wide internet exposure reaches " + target.Name + " (" + why + ")"
	}
	if lvl := configuredJewel(target, jewels); lvl >= 3 {
		return ToxicAdmin, fmt.Sprintf("wide internet exposure reaches %s, a configured crown jewel (tier %d)", target.Name, lvl)
	}
	return "", ""
}

// configuredJewel is the highest criticality a configured (not built-in) crown-jewel rule
// gives n; the CLI turns config crown_jewels very_high / high into criticality 4 / 3.
func configuredJewel(n *graph.Node, jewels []JewelRule) int {
	best := 0
	for _, r := range jewels {
		if r.Criticality > best && jewelMatch(n, r.Pattern) {
			best = r.Criticality
		}
	}
	return best
}

// jewelMatch is Criticality's matcher: glob on name / id / type, or a non-empty substring.
func jewelMatch(n *graph.Node, pattern string) bool {
	p := strings.ToLower(pattern)
	sub := strings.Trim(p, "*")
	for _, s := range []string{n.Name, n.ID, n.Type} {
		s = strings.ToLower(s)
		if ok, _ := path.Match(p, s); ok || (sub != "" && strings.Contains(s, sub)) {
			return true
		}
	}
	return false
}

var (
	adminPolicies = []string{"administratoraccess", "roles/owner", "roles/editor", "cluster-admin"}
	adminRoles    = map[string]bool{"owner": true, "contributor": true, "user access administrator": true}
)

// adminLevel says why n holds admin rights over a cluster, project, subscription or account
// ("" when it does not).
func adminLevel(n *graph.Node) string {
	switch {
	case n.HasWeakness("CLUSTER_ADMIN"):
		return "cluster-admin"
	case n.HasWeakness("OVERPRIVILEGED_IDENTITY"):
		return "admin / over-privileged identity"
	case strings.Contains(strings.ToLower(n.Type), "cluster_role") && strings.EqualFold(n.Name, "cluster-admin"):
		return "the cluster-admin ClusterRole"
	case strings.EqualFold(n.Type, "aws_iam_root"):
		return "the account root user"
	}
	for _, k := range []string{"attached_policies", "project_roles", "role_ref", "roles"} {
		for _, v := range toStrings(n.Attributes[k]) {
			lv := strings.ToLower(v)
			for _, a := range adminPolicies {
				if strings.HasSuffix(lv, a) || lv == a {
					return k + " " + v
				}
			}
		}
	}
	if ras, ok := n.Attributes["role_assignments"].([]any); ok {
		for _, ra := range ras {
			m, _ := ra.(map[string]any)
			role, _ := m["role"].(string)
			scope, _ := m["scope"].(string)
			ls := strings.ToLower(strings.TrimRight(scope, "/"))
			broad := ls == "/" || strings.HasPrefix(ls, "/providers/microsoft.management/") ||
				(strings.HasPrefix(ls, "/subscriptions/") && strings.Count(ls, "/") == 2)
			if adminRoles[strings.ToLower(role)] && broad {
				return role + " on " + scope
			}
		}
	}
	return ""
}

// applyToxicFloor returns the scoring likelihood and the toxic tag for a reportable path.
func applyToxicFloor(lik float64, entryWidth string, target *graph.Node, jewels []JewelRule) (float64, string, string) {
	kind, reason := toxicCombination(entryWidth, target, jewels)
	if kind == "" {
		return lik, "", ""
	}
	if lik < ToxicFloor {
		reason += fmt.Sprintf("; likelihood floored %.2f → %.2f", lik, ToxicFloor)
		lik = ToxicFloor
	}
	return lik, kind, reason
}

// entryWidthOf is the exposure width of an internet entry edge ("" for any other edge).
func entryWidthOf(g *graph.Graph, from *graph.Node, e *graph.Edge, trusted []string) string {
	if from.ID != graph.InternetNodeID || (e.Kind != graph.EdgeExposes && e.Kind != graph.EdgeAllowsTrafficTo) {
		return ""
	}
	w, _, _ := exposureAt(g, e, trusted)
	return w
}

// CI-entry floor (P1-PLANDIFF; planning decision on P12, docs/plan-diff.md "CI-entry floor").
// Pipeline poisoning is the CI/CD counterpart of exposed+admin: a repository whose default
// branch anyone with write access can change unreviewed (BRANCH_UNPROTECTED, or the attribute
// any_contributor_write) and a cloud role whose OIDC trust accepts that repository's workflows
// with a wildcard or unpinned subject (any ref / pull request / environment, or any repository)
// hand the role to whoever can push. A path whose entry is such a repository, whose trust hop
// (repository → role, can_assume) has a wildcard / unpinned subject that matches the repository,
// and whose target is admin-level (adminLevel, or a configured crown jewel tier >= 3) gets
// likelihood max(likelihood, 0.7), tag toxic_combination = "ci-entry", and the trust hop carries
// the hop attributes oidc_subject / oidc_subject_class (visible on the step's evidence).
//
// It does not apply to a pinned subject (one ref, tag or environment: F05), to a protected
// repository (no entry at all), to a subject the graph does not state (unknown is not
// wildcard), to a subject naming another repository, or to a non-admin target; like the toxic
// floor it lifts reported paths and never creates one.
const ToxicCIEntry = "ci-entry"

// applyCIEntryFloor returns the scoring likelihood, the tag and reason, and the steps (copied
// when the trust hop gains its OIDC attributes).
func applyCIEntryFloor(g *graph.Graph, lik float64, entry *graph.Node, steps []model.Step, target *graph.Node, jewels []JewelRule) (float64, string, string, []model.Step) {
	if entry == nil || target == nil || entry.Class != graph.ClassSaaS || !ciWritable(entry) {
		return lik, "", "", steps
	}
	admin := adminLevel(target)
	if admin == "" {
		if lvl := configuredJewel(target, jewels); lvl >= 3 {
			admin = fmt.Sprintf("configured crown jewel tier %d", lvl)
		}
	}
	if admin == "" {
		return lik, "", "", steps
	}
	for i, s := range steps {
		if s.Relation != graph.EdgeCanAssume || s.Evidence["from"] != entry.ID {
			continue
		}
		role, _ := g.Node(s.Resource)
		sub, class, why := ciTrustSubject(entry, s.Evidence, role)
		if class != saas.OIDCSubjectWildcard && class != saas.OIDCSubjectUnpinned {
			return lik, "", "", steps
		}
		out := append([]model.Step(nil), steps...)
		ev := make(map[string]any, len(s.Evidence)+2)
		for k, v := range s.Evidence {
			ev[k] = v
		}
		ev["oidc_subject"], ev["oidc_subject_class"] = sub, class
		out[i].Evidence = ev
		reason := fmt.Sprintf("%s on %s and an OIDC trust with %s subject (%s) reach %s (%s)", ciWhy(entry), entry.Name, article(class), why, target.Name, admin)
		if lik < ToxicFloor {
			reason += fmt.Sprintf("; likelihood floored %.2f → %.2f", lik, ToxicFloor)
			lik = ToxicFloor
		}
		return lik, ToxicCIEntry, reason, out
	}
	return lik, "", "", steps
}

func ciWritable(n *graph.Node) bool {
	if n.HasWeakness("BRANCH_UNPROTECTED") {
		return true
	}
	v, _ := n.Attributes["any_contributor_write"].(bool)
	return v
}

func ciWhy(n *graph.Node) string {
	if n.HasWeakness("BRANCH_UNPROTECTED") {
		return "unprotected default branch"
	}
	return "default branch writable by any contributor"
}

// ciTrustSubject is the worst subject, among those that match the repository, stated on the
// trust hop (oidc_subject / oidc_subjects / sub, or the via / because text) or on the role
// (trust_policy / assume_role_policy, oidc_subjects, trust text). class "" = not stated.
func ciTrustSubject(repo *graph.Node, edge map[string]any, role *graph.Node) (sub, class, why string) {
	var subs []string
	for _, k := range []string{"oidc_subject", "oidc_subjects", "sub"} {
		subs = append(subs, toStrings(edge[k])...)
	}
	if len(subs) == 0 {
		for _, k := range []string{"via", "because"} {
			if t, _ := edge[k].(string); t != "" {
				if subs = saas.OIDCSubjectsFromText(t); len(subs) > 0 {
					break
				}
			}
		}
	}
	if len(subs) == 0 && role != nil {
		for _, k := range []string{"trust_policy", "assume_role_policy"} {
			if tr, ok := saas.GitHubOIDCTrust(role.Attributes[k]); ok {
				subs = append(subs, tr.Subjects...)
				if tr.NoSubject {
					subs = append(subs, "")
				}
			}
		}
		subs = append(subs, toStrings(role.Attributes["oidc_subjects"])...)
		if t, _ := role.Attributes["trust"].(string); len(subs) == 0 && t != "" {
			subs = saas.OIDCSubjectsFromText(t)
		}
	}
	best := -1
	rank := map[string]int{saas.OIDCSubjectWildcard: 0, saas.OIDCSubjectUnpinned: 1, saas.OIDCSubjectPinned: 2}
	for _, s := range subs {
		if !saas.OIDCSubjectMatchesRepo(s, repo.ID) && !saas.OIDCSubjectMatchesRepo(s, repo.Name) {
			continue
		}
		c, w := saas.ClassifyOIDCSubject(s)
		if best < 0 || rank[c] < best {
			best, sub, class, why = rank[c], s, c, w
		}
	}
	return sub, class, why
}

func article(class string) string {
	if class == saas.OIDCSubjectUnpinned {
		return "an unpinned"
	}
	return "a " + class
}

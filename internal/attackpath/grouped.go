package attackpath

import (
	"sort"

	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// PathSeverity is the severity label of a path with this score: the band of the score
// (model.ScoreBand: Critical ≥ 9, High ≥ 7, Medium ≥ 5, Low < 5), the same scale risk.BandFor
// and path Issues use (competitive delta 2026-10-09 shortfall #1). Traversal paths, rule chains,
// Grouped rows and the plan diff all label a path with it, so "[CRITICAL 5.2]" cannot exist.
func PathSeverity(score float64) model.Severity {
	switch model.ScoreBand(score) {
	case "Critical":
		return model.Critical
	case "High":
		return model.High
	case "Medium":
		return model.Medium
	}
	return model.Low
}

// PathGroup is one path Issue (model.PathIssueID over entry | anchor | rule) with the paths that
// share it: the default `paths` view lists one row per group (Best, "+Variants variants"); the
// full list (`--all-variants`) is Paths. Wiz "one Issue per path" (shortfall #11).
type PathGroup struct {
	IssueID  string             `json:"issue_id"`
	Entry    string             `json:"entry"`
	Anchor   string             `json:"anchor"`
	Rule     string             `json:"rule"`
	Best     model.AttackPath   `json:"best"`
	Score    float64            `json:"score"` // Best.Score: the Issue score is the max over its paths
	Band     string             `json:"band"`
	Severity model.Severity     `json:"severity"`
	Variants int                `json:"variants"` // len(Paths) - 1
	PathIDs  []string           `json:"path_ids"` // best first
	Paths    []model.AttackPath `json:"paths"`    // best first, then by score
}

// Grouped returns an.Paths grouped by path Issue, best-scoring group first. It is lossless: every
// path of an.Paths is in exactly one group.
func (an *Analysis) Grouped() []PathGroup {
	if an == nil {
		return nil
	}
	return GroupPaths(an.Paths)
}

// GroupPaths groups paths by model.PathIssueID (kind path, model.PathIssueKey). Within a group
// paths are ordered by score, then by secondary key (the stored Issue's choice of best path).
func GroupPaths(paths []model.AttackPath) []PathGroup {
	idx := map[string]int{}
	var out []PathGroup
	for _, p := range paths {
		if len(p.Steps) == 0 {
			continue
		}
		e, a, r := model.PathIssueKey(p)
		id := model.PathIssueID(model.IssuePath, e, a, r)
		i, ok := idx[id]
		if !ok {
			i = len(out)
			idx[id] = i
			out = append(out, PathGroup{IssueID: id, Entry: e, Anchor: a, Rule: r})
		}
		out[i].Paths = append(out[i].Paths, p)
	}
	for i := range out {
		g := &out[i]
		sort.SliceStable(g.Paths, func(a, b int) bool {
			if g.Paths[a].Score != g.Paths[b].Score {
				return g.Paths[a].Score > g.Paths[b].Score
			}
			return model.PathSecondaryKey(g.Paths[a]) < model.PathSecondaryKey(g.Paths[b])
		})
		g.Best = g.Paths[0]
		g.Score = g.Best.Score
		g.Band = model.ScoreBand(g.Score)
		g.Severity = PathSeverity(g.Score)
		g.Variants = len(g.Paths) - 1
		for _, p := range g.Paths {
			g.PathIDs = append(g.PathIDs, p.ID)
		}
	}
	sort.SliceStable(out, func(a, b int) bool {
		if out[a].Score != out[b].Score {
			return out[a].Score > out[b].Score
		}
		return out[a].IssueID < out[b].IssueID
	})
	return out
}

// InternetEntryNode is the exposed node an internet-entry path enters at (its first hop's
// resource); "" for an identity / SaaS entry (relation "entry"). Defect 10c / verify-4 D5: the
// path Issue key's entry is "internet" for every internet path, so a second public host
// reaching an already-reachable anchor opens no new Issue; pathdiff tells such entries apart
// with this (or EntryKey) without changing the Issue id.
func InternetEntryNode(p model.AttackPath) string {
	if len(p.Steps) == 0 || p.Steps[0].Relation == "entry" {
		return ""
	}
	return p.Steps[0].Resource
}

// EntryKey is model.PathIssueKey with the internet entry refined by the exposed node
// ("internet:<node id>"): two internet paths to the same anchor through different public hosts
// have the same Issue id but different EntryKeys. PRODUCT (pathdiff) compares the EntryKey sets
// of base and plan per Issue: a key only in the plan is a newly exposed entry.
func EntryKey(p model.AttackPath) (entry, anchor, rule string) {
	entry, anchor, rule = model.PathIssueKey(p)
	if n := InternetEntryNode(p); n != "" && entry == model.PathEntryInternet {
		entry = model.PathEntryInternet + ":" + n
	}
	return entry, anchor, rule
}

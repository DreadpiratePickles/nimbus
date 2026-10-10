package cli

import (
	"sort"

	"github.com/DreadpiratePickles/nimbus/internal/graph"
)

// exposureRow is one internet-facing resource in `paths --exposures --format json`, with the
// node's one verdict (graph.Verdict: status, reason, label) every surface must print.
type exposureRow struct {
	NodeID     string        `json:"node_id"`
	Name       string        `json:"name"`
	Type       string        `json:"type,omitempty"`
	Width      string        `json:"width"` // wide | narrow | blocked (exposures), trusted | private (suppressed), entry (path entries)
	Because    string        `json:"because,omitempty"`
	FindingIDs []string      `json:"finding_ids,omitempty"`
	Verdict    graph.Verdict `json:"verdict"`
}

// exposuresDoc: exposures (not attack paths, blocked ones included), suppressed exposures
// (trusted / private) and the internet entries of attack paths, each with its verdict.
type exposuresDoc struct {
	Exposures  []exposureRow `json:"exposures"`
	Suppressed []exposureRow `json:"suppressed"`
	Entries    []exposureRow `json:"entries"`
}

func exposuresJSON(res *scanResult) exposuresDoc {
	doc := exposuresDoc{Exposures: []exposureRow{}, Suppressed: []exposureRow{}, Entries: []exposureRow{}}
	verdict := func(id string) graph.Verdict {
		if res.Graph == nil {
			return graph.Verdict{NodeID: id}
		}
		return res.Graph.Verdict(id)
	}
	if an := res.Analysis; an != nil {
		for _, e := range an.Exposures {
			doc.Exposures = append(doc.Exposures, exposureRow{NodeID: e.NodeID, Name: e.Name, Type: e.Type, Width: e.Width,
				Because: firstNonEmpty(e.Reason, e.Because), FindingIDs: e.FindingIDs, Verdict: verdict(e.NodeID)})
		}
		for _, s := range an.Suppressed {
			doc.Suppressed = append(doc.Suppressed, exposureRow{NodeID: s.NodeID, Name: s.Name, Width: s.Exposure,
				Because: s.Reason, FindingIDs: s.FindingIDs, Verdict: verdict(s.NodeID)})
		}
	}
	seen := map[string]bool{}
	for _, p := range res.Paths {
		if len(p.Steps) == 0 {
			continue
		}
		st := p.Steps[0]
		if from, _ := st.Evidence["from"].(string); from != graph.InternetNodeID || st.Resource == "" || seen[st.Resource] {
			continue
		}
		seen[st.Resource] = true
		r := exposureRow{NodeID: st.Resource, Name: st.Title, Width: "entry", Because: st.Because, Verdict: verdict(st.Resource)}
		if res.Graph != nil {
			if n, ok := res.Graph.Node(st.Resource); ok {
				r.Name, r.Type, r.FindingIDs = firstNonEmpty(n.Name, r.Name), n.Type, n.FindingIDs
			}
		}
		doc.Entries = append(doc.Entries, r)
	}
	sort.Slice(doc.Entries, func(i, j int) bool { return doc.Entries[i].NodeID < doc.Entries[j].NodeID })
	return doc
}

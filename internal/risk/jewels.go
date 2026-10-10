package risk

import (
	"strings"

	"github.com/DreadpiratePickles/nimbus/internal/config"
	"github.com/DreadpiratePickles/nimbus/internal/graph"
)

// JewelFromConfig turns the config crown_jewels block (Track C, O62) into a JewelFunc via
// config.MatchCrownJewel: the highest matching level wins. Nil config or no rules → nil (the
// criticality factor then falls back to node attrs / criticality, else "not scored").
func JewelFromConfig(cfg *config.Config) JewelFunc {
	if cfg == nil || len(cfg.CrownJewels) == 0 {
		return nil
	}
	rules := cfg.CrownJewels
	return func(n *graph.Node) (string, string, bool) {
		if n == nil {
			return "", "", false
		}
		subj := config.JewelSubjectFromAttrs(n.Type, n.Name, n.Account, n.Attributes)
		level, ok := config.MatchCrownJewel(rules, subj)
		if !ok {
			return "", "", false
		}
		rule := "crown_jewels rule"
		for i := range rules {
			if strings.EqualFold(rules[i].Level, level) && rules[i].Matches(subj) {
				if rules[i].Name != "" {
					rule = "crown_jewels rule " + rules[i].Name
				}
				break
			}
		}
		return level, rule, true
	}
}

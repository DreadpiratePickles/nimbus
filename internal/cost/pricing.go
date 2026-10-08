package cost

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"sync"
)

//go:embed pricing.json
var pricingJSON []byte

// Pricing is the on-demand price book used to value cost signals.
type Pricing struct {
	ComputeHourly  map[string]map[string]float64 `json:"compute_hourly"`
	StorageGBMonth map[string]map[string]float64 `json:"storage_gb_month"`
	DefaultStorage map[string]string             `json:"default_storage"`
	IPMonthly      map[string]float64            `json:"ip_monthly"`
	EgressPerGB    map[string]float64            `json:"egress_per_gb"`
}

var (
	defaultOnce    sync.Once
	defaultPricing *Pricing
)

// DefaultPricing returns the embedded price book.
func DefaultPricing() *Pricing {
	defaultOnce.Do(func() {
		p, err := ParsePricing(pricingJSON)
		if err != nil {
			panic(fmt.Sprintf("embedded pricing invalid: %v", err))
		}
		defaultPricing = p
	})
	return defaultPricing
}

// ParsePricing decodes a price book in the pricing.json shape.
func ParsePricing(data []byte) (*Pricing, error) {
	var p Pricing
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

func normProvider(p string) string { return strings.ToLower(strings.TrimSpace(p)) }

// lookup is case-insensitive on the key.
func lookup(m map[string]float64, key string) (float64, bool) {
	if v, ok := m[key]; ok {
		return v, true
	}
	for k, v := range m {
		if strings.EqualFold(k, key) {
			return v, true
		}
	}
	return 0, false
}

// InstanceHourly returns the on-demand hourly price of an instance / VM size / machine type.
func (p *Pricing) InstanceHourly(provider, instanceType string) (float64, bool) {
	t := instanceType
	if i := strings.LastIndex(t, "/"); i >= 0 { // GCE machineType URLs
		t = t[i+1:]
	}
	return lookup(p.ComputeHourly[normProvider(provider)], t)
}

// StorageGB returns the per GB-month price of a disk class (default class when empty/unknown).
func (p *Pricing) StorageGB(provider, class string) float64 {
	prov := normProvider(provider)
	if class != "" {
		if v, ok := lookup(p.StorageGBMonth[prov], class); ok {
			return v
		}
	}
	if v, ok := lookup(p.StorageGBMonth[prov], p.DefaultStorage[prov]); ok {
		return v
	}
	return 0.10
}

// IP returns the monthly price of an idle public / static IP.
func (p *Pricing) IP(provider string) float64 {
	if v, ok := p.IPMonthly[normProvider(provider)]; ok {
		return v
	}
	return 3.60
}

// Egress returns the per-GB internet egress price.
func (p *Pricing) Egress(provider string) float64 {
	if v, ok := p.EgressPerGB[normProvider(provider)]; ok {
		return v
	}
	return 0.09
}

var azureSizeRE = regexp.MustCompile(`^(?i)standard_([a-z]+)(\d+)([a-z]*)(_v\d+)?$`)

// familyKey groups sizes that can be swapped one-for-one when rightsizing.
func familyKey(provider, t string) string {
	switch normProvider(provider) {
	case "aws":
		if i := strings.Index(t, "."); i > 0 {
			return strings.ToLower(t[:i])
		}
	case "azure":
		if m := azureSizeRE.FindStringSubmatch(t); m != nil {
			return strings.ToLower(m[1] + "|" + m[3] + "|" + m[4])
		}
	case "gcp":
		if i := strings.Index(t, "-"); i > 0 {
			return strings.ToLower(t[:i])
		}
	}
	return strings.ToLower(t)
}

// Downsize returns the next smaller size in the same family (the priciest size cheaper
// than the current one) and its hourly price.
func (p *Pricing) Downsize(provider, instanceType string) (string, float64, bool) {
	cur, ok := p.InstanceHourly(provider, instanceType)
	if !ok {
		return "", 0, false
	}
	key := familyKey(provider, instanceType)
	best, bestPrice := "", 0.0
	for t, price := range p.ComputeHourly[normProvider(provider)] {
		if familyKey(provider, t) != key || price >= cur {
			continue
		}
		if price > bestPrice || (price == bestPrice && t < best) {
			best, bestPrice = t, price
		}
	}
	return best, bestPrice, best != ""
}

// Price is the package-level lookup against the embedded price book.
func Price(provider, instanceType string) (hourly float64, ok bool) {
	return DefaultPricing().InstanceHourly(provider, instanceType)
}

// StoragePrice is the per GB-month price for a disk class in the embedded price book.
func StoragePrice(provider, class string) float64 { return DefaultPricing().StorageGB(provider, class) }

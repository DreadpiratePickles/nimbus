package model

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// Relation is a typed relationship from a finding's resource to another resource.
//
// Native findings (and inventory records) declare relationships in resource.related. An entry
// is either a legacy string (an untyped hint, turned into an `attached_to` edge) or an object:
//
//	{"id": "<target resource id>", "kind": "<edge kind>", "attr": {...}}
//
// kind is one of the graph's edge kinds (internal/graph: attached_to, runs_as, bound_to,
// member_of, trusts, has_policy, grants_access_to, runs_on, allows_traffic_to, can_assume,
// exposes, contains, stores_data_in) or an accepted alias (sts_assume_role_allows,
// exposed_to_internet, policy, resource); graph.RelationEdge resolves direction and alias.
// attr is copied onto the edge; attr.because (when set) becomes the hop's explanation.
type Relation struct {
	ID   string         `json:"id"`
	Kind string         `json:"kind"`
	Attr map[string]any `json:"attr,omitempty"`
}

// resourceWire is Resource without its methods (avoids recursion in the JSON hooks).
type resourceWire struct {
	ID         string            `json:"id"`
	Type       string            `json:"type"`
	Name       string            `json:"name"`
	Attributes map[string]any    `json:"attributes,omitempty"`
	Related    []json.RawMessage `json:"related,omitempty"`
	Relations  []Relation        `json:"relations,omitempty"`
}

// UnmarshalJSON accepts `related` entries as strings or typed objects, plus an explicit
// `relations` array (the form MarshalJSON writes). Every related ID lands in Related, so
// consumers that only know the string list keep working; typed entries land in Relations.
func (r *Resource) UnmarshalJSON(b []byte) error {
	var w resourceWire
	if err := json.Unmarshal(b, &w); err != nil {
		return err
	}
	*r = Resource{ID: w.ID, Type: w.Type, Name: w.Name, Attributes: w.Attributes}
	for i, raw := range w.Related {
		raw = bytes.TrimSpace(raw)
		switch {
		case len(raw) > 0 && raw[0] == '"':
			var s string
			if err := json.Unmarshal(raw, &s); err != nil {
				return err
			}
			if s != "" {
				r.Related = appendUniqueID(r.Related, s)
			}
		case len(raw) > 0 && raw[0] == '{':
			var rel Relation
			if err := json.Unmarshal(raw, &rel); err != nil {
				return fmt.Errorf("resource %s: related[%d]: %w", w.ID, i, err)
			}
			if err := r.addRelation(rel); err != nil {
				return fmt.Errorf("resource %s: related[%d]: %w", w.ID, i, err)
			}
		case bytes.Equal(raw, []byte("null")):
		default:
			return fmt.Errorf("resource %s: related[%d] must be a resource id string or {id, kind, attr}", w.ID, i)
		}
	}
	for i, rel := range w.Relations {
		if err := r.addRelation(rel); err != nil {
			return fmt.Errorf("resource %s: relations[%d]: %w", w.ID, i, err)
		}
	}
	return nil
}

func (r *Resource) addRelation(rel Relation) error {
	if rel.ID == "" {
		return fmt.Errorf("typed relation needs an id")
	}
	if rel.Kind == "" {
		return fmt.Errorf("typed relation to %s needs a kind", rel.ID)
	}
	for _, x := range r.Relations {
		if x.ID == rel.ID && x.Kind == rel.Kind {
			return nil
		}
	}
	r.Relations = append(r.Relations, rel)
	r.Related = appendUniqueID(r.Related, rel.ID)
	return nil
}

// MarshalJSON writes `related` as strings only (every ID, typed or not) and the typed
// entries as `relations`, so the Python SDK and the resources table see a string list.
func (r Resource) MarshalJSON() ([]byte, error) {
	type plain struct {
		ID         string         `json:"id"`
		Type       string         `json:"type"`
		Name       string         `json:"name"`
		Attributes map[string]any `json:"attributes,omitempty"`
		Related    []string       `json:"related,omitempty"`
		Relations  []Relation     `json:"relations,omitempty"`
	}
	related := append([]string(nil), r.Related...)
	for _, rel := range r.Relations {
		related = appendUniqueID(related, rel.ID)
	}
	return json.Marshal(plain{ID: r.ID, Type: r.Type, Name: r.Name, Attributes: r.Attributes, Related: related, Relations: r.Relations})
}

func appendUniqueID(list []string, id string) []string {
	for _, x := range list {
		if x == id {
			return list
		}
	}
	return append(list, id)
}

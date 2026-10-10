package graph

import "github.com/DreadpiratePickles/nimbus/internal/model"

// Typed access to the edge attribute contract (internal/model/edge_attrs.go). Getters read
// both in-memory typed values and JSON-decoded values loaded from graph_edges. Setters copy
// the attr map before writing (Clone shares attr maps between graphs), so they never change a
// clone's edge. They are not safe for concurrent use on the same edge.

// Attrs parses the whole contract; an error means a value outside the contract vocabulary.
func (e *Edge) Attrs() (model.EdgeAttrs, error) { return model.ParseEdgeAttrs(e.Attr) }

// SetAttrs merges every set field of a into the edge's attributes.
func (e *Edge) SetAttrs(a model.EdgeAttrs) {
	m := e.cowAttr()
	model.SetEdgeAttrs(m, a)
}

// Permission returns the permission the edge carries (ok=false when it carries none).
func (e *Edge) Permission() (model.PermissionAttr, bool) {
	a, _ := model.ParseEdgeAttrs(e.Attr)
	if a.PermissionAttr == nil {
		return model.PermissionAttr{}, false
	}
	return *a.PermissionAttr, true
}

func (e *Edge) SetPermission(p model.PermissionAttr) { model.SetPermission(e.cowAttr(), p) }

// Exposure returns the edge's exposure width/sources (ok=false when it carries none).
func (e *Edge) Exposure() (model.Exposure, bool) {
	a, _ := model.ParseEdgeAttrs(e.Attr)
	if a.Exposure == nil {
		return model.Exposure{}, false
	}
	return *a.Exposure, true
}

func (e *Edge) SetExposure(x model.Exposure) { model.SetExposure(e.cowAttr(), x) }

// Confidence is "" when the edge has not been labelled.
func (e *Edge) Confidence() model.Confidence {
	s, _ := e.Attr[model.AttrConfidence].(string)
	return model.Confidence(s)
}

func (e *Edge) SetConfidence(c model.Confidence) { e.cowAttr()[model.AttrConfidence] = string(c) }

// Because is the hop's explanation (AddEdge always sets one).
func (e *Edge) Because() string {
	s, _ := e.Attr[model.AttrBecause].(string)
	return s
}

func (e *Edge) SetBecause(s string) { e.cowAttr()[model.AttrBecause] = s }

// cowAttr replaces e.Attr with a private copy and returns it.
func (e *Edge) cowAttr() map[string]any {
	m := make(map[string]any, len(e.Attr)+4)
	for k, v := range e.Attr {
		m[k] = v
	}
	e.Attr = m
	return m
}

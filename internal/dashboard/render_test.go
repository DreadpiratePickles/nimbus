package dashboard

import (
	"strings"
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/model"
)

func TestRenderEscapes(t *testing.T) {
	html, err := Render(Data{Findings: []model.Finding{{ID: "x", Title: "</script><img src=x onerror=alert(1)>", Status: model.Fail, Severity: model.High, Resource: model.Resource{ID: "r"}}}})
	if err != nil {
		t.Fatal(err)
	}
	s := string(html)
	if strings.Contains(s, "</script><img") {
		t.Fatalf("script breakout not neutralised")
	}
	if !strings.Contains(s, `<script id="data" type="application/json">`) || !strings.Contains(s, "cytoscape") {
		t.Errorf("template structure")
	}
}

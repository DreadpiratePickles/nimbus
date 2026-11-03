package dashboard

import (
	"fmt"
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

func TestRenderCwmTheme(t *testing.T) {
	html, err := Render(Data{})
	if err != nil {
		t.Fatal(err)
	}
	s := string(html)
	// brown root, cream windows, focused/idle borders
	for _, tok := range []string{"--root:#2b1d14", "--win:#efe4cf", "--ink:#2a1a10", "--focus:#c9a87a", "--idle:#6b4e36"} {
		if !strings.Contains(s, tok) {
			t.Errorf("missing theme token %s", tok)
		}
	}
	// tabs are cwm groups bound to keys 1-9
	for i := 1; i <= 9; i++ {
		if !strings.Contains(s, fmt.Sprintf(`data-key="%d"`, i)) {
			t.Errorf("missing group key %d", i)
		}
	}
	if !strings.Contains(s, `id="fPrompt"`) || !strings.Contains(s, "»") || !strings.Contains(s, "«") {
		t.Errorf("findings search is not a cwm » prompt «")
	}
	if strings.Contains(s, "border-radius") || strings.Contains(s, "box-shadow") || strings.Contains(s, "themeBtn") {
		t.Errorf("modern chrome left over (rounded corners, shadows or theme toggle)")
	}
}

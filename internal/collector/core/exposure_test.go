package core

import (
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/graph"
)

func TestIsPublicSource(t *testing.T) {
	cases := map[string]bool{
		"0.0.0.0/0": true, "::/0": true, "*": true, "Internet": true, "203.0.113.0/24": true, "198.51.100.7": true, "52.0.0.0/16": true,
		"10.0.0.0/8": false, "172.16.4.0/24": false, "192.168.1.1/32": false, "127.0.0.1": false, "169.254.0.0/16": false,
		"100.64.0.0/10": false, "fd00::/8": false, "VirtualNetwork": false, "sg-123": false, "": false,
	}
	for in, want := range cases {
		if got := IsPublicSource(in); got != want {
			t.Errorf("IsPublicSource(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestExposureWidth(t *testing.T) {
	trusted := []string{"203.0.113.0/24", "2001:db8::/32"}
	cases := []struct {
		name    string
		sources []string
		want    string
	}{
		{"ipv4 any", []string{"0.0.0.0/0"}, ExposureWide},
		{"ipv6 any", []string{"::/0"}, ExposureWide},
		{"azure star", []string{"*"}, ExposureWide},
		{"wide beats trusted", []string{"203.0.113.0/24", "0.0.0.0/0"}, ExposureWide},
		{"public /16", []string{"52.10.0.0/16"}, ExposureNarrow},
		{"bare public ip", []string{"198.51.100.7"}, ExposureNarrow},
		{"trusted subnet", []string{"203.0.113.128/25"}, ExposureTrusted},
		{"trusted ip and v6", []string{"203.0.113.9", "2001:db8:1::/48"}, ExposureTrusted},
		{"partly trusted is narrow", []string{"203.0.113.0/24", "198.51.100.0/24"}, ExposureNarrow},
		{"supernet of trusted is narrow", []string{"203.0.112.0/23"}, ExposureNarrow},
		{"no sources means wide", nil, ExposureWide},
	}
	for _, tc := range cases {
		if got := ExposureWidth(tc.sources, trusted); got != tc.want {
			t.Errorf("%s: ExposureWidth(%v) = %q, want %q", tc.name, tc.sources, got, tc.want)
		}
	}
	if got := ExposureWidth([]string{"203.0.113.0/24"}, nil); got != ExposureNarrow {
		t.Errorf("no trusted list: got %q, want narrow", got)
	}
}

func TestExposeMergesWidestOnEdgeAndNode(t *testing.T) {
	g := graph.New()
	g.AddNode(&graph.Node{ID: "vm1", Type: "aws_instance"})
	trusted := []string{"203.0.113.0/24"}
	Expose(g, "vm1", map[string]any{"via": "sg-a"}, []string{"203.0.113.0/24"}, trusted)
	e := exposesEdge(g, "vm1")
	if e == nil || e.Attr[AttrExposure] != ExposureTrusted || e.Attr["via"] != "sg-a" {
		t.Fatalf("trusted-only edge = %+v", e)
	}
	if e.Attr[AttrExposureReason] == nil {
		t.Error("trusted exposure must carry exposure_reason")
	}
	n, _ := g.Node("vm1")
	if n.Attributes[AttrExposure] != ExposureTrusted {
		t.Fatalf("node exposure = %v", n.Attributes[AttrExposure])
	}
	// A second rule opening to a public /16 widens both edge and node to narrow; sources union.
	Expose(g, "vm1", map[string]any{"via": "sg-b"}, []string{"52.10.0.0/16"}, trusted)
	e = exposesEdge(g, "vm1")
	if e.Attr[AttrExposure] != ExposureNarrow {
		t.Fatalf("edge exposure = %v, want narrow", e.Attr[AttrExposure])
	}
	cidrs, _ := e.Attr[AttrExposureCIDRs].([]string)
	if len(cidrs) != 2 {
		t.Fatalf("exposure_cidrs = %v", e.Attr[AttrExposureCIDRs])
	}
	if _, ok := e.Attr[AttrExposureReason]; ok {
		t.Error("exposure_reason must be cleared once not trusted")
	}
	Expose(g, "vm1", nil, []string{"0.0.0.0/0"}, trusted)
	n, _ = g.Node("vm1")
	if n.Attributes[AttrExposure] != ExposureWide || exposesEdge(g, "vm1").Attr[AttrExposure] != ExposureWide {
		t.Fatalf("node/edge should be wide: %v", n.Attributes)
	}
	if n.Type != "aws_instance" {
		t.Errorf("node type clobbered: %q", n.Type)
	}
	// Only one exposes edge exists.
	count := 0
	for _, e := range g.Out(graph.InternetNodeID) {
		if e.To == "vm1" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("exposes edges = %d", count)
	}
}

func exposesEdge(g *graph.Graph, to string) *graph.Edge {
	for _, e := range g.Out(graph.InternetNodeID) {
		if e.To == to && e.Kind == graph.EdgeExposes {
			return e
		}
	}
	return nil
}

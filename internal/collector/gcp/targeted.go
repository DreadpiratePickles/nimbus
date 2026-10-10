package gcp

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	compute "google.golang.org/api/compute/v1"

	"github.com/DreadpiratePickles/nimbus/internal/collector/core"
	"github.com/DreadpiratePickles/nimbus/internal/graph"
)

// Targeted re-collection (plan v3 RM4, W7-VERIFY r5 #6): `cloud-posture verify` re-reads the
// firewall rules, instances and Cloud Storage buckets of one Issue through the same builder as
// Collect and returns the findings and graph fragment of the anchors plus their one-hop
// neighbours. A firewall rule or an instance needs the project's instances and firewall rules
// (a rule's exposure verdict depends on every rule of the network: priorities and shadowing
// denies), but only the anchor and what is one hop from it is returned; a bucket needs only the
// bucket listing and its IAM policy. A failed listing, or a bucket whose IAM policy cannot be
// read, is a partial error: the read is inconclusive, never a confirmation or a deletion.

type gcpRef struct{ id, kind, project, zone, name string } // kind: firewall | instance | bucket

// parseGCPTarget classifies a GCP resource id (a compute self link or the storage full resource
// name the collector emits); ok=false for a type this collector cannot target yet.
func parseGCPTarget(id string) (gcpRef, bool) {
	if strings.HasPrefix(id, "//storage.googleapis.com/projects/_/buckets/") {
		name := strings.TrimPrefix(id, "//storage.googleapis.com/projects/_/buckets/")
		if name == "" || strings.Contains(name, "/") {
			return gcpRef{}, false
		}
		return gcpRef{id: id, kind: "bucket", name: name}, true
	}
	i := strings.Index(id, "/projects/")
	if i < 0 || !strings.Contains(id[:i], "compute") {
		return gcpRef{}, false
	}
	parts := strings.Split(strings.TrimPrefix(id[i:], "/"), "/")
	switch {
	case len(parts) == 5 && parts[2] == "global" && parts[3] == "firewalls" && parts[1] != "" && parts[4] != "":
		return gcpRef{id: id, kind: "firewall", project: parts[1], name: parts[4]}, true
	case len(parts) == 6 && parts[2] == "zones" && parts[4] == "instances" && parts[1] != "" && parts[3] != "" && parts[5] != "":
		return gcpRef{id: id, kind: "instance", project: parts[1], zone: parts[3], name: parts[5]}, true
	}
	return gcpRef{}, false
}

// Target implements core.Targeted. Only client construction failures are fatal.
func (c *Collector) Target(ctx context.Context, spec core.AccountSpec, ids []string) (*core.TargetResult, error) {
	out := &core.TargetResult{Graph: graph.New()}
	byProject := map[string][]gcpRef{}
	for _, id := range ids {
		r, ok := parseGCPTarget(id)
		if !ok {
			out.Unsupported = append(out.Unsupported, id)
			continue
		}
		if r.project == "" {
			r.project = spec.ProjectID // buckets: the configured project lists them
		}
		if r.project == "" {
			out.Unsupported = append(out.Unsupported, id)
			continue
		}
		byProject[r.project] = append(byProject[r.project], r)
	}
	if len(byProject) == 0 {
		return out, nil
	}
	newClients := c.NewClients
	if newClients == nil {
		newClients = NewClients
	}
	cl, err := newClients(ctx, spec)
	if err != nil {
		return nil, fmt.Errorf("gcp clients: %w", err)
	}
	defer cl.Close()
	now := time.Now
	if c.Now != nil {
		now = c.Now
	}
	for _, project := range core.SortedKeys(byProject) {
		c.targetProject(ctx, spec, cl, project, byProject[project], now(), out)
	}
	return out, nil
}

func (c *Collector) targetProject(ctx context.Context, spec core.AccountSpec, cl *Clients, project string, refs []gcpRef, now time.Time, out *core.TargetResult) {
	acc := &core.Acc{}
	inv := &inventory{}
	needCompute, needStorage := false, false
	for _, r := range refs {
		if r.kind == "bucket" {
			needStorage = true
		} else {
			needCompute = true
		}
	}
	listed := map[string]bool{} // compute | storage
	pfx := "gcp/" + project + "/"
	if needCompute {
		ok := true
		if cl.Compute == nil {
			ok = false
			acc.Error(pfx+"compute", errors.New("no compute client"))
		} else {
			var err error
			if inv.instances, err = cl.Compute.Instances(ctx, project); err != nil {
				ok = false
				acc.Error(pfx+"compute.instances", err)
			}
			if inv.firewalls, err = cl.Compute.Firewalls(ctx, project); err != nil {
				ok = false
				acc.Error(pfx+"compute.firewalls", err)
			}
		}
		listed["compute"] = ok
	}
	badPolicy := map[string]bool{}
	if needStorage {
		want := map[string]bool{}
		for _, r := range refs {
			if r.kind == "bucket" {
				want[r.name] = true
			}
		}
		if cl.Storage == nil {
			acc.Error(pfx+"storage", errors.New("no storage client"))
		} else if bs, err := cl.Storage.Buckets(ctx, project); err != nil {
			acc.Error(pfx+"storage", err)
		} else {
			listed["storage"] = true
			for _, b := range bs {
				if !want[b.Name] {
					continue // other buckets are neither anchors nor one hop away
				}
				if b.PolicyErr != nil {
					// The public verdict depends on the IAM policy: no verdict either way.
					acc.Error(pfx+"storage.getIamPolicy/"+b.Name, b.PolicyErr)
					badPolicy[b.Name] = true
				}
				inv.buckets = append(inv.buckets, b)
			}
		}
	}
	g := graph.New()
	b := &builder{g: g, acc: acc, spec: spec, project: project, now: now}
	b.build(inv)

	have := map[string]string{} // match key -> graph id
	for _, fw := range inv.firewalls {
		have["firewall|"+fw.Name] = fwID(project, fw)
	}
	for _, in := range inv.instances {
		id := in.SelfLink
		zone := lastSegment(in.Zone)
		if id == "" {
			id = fmt.Sprintf("https://www.googleapis.com/compute/v1/projects/%s/zones/%s/instances/%s", project, zone, in.Name)
		}
		have["instance|"+zone+"|"+in.Name] = id
	}
	for _, bk := range inv.buckets {
		have["bucket|"+bk.Name] = BucketID(bk.Name)
	}
	var anchors []string
	for _, r := range refs {
		kind := "compute"
		if r.kind == "bucket" {
			kind = "storage"
		}
		if !listed[kind] {
			continue // a failed listing proves nothing either way
		}
		k := r.kind + "|" + r.name
		if r.kind == "instance" {
			k = "instance|" + r.zone + "|" + r.name
		}
		if gid, ok := have[k]; ok {
			anchors = append(anchors, gid)
			if !badPolicy[r.name] || r.kind != "bucket" {
				out.Observed = append(out.Observed, r.id)
			}
		} else {
			out.Missing = append(out.Missing, r.id)
		}
	}
	keep := core.OneHop(g, anchors)
	res := acc.Result()
	for _, f := range res.Findings {
		if keep[f.Resource.ID] {
			out.Findings = append(out.Findings, f)
		}
	}
	out.Graph.Merge(core.Subgraph(g, keep))
	for _, e := range res.Errors {
		out.Errors = append(out.Errors, fmt.Errorf("gcp %s: %w", project, e))
	}
	out.Warnings = append(out.Warnings, res.Warnings...)
}

// compile-time: the compute types the builder consumes are the ones listed here.
var _ = (*compute.Firewall)(nil)

package gcp

import (
	"context"
	"errors"
	"fmt"
	"time"

	"cloud.google.com/go/storage"
	"github.com/DreadpiratePickles/nimbus/internal/collector/core"
	crm "google.golang.org/api/cloudresourcemanager/v1"
	compute "google.golang.org/api/compute/v1"
	iamv1 "google.golang.org/api/iam/v1"
	"google.golang.org/api/iterator"
	sqladmin "google.golang.org/api/sqladmin/v1"
)

// ComputeAPI is the narrow Compute Engine surface the collector reads.
type ComputeAPI interface {
	Instances(ctx context.Context, project string) ([]*compute.Instance, error)
	Firewalls(ctx context.Context, project string) ([]*compute.Firewall, error)
	Disks(ctx context.Context, project string) ([]*compute.Disk, error)
	Addresses(ctx context.Context, project string) ([]*compute.Address, error)
}

// BucketInfo is the security-relevant view of a Cloud Storage bucket.
type BucketInfo struct {
	Name     string
	Location string
	Labels   map[string]string
	Created  time.Time
	// Members are every principal in the bucket IAM policy (any role).
	Members                []string
	PublicAccessPrevention string // "enforced" | "inherited" | ""
	UniformAccess          bool
	// PolicyErr is set when the IAM policy could not be read.
	PolicyErr error
}

// StorageAPI lists buckets with their IAM members.
type StorageAPI interface {
	Buckets(ctx context.Context, project string) ([]BucketInfo, error)
}

// SQLAPI lists Cloud SQL instances.
type SQLAPI interface {
	Instances(ctx context.Context, project string) ([]*sqladmin.DatabaseInstance, error)
}

// ProjectInfo is the subset of the resource-manager project the graph uses.
type ProjectInfo struct {
	ID     string
	Number int64
	Name   string
	Labels map[string]string
}

// ProjectAPI reads project metadata.
type ProjectAPI interface {
	Project(ctx context.Context, project string) (*ProjectInfo, error)
}

// IAMAPI lists service accounts.
type IAMAPI interface {
	ServiceAccounts(ctx context.Context, project string) ([]*iamv1.ServiceAccount, error)
}

// Clients groups the per-service clients; nil members are skipped.
type Clients struct {
	Compute  ComputeAPI
	Storage  StorageAPI
	SQL      SQLAPI
	Projects ProjectAPI
	IAM      IAMAPI
	closers  []func() error
}

// Close releases underlying SDK clients.
func (c *Clients) Close() error {
	var errs []error
	for _, f := range c.closers {
		errs = append(errs, f())
	}
	return errors.Join(errs...)
}

// NewClients builds SDK-backed clients using core.GCPOptions (ADC or a key file).
func NewClients(ctx context.Context, spec core.AccountSpec) (*Clients, error) {
	opts := core.GCPOptions(spec)
	cs := &Clients{}
	csvc, err := compute.NewService(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("compute client: %w", err)
	}
	cs.Compute = &computeClient{svc: csvc}
	sc, err := storage.NewClient(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("storage client: %w", err)
	}
	cs.Storage = &storageClient{c: sc}
	cs.closers = append(cs.closers, sc.Close)
	sq, err := sqladmin.NewService(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("sqladmin client: %w", err)
	}
	cs.SQL = &sqlClient{svc: sq}
	rm, err := crm.NewService(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("resourcemanager client: %w", err)
	}
	cs.Projects = &projectClient{svc: rm}
	is, err := iamv1.NewService(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("iam client: %w", err)
	}
	cs.IAM = &iamClient{svc: is}
	return cs, nil
}

type computeClient struct{ svc *compute.Service }

func (c *computeClient) Instances(ctx context.Context, project string) ([]*compute.Instance, error) {
	var out []*compute.Instance
	err := c.svc.Instances.AggregatedList(project).Context(ctx).Pages(ctx, func(l *compute.InstanceAggregatedList) error {
		for _, k := range sortedScopes(l.Items) {
			out = append(out, l.Items[k].Instances...)
		}
		return nil
	})
	return out, err
}

func (c *computeClient) Firewalls(ctx context.Context, project string) ([]*compute.Firewall, error) {
	var out []*compute.Firewall
	err := c.svc.Firewalls.List(project).Context(ctx).Pages(ctx, func(l *compute.FirewallList) error {
		out = append(out, l.Items...)
		return nil
	})
	return out, err
}

func (c *computeClient) Disks(ctx context.Context, project string) ([]*compute.Disk, error) {
	var out []*compute.Disk
	err := c.svc.Disks.AggregatedList(project).Context(ctx).Pages(ctx, func(l *compute.DiskAggregatedList) error {
		for _, k := range sortedScopes(l.Items) {
			out = append(out, l.Items[k].Disks...)
		}
		return nil
	})
	return out, err
}

func (c *computeClient) Addresses(ctx context.Context, project string) ([]*compute.Address, error) {
	var out []*compute.Address
	err := c.svc.Addresses.AggregatedList(project).Context(ctx).Pages(ctx, func(l *compute.AddressAggregatedList) error {
		for _, k := range sortedScopes(l.Items) {
			out = append(out, l.Items[k].Addresses...)
		}
		return nil
	})
	return out, err
}

func sortedScopes[V any](m map[string]V) []string { return core.SortedKeys(m) }

type storageClient struct{ c *storage.Client }

func (s *storageClient) Buckets(ctx context.Context, project string) ([]BucketInfo, error) {
	var out []BucketInfo
	it := s.c.Buckets(ctx, project)
	for {
		a, err := it.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			return out, err
		}
		b := BucketInfo{Name: a.Name, Location: a.Location, Labels: a.Labels, Created: a.Created,
			UniformAccess: a.UniformBucketLevelAccess.Enabled}
		if a.PublicAccessPrevention == storage.PublicAccessPreventionEnforced {
			b.PublicAccessPrevention = "enforced"
		} else if a.PublicAccessPrevention == storage.PublicAccessPreventionInherited {
			b.PublicAccessPrevention = "inherited"
		}
		pol, err := s.c.Bucket(a.Name).IAM().Policy(ctx)
		if err != nil {
			b.PolicyErr = err
		} else {
			for _, r := range pol.Roles() {
				b.Members = append(b.Members, pol.Members(r)...)
			}
		}
		out = append(out, b)
	}
	return out, nil
}

type sqlClient struct{ svc *sqladmin.Service }

func (s *sqlClient) Instances(ctx context.Context, project string) ([]*sqladmin.DatabaseInstance, error) {
	var out []*sqladmin.DatabaseInstance
	err := s.svc.Instances.List(project).Context(ctx).Pages(ctx, func(r *sqladmin.InstancesListResponse) error {
		out = append(out, r.Items...)
		return nil
	})
	return out, err
}

type projectClient struct{ svc *crm.Service }

func (p *projectClient) Project(ctx context.Context, project string) (*ProjectInfo, error) {
	pr, err := p.svc.Projects.Get(project).Context(ctx).Do()
	if err != nil {
		return nil, err
	}
	return &ProjectInfo{ID: pr.ProjectId, Number: pr.ProjectNumber, Name: pr.Name, Labels: pr.Labels}, nil
}

type iamClient struct{ svc *iamv1.Service }

func (i *iamClient) ServiceAccounts(ctx context.Context, project string) ([]*iamv1.ServiceAccount, error) {
	var out []*iamv1.ServiceAccount
	err := i.svc.Projects.ServiceAccounts.List("projects/"+project).Context(ctx).Pages(ctx, func(r *iamv1.ListServiceAccountsResponse) error {
		out = append(out, r.Accounts...)
		return nil
	})
	return out, err
}

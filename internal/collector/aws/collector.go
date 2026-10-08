// Package aws is the agentless AWS collector: EC2, S3, IAM (authorization details,
// credential report, policy documents), RDS, Lambda, EKS, Secrets Manager, KMS,
// CloudTrail, CloudWatch utilisation and Cost Explorer spend. It builds the
// security graph (Cartography-style relationships) and emits Prowler-aliased findings.
package aws

import (
	"context"
	"errors"
	"fmt"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/DreadpiratePickles/nimbus/internal/collector/core"
	"github.com/DreadpiratePickles/nimbus/internal/graph"
	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// Collector implements core.Collector for AWS.
type Collector struct {
	NewClients ClientFactory
	// Concurrency bounds regions in flight and services per region (default 8).
	Concurrency int
	Now         func() time.Time
	// CPULookback is the CloudWatch window for idle/oversized detection (default 14 days).
	CPULookback time.Duration
	// CredentialReportPoll is the wait between GenerateCredentialReport polls (default 2s).
	CredentialReportPoll time.Duration
	// SkipMetrics disables CloudWatch and Cost Explorer calls.
	SkipMetrics bool
}

// New returns a collector backed by the real SDK clients.
func New() *Collector { return &Collector{NewClients: SDKClientFactory()} }

func (c *Collector) Name() string     { return "aws" }
func (c *Collector) Provider() string { return model.ProviderAWS }

func (c *Collector) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now().UTC()
}

// Collect gathers one AWS account. Only credential / identity failures are fatal;
// every service or region failure is recorded in Result.Errors.
func (c *Collector) Collect(ctx context.Context, spec core.AccountSpec, g *graph.Graph) (core.Result, error) {
	if c.NewClients == nil {
		c.NewClients = SDKClientFactory()
	}
	limit := c.Concurrency
	if limit <= 0 {
		limit = 8
	}
	lookback := c.CPULookback
	if lookback <= 0 {
		lookback = 14 * 24 * time.Hour
	}
	poll := c.CredentialReportPoll
	if poll <= 0 {
		poll = 2 * time.Second
	}
	now := c.now()
	home := core.DefaultAWSRegion
	if len(spec.Regions) > 0 && spec.Regions[0] != "" {
		home = spec.Regions[0]
	}
	hc, err := c.NewClients(ctx, spec, home)
	if err != nil {
		return core.Result{}, fmt.Errorf("aws %s: credentials: %w", spec.Label(), err)
	}
	ident, err := hc.STS.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return core.Result{}, fmt.Errorf("aws %s: sts:GetCallerIdentity: %w", spec.Label(), err)
	}
	inv := &inventory{account: awssdk.ToString(ident.Account), cpu: map[string]float64{}, egress: map[string]float64{}}
	acc := &core.Acc{}

	regions := spec.Regions
	if len(regions) == 0 {
		regions, err = enabledRegions(ctx, hc.EC2)
		if err != nil || len(regions) == 0 {
			acc.Warn("aws %s: region discovery failed (%v); scanning %s only", inv.account, err, home)
			regions = []string{home}
		}
	}

	tasks := []core.Task{
		{Name: "iam", Fn: func(ctx context.Context) error { return fetchIAM(ctx, hc.IAM, inv) }},
		{Name: "iam:summary", Fn: func(ctx context.Context) error { return fetchAccountSummary(ctx, hc.IAM, inv) }},
		{Name: "iam:credential-report", Fn: func(ctx context.Context) error { return fetchCredentialReport(ctx, hc.IAM, inv, poll) }},
		{Name: "s3", Fn: func(ctx context.Context) error { return fetchS3(ctx, hc.S3, inv, limit*2) }},
		{Name: "cloudtrail", Fn: func(ctx context.Context) error { return fetchCloudTrail(ctx, hc.CloudTrail, inv) }},
	}
	if !c.SkipMetrics {
		tasks = append(tasks, core.Task{Name: "costexplorer", Fn: func(ctx context.Context) error {
			if err := fetchSpend(ctx, hc.CostExplorer, inv, now); err != nil {
				// Cost data is optional: never a collection failure.
				acc.Warn("aws %s: cost explorer unavailable: %v", inv.account, err)
			}
			return nil
		}})
	}
	for _, region := range regions {
		tasks = append(tasks, core.Task{Name: "region:" + region, Fn: func(ctx context.Context) error {
			rc := hc
			if region != home {
				var err error
				if rc, err = c.NewClients(ctx, spec, region); err != nil {
					return err
				}
			}
			services := []core.Task{
				{Name: region + ":ec2", Fn: func(ctx context.Context) error {
					err := fetchEC2(ctx, rc.EC2, region, inv)
					if !c.SkipMetrics && rc.CloudWatch != nil {
						if merr := fetchMetrics(ctx, rc.CloudWatch, region, inv, lookback, now); merr != nil {
							acc.Warn("aws %s %s: cloudwatch metrics: %v", inv.account, region, merr)
						}
					}
					return err
				}},
				{Name: region + ":rds", Fn: func(ctx context.Context) error { return fetchRDS(ctx, rc.RDS, region, inv) }},
				{Name: region + ":lambda", Fn: func(ctx context.Context) error { return fetchLambda(ctx, rc.Lambda, region, inv) }},
				{Name: region + ":eks", Fn: func(ctx context.Context) error { return fetchEKS(ctx, rc.EKS, region, inv) }},
				{Name: region + ":secretsmanager", Fn: func(ctx context.Context) error { return fetchSecrets(ctx, rc.Secrets, region, inv) }},
				{Name: region + ":kms", Fn: func(ctx context.Context) error { return fetchKMS(ctx, rc.KMS, region, inv) }},
			}
			core.RunTasks(ctx, limit, acc, services)
			return nil
		}})
	}
	core.RunTasks(ctx, limit, acc, tasks)

	findings, cost := analyze(inv, spec, g, now)
	acc.Finding(findings...)
	acc.Cost(cost...)
	res := acc.Result()
	for i, e := range res.Errors {
		res.Errors[i] = fmt.Errorf("aws %s: %w", inv.account, e)
	}
	return res, nil
}

func enabledRegions(ctx context.Context, c EC2API) ([]string, error) {
	out, err := c.DescribeRegions(ctx, &ec2.DescribeRegionsInput{AllRegions: awssdk.Bool(false)})
	if err != nil {
		return nil, err
	}
	var regions []string
	for _, r := range out.Regions {
		if name := awssdk.ToString(r.RegionName); name != "" {
			regions = append(regions, name)
		}
	}
	if len(regions) == 0 {
		return nil, errors.New("no regions returned")
	}
	return regions, nil
}

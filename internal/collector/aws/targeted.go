package aws

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	ekstypes "github.com/aws/aws-sdk-go-v2/service/eks/types"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	smtypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/DreadpiratePickles/nimbus/internal/collector/core"
	"github.com/DreadpiratePickles/nimbus/internal/graph"
)

// Targeted re-collection (plan v3 RM4): `cloud-posture verify` re-reads only the resources of
// one Issue — S3 buckets (Block Public Access, policy status, ACL), EC2 instances, security
// groups, IAM roles and users (MFA, access keys, group / policy attachments from the credential
// report and authorization details), RDS instances, Lambda functions (URL auth type, resource
// policy, execution role) and EKS clusters (endpoint access) — through the same fetch / analyze
// code paths as Collect, and returns the findings and graph fragment of the anchors plus their
// one-hop neighbours (an instance brings its security groups and role, a security group the
// instances it guards, a bucket the identities granted access to it, a database / function /
// cluster its security groups and role, a user its groups and policies), Secrets Manager secrets
// (resource policy) and KMS customer keys (rotation, key policy) with the identities granted
// access to them (W7-VERIFY r5 #6).

// targetRef is one requested id, classified.
type targetRef struct {
	id, kind, region, name string // kind: bucket | instance | sg | role | user | db | function | cluster | secret | key
}

// parseTarget understands the ARNs the collector itself emits (and bare i-/sg- ids in the
// home region). ok=false: a resource type this collector cannot target yet.
func parseTarget(id, home string) (targetRef, bool) {
	switch {
	case strings.HasPrefix(id, "arn:aws:s3:::") && !strings.Contains(strings.TrimPrefix(id, "arn:aws:s3:::"), "/"):
		return targetRef{id: id, kind: "bucket", name: strings.TrimPrefix(id, "arn:aws:s3:::")}, true
	case strings.HasPrefix(id, "arn:aws:iam::") && strings.Contains(id, ":role/"):
		return targetRef{id: id, kind: "role", name: id}, true
	case strings.HasPrefix(id, "arn:aws:iam::") && strings.Contains(id, ":user/"):
		return targetRef{id: id, kind: "user", name: id[strings.LastIndex(id, "/")+1:]}, true
	case strings.HasPrefix(id, "arn:aws:rds:"):
		// arn:aws:rds:<region>:<account>:db:<identifier>
		parts := strings.SplitN(id, ":", 7)
		if len(parts) == 7 && parts[5] == "db" && parts[6] != "" {
			return targetRef{id: id, kind: "db", region: parts[3], name: parts[6]}, true
		}
		return targetRef{}, false
	case strings.HasPrefix(id, "arn:aws:lambda:"):
		// arn:aws:lambda:<region>:<account>:function:<name>[:<qualifier>]
		parts := strings.SplitN(id, ":", 8)
		if len(parts) >= 7 && parts[5] == "function" && parts[6] != "" {
			return targetRef{id: id, kind: "function", region: parts[3], name: parts[6]}, true
		}
		return targetRef{}, false
	case strings.HasPrefix(id, "arn:aws:eks:"):
		// arn:aws:eks:<region>:<account>:cluster/<name>
		parts := strings.SplitN(id, ":", 6)
		if len(parts) == 6 && strings.HasPrefix(parts[5], "cluster/") && len(parts[5]) > len("cluster/") {
			return targetRef{id: id, kind: "cluster", region: parts[3], name: strings.TrimPrefix(parts[5], "cluster/")}, true
		}
		return targetRef{}, false
	case strings.HasPrefix(id, "arn:aws:secretsmanager:"):
		// arn:aws:secretsmanager:<region>:<account>:secret:<name-suffix>
		parts := strings.SplitN(id, ":", 7)
		if len(parts) == 7 && parts[5] == "secret" && parts[6] != "" {
			return targetRef{id: id, kind: "secret", region: parts[3], name: parts[6]}, true
		}
		return targetRef{}, false
	case strings.HasPrefix(id, "arn:aws:kms:"):
		// arn:aws:kms:<region>:<account>:key/<key-id>
		parts := strings.SplitN(id, ":", 6)
		if len(parts) == 6 && strings.HasPrefix(parts[5], "key/") && len(parts[5]) > len("key/") {
			return targetRef{id: id, kind: "key", region: parts[3], name: strings.TrimPrefix(parts[5], "key/")}, true
		}
		return targetRef{}, false
	case strings.HasPrefix(id, "arn:aws:ec2:"):
		parts := strings.SplitN(id, ":", 6)
		if len(parts) != 6 {
			return targetRef{}, false
		}
		res := parts[5]
		switch {
		case strings.HasPrefix(res, "instance/"):
			return targetRef{id: id, kind: "instance", region: parts[3], name: strings.TrimPrefix(res, "instance/")}, true
		case strings.HasPrefix(res, "security-group/"):
			return targetRef{id: id, kind: "sg", region: parts[3], name: strings.TrimPrefix(res, "security-group/")}, true
		}
	case strings.HasPrefix(id, "i-"):
		return targetRef{id: id, kind: "instance", region: home, name: id}, true
	case strings.HasPrefix(id, "sg-"):
		return targetRef{id: id, kind: "sg", region: home, name: id}, true
	}
	return targetRef{}, false
}

// Target implements core.Targeted. Only credential / identity failures are fatal; a failed
// service call is a partial error (the read is then inconclusive, never a confirmation).
func (c *Collector) Target(ctx context.Context, spec core.AccountSpec, ids []string) (*core.TargetResult, error) {
	if c.NewClients == nil {
		c.NewClients = SDKClientFactory()
	}
	home := core.DefaultAWSRegion
	if len(spec.Regions) > 0 && spec.Regions[0] != "" {
		home = spec.Regions[0]
	}
	out := &core.TargetResult{}
	var refs []targetRef
	for _, id := range ids {
		if r, ok := parseTarget(id, home); ok {
			refs = append(refs, r)
		} else {
			out.Unsupported = append(out.Unsupported, id)
		}
	}
	hc, err := c.NewClients(ctx, spec, home)
	if err != nil {
		return nil, fmt.Errorf("aws %s: credentials: %w", spec.Label(), err)
	}
	ident, err := hc.STS.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return nil, fmt.Errorf("aws %s: sts:GetCallerIdentity: %w", spec.Label(), err)
	}
	inv := &inventory{account: awssdk.ToString(ident.Account), cpu: map[string]float64{}, egress: map[string]float64{}}
	acc := &core.Acc{}

	var buckets []targetRef
	regionInst, regionSG := map[string][]targetRef{}, map[string][]targetRef{}
	regionDB, regionFn, regionEKS := map[string][]targetRef{}, map[string][]targetRef{}, map[string][]targetRef{}
	regionSecret, regionKey := map[string][]targetRef{}, map[string][]targetRef{}
	needIAM, needCreds := false, false
	for _, r := range refs {
		switch r.kind {
		case "bucket":
			buckets = append(buckets, r)
			needIAM = true // identities granted access to the bucket are one hop away
		case "instance":
			regionInst[r.region] = append(regionInst[r.region], r)
			needIAM = true // instance profile -> role
		case "sg":
			regionSG[r.region] = append(regionSG[r.region], r)
			needIAM = true // the instances it guards bring their roles
		case "role":
			needIAM = true
		case "user":
			needIAM, needCreds = true, true // groups / policies, and MFA / keys from the credential report
		case "db":
			regionDB[r.region] = append(regionDB[r.region], r)
			needIAM = true // identities granted rds access
		case "function":
			regionFn[r.region] = append(regionFn[r.region], r)
			needIAM = true // execution role
		case "cluster":
			regionEKS[r.region] = append(regionEKS[r.region], r)
			needIAM = true // cluster role
		case "secret":
			regionSecret[r.region] = append(regionSecret[r.region], r)
			needIAM = true // identities granted secretsmanager access
		case "key":
			regionKey[r.region] = append(regionKey[r.region], r)
			needIAM = true // identities granted kms access
		}
	}
	found := map[string]bool{}
	missing := map[string]bool{}
	iamOK := false
	if needIAM {
		if err := fetchIAM(ctx, hc.IAM, inv); err != nil {
			acc.Error("iam", err)
		} else {
			iamOK = true
		}
	}
	credsOK := false
	if needCreds {
		poll := c.CredentialReportPoll
		if poll <= 0 {
			poll = 2 * time.Second
		}
		if err := fetchCredentialReport(ctx, hc.IAM, inv, poll); err != nil {
			acc.Error("iam:credential-report", err)
		} else {
			credsOK = true
		}
	}
	if len(buckets) > 0 {
		if err := fetchAccountPAB(ctx, hc.S3Control, inv); err != nil {
			acc.Error("s3control:account-public-access-block", err)
		}
		if err := targetBuckets(ctx, hc.S3, inv, buckets, found, missing); err != nil {
			acc.Error("s3", err)
		}
	}
	regions := map[string]bool{}
	for _, m := range []map[string][]targetRef{regionInst, regionSG, regionDB, regionFn, regionEKS, regionSecret, regionKey} {
		for r := range m {
			regions[r] = true
		}
	}
	for _, region := range sortedSet(regions) {
		rc := hc
		if region != home {
			if rc, err = c.NewClients(ctx, spec, region); err != nil {
				acc.Error(region+":clients", err)
				continue
			}
		}
		// Databases, functions and clusters first: their security groups are one hop away and
		// are read with the requested ones.
		var extraSGs []string
		if len(regionDB[region]) > 0 {
			sgs, err := targetRDS(ctx, rc.RDS, region, inv, regionDB[region], found, missing)
			if err != nil {
				acc.Error(region+":rds", err)
			}
			extraSGs = append(extraSGs, sgs...)
		}
		if len(regionFn[region]) > 0 {
			sgs, err := targetLambda(ctx, rc.Lambda, region, inv, regionFn[region], found, missing)
			if err != nil {
				acc.Error(region+":lambda", err)
			}
			extraSGs = append(extraSGs, sgs...)
		}
		if len(regionEKS[region]) > 0 {
			sgs, err := targetEKS(ctx, rc.EKS, region, inv, regionEKS[region], found, missing)
			if err != nil {
				acc.Error(region+":eks", err)
			}
			extraSGs = append(extraSGs, sgs...)
		}
		if len(regionSecret[region]) > 0 {
			if err := targetSecrets(ctx, rc.Secrets, region, inv, regionSecret[region], found, missing); err != nil {
				acc.Error(region+":secretsmanager", err)
			}
		}
		if len(regionKey[region]) > 0 {
			if err := targetKMS(ctx, rc.KMS, region, inv, regionKey[region], found, missing); err != nil {
				acc.Error(region+":kms", err)
			}
		}
		if len(regionInst[region])+len(regionSG[region])+len(extraSGs) == 0 && len(regionSecret[region])+len(regionKey[region]) > 0 {
			continue // a secret / key read needs neither EC2 nor the network inputs
		}
		if err := targetEC2(ctx, rc.EC2, region, inv, regionInst[region], regionSG[region], extraSGs, found, missing); err != nil {
			acc.Error(region+":ec2", err)
		}
		// Reachability inputs (route tables, NACLs, subnets, ENIs) decide exposure exactly as
		// in a full scan.
		if err := fetchNetwork(ctx, rc.EC2, region, inv, acc); err != nil {
			acc.Error(region+":network", err)
		}
	}
	if iamOK {
		have := map[string]bool{}
		for _, r := range inv.roles {
			have[awssdk.ToString(r.Arn)] = true
		}
		for _, u := range inv.users {
			have[awssdk.ToString(u.Arn)] = true
		}
		for _, r := range refs {
			// A user is confirmed only when its credential report row was read too (MFA / keys);
			// a role needs the authorization details alone.
			if r.kind == "role" || (r.kind == "user" && credsOK) {
				if have[r.id] {
					found[r.id] = true
				} else {
					missing[r.id] = true
				}
			}
		}
	}

	g := graph.New()
	findings, _ := analyze(inv, spec, g, c.now())
	var observed []string
	for _, r := range refs {
		if found[r.id] {
			observed = append(observed, canonicalTargetID(r, inv.account))
		}
	}
	keep := core.OneHop(g, observed)
	for _, f := range findings {
		if keep[f.Resource.ID] {
			out.Findings = append(out.Findings, f)
		}
	}
	out.Graph = core.Subgraph(g, keep)
	res := acc.Result()
	out.Errors, out.Warnings = res.Errors, res.Warnings
	for i, e := range out.Errors {
		out.Errors[i] = fmt.Errorf("aws %s: %w", inv.account, e)
	}
	for _, r := range refs {
		if found[r.id] {
			out.Observed = append(out.Observed, r.id)
		} else if missing[r.id] {
			out.Missing = append(out.Missing, r.id)
		}
	}
	return out, nil
}

// canonicalTargetID is the graph id analyze gives the resource (bare i-/sg- ids become ARNs).
func canonicalTargetID(r targetRef, account string) string {
	switch r.kind {
	case "instance":
		return arnEC2(r.region, account, "instance", r.name)
	case "sg":
		return arnEC2(r.region, account, "security-group", r.name)
	case "function":
		// a qualified ARN (version / alias) re-reads the function itself
		return "arn:aws:lambda:" + r.region + ":" + account + ":function:" + r.name
	}
	return r.id
}

func sortedSet(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// targetBuckets lists buckets (one call) and describes only the requested ones; a bucket the
// listing does not contain was deleted.
func targetBuckets(ctx context.Context, c S3API, inv *inventory, want []targetRef, found, missing map[string]bool) error {
	byName := map[string]targetRef{}
	for _, r := range want {
		byName[r.name] = r
	}
	var list []s3types.Bucket
	p := s3.NewListBucketsPaginator(c, &s3.ListBucketsInput{MaxBuckets: awssdk.Int32(1000)})
	for p.HasMorePages() {
		out, err := p.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("ListBuckets: %w", err)
		}
		list = append(list, out.Buckets...)
	}
	var errs []error
	for _, b := range list {
		r, ok := byName[awssdk.ToString(b.Name)]
		if !ok {
			continue
		}
		found[r.id] = true
		bk, err := describeBucket(ctx, c, b)
		inv.buckets = append(inv.buckets, bk)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", r.name, err))
		}
	}
	for _, r := range want {
		if !found[r.id] {
			missing[r.id] = true
		}
	}
	return errors.Join(errs...)
}

func notFound(err error, prefix string) bool {
	return err != nil && strings.HasPrefix(apiCode(err), prefix)
}

// describeInstances returns the requested instances (by id) or, with filters, the instances
// matching them; a NotFound for a batch is retried per id so one deleted instance does not
// hide the others.
func describeInstances(ctx context.Context, c EC2API, in *ec2.DescribeInstancesInput) ([]ec2types.Instance, []string, error) {
	var out []ec2types.Instance
	p := ec2.NewDescribeInstancesPaginator(c, in)
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if notFound(err, "InvalidInstanceID") && len(in.InstanceIds) > 1 {
			var gone []string
			out = out[:0]
			for _, id := range in.InstanceIds {
				one, g, err := describeInstances(ctx, c, &ec2.DescribeInstancesInput{InstanceIds: []string{id}})
				if err != nil {
					return nil, nil, err
				}
				out = append(out, one...)
				gone = append(gone, g...)
			}
			return out, gone, nil
		}
		if notFound(err, "InvalidInstanceID") {
			return nil, in.InstanceIds, nil
		}
		if err != nil {
			return nil, nil, fmt.Errorf("DescribeInstances: %w", err)
		}
		for _, r := range page.Reservations {
			for _, i := range r.Instances {
				if i.State != nil && i.State.Name == ec2types.InstanceStateNameTerminated {
					continue
				}
				out = append(out, i)
			}
		}
	}
	return out, nil, nil
}

func describeSGs(ctx context.Context, c EC2API, ids []string) ([]ec2types.SecurityGroup, []string, error) {
	var out []ec2types.SecurityGroup
	p := ec2.NewDescribeSecurityGroupsPaginator(c, &ec2.DescribeSecurityGroupsInput{GroupIds: ids})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if notFound(err, "InvalidGroup") {
			if len(ids) == 1 {
				return nil, ids, nil
			}
			var gone []string
			out = out[:0]
			for _, id := range ids {
				one, g, err := describeSGs(ctx, c, []string{id})
				if err != nil {
					return nil, nil, err
				}
				out = append(out, one...)
				gone = append(gone, g...)
			}
			return out, gone, nil
		}
		if err != nil {
			return nil, nil, fmt.Errorf("DescribeSecurityGroups: %w", err)
		}
		out = append(out, page.SecurityGroups...)
	}
	return out, nil, nil
}

// targetEC2 reads the requested instances (and the security groups they use) and the
// requested security groups (and the instances that use them) in one region. Results are
// filtered by id again, so an API (or fake) that ignores the filter cannot widen the read.
func targetEC2(ctx context.Context, c EC2API, region string, inv *inventory, insts, sgs []targetRef, extraSGs []string, found, missing map[string]bool) error {
	var errs []error
	wantInst := map[string]targetRef{}
	var instIDs []string
	for _, r := range insts {
		wantInst[r.name] = r
		instIDs = append(instIDs, r.name)
	}
	wantSG := map[string]targetRef{}
	var sgIDs []string
	for _, r := range sgs {
		wantSG[r.name] = r
		sgIDs = append(sgIDs, r.name)
	}
	keepInst := map[string]ec2types.Instance{}
	if len(instIDs) > 0 {
		got, _, err := describeInstances(ctx, c, &ec2.DescribeInstancesInput{InstanceIds: instIDs})
		if err != nil {
			errs = append(errs, err)
		} else {
			for _, i := range got {
				if r, ok := wantInst[awssdk.ToString(i.InstanceId)]; ok {
					keepInst[awssdk.ToString(i.InstanceId)] = i
					found[r.id] = true
				}
			}
			for _, r := range insts {
				if !found[r.id] {
					missing[r.id] = true
				}
			}
		}
	}
	if len(sgIDs) > 0 {
		// One hop from a security group: the instances it is attached to.
		got, _, err := describeInstances(ctx, c, &ec2.DescribeInstancesInput{Filters: []ec2types.Filter{{Name: awssdk.String("instance.group-id"), Values: sgIDs}}})
		if err != nil {
			errs = append(errs, err)
		}
		for _, i := range got {
			for _, g := range i.SecurityGroups {
				if _, ok := wantSG[awssdk.ToString(g.GroupId)]; ok {
					keepInst[awssdk.ToString(i.InstanceId)] = i
				}
			}
		}
	}
	// Security groups: the requested ones plus those of every kept instance (one hop).
	sgSet := map[string]bool{}
	for _, id := range sgIDs {
		sgSet[id] = true
	}
	for _, id := range extraSGs {
		if id != "" {
			sgSet[id] = true
		}
	}
	for _, i := range keepInst {
		for _, g := range i.SecurityGroups {
			sgSet[awssdk.ToString(g.GroupId)] = true
		}
	}
	if len(sgSet) > 0 {
		all := sortedSet(sgSet)
		got, _, err := describeSGs(ctx, c, all)
		if err != nil {
			errs = append(errs, err)
		} else {
			for _, s := range got {
				gid := awssdk.ToString(s.GroupId)
				if !sgSet[gid] {
					continue
				}
				inv.sgs = append(inv.sgs, regional[ec2types.SecurityGroup]{region, s})
				if r, ok := wantSG[gid]; ok {
					found[r.id] = true
				}
			}
			for _, r := range sgs {
				if !found[r.id] {
					missing[r.id] = true
				}
			}
		}
	}
	ids := make([]string, 0, len(keepInst))
	for id := range keepInst {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		inv.instances = append(inv.instances, regional[ec2types.Instance]{region, keepInst[id]})
	}
	return errors.Join(errs...)
}

// targetRDS describes the requested DB instances by identifier (one call each, so a deleted one
// does not hide the others) and returns their security groups (one hop). Results are filtered
// by ARN again.
func targetRDS(ctx context.Context, c RDSAPI, region string, inv *inventory, want []targetRef, found, missing map[string]bool) ([]string, error) {
	if c == nil {
		return nil, errors.New("no RDS client")
	}
	var errs []error
	var sgs []string
	for _, r := range want {
		out, err := c.DescribeDBInstances(ctx, &rds.DescribeDBInstancesInput{DBInstanceIdentifier: awssdk.String(r.name)})
		if notFound(err, "DBInstanceNotFound") {
			missing[r.id] = true
			continue
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("DescribeDBInstances %s: %w", r.name, err))
			continue
		}
		hit := false
		for _, d := range out.DBInstances {
			arn := awssdk.ToString(d.DBInstanceArn)
			if arn != r.id && !(arn == "" && awssdk.ToString(d.DBInstanceIdentifier) == r.name) {
				continue // an API (or fake) that ignores the identifier cannot widen the read
			}
			d.DBInstanceArn = awssdk.String(r.id)
			hit = true
			inv.dbs = append(inv.dbs, regional[rdstypes.DBInstance]{region, d})
			for _, v := range d.VpcSecurityGroups {
				sgs = append(sgs, awssdk.ToString(v.VpcSecurityGroupId))
			}
		}
		if hit {
			found[r.id] = true
		} else {
			missing[r.id] = true
		}
	}
	return sgs, errors.Join(errs...)
}

// targetLambda lists the region's functions (one paged call; there is no batch describe that
// also returns the URL config) and reads URL config and resource policy for the requested ones
// only, exactly as fetchLambda does. Returns the functions' VPC security groups (one hop).
func targetLambda(ctx context.Context, c LambdaAPI, region string, inv *inventory, want []targetRef, found, missing map[string]bool) ([]string, error) {
	if c == nil {
		return nil, errors.New("no Lambda client")
	}
	byName := map[string]targetRef{}
	for _, r := range want {
		byName[r.name] = r
	}
	p := lambda.NewListFunctionsPaginator(c, &lambda.ListFunctionsInput{})
	var errs []error
	var sgs []string
	for p.HasMorePages() {
		out, err := p.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("ListFunctions: %w", err)
		}
		for _, fn := range out.Functions {
			r, ok := byName[awssdk.ToString(fn.FunctionName)]
			if !ok || found[r.id] {
				continue
			}
			found[r.id] = true
			rec := lambdaFn{Region: region, Fn: fn}
			up := lambda.NewListFunctionUrlConfigsPaginator(c, &lambda.ListFunctionUrlConfigsInput{FunctionName: fn.FunctionName})
			for up.HasMorePages() {
				uo, err := up.NextPage(ctx)
				if err != nil {
					errs = append(errs, fmt.Errorf("ListFunctionUrlConfigs %s: %w", r.name, err))
					break
				}
				for _, u := range uo.FunctionUrlConfigs {
					rec.URL = awssdk.ToString(u.FunctionUrl)
					rec.URLAuth = string(u.AuthType)
				}
			}
			rec.Policy, rec.PolicyStatus = "", "none"
			if pol, err := c.GetFunctionPolicy(ctx, r.name); err == nil {
				rec.Policy, rec.PolicyStatus = pol, "collected"
			} else if apiCode(err) != "ResourceNotFoundException" {
				rec.PolicyStatus = policyErrStatus(err)
				errs = append(errs, fmt.Errorf("lambda:GetPolicy %s: %w", r.name, err))
			}
			if fn.VpcConfig != nil {
				sgs = append(sgs, fn.VpcConfig.SecurityGroupIds...)
			}
			inv.functions = append(inv.functions, rec)
		}
	}
	for _, r := range want {
		if !found[r.id] {
			missing[r.id] = true
		}
	}
	return sgs, errors.Join(errs...)
}

// targetEKS describes the requested clusters by name (no ListClusters) and returns their
// security groups (one hop).
func targetEKS(ctx context.Context, c EKSAPI, region string, inv *inventory, want []targetRef, found, missing map[string]bool) ([]string, error) {
	if c == nil {
		return nil, errors.New("no EKS client")
	}
	var errs []error
	var sgs []string
	for _, r := range want {
		out, err := c.DescribeCluster(ctx, &eks.DescribeClusterInput{Name: awssdk.String(r.name)})
		if notFound(err, "ResourceNotFoundException") {
			missing[r.id] = true
			continue
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("DescribeCluster %s: %w", r.name, err))
			continue
		}
		if out.Cluster == nil || awssdk.ToString(out.Cluster.Name) != r.name {
			missing[r.id] = true
			continue
		}
		found[r.id] = true
		inv.clusters = append(inv.clusters, regional[ekstypes.Cluster]{region, *out.Cluster})
		if v := out.Cluster.ResourcesVpcConfig; v != nil {
			sgs = append(sgs, v.SecurityGroupIds...)
			if v.ClusterSecurityGroupId != nil {
				sgs = append(sgs, *v.ClusterSecurityGroupId)
			}
		}
	}
	return sgs, errors.Join(errs...)
}

// targetSecrets lists the region's secrets (ListSecrets has no batch get by ARN that also omits
// the secret value) and reads the resource policy of the requested ones only, exactly as
// fetchSecrets does. A secret the listing does not contain was deleted (ListSecrets omits
// secrets scheduled for deletion, as a full scan does); a failed policy read is a partial error.
func targetSecrets(ctx context.Context, c SecretsAPI, region string, inv *inventory, want []targetRef, found, missing map[string]bool) error {
	if c == nil {
		return errors.New("no Secrets Manager client")
	}
	byARN := map[string]targetRef{}
	for _, r := range want {
		byARN[r.id] = r
	}
	var list []smtypes.SecretListEntry
	p := secretsmanager.NewListSecretsPaginator(c, &secretsmanager.ListSecretsInput{})
	for p.HasMorePages() {
		out, err := p.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("ListSecrets: %w", err)
		}
		list = append(list, out.SecretList...)
	}
	var errs []error
	for _, sec := range list {
		arn := awssdk.ToString(sec.ARN)
		r, ok := byARN[arn]
		if !ok || found[r.id] {
			continue
		}
		found[r.id] = true
		rp, err := c.GetResourcePolicy(ctx, &secretsmanager.GetResourcePolicyInput{SecretId: sec.ARN})
		if inv.secretPolicies == nil {
			inv.secretPolicies, inv.secretPolicyErr = map[string]string{}, map[string]bool{}
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("secretsmanager:GetResourcePolicy %s: %w", arn, err))
			inv.secretPolicyErr[arn] = true
		} else {
			inv.secretPolicies[arn] = awssdk.ToString(rp.ResourcePolicy)
		}
		inv.secrets = append(inv.secrets, regional[smtypes.SecretListEntry]{region, sec})
	}
	for _, r := range want {
		if !found[r.id] {
			missing[r.id] = true
		}
	}
	return errors.Join(errs...)
}

// targetKMS describes the requested keys by id (no ListKeys) and reads rotation and the key
// policy exactly as fetchKMS does. A key that is not found, or is no longer an enabled customer
// symmetric key (pending deletion, disabled), is gone as a full scan sees it; any other failure
// is a partial error.
func targetKMS(ctx context.Context, c KMSAPI, region string, inv *inventory, want []targetRef, found, missing map[string]bool) error {
	if c == nil {
		return errors.New("no KMS client")
	}
	var errs []error
	for _, r := range want {
		d, err := c.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: awssdk.String(r.name)})
		if notFound(err, "NotFoundException") {
			missing[r.id] = true
			continue
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("DescribeKey %s: %w", r.name, err))
			continue
		}
		md := d.KeyMetadata
		if md == nil || (awssdk.ToString(md.Arn) != "" && awssdk.ToString(md.Arn) != r.id) {
			missing[r.id] = true // an API (or fake) that answers for another key cannot widen the read
			continue
		}
		if md.KeyManager != kmstypes.KeyManagerTypeCustomer || md.KeyState != kmstypes.KeyStateEnabled || md.KeySpec != kmstypes.KeySpecSymmetricDefault {
			missing[r.id] = true
			continue
		}
		rs, err := c.GetKeyRotationStatus(ctx, &kms.GetKeyRotationStatusInput{KeyId: awssdk.String(r.name)})
		if err != nil {
			errs = append(errs, fmt.Errorf("GetKeyRotationStatus %s: %w", r.name, err))
			continue
		}
		key := kmsKey{Region: region, ARN: r.id, ID: awssdk.ToString(md.KeyId), Rotation: rs.KeyRotationEnabled, PolicyStatus: "collected"}
		if kp, err := c.GetKeyPolicy(ctx, &kms.GetKeyPolicyInput{KeyId: awssdk.String(r.name), PolicyName: awssdk.String("default")}); err == nil {
			key.Policy = awssdk.ToString(kp.Policy)
		} else {
			key.PolicyStatus = policyErrStatus(err)
			errs = append(errs, fmt.Errorf("kms:GetKeyPolicy %s: %w", r.name, err))
		}
		found[r.id] = true
		inv.keys = append(inv.keys, key)
	}
	return errors.Join(errs...)
}

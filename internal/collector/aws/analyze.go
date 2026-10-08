package aws

import (
	"fmt"
	"sort"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"

	"github.com/DreadpiratePickles/nimbus/internal/collector/core"
	"github.com/DreadpiratePickles/nimbus/internal/graph"
	"github.com/DreadpiratePickles/nimbus/internal/model"
)

const (
	unusedKeyDays   = 90
	idleCPUPercent  = 5.0
	oversizedCPUPct = 20.0
)

// analyzer turns an inventory into findings, graph nodes/edges and cost signals.
type analyzer struct {
	inv   *inventory
	spec  core.AccountSpec
	g     *graph.Graph
	now   time.Time
	acct  string
	acctN string // account node id

	findings []model.Finding
	cost     []core.CostSignal

	sgByID       map[string]ec2types.SecurityGroup // sg-id -> sg
	sgRegion     map[string]string
	sgOpen       map[string]openInfo
	profileRoles map[string]string // instance profile ARN -> role ARN
	datastores   map[string][]string // service -> datastore node IDs
}

type openInfo struct {
	Ports      []string // every internet-open port spec
	SSH, RDP   bool
	All        bool
	AllIngress []string // every ingress port spec (any source)
	SGSources  map[string][]string // source sg-id -> ports
}

func (a *analyzer) check(id string, res model.Resource, region string, pass bool, detail string) {
	f := core.Check{CheckID: id, Provider: model.ProviderAWS, Account: a.acct, AccountLabel: a.spec.Name, Region: region, Resource: res, Pass: pass, Detail: detail}.Finding(a.now)
	a.findings = append(a.findings, f)
}

func (a *analyzer) add(region string, res model.Resource, tags map[string]string, created time.Time, sensitive bool) string {
	return core.AddResource(a.g, core.Res{Provider: model.ProviderAWS, Account: a.acct, Region: region, Resource: res, Tags: tags, Created: created, ForceSensitive: sensitive})
}

func arnEC2(region, acct, kind, id string) string {
	return fmt.Sprintf("arn:aws:ec2:%s:%s:%s/%s", region, acct, kind, id)
}

func analyze(inv *inventory, spec core.AccountSpec, g *graph.Graph, now time.Time) ([]model.Finding, []core.CostSignal) {
	a := &analyzer{inv: inv, spec: spec, g: g, now: now, acct: inv.account,
		sgByID: map[string]ec2types.SecurityGroup{}, sgRegion: map[string]string{}, sgOpen: map[string]openInfo{},
		profileRoles: map[string]string{}, datastores: map[string][]string{}}
	a.acctN = core.EnsureAccount(g, model.ProviderAWS, a.acct, spec.Name)
	// Datastores first so IAM grants can resolve "*" to every store in the account.
	a.buckets()
	a.databases()
	a.secrets()
	a.securityGroups()
	a.iam()
	a.instances()
	a.volumes()
	a.addresses()
	a.lambdas()
	a.eks()
	a.kms()
	a.cloudtrail()
	a.spend()
	sort.SliceStable(a.findings, func(i, j int) bool { return a.findings[i].ID < a.findings[j].ID })
	core.AttachFindings(g, a.findings)
	return a.findings, a.cost
}

// ---------------------------------------------------------------- S3

func (a *analyzer) buckets() {
	sort.Slice(a.inv.buckets, func(i, j int) bool { return a.inv.buckets[i].Name < a.inv.buckets[j].Name })
	for _, b := range a.inv.buckets {
		public := !b.PABAll && (b.PolicyPublic || b.ACLPublic)
		res := model.Resource{ID: "arn:aws:s3:::" + b.Name, Type: "aws_s3_bucket", Name: b.Name, Attributes: map[string]any{
			"region": b.Region, "public": public, "public_access_block": b.PABAll, "policy_public": b.PolicyPublic, "acl_public": b.ACLPublic, "encrypted": b.Encrypted,
		}}
		id := a.add(b.Region, res, b.Tags, b.Created, false)
		a.datastores["s3"] = append(a.datastores["s3"], id)
		detail := "Bucket is not publicly accessible."
		switch {
		case b.PABAll:
			detail = "All four S3 Block Public Access settings are enabled on the bucket."
		case public:
			detail = fmt.Sprintf("Bucket is public (policy public: %v, ACL grants AllUsers/AuthenticatedUsers: %v) and Block Public Access is not fully enabled.", b.PolicyPublic, b.ACLPublic)
			a.g.AddEdge(graph.InternetNodeID, id, graph.EdgeExposes, map[string]any{"via": "s3_public_access"})
		}
		a.check("s3_bucket_public_access", res, b.Region, !public, detail)
		if b.EncKnown {
			d := "Default server-side encryption is configured."
			if !b.Encrypted {
				d = "No default server-side encryption configuration."
			}
			a.check("s3_bucket_default_encryption", res, b.Region, b.Encrypted, d)
		}
	}
}

// ---------------------------------------------------------------- RDS

func (a *analyzer) databases() {
	for _, d := range a.inv.dbs {
		db := d.Item
		arn := awssdk.ToString(db.DBInstanceArn)
		var sgs []string
		for _, v := range db.VpcSecurityGroups {
			sgs = append(sgs, awssdk.ToString(v.VpcSecurityGroupId))
		}
		tags := map[string]string{}
		for _, t := range db.TagList {
			tags[awssdk.ToString(t.Key)] = awssdk.ToString(t.Value)
		}
		attrs := map[string]any{"engine": awssdk.ToString(db.Engine), "instance_class": awssdk.ToString(db.DBInstanceClass), "publicly_accessible": awssdk.ToBool(db.PubliclyAccessible),
			"storage_encrypted": awssdk.ToBool(db.StorageEncrypted), "security_groups": sgs, "allocated_storage_gb": awssdk.ToInt32(db.AllocatedStorage)}
		if db.DBSubnetGroup != nil {
			attrs["vpc_id"] = awssdk.ToString(db.DBSubnetGroup.VpcId)
		}
		if db.Endpoint != nil {
			attrs["endpoint"] = awssdk.ToString(db.Endpoint.Address)
		}
		res := model.Resource{ID: arn, Type: "aws_db_instance", Name: awssdk.ToString(db.DBInstanceIdentifier), Attributes: attrs}
		var created time.Time
		if db.InstanceCreateTime != nil {
			created = *db.InstanceCreateTime
		}
		// Databases are crown jewels by default (matches graph heuristics for rds/sql types).
		id := a.add(d.Region, res, tags, created, true)
		a.datastores["rds"] = append(a.datastores["rds"], id)
		for _, sg := range sgs {
			res.Related = append(res.Related, arnEC2(d.Region, a.acct, "security-group", sg))
		}
		public := awssdk.ToBool(db.PubliclyAccessible)
		a.check("rds_instance_no_public_access", res, d.Region, !public, map[bool]string{true: "DB instance is publicly accessible.", false: "DB instance is not publicly accessible."}[public])
		enc := awssdk.ToBool(db.StorageEncrypted)
		a.check("rds_instance_storage_encrypted", res, d.Region, enc, map[bool]string{true: "Storage is encrypted at rest.", false: "Storage is not encrypted at rest."}[enc])
		a.attachSGs(id, d.Region, sgs, public, "rds_publicly_accessible")
		if public {
			a.g.AddEdge(graph.InternetNodeID, id, graph.EdgeExposes, map[string]any{"via": "rds_publicly_accessible"})
		}
	}
}

// ---------------------------------------------------------------- Secrets

func (a *analyzer) secrets() {
	for _, s := range a.inv.secrets {
		tags := map[string]string{}
		for _, t := range s.Item.Tags {
			tags[awssdk.ToString(t.Key)] = awssdk.ToString(t.Value)
		}
		var created time.Time
		if s.Item.CreatedDate != nil {
			created = *s.Item.CreatedDate
		}
		res := model.Resource{ID: awssdk.ToString(s.Item.ARN), Type: "aws_secretsmanager_secret", Name: awssdk.ToString(s.Item.Name),
			Attributes: map[string]any{"rotation_enabled": awssdk.ToBool(s.Item.RotationEnabled), "kms_key_id": awssdk.ToString(s.Item.KmsKeyId)}}
		id := a.add(s.Region, res, tags, created, true)
		a.datastores["secretsmanager"] = append(a.datastores["secretsmanager"], id)
	}
}

// ---------------------------------------------------------------- Security groups

func sgOpenInfo(sg ec2types.SecurityGroup) openInfo {
	oi := openInfo{SGSources: map[string][]string{}}
	for _, p := range sg.IpPermissions {
		proto := awssdk.ToString(p.IpProtocol)
		from, to := awssdk.ToInt32(p.FromPort), awssdk.ToInt32(p.ToPort)
		all := proto == "-1" || proto == "all"
		spec := "all"
		if !all {
			spec = proto + "/" + core.Ports(from, to)
			if from == 0 && to == 65535 {
				all = true
			}
		}
		oi.AllIngress = append(oi.AllIngress, spec)
		open := false
		for _, r := range p.IpRanges {
			if core.IsOpenCIDR(awssdk.ToString(r.CidrIp)) {
				open = true
			}
		}
		for _, r := range p.Ipv6Ranges {
			if core.IsOpenCIDR(awssdk.ToString(r.CidrIpv6)) {
				open = true
			}
		}
		for _, pair := range p.UserIdGroupPairs {
			if id := awssdk.ToString(pair.GroupId); id != "" {
				oi.SGSources[id] = append(oi.SGSources[id], spec)
			}
		}
		if !open {
			continue
		}
		oi.Ports = append(oi.Ports, spec)
		tcp := all || proto == "tcp" || proto == "6"
		if all {
			oi.All = true
		}
		if tcp && (all || core.PortInRange(22, from, to)) {
			oi.SSH = true
		}
		if tcp && (all || core.PortInRange(3389, from, to)) {
			oi.RDP = true
		}
	}
	return oi
}

func (a *analyzer) securityGroups() {
	for _, s := range a.inv.sgs {
		sg := s.Item
		gid := awssdk.ToString(sg.GroupId)
		a.sgByID[gid], a.sgRegion[gid] = sg, s.Region
		oi := sgOpenInfo(sg)
		a.sgOpen[gid] = oi
		id := arnEC2(s.Region, a.acct, "security-group", gid)
		res := model.Resource{ID: id, Type: "aws_security_group", Name: awssdk.ToString(sg.GroupName), Attributes: map[string]any{
			"group_id": gid, "vpc_id": awssdk.ToString(sg.VpcId), "description": awssdk.ToString(sg.Description), "open_to_internet": oi.Ports, "ingress": oi.AllIngress,
		}}
		a.add(s.Region, res, tagsEC2(sg.Tags), time.Time{}, false)
		ports := strings.Join(oi.Ports, ",")
		a.check("ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22", res, s.Region, !oi.SSH, openDetail(oi.SSH, "SSH (22)", ports))
		a.check("ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_3389", res, s.Region, !oi.RDP, openDetail(oi.RDP, "RDP (3389)", ports))
		a.check("ec2_securitygroup_allow_ingress_from_internet_to_any_port", res, s.Region, !oi.All, openDetail(oi.All, "all ports", ports))
	}
	// SG-to-SG references: members of the source group can reach members of this group.
	for _, gid := range core.SortedKeys(a.sgOpen) {
		for src, ports := range a.sgOpen[gid].SGSources {
			if src == gid {
				continue
			}
			region := a.sgRegion[gid]
			a.g.AddEdge(arnEC2(region, a.acct, "security-group", src), arnEC2(region, a.acct, "security-group", gid), graph.EdgeAllowsTrafficTo, map[string]any{"ports": ports, "via": "sg_reference"})
		}
	}
}

func openDetail(open bool, what, ports string) string {
	if open {
		return fmt.Sprintf("Ingress from 0.0.0.0/0 or ::/0 allows %s (open rules: %s).", what, ports)
	}
	return fmt.Sprintf("No ingress rule allows %s from the internet.", what)
}

// attachSGs wires resource→sg attached_to, sg→resource allows_traffic_to, and internet
// exposure when the resource is publicly addressable and an attached group is open.
func (a *analyzer) attachSGs(resID, region string, sgs []string, publiclyAddressable bool, via string) {
	var openPorts, openSGs []string
	for _, sg := range sgs {
		sgN := arnEC2(region, a.acct, "security-group", sg)
		a.g.AddEdge(resID, sgN, graph.EdgeAttachedTo, nil)
		oi := a.sgOpen[sg]
		a.g.AddEdge(sgN, resID, graph.EdgeAllowsTrafficTo, map[string]any{"ports": oi.AllIngress, "internet_ports": oi.Ports})
		if len(oi.Ports) > 0 {
			openPorts = append(openPorts, oi.Ports...)
			openSGs = append(openSGs, sg)
		}
	}
	if publiclyAddressable && len(openPorts) > 0 {
		a.g.AddEdge(graph.InternetNodeID, resID, graph.EdgeExposes, map[string]any{"via": via, "ports": openPorts, "security_groups": openSGs})
	}
}

// ---------------------------------------------------------------- IAM

func (a *analyzer) iam() {
	if !a.inv.iamKnown && a.inv.credReport == nil && a.inv.rootMFA == nil {
		return
	}
	attached := map[string]bool{}
	// Policies.
	for _, arn := range core.SortedKeys(a.inv.policies) {
		pi := a.inv.policies[arn]
		a.policyNode(pi.ARN, pi.Name, pi.Document, pi.AWSManaged, "")
	}
	link := func(from string, aps []iamtypes.AttachedPolicy) {
		for _, ap := range aps {
			parn := awssdk.ToString(ap.PolicyArn)
			attached[parn] = true
			a.g.AddEdge(from, parn, graph.EdgeHasPolicy, map[string]any{"type": "managed"})
		}
	}
	inline := func(from string, pds []iamtypes.PolicyDetail) {
		for _, pd := range pds {
			name := awssdk.ToString(pd.PolicyName)
			pid := from + "/inline-policy/" + name
			doc := a.policyNode(pid, name, awssdk.ToString(pd.PolicyDocument), false, from)
			a.g.AddEdge(from, pid, graph.EdgeHasPolicy, map[string]any{"type": "inline"})
			if doc != nil {
				res := model.Resource{ID: pid, Type: "aws_iam_policy", Name: name, Related: []string{from}}
				admin := doc.IsAdmin()
				a.check("iam_inline_policy_no_administrative_privileges", res, "", !admin, adminDetail(admin))
			}
		}
	}
	creds := map[string]credRow{}
	for _, r := range a.inv.credReport {
		creds[r["arn"]] = r
	}
	for _, gd := range a.inv.groups {
		arn := awssdk.ToString(gd.Arn)
		a.add("", model.Resource{ID: arn, Type: "aws_iam_group", Name: awssdk.ToString(gd.GroupName)}, nil, timeOf(gd.CreateDate), false)
		link(arn, gd.AttachedManagedPolicies)
		inline(arn, gd.GroupPolicyList)
	}
	groupArn := map[string]string{}
	for _, gd := range a.inv.groups {
		groupArn[awssdk.ToString(gd.GroupName)] = awssdk.ToString(gd.Arn)
	}
	for _, u := range a.inv.users {
		arn := awssdk.ToString(u.Arn)
		row := creds[arn]
		attrs := map[string]any{"groups": u.GroupList, "console_access": row["password_enabled"] == "true", "mfa_active": row["mfa_active"] == "true"}
		a.add("", model.Resource{ID: arn, Type: "aws_iam_user", Name: awssdk.ToString(u.UserName), Attributes: attrs}, tagsIAM(u.Tags), timeOf(u.CreateDate), false)
		link(arn, u.AttachedManagedPolicies)
		inline(arn, u.UserPolicyList)
		for _, gname := range u.GroupList {
			if garn, ok := groupArn[gname]; ok {
				a.g.AddEdge(arn, garn, graph.EdgeMemberOf, nil)
			}
		}
	}
	for _, r := range a.inv.roles {
		a.role(r, link, inline)
	}
	// Admin checks for attached managed policies.
	for _, arn := range core.SortedKeys(a.inv.policies) {
		if !attached[arn] {
			continue
		}
		pi := a.inv.policies[arn]
		doc, err := ParsePolicy(pi.Document)
		if pi.Document == "" || err != nil {
			continue
		}
		admin := doc.IsAdmin()
		res := model.Resource{ID: arn, Type: "aws_iam_policy", Name: pi.Name}
		id := "iam_customer_attached_policy_no_administrative_privileges"
		if pi.AWSManaged {
			id = "iam_aws_attached_policy_no_administrative_privileges"
		}
		a.check(id, res, "", !admin, adminDetail(admin))
	}
	a.credentialChecks()
}

func adminDetail(admin bool) string {
	if admin {
		return `Policy allows "*" actions on "*" resources (full administrative privileges).`
	}
	return "Policy does not grant full administrative privileges."
}

func timeOf(t *time.Time) time.Time {
	if t == nil {
		return time.Time{}
	}
	return *t
}

// policyNode adds the policy node and its datastore grants; it returns the parsed document.
func (a *analyzer) policyNode(id, name, document string, awsManaged bool, owner string) *PolicyDocument {
	attrs := map[string]any{"aws_managed": awsManaged}
	if owner != "" {
		attrs["inline_of"] = owner
	}
	var doc *PolicyDocument
	if document != "" {
		if d, err := ParsePolicy(document); err == nil {
			doc = &d
			attrs["admin"] = d.IsAdmin()
		}
	}
	a.add("", model.Resource{ID: id, Type: "aws_iam_policy", Name: name, Attributes: attrs}, nil, time.Time{}, false)
	if doc == nil {
		return nil
	}
	for _, da := range doc.DataAccess() {
		for _, target := range a.datastores[da.Service] {
			for _, pat := range da.Resources {
				if MatchesResource(pat, target) {
					a.g.AddEdge(id, target, graph.EdgeGrantsAccessTo, map[string]any{"actions": da.Actions, "service": da.Service, "resource_pattern": pat})
					break
				}
			}
		}
	}
	return doc
}

func (a *analyzer) role(r iamtypes.RoleDetail, link func(string, []iamtypes.AttachedPolicy), inline func(string, []iamtypes.PolicyDetail)) {
	arn := awssdk.ToString(r.Arn)
	path := awssdk.ToString(r.Path)
	var profiles []string
	for _, ip := range r.InstanceProfileList {
		parn := awssdk.ToString(ip.Arn)
		profiles = append(profiles, parn)
		a.profileRoles[parn] = arn
	}
	attrs := map[string]any{"path": path, "instance_profiles": profiles, "service_linked": strings.HasPrefix(path, "/aws-service-role/")}
	if r.RoleLastUsed != nil && r.RoleLastUsed.LastUsedDate != nil {
		attrs["last_used"] = r.RoleLastUsed.LastUsedDate.UTC().Format(time.RFC3339)
	}
	res := model.Resource{ID: arn, Type: "aws_iam_role", Name: awssdk.ToString(r.RoleName), Attributes: attrs}
	a.add("", res, tagsIAM(r.Tags), timeOf(r.CreateDate), false)
	link(arn, r.AttachedManagedPolicies)
	inline(arn, r.RolePolicyList)

	doc, err := ParsePolicy(awssdk.ToString(r.AssumeRolePolicyDocument))
	if err != nil {
		return
	}
	var external, services []string
	anyone := false
	for _, tp := range doc.TrustedPrincipals() {
		edgeAttr := map[string]any{"conditional": tp.Conditional, "principal": tp.Value}
		switch tp.Kind {
		case "any":
			anyone = true
			a.g.AddEdge(graph.InternetNodeID, arn, graph.EdgeCanAssume, edgeAttr)
		case "service":
			services = append(services, tp.Value)
		case "federated":
			a.g.AddNode(&graph.Node{ID: tp.Value, Type: "aws_iam_identity_provider", Class: graph.ClassIdentity, Provider: model.ProviderAWS, Account: a.acct})
			a.g.AddEdge(tp.Value, arn, graph.EdgeCanAssume, edgeAttr)
		case "aws":
			from := tp.Value
			if tp.Account != "" && (from == tp.Account || strings.HasSuffix(from, ":root")) {
				from = core.AccountNodeID(model.ProviderAWS, tp.Account)
				if tp.Account != a.acct {
					a.g.AddNode(&graph.Node{ID: from, Type: "aws_account", Class: graph.ClassAccount, Name: tp.Account, Provider: model.ProviderAWS, Account: tp.Account, Attributes: map[string]any{"external": true}})
				}
			}
			a.g.AddEdge(from, arn, graph.EdgeCanAssume, edgeAttr)
			if tp.Account != "" && tp.Account != a.acct {
				external = append(external, tp.Account)
				extN := core.AccountNodeID(model.ProviderAWS, tp.Account)
				a.g.AddNode(&graph.Node{ID: extN, Type: "aws_account", Class: graph.ClassAccount, Name: tp.Account, Provider: model.ProviderAWS, Account: tp.Account, Attributes: map[string]any{"external": true}})
				a.g.AddEdge(arn, extN, graph.EdgeTrusts, map[string]any{"principal": tp.Value, "conditional": tp.Conditional})
			}
		}
	}
	if len(services) > 0 {
		a.g.AddNode(&graph.Node{ID: arn, Attributes: map[string]any{"trusted_services": services}, Type: "aws_iam_role", Class: graph.ClassIdentity})
	}
	if strings.HasPrefix(path, "/aws-service-role/") {
		return
	}
	fail := anyone || len(external) > 0
	detail := "Role trust policy only allows principals in this account or AWS services."
	switch {
	case anyone:
		detail = `Role trust policy allows any principal ("*") to assume it.`
	case len(external) > 0:
		detail = "Role can be assumed from external accounts: " + strings.Join(dedupe(external), ", ") + "."
	}
	res.Attributes["trusted_accounts"] = dedupe(external)
	a.check("iam_role_cross_account_readonlyaccess_policy", res, "", !fail, detail)
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

func (a *analyzer) credentialChecks() {
	rootRes := model.Resource{ID: fmt.Sprintf("arn:aws:iam::%s:root", a.acct), Type: "aws_iam_root", Name: "root"}
	rootMFA := a.inv.rootMFA
	for _, r := range a.inv.credReport {
		if r["user"] == "<root_account>" && rootMFA == nil {
			v := r["mfa_active"] == "true"
			rootMFA = &v
		}
	}
	if rootMFA != nil {
		a.add("", rootRes, nil, time.Time{}, false)
		a.g.AddNode(&graph.Node{ID: rootRes.ID, Type: "aws_iam_root", Class: graph.ClassIdentity})
		a.check("iam_root_mfa_enabled", rootRes, "", *rootMFA, map[bool]string{true: "Root account has MFA enabled.", false: "Root account has no MFA device."}[*rootMFA])
	}
	for _, r := range a.inv.credReport {
		if r["user"] == "<root_account>" {
			continue
		}
		res := model.Resource{ID: r["arn"], Type: "aws_iam_user", Name: r["user"]}
		if r["password_enabled"] == "true" {
			mfa := r["mfa_active"] == "true"
			a.check("iam_user_mfa_enabled_console_access", res, "", mfa, map[bool]string{true: "Console user has MFA enabled.", false: "User has a console password but no MFA device."}[mfa])
		}
		for _, n := range []string{"1", "2"} {
			if r["access_key_"+n+"_active"] != "true" {
				continue
			}
			lastUsed, used := parseCredTime(r["access_key_"+n+"_last_used_date"])
			rotated, _ := parseCredTime(r["access_key_"+n+"_last_rotated"])
			ref := lastUsed
			if !used {
				ref = rotated
			}
			stale := ref.IsZero() || a.now.Sub(ref) > unusedKeyDays*24*time.Hour
			detail := fmt.Sprintf("Access key %s last used %s.", n, r["access_key_"+n+"_last_used_date"])
			if stale {
				detail = fmt.Sprintf("Active access key %s has not been used in %d days (last used: %s, rotated: %s).", n, unusedKeyDays, r["access_key_"+n+"_last_used_date"], r["access_key_"+n+"_last_rotated"])
			}
			kres := res
			kres.Attributes = map[string]any{"access_key": n}
			a.check("iam_user_accesskey_unused", kres, "", !stale, detail)
		}
	}
}

func parseCredTime(s string) (time.Time, bool) {
	if s == "" || s == "N/A" || s == "no_information" || s == "not_supported" {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

// ---------------------------------------------------------------- EC2

func (a *analyzer) instances() {
	volGB := map[string]float64{}
	for _, v := range a.inv.volumes {
		for _, at := range v.Item.Attachments {
			volGB[awssdk.ToString(at.InstanceId)] += float64(awssdk.ToInt32(v.Item.Size))
		}
	}
	for _, ri := range a.inv.instances {
		in := ri.Item
		iid := awssdk.ToString(in.InstanceId)
		id := arnEC2(ri.Region, a.acct, "instance", iid)
		var sgs []string
		for _, s := range in.SecurityGroups {
			sgs = append(sgs, awssdk.ToString(s.GroupId))
		}
		tags := tagsEC2(in.Tags)
		name := tags["Name"]
		if name == "" {
			name = iid
		}
		state := ""
		if in.State != nil {
			state = string(in.State.Name)
		}
		attrs := map[string]any{"instance_id": iid, "instance_type": string(in.InstanceType), "state": state, "vpc_id": awssdk.ToString(in.VpcId),
			"subnet_id": awssdk.ToString(in.SubnetId), "security_groups": sgs, "image_id": awssdk.ToString(in.ImageId), "private_ip": awssdk.ToString(in.PrivateIpAddress)}
		if in.PublicIpAddress != nil {
			attrs["public_ip"] = awssdk.ToString(in.PublicIpAddress)
		}
		var related []string
		profile, role := "", ""
		if in.IamInstanceProfile != nil {
			profile = awssdk.ToString(in.IamInstanceProfile.Arn)
			attrs["instance_profile"] = profile
			role = a.profileRoles[profile]
			if role != "" {
				attrs["iam_role"] = role
			}
		}
		if in.MetadataOptions != nil {
			attrs["http_tokens"] = string(in.MetadataOptions.HttpTokens)
		}
		res := model.Resource{ID: id, Type: "aws_instance", Name: name, Attributes: attrs}
		a.add(ri.Region, res, tags, timeOf(in.LaunchTime), false)
		for _, sg := range sgs {
			related = append(related, arnEC2(ri.Region, a.acct, "security-group", sg))
		}
		if role != "" {
			related = append(related, role)
			a.g.AddEdge(id, role, graph.EdgeRunsAs, map[string]any{"instance_profile": profile})
		} else if profile != "" {
			related = append(related, profile)
			a.g.AddEdge(id, profile, graph.EdgeRunsAs, nil)
		}
		res.Related = related
		a.attachSGs(id, ri.Region, sgs, in.PublicIpAddress != nil, "public_ip+open_security_group")

		imdsv2 := in.MetadataOptions != nil && (in.MetadataOptions.HttpTokens == ec2types.HttpTokensStateRequired || in.MetadataOptions.HttpEndpoint == ec2types.InstanceMetadataEndpointStateDisabled)
		a.check("ec2_instance_imdsv2_enabled", res, ri.Region, imdsv2, map[bool]string{true: "IMDSv2 is required (or the metadata endpoint is disabled).", false: "Instance metadata service accepts IMDSv1 requests (HttpTokens optional)."}[imdsv2])
		pub := in.PublicIpAddress != nil
		a.check("ec2_instance_public_ip", res, ri.Region, !pub, map[bool]string{true: "Instance has public IP " + awssdk.ToString(in.PublicIpAddress) + ".", false: "Instance has no public IP."}[pub])

		a.instanceCost(ri.Region, id, string(in.InstanceType), state, volGB[iid], iid, pub)
	}
}

func isLargeType(t string) bool {
	i := strings.Index(t, ".")
	if i < 0 {
		return false
	}
	size := t[i+1:]
	return strings.Contains(size, "xlarge") || size == "metal"
}

func (a *analyzer) instanceCost(region, id, itype, state string, volumeGB float64, iid string, public bool) {
	base := core.CostSignal{Provider: model.ProviderAWS, Account: a.acct, Region: region, ResourceID: id, ResourceType: "aws_instance", InstanceType: itype, Attributes: map[string]any{"volume_gb": volumeGB}}
	switch state {
	case string(ec2types.InstanceStateNameStopped):
		s := base
		s.Kind = core.KindStoppedInstance
		s.SizeGB = volumeGB
		a.cost = append(a.cost, s)
		return
	case string(ec2types.InstanceStateNameRunning):
	default:
		return
	}
	if cpu, ok := a.inv.cpu[iid]; ok {
		s := base
		s.AvgCPU = cpu
		switch {
		case cpu < idleCPUPercent:
			s.Kind = core.KindIdleInstance
			a.cost = append(a.cost, s)
		case cpu < oversizedCPUPct && isLargeType(itype):
			s.Kind = core.KindOversizedInstance
			a.cost = append(a.cost, s)
		}
	}
	if gb, ok := a.inv.egress[iid]; ok && public && gb > 0 {
		s := base
		s.Kind = core.KindPublicEgress
		s.SizeGB = gb
		s.Attributes = map[string]any{"egress_gb": gb}
		a.cost = append(a.cost, s)
	}
}

func (a *analyzer) volumes() {
	for _, rv := range a.inv.volumes {
		v := rv.Item
		vid := awssdk.ToString(v.VolumeId)
		id := arnEC2(rv.Region, a.acct, "volume", vid)
		tags := tagsEC2(v.Tags)
		name := tags["Name"]
		if name == "" {
			name = vid
		}
		enc := awssdk.ToBool(v.Encrypted)
		res := model.Resource{ID: id, Type: "aws_ebs_volume", Name: name, Attributes: map[string]any{"volume_id": vid, "size_gb": awssdk.ToInt32(v.Size), "volume_type": string(v.VolumeType), "state": string(v.State), "encrypted": enc}}
		a.add(rv.Region, res, tags, timeOf(v.CreateTime), false)
		for _, at := range v.Attachments {
			a.g.AddEdge(arnEC2(rv.Region, a.acct, "instance", awssdk.ToString(at.InstanceId)), id, graph.EdgeAttachedTo, map[string]any{"device": awssdk.ToString(at.Device)})
		}
		a.check("ec2_ebs_volume_encryption", res, rv.Region, enc, map[bool]string{true: "Volume is encrypted.", false: "Volume is not encrypted."}[enc])
		if v.State == ec2types.VolumeStateAvailable {
			a.cost = append(a.cost, core.CostSignal{Provider: model.ProviderAWS, Account: a.acct, Region: rv.Region, ResourceID: id, ResourceType: "aws_ebs_volume", Kind: core.KindUnattachedVolume,
				SizeGB: float64(awssdk.ToInt32(v.Size)), Attributes: map[string]any{"volume_type": string(v.VolumeType), "iops": awssdk.ToInt32(v.Iops)}})
		}
	}
}

func (a *analyzer) addresses() {
	for _, ra := range a.inv.addresses {
		ad := ra.Item
		if ad.AssociationId != nil || ad.InstanceId != nil || ad.NetworkInterfaceId != nil {
			continue
		}
		alloc := awssdk.ToString(ad.AllocationId)
		if alloc == "" {
			alloc = awssdk.ToString(ad.PublicIp)
		}
		a.cost = append(a.cost, core.CostSignal{Provider: model.ProviderAWS, Account: a.acct, Region: ra.Region, ResourceID: arnEC2(ra.Region, a.acct, "elastic-ip", alloc),
			ResourceType: "aws_eip", Kind: core.KindUnassociatedIP, Attributes: map[string]any{"public_ip": awssdk.ToString(ad.PublicIp)}})
	}
}

// ---------------------------------------------------------------- Lambda / EKS / KMS / CloudTrail

func (a *analyzer) lambdas() {
	for _, lf := range a.inv.functions {
		fn := lf.Fn
		arn := awssdk.ToString(fn.FunctionArn)
		role := awssdk.ToString(fn.Role)
		attrs := map[string]any{"runtime": string(fn.Runtime), "iam_role": role, "function_url": lf.URL, "url_auth_type": lf.URLAuth}
		var sgs []string
		if fn.VpcConfig != nil {
			sgs = fn.VpcConfig.SecurityGroupIds
			attrs["vpc_id"] = awssdk.ToString(fn.VpcConfig.VpcId)
			attrs["security_groups"] = sgs
		}
		res := model.Resource{ID: arn, Type: "aws_lambda_function", Name: awssdk.ToString(fn.FunctionName), Attributes: attrs}
		var modified time.Time
		if t, err := time.Parse("2006-01-02T15:04:05.000-0700", awssdk.ToString(fn.LastModified)); err == nil {
			modified = t
		}
		a.add(lf.Region, res, nil, modified, false)
		if role != "" {
			a.g.AddEdge(arn, role, graph.EdgeRunsAs, nil)
		}
		a.attachSGs(arn, lf.Region, sgs, false, "")
		public := lf.URL != "" && strings.EqualFold(lf.URLAuth, "NONE")
		if public {
			a.g.AddEdge(graph.InternetNodeID, arn, graph.EdgeExposes, map[string]any{"via": "lambda_function_url", "url": lf.URL})
		}
		d := "Function has no public function URL."
		if public {
			d = "Function URL " + lf.URL + " uses AuthType NONE (publicly invocable)."
		}
		a.check("awslambda_function_url_public", res, lf.Region, !public, d)
	}
}

func (a *analyzer) eks() {
	for _, rc := range a.inv.clusters {
		c := rc.Item
		arn := awssdk.ToString(c.Arn)
		attrs := map[string]any{"version": awssdk.ToString(c.Version), "iam_role": awssdk.ToString(c.RoleArn)}
		var sgs []string
		public := false
		if v := c.ResourcesVpcConfig; v != nil {
			sgs = append(sgs, v.SecurityGroupIds...)
			if v.ClusterSecurityGroupId != nil {
				sgs = append(sgs, *v.ClusterSecurityGroupId)
			}
			attrs["vpc_id"] = awssdk.ToString(v.VpcId)
			attrs["endpoint_public_access"] = v.EndpointPublicAccess
			attrs["public_access_cidrs"] = v.PublicAccessCidrs
			attrs["security_groups"] = sgs
			if v.EndpointPublicAccess {
				for _, cidr := range v.PublicAccessCidrs {
					if core.IsOpenCIDR(cidr) {
						public = true
					}
				}
				if len(v.PublicAccessCidrs) == 0 {
					public = true
				}
			}
		}
		res := model.Resource{ID: arn, Type: "aws_eks_cluster", Name: awssdk.ToString(c.Name), Attributes: attrs}
		a.add(rc.Region, res, c.Tags, timeOf(c.CreatedAt), false)
		if role := awssdk.ToString(c.RoleArn); role != "" {
			a.g.AddEdge(arn, role, graph.EdgeRunsAs, nil)
		}
		a.attachSGs(arn, rc.Region, sgs, false, "")
		if public {
			a.g.AddEdge(graph.InternetNodeID, arn, graph.EdgeExposes, map[string]any{"via": "eks_public_endpoint"})
		}
		d := "Cluster API endpoint is private or restricted to specific CIDRs."
		if public {
			d = "Cluster API endpoint is publicly accessible from 0.0.0.0/0."
		}
		a.check("eks_control_plane_endpoint_access_publicly_accessible", res, rc.Region, !public, d)
	}
}

func (a *analyzer) kms() {
	for _, k := range a.inv.keys {
		res := model.Resource{ID: k.ARN, Type: "aws_kms_key", Name: k.ID, Attributes: map[string]any{"rotation_enabled": k.Rotation}}
		a.add(k.Region, res, nil, time.Time{}, false)
		a.check("kms_cmk_rotation_enabled", res, k.Region, k.Rotation, map[bool]string{true: "Automatic key rotation is enabled.", false: "Automatic key rotation is disabled."}[k.Rotation])
	}
}

func (a *analyzer) cloudtrail() {
	if !a.inv.trailsKnown {
		return
	}
	var good string
	for _, t := range a.inv.trails {
		arn := awssdk.ToString(t.TrailARN)
		a.add(awssdk.ToString(t.HomeRegion), model.Resource{ID: arn, Type: "aws_cloudtrail", Name: awssdk.ToString(t.Name), Attributes: map[string]any{
			"multi_region": awssdk.ToBool(t.IsMultiRegionTrail), "logging": a.inv.trailLogging[arn], "log_file_validation": awssdk.ToBool(t.LogFileValidationEnabled), "s3_bucket": awssdk.ToString(t.S3BucketName)}}, nil, time.Time{}, false)
		if awssdk.ToBool(t.IsMultiRegionTrail) && a.inv.trailLogging[arn] && good == "" {
			good = arn
		}
	}
	if good != "" {
		a.check("cloudtrail_multi_region_enabled", model.Resource{ID: good, Type: "aws_cloudtrail", Name: lastSeg(good)}, "", true, "A multi-region trail is enabled and logging.")
		return
	}
	res := model.Resource{ID: fmt.Sprintf("arn:aws:cloudtrail:%s:%s:trail/none", core.DefaultAWSRegion, a.acct), Type: "aws_cloudtrail", Name: "cloudtrail"}
	a.check("cloudtrail_multi_region_enabled", res, "", false, "No multi-region CloudTrail trail is enabled and logging in this account.")
}

func lastSeg(s string) string {
	if i := strings.LastIndexAny(s, "/:"); i >= 0 {
		return s[i+1:]
	}
	return s
}

func (a *analyzer) spend() {
	for _, svc := range core.SortedKeys(a.inv.spend) {
		v := a.inv.spend[svc]
		if v <= 0 {
			continue
		}
		a.cost = append(a.cost, core.CostSignal{Provider: model.ProviderAWS, Account: a.acct, Region: "global", ResourceID: "aws:service:" + svc, ResourceType: "aws_service",
			Kind: core.KindServiceSpend, MonthlySpend: v, Attributes: map[string]any{"service": svc}})
	}
}

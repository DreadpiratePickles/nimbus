package aws

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"

	"github.com/DreadpiratePickles/nimbus/internal/graph"
)

func s(v string) *string { return awssdk.String(v) }

func naclEntry(n int32, egress bool, proto string, from, to int32, cidr string, allow bool) ec2types.NetworkAclEntry {
	e := ec2types.NetworkAclEntry{RuleNumber: awssdk.Int32(n), Egress: awssdk.Bool(egress), Protocol: s(proto), CidrBlock: s(cidr), RuleAction: ec2types.RuleActionDeny}
	if allow {
		e.RuleAction = ec2types.RuleActionAllow
	}
	if proto != "-1" {
		e.PortRange = &ec2types.PortRange{From: awssdk.Int32(from), To: awssdk.Int32(to)}
	}
	return e
}

func allowAllEntries() []ec2types.NetworkAclEntry {
	return []ec2types.NetworkAclEntry{
		naclEntry(100, false, "-1", 0, 0, "0.0.0.0/0", true), naclEntry(32767, false, "-1", 0, 0, "0.0.0.0/0", false),
		naclEntry(100, true, "-1", 0, 0, "0.0.0.0/0", true), naclEntry(32767, true, "-1", 0, 0, "0.0.0.0/0", false),
	}
}

const (
	albARN = "arn:aws:elasticloadbalancing:us-east-1:" + acct + ":loadbalancer/app/web/1"
	tgARN  = "arn:aws:elasticloadbalancing:us-east-1:" + acct + ":targetgroup/app/1"
)

// netFixture: one VPC with a public subnet (IGW route), a NAT-only private subnet, an SFTP
// subnet whose NACL denies 22 (F03 shape), an isolated subnet for a public-flag RDS (F04 shape),
// and an internet-facing ALB forwarding 443 to a private app instance on 8080.
func netFixture() *fakeAWS {
	running := &ec2types.InstanceState{Name: ec2types.InstanceStateNameRunning}
	inst := func(id, subnet, pub, sg string) ec2types.Instance {
		i := ec2types.Instance{InstanceId: s(id), State: running, VpcId: s("vpc-1"), SubnetId: s(subnet), SecurityGroups: []ec2types.GroupIdentifier{{GroupId: s(sg)}}}
		if pub != "" {
			i.PublicIpAddress = s(pub)
		}
		return i
	}
	return &fakeAWS{
		account: acct,
		fail:    map[string]error{},
		instPages: [][]ec2types.Instance{{
			inst("i-web", "subnet-pub", "54.1.1.1", "sg-ssh"),
			inst("i-sftp", "subnet-sftp", "54.1.1.2", "sg-ssh"),
			inst("i-app", "subnet-priv", "", "sg-app"),
		}},
		sgs: []ec2types.SecurityGroup{
			{GroupId: s("sg-ssh"), GroupName: s("ssh"), VpcId: s("vpc-1"), IpPermissions: []ec2types.IpPermission{tcp(22, 22, "0.0.0.0/0")}},
			{GroupId: s("sg-alb"), GroupName: s("alb"), VpcId: s("vpc-1"), IpPermissions: []ec2types.IpPermission{tcp(443, 443, "0.0.0.0/0")}},
			{GroupId: s("sg-app"), GroupName: s("app"), VpcId: s("vpc-1"), IpPermissions: []ec2types.IpPermission{
				{IpProtocol: s("tcp"), FromPort: awssdk.Int32(8080), ToPort: awssdk.Int32(8080), UserIdGroupPairs: []ec2types.UserIdGroupPair{{GroupId: s("sg-alb")}}}}},
			{GroupId: s("sg-db"), GroupName: s("db"), VpcId: s("vpc-1"), IpPermissions: []ec2types.IpPermission{tcp(5432, 5432, "0.0.0.0/0")}},
		},
		dbs: []rdstypes.DBInstance{{
			DBInstanceArn: s("arn:aws:rds:us-east-1:" + acct + ":db:ledger"), DBInstanceIdentifier: s("ledger"), PubliclyAccessible: awssdk.Bool(true),
			VpcSecurityGroups: []rdstypes.VpcSecurityGroupMembership{{VpcSecurityGroupId: s("sg-db")}},
			DBSubnetGroup:     &rdstypes.DBSubnetGroup{DBSubnetGroupName: s("isolated"), VpcId: s("vpc-1"), Subnets: []rdstypes.Subnet{{SubnetIdentifier: s("subnet-iso")}}},
		}},
		net: fakeNet{
			subnets: []ec2types.Subnet{
				{SubnetId: s("subnet-pub"), VpcId: s("vpc-1"), CidrBlock: s("10.0.1.0/24")},
				{SubnetId: s("subnet-priv"), VpcId: s("vpc-1"), CidrBlock: s("10.0.2.0/24")},
				{SubnetId: s("subnet-sftp"), VpcId: s("vpc-1"), CidrBlock: s("10.0.3.0/24")},
				{SubnetId: s("subnet-iso"), VpcId: s("vpc-1"), CidrBlock: s("10.0.4.0/24")},
			},
			routeTables: []ec2types.RouteTable{
				{RouteTableId: s("rtb-main"), VpcId: s("vpc-1"), Associations: []ec2types.RouteTableAssociation{{Main: awssdk.Bool(true)}},
					Routes: []ec2types.Route{{DestinationCidrBlock: s("10.0.0.0/16"), GatewayId: s("local"), State: ec2types.RouteStateActive}, {DestinationCidrBlock: s("0.0.0.0/0"), NatGatewayId: s("nat-1"), State: ec2types.RouteStateActive}}},
				{RouteTableId: s("rtb-pub"), VpcId: s("vpc-1"), Associations: []ec2types.RouteTableAssociation{{SubnetId: s("subnet-pub")}, {SubnetId: s("subnet-sftp")}},
					Routes: []ec2types.Route{{DestinationCidrBlock: s("10.0.0.0/16"), GatewayId: s("local"), State: ec2types.RouteStateActive}, {DestinationCidrBlock: s("0.0.0.0/0"), GatewayId: s("igw-1"), State: ec2types.RouteStateActive}}},
				{RouteTableId: s("rtb-iso"), VpcId: s("vpc-1"), Associations: []ec2types.RouteTableAssociation{{SubnetId: s("subnet-iso")}},
					Routes: []ec2types.Route{{DestinationCidrBlock: s("10.0.0.0/16"), GatewayId: s("local"), State: ec2types.RouteStateActive}}},
			},
			nacls: []ec2types.NetworkAcl{
				{NetworkAclId: s("acl-default"), VpcId: s("vpc-1"), IsDefault: awssdk.Bool(true), Entries: allowAllEntries(),
					Associations: []ec2types.NetworkAclAssociation{{SubnetId: s("subnet-pub")}, {SubnetId: s("subnet-priv")}, {SubnetId: s("subnet-iso")}}},
				{NetworkAclId: s("acl-sftp"), VpcId: s("vpc-1"), Associations: []ec2types.NetworkAclAssociation{{SubnetId: s("subnet-sftp")}},
					Entries: append([]ec2types.NetworkAclEntry{naclEntry(90, false, "6", 22, 22, "0.0.0.0/0", false)}, allowAllEntries()...)},
			},
			igws: []ec2types.InternetGateway{{InternetGatewayId: s("igw-1"), Attachments: []ec2types.InternetGatewayAttachment{{VpcId: s("vpc-1"), State: ec2types.AttachmentStatusAttached}}}},
			nats: []ec2types.NatGateway{{NatGatewayId: s("nat-1"), SubnetId: s("subnet-pub"), State: ec2types.NatGatewayStateAvailable}},
			enis: []ec2types.NetworkInterface{{NetworkInterfaceId: s("eni-web"), SubnetId: s("subnet-pub"),
				Attachment: &ec2types.NetworkInterfaceAttachment{InstanceId: s("i-web")}, Association: &ec2types.NetworkInterfaceAssociation{PublicIp: s("54.1.1.1")}}},
			lbs:       []ELBLoadBalancer{{ARN: albARN, Name: "web", Scheme: "internet-facing", Type: "application", VPCID: "vpc-1", Subnets: []string{"subnet-pub"}, SecurityGroups: []string{"sg-alb"}}},
			listeners: map[string][]ELBListener{albARN: {{ARN: albARN + "/listener/443", Protocol: "HTTPS", Port: 443, TargetGroups: []string{tgARN}}}},
			tgs:       map[string][]ELBTargetGroup{albARN: {{ARN: tgARN, Name: "app", Protocol: "HTTP", Port: 8080, TargetType: "instance"}}},
			targets:   map[string][]ELBTarget{tgARN: {{ID: "i-app", Port: 8080}}},
		},
	}
}

func reachOf(t *testing.T, g *graph.Graph, id string) graph.Reachability {
	t.Helper()
	r, ok := g.ReachabilityOf(id)
	if !ok {
		t.Fatalf("%s carries no reachability", id)
	}
	return r
}

func TestNetworkReachability(t *testing.T) {
	_, g := collect(t, netFixture())
	web := arnEC2("us-east-1", acct, "instance", "i-web")
	if r := reachOf(t, g, web); r.Status != "reachable" || r.Width != "wide" || r.Confidence != "verified" || r.Port != "22/tcp" {
		t.Errorf("i-web = %+v", r)
	}
	// F03 shape: SG open 22, NACL rule 90 denies 22.
	sftp := arnEC2("us-east-1", acct, "instance", "i-sftp")
	r := reachOf(t, g, sftp)
	if r.Status != "blocked" || !strings.Contains(r.Blocker, "NACL acl-sftp rule 90 denies 22/tcp from 0.0.0.0/0") {
		t.Errorf("i-sftp = %+v", r)
	}
	var edge *graph.Edge
	for _, e := range g.Out(graph.InternetNodeID) {
		if e.To == sftp && e.Kind == graph.EdgeExposes {
			edge = e
		}
	}
	if edge == nil {
		t.Fatal("i-sftp has no exposes edge (the SG view still exposes it)")
	}
	if er, _ := edge.Reachability(); er.Status != "blocked" || edge.Attr[graph.AttrReachBlocker] == nil {
		t.Errorf("i-sftp edge = %v", edge.Attr)
	}
	// F04 shape: PubliclyAccessible with an isolated subnet group.
	if r := reachOf(t, g, "arn:aws:rds:us-east-1:"+acct+":db:ledger"); r.Status != "blocked" || !strings.Contains(r.Blocker, "route table rtb-iso has no route to an internet gateway") {
		t.Errorf("ledger = %+v", r)
	}
	// ALB public, app instance private: reachable through the ALB on 8080 only.
	if r := reachOf(t, g, albARN); r.Status != "reachable" {
		t.Errorf("alb = %+v", r)
	}
	app := arnEC2("us-east-1", acct, "instance", "i-app")
	ar := reachOf(t, g, app)
	if ar.Status != "reachable" || ar.Via != albARN || ar.Port != "8080/tcp" {
		t.Errorf("i-app = %+v", ar)
	}
	if !hasEdge(g, albARN, app, graph.EdgeAllowsTrafficTo) {
		t.Error("no alb -> app edge")
	}
	// Facts on the graph.
	sub, _ := g.Node(arnEC2("us-east-1", acct, "subnet", "subnet-priv"))
	if sub == nil || sub.Attributes["route_table_association"] != "main" || sub.Attributes["internet_gateway_route"] != false {
		t.Errorf("subnet-priv = %+v", sub)
	}
	acl, _ := g.Node(arnEC2("us-east-1", acct, "network-acl", "acl-sftp"))
	if acl == nil || len(acl.Attributes["ingress"].([]any)) != 3 {
		t.Errorf("acl-sftp = %+v", acl)
	}
	webN, _ := g.Node(web)
	if ips, _ := webN.Attributes["public_ips"].([]string); len(ips) != 1 || ips[0] != "54.1.1.1" {
		t.Errorf("public_ips = %v", webN.Attributes["public_ips"])
	}
	accN, _ := g.Node("aws:account:" + acct)
	cov, _ := accN.Attributes[graph.AttrReachCoverage].(map[string]any)
	for _, in := range netInputs {
		if cov[in] != "collected" {
			t.Errorf("coverage %s = %v", in, cov[in])
		}
	}
}

// Denied calls become coverage rows and the verdicts they would decide become unknown, never
// reachable; a NACL deny still decides.
func TestNetworkDeniedCoverage(t *testing.T) {
	f := netFixture()
	f.fail["DescribeRouteTables"] = apiErr("UnauthorizedOperation")
	f.fail["DescribeLoadBalancers"] = apiErr("AccessDenied")
	res, g := collect(t, f)
	got := map[string]string{}
	for _, ce := range res.CollectErrors() {
		got[ce.API] = ce.Reason
	}
	if got["us-east-1:ec2:DescribeRouteTables"] != "access_denied" || got["us-east-1:elasticloadbalancing:DescribeLoadBalancers"] != "access_denied" {
		t.Fatalf("coverage rows = %v", got)
	}
	accN, _ := g.Node("aws:account:" + acct)
	cov, _ := accN.Attributes[graph.AttrReachCoverage].(map[string]any)
	if cov[netRouteTables] != "access_denied" || cov[netNACLs] != "collected" {
		t.Errorf("coverage = %v", cov)
	}
	web := reachOf(t, g, arnEC2("us-east-1", acct, "instance", "i-web"))
	if web.Status != "unknown" || !strings.Contains(web.Unknown, "route table for subnet-pub not collected") || !strings.Contains(web.Unknown, "route_tables=access_denied") {
		t.Errorf("i-web = %+v", web)
	}
	if r := reachOf(t, g, arnEC2("us-east-1", acct, "instance", "i-sftp")); r.Status != "blocked" {
		t.Errorf("i-sftp = %+v (a NACL deny decides without routes)", r)
	}
}

// Collection with no network data at all (older fakes, ingest-only accounts): unknown.
func TestNetworkNotCollectedIsUnknown(t *testing.T) {
	f := netFixture()
	f.net = fakeNet{}
	_, g := collect(t, f)
	r := reachOf(t, g, arnEC2("us-east-1", acct, "instance", "i-web"))
	if r.Status != "unknown" {
		t.Errorf("i-web without subnets = %+v", r)
	}
}

const lbXML = `<DescribeLoadBalancersResponse xmlns="http://elasticloadbalancing.amazonaws.com/doc/2015-12-01/">
<DescribeLoadBalancersResult><LoadBalancers><member>
<LoadBalancerArn>arn:lb/1</LoadBalancerArn><LoadBalancerName>web</LoadBalancerName><DNSName>web.elb</DNSName>
<Scheme>internet-facing</Scheme><Type>application</Type><VpcId>vpc-1</VpcId>
<AvailabilityZones><member><SubnetId>subnet-a</SubnetId><ZoneName>us-east-1a</ZoneName></member><member><SubnetId>subnet-b</SubnetId></member></AvailabilityZones>
<SecurityGroups><member>sg-alb</member></SecurityGroups>
</member></LoadBalancers></DescribeLoadBalancersResult></DescribeLoadBalancersResponse>`

const listenerXML = `<DescribeListenersResponse><DescribeListenersResult><Listeners><member>
<ListenerArn>arn:listener/1</ListenerArn><Protocol>HTTPS</Protocol><Port>443</Port>
<DefaultActions><member><Type>forward</Type><ForwardConfig><TargetGroups><member><TargetGroupArn>arn:tg/a</TargetGroupArn></member><member><TargetGroupArn>arn:tg/b</TargetGroupArn></member></TargetGroups></ForwardConfig></member>
<member><Type>forward</Type><TargetGroupArn>arn:tg/a</TargetGroupArn></member></DefaultActions>
</member></Listeners></DescribeListenersResult></DescribeListenersResponse>`

const targetsXML = `<DescribeTargetHealthResponse><DescribeTargetHealthResult><TargetHealthDescriptions>
<member><Target><Id>i-1</Id><Port>8080</Port></Target><TargetHealth><State>healthy</State></TargetHealth></member>
</TargetHealthDescriptions></DescribeTargetHealthResult></DescribeTargetHealthResponse>`

// The hand-rolled ELBv2 query client: SigV4-signed POST, XML decode, AWS error codes.
func TestSDKELBv2(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if !strings.Contains(r.Header.Get("Authorization"), "elasticloadbalancing") || r.Form.Get("Version") != "2015-12-01" {
			w.WriteHeader(400)
			return
		}
		switch r.Form.Get("Action") {
		case "DescribeLoadBalancers":
			_, _ = w.Write([]byte(lbXML))
		case "DescribeListeners":
			_, _ = w.Write([]byte(listenerXML))
		case "DescribeTargetHealth":
			_, _ = w.Write([]byte(targetsXML))
		default:
			w.WriteHeader(403)
			_, _ = w.Write([]byte(`<ErrorResponse><Error><Code>AccessDenied</Code><Message>no</Message></Error></ErrorResponse>`))
		}
	}))
	defer srv.Close()
	c := &sdkELBv2{cfg: awssdk.Config{Region: "us-east-1", Credentials: credentials.NewStaticCredentialsProvider("AKID", "SECRET", "")}, endpoint: srv.URL}
	ctx := context.Background()
	lbs, err := c.DescribeLoadBalancers(ctx)
	if err != nil || len(lbs) != 1 || lbs[0].Scheme != "internet-facing" || strings.Join(lbs[0].Subnets, ",") != "subnet-a,subnet-b" || lbs[0].SecurityGroups[0] != "sg-alb" {
		t.Fatalf("lbs = %+v, %v", lbs, err)
	}
	ls, err := c.DescribeListeners(ctx, "arn:lb/1")
	if err != nil || len(ls) != 1 || ls[0].Port != 443 || strings.Join(ls[0].TargetGroups, ",") != "arn:tg/a,arn:tg/b" {
		t.Fatalf("listeners = %+v, %v", ls, err)
	}
	ts, err := c.DescribeTargetHealth(ctx, "arn:tg/a")
	if err != nil || len(ts) != 1 || ts[0].ID != "i-1" || ts[0].Port != 8080 {
		t.Fatalf("targets = %+v, %v", ts, err)
	}
	_, err = c.DescribeTargetGroups(ctx, "arn:lb/1")
	if err == nil || !isAccessDenied(err) {
		t.Fatalf("want AccessDenied, got %v", err)
	}
}

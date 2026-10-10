package reach

import "testing"

func v4Bool(b bool) *bool { return &b }

func v4RT(routes ...Route) *RouteTable {
	return &RouteTable{ID: "rtb-x", Routes: append([]Route{{Destination: "10.0.0.0/16", Target: "local"}}, routes...)}
}

var (
	v4AllowAllRules = []NACLRule{{Number: 100, Protocol: "-1", CIDR: "0.0.0.0/0", Action: "allow"}, {Number: 101, Protocol: "-1", CIDR: "::/0", Action: "allow"}}
	v4IGWv4         = Route{Destination: "0.0.0.0/0", Target: "igw-1", State: "active"}
	v4IGWv6         = Route{Destination: "::/0", Target: "igw-1", State: "active"}
	v4OpenACL       = &NACL{ID: "acl-open", Inbound: v4AllowAllRules, Outbound: v4AllowAllRules}
	v4SGssh         = []SecurityGroup{{ID: "sg-22", Ingress: []SGRule{{Protocol: "tcp", FromPort: 22, ToPort: 22, Sources: []string{"0.0.0.0/0"}}}}}
	v4Tcp22         = Port{"tcp", 22}
)

func v4Inst(sn Subnet, sgs []SecurityGroup) Target {
	return Target{ID: "i-1", Kind: KindInstance, PublicIP: v4Bool(true), Subnets: []Subnet{sn}, SecurityGroups: sgs}
}

func v4PubSubnet(n *NACL) Subnet {
	return Subnet{ID: "subnet-pub", RouteTable: v4RT(v4IGWv4, v4IGWv6), NACL: n}
}

type v4ReachCase struct {
	name string
	doc  string
	t    Target
	p    Port
	want Status
}

func TestV4ReachAdversarial(t *testing.T) {
	naclIn := func(in []NACLRule) *NACL { return &NACL{ID: "acl-t", Inbound: in, Outbound: v4AllowAllRules} }
	naclOut := func(out []NACLRule) *NACL { return &NACL{ID: "acl-t", Inbound: v4AllowAllRules, Outbound: out} }
	privSubnet := Subnet{ID: "subnet-priv", RouteTable: v4RT(Route{Destination: "0.0.0.0/0", Target: "nat-1", State: "active"}), NACL: v4OpenACL}
	alb := &Target{ID: "alb-1", Kind: KindLoadBalancer, Scheme: "internet-facing", LBType: "application", Subnets: []Subnet{v4PubSubnet(v4OpenACL)},
		SecurityGroups: []SecurityGroup{{ID: "sg-alb", Ingress: []SGRule{{Protocol: "tcp", FromPort: 443, ToPort: 443, Sources: []string{"0.0.0.0/0"}}}}}}
	ialb := *alb
	ialb.Scheme = "internal"
	appSG := []SecurityGroup{{ID: "sg-app", Ingress: []SGRule{{Protocol: "tcp", FromPort: 8080, ToPort: 8080, Groups: []string{"sg-alb"}}, {Protocol: "tcp", FromPort: 22, ToPort: 22, Groups: []string{"sg-alb"}}}}}
	behind := func(lb *Target) Target {
		return Target{ID: "i-app", Kind: KindInstance, PublicIP: v4Bool(false), Subnets: []Subnet{privSubnet}, SecurityGroups: appSG,
			FrontedBy: []Frontend{{LB: lb, Listener: Listener{ID: "l-443", Protocol: "HTTPS", Port: 443}, TargetGroup: TargetGroup{ID: "tg", Protocol: "HTTP", Port: 8080}, TargetPort: 8080}}}
	}
	sg6 := []SecurityGroup{{ID: "sg-6", Ingress: []SGRule{{Protocol: "tcp", FromPort: 443, ToPort: 443, Sources: []string{"::/0"}}}}}
	cases := []v4ReachCase{
		{"R01 NACL allow 100 before deny 200 -> reachable", "nacl-rules: lowest number first", v4Inst(v4PubSubnet(naclIn([]NACLRule{{Number: 100, Protocol: "tcp", FromPort: 22, ToPort: 22, CIDR: "0.0.0.0/0", Action: "allow"}, {Number: 200, Protocol: "tcp", FromPort: 22, ToPort: 22, CIDR: "0.0.0.0/0", Action: "deny"}})), v4SGssh), v4Tcp22, StatusReachable},
		{"R02 NACL deny 90 before allow 100 -> blocked", "nacl-rules", v4Inst(v4PubSubnet(naclIn([]NACLRule{{Number: 90, Protocol: "tcp", FromPort: 22, ToPort: 22, CIDR: "0.0.0.0/0", Action: "deny"}, {Number: 100, Protocol: "-1", CIDR: "0.0.0.0/0", Action: "allow"}})), v4SGssh), v4Tcp22, StatusBlocked},
		{"R03 NACL outbound allows only 0-1023 -> ephemeral return blocked", "custom-network-acl ephemeral ports", v4Inst(v4PubSubnet(naclOut([]NACLRule{{Number: 100, Protocol: "tcp", FromPort: 0, ToPort: 1023, CIDR: "0.0.0.0/0", Action: "allow"}})), v4SGssh), v4Tcp22, StatusBlocked},
		{"R04 NACL outbound allows only 443 -> blocked", "ephemeral ports", v4Inst(v4PubSubnet(naclOut([]NACLRule{{Number: 100, Protocol: "tcp", FromPort: 443, ToPort: 443, CIDR: "0.0.0.0/0", Action: "allow"}})), v4SGssh), v4Tcp22, StatusBlocked},
		{"R05 NACL outbound 1024-65535 + stateful SG -> reachable", "ephemeral ports", v4Inst(v4PubSubnet(naclOut([]NACLRule{{Number: 100, Protocol: "tcp", FromPort: 1024, ToPort: 65535, CIDR: "0.0.0.0/0", Action: "allow"}})), v4SGssh), v4Tcp22, StatusReachable},
		{"R06 NACL outbound deny 1024-65535 at 50 then allow all -> blocked", "first match", v4Inst(v4PubSubnet(naclOut([]NACLRule{{Number: 50, Protocol: "tcp", FromPort: 1024, ToPort: 65535, CIDR: "0.0.0.0/0", Action: "deny"}, {Number: 100, Protocol: "-1", CIDR: "0.0.0.0/0", Action: "allow"}})), v4SGssh), v4Tcp22, StatusBlocked},
		{"R07 NAT-only subnet + public IP -> blocked", "vpc-nat-gateway: outbound only", v4Inst(privSubnet, v4SGssh), v4Tcp22, StatusBlocked},
		{"R08 internet-facing ALB -> private target on 8080 -> reachable", "elb", behind(alb), Port{"tcp", 8080}, StatusReachable},
		{"R09 internet-facing ALB -> private target on SSH 22 -> blocked", "elb only listener port", behind(alb), v4Tcp22, StatusBlocked},
		{"R10 internal ALB -> target 8080 -> blocked", "internal scheme private IPs only", behind(&ialb), Port{"tcp", 8080}, StatusBlocked},
		{"R11 IPv6 ::/0 -> igw + SG ::/0 443 -> reachable", "egress-only igw / IPv6 via IGW", v4Inst(v4PubSubnet(v4OpenACL), sg6), Port{"tcp", 443}, StatusReachable},
		{"R12 IPv6 ::/0 -> eigw + SG ::/0 -> blocked", "egress-only-internet-gateway: inbound not allowed",
			v4Inst(Subnet{ID: "s6", RouteTable: v4RT(v4IGWv4, Route{Destination: "::/0", Target: "eigw-1", State: "active"}), NACL: v4OpenACL}, sg6), Port{"tcp", 443}, StatusBlocked},
		{"R13 IPv6 NACL with only v4 rules -> v6 blocked", "NACL IPv6 rules separate",
			v4Inst(v4PubSubnet(&NACL{ID: "acl-v4", Inbound: v4AllowAllRules[:1], Outbound: v4AllowAllRules[:1]}), sg6), Port{"tcp", 443}, StatusBlocked},
		{"R14 prefix-list route dest only (pl- -> igw) -> must not be blocked (unknown)", "docs/reachability.md: prefix lists not expanded",
			v4Inst(Subnet{ID: "spl", RouteTable: v4RT(Route{Destination: "pl-123", Target: "igw-1", State: "active"}), NACL: v4OpenACL}, v4SGssh), v4Tcp22, StatusUnknown},
		{"R15 SG source is a prefix list -> must not be blocked (unknown)", "SG prefix-list source can hold public CIDRs",
			v4Inst(v4PubSubnet(v4OpenACL), []SecurityGroup{{ID: "sg-pl", Ingress: []SGRule{{Protocol: "tcp", FromPort: 22, ToPort: 22, Sources: []string{"pl-abc"}}}}}), v4Tcp22, StatusUnknown},
		{"R16 route table missing -> unknown", "missing data never reachable", v4Inst(Subnet{ID: "s", NACL: v4OpenACL}, v4SGssh), v4Tcp22, StatusUnknown},
		{"R17 more-specific blackhole halves override igw default -> blocked", "route-tables-priority longest prefix",
			v4Inst(Subnet{ID: "s", RouteTable: v4RT(v4IGWv4, Route{Destination: "0.0.0.0/1", Target: "igw-1", State: "blackhole"}, Route{Destination: "128.0.0.0/1", Target: "igw-1", State: "blackhole"}), NACL: v4OpenACL}, v4SGssh), v4Tcp22, StatusBlocked},
		{"R18 more-specific pcx /24 + igw default -> reachable (rest of internet)", "longest prefix",
			v4Inst(Subnet{ID: "s", RouteTable: v4RT(v4IGWv4, Route{Destination: "198.51.100.0/24", Target: "pcx-1", State: "active"}), NACL: v4OpenACL}, v4SGssh), v4Tcp22, StatusReachable},
		{"R19 SG only references another SG -> blocked", "SG source group is not internet",
			v4Inst(v4PubSubnet(v4OpenACL), []SecurityGroup{{ID: "sg-g", Ingress: []SGRule{{Protocol: "tcp", FromPort: 22, ToPort: 22, Groups: []string{"sg-other"}}}}}), v4Tcp22, StatusBlocked},
		{"R20 NACL allow 0-21 does not cover 22 -> blocked", "port range edge",
			v4Inst(v4PubSubnet(naclIn([]NACLRule{{Number: 100, Protocol: "tcp", FromPort: 0, ToPort: 21, CIDR: "0.0.0.0/0", Action: "allow"}})), v4SGssh), v4Tcp22, StatusBlocked},
		{"R21 NACL allow 22-22 -> reachable", "port range edge",
			v4Inst(v4PubSubnet(naclIn([]NACLRule{{Number: 100, Protocol: "tcp", FromPort: 22, ToPort: 22, CIDR: "0.0.0.0/0", Action: "allow"}})), v4SGssh), v4Tcp22, StatusReachable},
		{"R22 protocol -1 everywhere, port 3389 -> reachable", "protocol -1 all",
			v4Inst(v4PubSubnet(v4OpenACL), []SecurityGroup{{ID: "sg-all", Ingress: []SGRule{{Protocol: "-1", Sources: []string{"0.0.0.0/0"}}}}}), Port{"tcp", 3389}, StatusReachable},
		{"R23 RDS publicly_accessible=false in public subnet -> blocked", "USER_VPC.WorkingWithRDSInstanceinaVPC",
			Target{ID: "db", Kind: KindDBInstance, PubliclyAccessible: v4Bool(false), Subnets: []Subnet{v4PubSubnet(v4OpenACL)}, SecurityGroups: []SecurityGroup{{ID: "sg-db", Ingress: []SGRule{{Protocol: "tcp", FromPort: 5432, ToPort: 5432, Sources: []string{"0.0.0.0/0"}}}}}}, Port{"tcp", 5432}, StatusBlocked},
		{"R24 public IP false but instance has IPv6 + ::/0 igw + SG ::/0 IPv6 addresses not collected -> unknown", "IPv6 GUA is reachable via IGW",
			Target{ID: "i-6", Kind: KindInstance, PublicIP: v4Bool(false), Subnets: []Subnet{v4PubSubnet(v4OpenACL)}, SecurityGroups: sg6}, Port{"tcp", 443}, StatusUnknown},
		{"R24b public IP false, IPv6 address assigned, ::/0 igw + SG ::/0 -> reachable", "IPv6 addresses are globally unique and reachable through an IGW route",
			Target{ID: "i-6", Kind: KindInstance, PublicIP: v4Bool(false), IPv6Addresses: []string{"2600:1f18::10"}, Subnets: []Subnet{v4PubSubnet(v4OpenACL)}, SecurityGroups: sg6}, Port{"tcp", 443}, StatusReachable},
		{"R24c public IP false, IPv6 collected as none -> blocked", "no public IPv4 and no IPv6 address",
			Target{ID: "i-6", Kind: KindInstance, PublicIP: v4Bool(false), IPv6Addresses: []string{}, Subnets: []Subnet{v4PubSubnet(v4OpenACL)}, SecurityGroups: sg6}, Port{"tcp", 443}, StatusBlocked},
		{"R24d public IP false, IPv6 assigned, but SG v4-only -> blocked", "IPv6 needs an IPv6 SG source",
			Target{ID: "i-6", Kind: KindInstance, PublicIP: v4Bool(false), IPv6Addresses: []string{"2600:1f18::10"}, Subnets: []Subnet{v4PubSubnet(v4OpenACL)}, SecurityGroups: v4SGssh}, v4Tcp22, StatusBlocked},
		{"R15b SG prefix list via PrefixLists field -> unknown", "SG prefix-list source",
			v4Inst(v4PubSubnet(v4OpenACL), []SecurityGroup{{ID: "sg-pl", Ingress: []SGRule{{Protocol: "tcp", FromPort: 22, ToPort: 22, PrefixLists: []string{"pl-abc"}}}}}), v4Tcp22, StatusUnknown},
		{"R15c SG prefix list plus 0.0.0.0/0 -> reachable", "a definite source decides",
			v4Inst(v4PubSubnet(v4OpenACL), []SecurityGroup{{ID: "sg-pl", Ingress: []SGRule{{Protocol: "tcp", FromPort: 22, ToPort: 22, Sources: []string{"0.0.0.0/0"}, PrefixLists: []string{"pl-abc"}}}}}), v4Tcp22, StatusReachable},
		{"R14b S3 gateway endpoint prefix-list route -> vpce does not change an igw verdict", "gateway endpoint routes carry AWS service ranges only",
			v4Inst(Subnet{ID: "spl", RouteTable: v4RT(v4IGWv4, Route{Destination: "pl-63a5400a", Target: "vpce-1", State: "active"}), NACL: v4OpenACL}, v4SGssh), v4Tcp22, StatusReachable},
		{"R08b internet-facing ALB -> target SG admits only a prefix list -> unknown", "prefix list may hold the LB subnets",
			func() Target {
				tg := behind(alb)
				tg.SecurityGroups = []SecurityGroup{{ID: "sg-app", Ingress: []SGRule{{Protocol: "tcp", FromPort: 8080, ToPort: 8080, PrefixLists: []string{"pl-vpc"}}}}}
				return tg
			}(), Port{"tcp", 8080}, StatusUnknown},
		{"R28b SG tcp 0-65535 is all ports -> reachable on 22", "full range",
			v4Inst(v4PubSubnet(v4OpenACL), []SecurityGroup{{ID: "sgall", Ingress: []SGRule{{Protocol: "tcp", FromPort: 0, ToPort: 65535, Sources: []string{"0.0.0.0/0"}}}}}), v4Tcp22, StatusReachable},
		{"R28c NACL tcp 0-0 does not open 22 -> blocked", "NACL port range literal",
			v4Inst(v4PubSubnet(&NACL{ID: "acl-t", Inbound: []NACLRule{{Number: 100, Protocol: "tcp", FromPort: 0, ToPort: 0, CIDR: "0.0.0.0/0", Action: "allow"}}, Outbound: v4AllowAllRules}), v4SGssh), v4Tcp22, StatusBlocked},
		{"R25 port 0: SG all tcp, NACL allows only 8443 -> reachable", "candidate ports",
			v4Inst(v4PubSubnet(naclIn([]NACLRule{{Number: 100, Protocol: "tcp", FromPort: 8443, ToPort: 8443, CIDR: "0.0.0.0/0", Action: "allow"}})), []SecurityGroup{{ID: "sg", Ingress: []SGRule{{Protocol: "tcp", FromPort: 0, ToPort: 65535, Sources: []string{"0.0.0.0/0"}}}}}), Port{}, StatusReachable},
		{"R26 NLB preserve-client-IP, target SG only VPC CIDR -> blocked", "NLB client IP preservation",
			Target{ID: "i-nlb", Kind: KindInstance, PublicIP: v4Bool(false), Subnets: []Subnet{privSubnet},
				SecurityGroups: []SecurityGroup{{ID: "sg-t", Ingress: []SGRule{{Protocol: "tcp", FromPort: 80, ToPort: 80, Sources: []string{"10.0.0.0/16"}}}}},
				FrontedBy: []Frontend{{LB: &Target{ID: "nlb", Kind: KindLoadBalancer, Scheme: "internet-facing", LBType: "network", Subnets: []Subnet{v4PubSubnet(v4OpenACL)}, SecurityGroups: []SecurityGroup{}},
					Listener: Listener{ID: "l80", Protocol: "TCP", Port: 80}, TargetGroup: TargetGroup{ID: "tg", Protocol: "TCP", Port: 80, PreserveClientIP: true}, TargetPort: 80}}}, Port{"tcp", 80}, StatusBlocked},
		{"R27 ALB in public subnet whose NACL denies 443 -> target blocked", "LB subnet NACL",
			func() Target {
				lb := *alb
				lb.Subnets = []Subnet{v4PubSubnet(naclIn([]NACLRule{{Number: 10, Protocol: "tcp", FromPort: 443, ToPort: 443, CIDR: "0.0.0.0/0", Action: "deny"}, {Number: 100, Protocol: "-1", CIDR: "0.0.0.0/0", Action: "allow"}}))}
				return behind(&lb)
			}(), Port{"tcp", 8080}, StatusBlocked},
		{"R28 SG tcp 0-0 (port 0 only in AWS) on port 22 -> blocked", "SG port range from/to literal",
			v4Inst(v4PubSubnet(v4OpenACL), []SecurityGroup{{ID: "sg0", Ingress: []SGRule{{Protocol: "tcp", FromPort: 0, ToPort: 0, Sources: []string{"0.0.0.0/0"}}}}}), v4Tcp22, StatusBlocked},
		{"R29 route 0.0.0.0/0 -> vgw (VPN) only -> unknown", "docs limit", v4Inst(Subnet{ID: "s", RouteTable: v4RT(Route{Destination: "0.0.0.0/0", Target: "vgw-1", State: "active"}), NACL: v4OpenACL}, v4SGssh), v4Tcp22, StatusUnknown},
		{"R30 NACL inbound protocol number 6", "protocol by number", v4Inst(v4PubSubnet(naclIn([]NACLRule{{Number: 100, Protocol: "6", FromPort: 22, ToPort: 22, CIDR: "0.0.0.0/0", Action: "allow"}})), v4SGssh), v4Tcp22, StatusReachable},
		{"R31 NACL allow only udp 22 -> tcp 22 blocked", "protocol mismatch", v4Inst(v4PubSubnet(naclIn([]NACLRule{{Number: 100, Protocol: "udp", FromPort: 22, ToPort: 22, CIDR: "0.0.0.0/0", Action: "allow"}})), v4SGssh), v4Tcp22, StatusBlocked},
	}
	pass, fail := 0, 0
	for _, c := range cases {
		r := Reachable(c.t, Internet(), c.p)
		st := "PASS"
		if r.Status != c.want {
			st = "FAIL"
			fail++
			t.Errorf("%s: want %s got %s blockers=%q unknown=%q", c.name, c.want, r.Status, r.Blocker(), r.UnknownReason())
		} else {
			pass++
		}
		t.Logf("V4ROW|%s|%s|%s|%s|w=%s port=%s", c.name, c.want, r.Status, st, r.Width, r.Port)
	}
	t.Logf("pass=%d fail=%d", pass, fail)
}

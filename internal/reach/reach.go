// Package reach is nimbus's effective internet-reachability model (plan v3 §3.2.2, P2-REACH v1).
//
// Reachable is a pure, deterministic evaluator: given a target's network facts (public address,
// subnet route table, network ACL, security groups, load-balancer front ends, managed-endpoint
// flags) it answers "can a host on the internet open a connection to this target on this port?"
// with per-hop evidence: the hops that let traffic through (Path), the controls that stop it
// (Blockers) and the layers it could not evaluate for lack of data (Unknown).
//
// The model is published in docs/reachability.md. Three rules matter to consumers:
//   - Every layer can only remove sources, so a definite blocker is decisive even when other
//     layers are unknown (a deny is a deny).
//   - Missing data never makes a target reachable: no blocker plus any unknown layer = unknown.
//   - Width (wide | narrow | trusted | private) is computed on the sources that survive every
//     layer, so a NACL that admits only a partner range narrows a 0.0.0.0/0 security group.
//
// The package imports only the standard library and internal/model (vocabulary), so
// internal/graph can call it without an import cycle.
package reach

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// Status is the verdict.
type Status string

const (
	StatusReachable Status = "reachable"
	StatusBlocked   Status = "blocked"
	StatusUnknown   Status = "unknown"
)

// Kind is the target's reachability model.
type Kind string

const (
	KindInstance        Kind = "instance"          // EC2 instance (primary ENI)
	KindNetworkIface    Kind = "network_interface" // ENI with its own public IP / EIP
	KindDBInstance      Kind = "db_instance"       // RDS: PubliclyAccessible + subnet group
	KindLoadBalancer    Kind = "load_balancer"     // ALB / NLB / CLB node
	KindFunctionURL     Kind = "function_url"      // Lambda function URL (no VPC network layer)
	KindAPIGateway      Kind = "api_gateway"       // API Gateway (no VPC network layer unless PRIVATE)
	KindEKSEndpoint     Kind = "eks_endpoint"      // EKS API server endpoint
	KindServiceEndpoint Kind = "service_endpoint"  // S3 / other AWS-managed public endpoints
	KindVM              Kind = "vm"                // Azure / GCP VM: NSG / firewall only in v1
)

// Hop kinds (Hop.Kind).
const (
	HopPublicIP        = "public_ip"
	HopRDSPublic       = "rds_public_flag"
	HopRoute           = "route"
	HopNACLInbound     = "nacl_inbound"
	HopNACLOutbound    = "nacl_outbound"
	HopSecurityGroup   = "security_group"
	HopLoadBalancer    = "load_balancer"
	HopListener        = "listener"
	HopTargetGroup     = "target_group"
	HopManagedEndpoint = "managed_endpoint"
	HopEKSEndpoint     = "eks_endpoint"
	HopSubnet          = "subnet"
	HopModel           = "model"
)

// Hop is one piece of evidence: the control, its id, and why it lets traffic through / stops it.
type Hop struct {
	Kind    string `json:"kind" yaml:"kind"`
	ID      string `json:"id,omitempty" yaml:"id"`
	Because string `json:"because" yaml:"because"`

	inferred bool // derived from a summary / scanner attribute rather than the control itself
}

// Port is a protocol and port. Number 0 means "any port the target admits": Reachable then
// evaluates every candidate port and returns the best verdict.
type Port struct {
	Protocol string `json:"protocol" yaml:"protocol"`
	Number   int    `json:"number" yaml:"number"`
}

func (p Port) String() string {
	proto := normProto(p.Protocol)
	if proto == "" || proto == "-1" {
		proto = "tcp"
	}
	if p.Number == 0 {
		return "any/" + proto
	}
	return fmt.Sprintf("%d/%s", p.Number, proto)
}

// Endpoint is where traffic comes from. v1 evaluates the internet only.
type Endpoint struct {
	Kind         string   `json:"kind"`
	TrustedCIDRs []string `json:"trusted_cidrs,omitempty"`
}

// Internet is the anonymous internet; trusted CIDRs turn an exposure whose every surviving
// source lies inside them into width "trusted" (Microsoft Defender trusted IPs).
func Internet(trusted ...string) Endpoint { return Endpoint{Kind: "internet", TrustedCIDRs: trusted} }

// Target is everything the model knows about one resource. Pointers and nil slices mean
// "not collected"; an empty non-nil slice means "collected, none".
type Target struct {
	ID       string `json:"id" yaml:"id"`
	Kind     Kind   `json:"kind" yaml:"kind"`
	Provider string `json:"provider,omitempty" yaml:"provider"`

	// Address layer (instance / ENI / VM).
	PublicIP      *bool  `json:"public_ip,omitempty" yaml:"public_ip"`
	PublicAddress string `json:"public_address,omitempty" yaml:"public_address"`
	// IPv6Addresses are the target's IPv6 addresses (globally unique, so internet-routable
	// through an IGW ::/0 route). nil = not collected; empty = collected, none.
	IPv6Addresses []string `json:"ipv6_addresses,omitempty" yaml:"ipv6_addresses"`
	// RDS.
	PubliclyAccessible *bool `json:"publicly_accessible,omitempty" yaml:"publicly_accessible"`
	// Load balancer.
	Scheme string `json:"scheme,omitempty" yaml:"scheme"`   // internet-facing | internal
	LBType string `json:"lb_type,omitempty" yaml:"lb_type"` // application | network | classic
	// Lambda URL / API Gateway / EKS.
	AuthType          string   `json:"auth_type,omitempty" yaml:"auth_type"`
	EndpointType      string   `json:"endpoint_type,omitempty" yaml:"endpoint_type"` // EDGE | REGIONAL | PRIVATE
	EndpointPublic    *bool    `json:"endpoint_public,omitempty" yaml:"endpoint_public"`
	PublicAccessCIDRs []string `json:"public_access_cidrs,omitempty" yaml:"public_access_cidrs"`

	// Subnets: one for an instance / ENI, the DB subnet group for RDS, the enabled subnets of
	// a load balancer. nil = not known.
	Subnets []Subnet `json:"subnets,omitempty" yaml:"subnets"`
	// SecurityGroups attached (nil = rules not collected). Sources is the fallback when only
	// the exposure's public sources are known (the exposes edge's exposure_cidrs).
	SecurityGroups []SecurityGroup `json:"security_groups,omitempty" yaml:"security_groups"`
	Sources        []string        `json:"sources,omitempty" yaml:"sources"`
	// Ports are candidate ports when the rules are not known (the exposes edge's "ports").
	Ports []Port `json:"ports,omitempty" yaml:"ports"`
	// FrontedBy lists the load-balancer listeners that forward to this target.
	FrontedBy []Frontend `json:"fronted_by,omitempty" yaml:"fronted_by"`
}

// Subnet carries the subnet's route table and network ACL.
type Subnet struct {
	ID         string      `json:"id" yaml:"id"`
	CIDR       string      `json:"cidr,omitempty" yaml:"cidr"`
	RouteTable *RouteTable `json:"route_table,omitempty" yaml:"route_table"`
	// IGWRoute is a summary fact (native ingest "internet_gateway_route") used when the
	// route table itself is not known.
	IGWRoute *bool `json:"igw_route,omitempty" yaml:"igw_route"`
	NACL     *NACL `json:"nacl,omitempty" yaml:"nacl"`
}

// RouteTable is the subnet's effective route table (explicit association or the VPC main table).
type RouteTable struct {
	ID     string  `json:"id" yaml:"id"`
	Routes []Route `json:"routes" yaml:"routes"`
}

// Route is one route: destination CIDR (or prefix list id) -> target id (igw-, nat-, local, ...).
type Route struct {
	Destination string `json:"destination" yaml:"destination"`
	Target      string `json:"target" yaml:"target"`
	State       string `json:"state,omitempty" yaml:"state"` // active | blackhole
}

// NACL is a network ACL; Outbound nil = outbound rules not collected.
type NACL struct {
	ID       string     `json:"id" yaml:"id"`
	Inbound  []NACLRule `json:"inbound" yaml:"inbound"`
	Outbound []NACLRule `json:"outbound" yaml:"outbound"`
}

// NACLRule is one numbered rule. Protocol "-1" is all traffic; ports are ignored for it.
type NACLRule struct {
	Number   int    `json:"rule" yaml:"rule"`
	Protocol string `json:"protocol" yaml:"protocol"`
	FromPort int    `json:"from,omitempty" yaml:"from"`
	ToPort   int    `json:"to,omitempty" yaml:"to"`
	CIDR     string `json:"cidr" yaml:"cidr"`
	Action   string `json:"action" yaml:"action"` // allow | deny
}

// SecurityGroup is a group and its ingress rules.
type SecurityGroup struct {
	ID      string   `json:"id" yaml:"id"`
	Ingress []SGRule `json:"ingress" yaml:"ingress"`
}

// SGRule admits Sources (CIDRs) and Groups (source security groups) on a protocol / port range.
type SGRule struct {
	Protocol string   `json:"protocol" yaml:"protocol"`
	FromPort int      `json:"from,omitempty" yaml:"from"`
	ToPort   int      `json:"to,omitempty" yaml:"to"`
	Sources  []string `json:"sources,omitempty" yaml:"sources"`
	Groups   []string `json:"groups,omitempty" yaml:"groups"`
	// PrefixLists are managed prefix-list sources (pl-…). Their CIDRs are not expanded in
	// v1, so a rule whose only internet source is a prefix list leaves the verdict unknown.
	PrefixLists []string `json:"prefix_lists,omitempty" yaml:"prefix_lists"`
}

// Frontend is one load-balancer listener -> target group -> this target.
type Frontend struct {
	LB          *Target     `json:"lb" yaml:"lb"`
	Listener    Listener    `json:"listener" yaml:"listener"`
	TargetGroup TargetGroup `json:"target_group" yaml:"target_group"`
	// TargetPort is the port traffic reaches the target on (the registration port, else the
	// target group port).
	TargetPort int `json:"target_port" yaml:"target_port"`
}

type Listener struct {
	ID       string `json:"id" yaml:"id"`
	Protocol string `json:"protocol" yaml:"protocol"`
	Port     int    `json:"port" yaml:"port"`
}

type TargetGroup struct {
	ID               string `json:"id" yaml:"id"`
	Protocol         string `json:"protocol" yaml:"protocol"`
	Port             int    `json:"port" yaml:"port"`
	PreserveClientIP bool   `json:"preserve_client_ip,omitempty" yaml:"preserve_client_ip"`
}

// Result is the verdict with its evidence.
type Result struct {
	Reachable bool   `json:"reachable"`
	Status    Status `json:"status"`
	// Width of the surviving sources: wide | narrow | trusted (reachable), private (no public source).
	Width string `json:"width,omitempty"`
	// Port evaluated (for Number 0 requests: the port of the returned verdict).
	Port Port `json:"port"`
	// Sources that reach the target after every layer (CIDR cover).
	Sources  []string `json:"sources,omitempty"`
	Path     []Hop    `json:"path,omitempty"`
	Blockers []Hop    `json:"blockers,omitempty"`
	Unknown  []Hop    `json:"unknown,omitempty"`
	// Confidence uses the edge vocabulary: verified (every deciding fact is a collected
	// control), inferred (a summary / scanner fact decided it), hint (unknown).
	Confidence string `json:"confidence"`
}

// Blocker is the joined because of every blocker ("" when none).
func (r Result) Blocker() string {
	var parts []string
	for _, b := range r.Blockers {
		parts = append(parts, b.Because)
	}
	return strings.Join(parts, "; ")
}

// UnknownReason is the joined because of every unknown layer.
func (r Result) UnknownReason() string {
	var parts []string
	for _, b := range r.Unknown {
		parts = append(parts, b.Because)
	}
	return strings.Join(parts, "; ")
}

// String renders the result as indented JSON (test dumps, determinism checks).
func (r Result) String() string {
	b, _ := json.MarshalIndent(r, "", "  ")
	return string(b)
}

// Confidence vocabulary (model.Confidence values).
var (
	confVerified = string(model.ConfidenceVerified)
	confInferred = string(model.ConfidenceInferred)
	confHint     = string(model.ConfidenceHint)
)

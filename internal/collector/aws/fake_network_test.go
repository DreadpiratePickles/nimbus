package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

// fakeNet is the network side of fakeAWS (zero value = collected, nothing there).
type fakeNet struct {
	routeTables []ec2types.RouteTable
	nacls       []ec2types.NetworkAcl
	subnets     []ec2types.Subnet
	enis        []ec2types.NetworkInterface
	igws        []ec2types.InternetGateway
	nats        []ec2types.NatGateway
	lbs         []ELBLoadBalancer
	listeners   map[string][]ELBListener
	tgs         map[string][]ELBTargetGroup
	targets     map[string][]ELBTarget
}

func (f *fakeAWS) DescribeRouteTables(context.Context, *ec2.DescribeRouteTablesInput, ...func(*ec2.Options)) (*ec2.DescribeRouteTablesOutput, error) {
	if err := f.err("DescribeRouteTables"); err != nil {
		return nil, err
	}
	return &ec2.DescribeRouteTablesOutput{RouteTables: f.net.routeTables}, nil
}
func (f *fakeAWS) DescribeNetworkAcls(context.Context, *ec2.DescribeNetworkAclsInput, ...func(*ec2.Options)) (*ec2.DescribeNetworkAclsOutput, error) {
	if err := f.err("DescribeNetworkAcls"); err != nil {
		return nil, err
	}
	return &ec2.DescribeNetworkAclsOutput{NetworkAcls: f.net.nacls}, nil
}
func (f *fakeAWS) DescribeSubnets(context.Context, *ec2.DescribeSubnetsInput, ...func(*ec2.Options)) (*ec2.DescribeSubnetsOutput, error) {
	if err := f.err("DescribeSubnets"); err != nil {
		return nil, err
	}
	return &ec2.DescribeSubnetsOutput{Subnets: f.net.subnets}, nil
}
func (f *fakeAWS) DescribeNetworkInterfaces(context.Context, *ec2.DescribeNetworkInterfacesInput, ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error) {
	if err := f.err("DescribeNetworkInterfaces"); err != nil {
		return nil, err
	}
	return &ec2.DescribeNetworkInterfacesOutput{NetworkInterfaces: f.net.enis}, nil
}
func (f *fakeAWS) DescribeInternetGateways(context.Context, *ec2.DescribeInternetGatewaysInput, ...func(*ec2.Options)) (*ec2.DescribeInternetGatewaysOutput, error) {
	if err := f.err("DescribeInternetGateways"); err != nil {
		return nil, err
	}
	return &ec2.DescribeInternetGatewaysOutput{InternetGateways: f.net.igws}, nil
}
func (f *fakeAWS) DescribeNatGateways(context.Context, *ec2.DescribeNatGatewaysInput, ...func(*ec2.Options)) (*ec2.DescribeNatGatewaysOutput, error) {
	if err := f.err("DescribeNatGateways"); err != nil {
		return nil, err
	}
	return &ec2.DescribeNatGatewaysOutput{NatGateways: f.net.nats}, nil
}

// ELBv2
func (f *fakeAWS) DescribeLoadBalancers(context.Context) ([]ELBLoadBalancer, error) {
	if err := f.err("DescribeLoadBalancers"); err != nil {
		return nil, err
	}
	return f.net.lbs, nil
}
func (f *fakeAWS) DescribeListeners(_ context.Context, lb string) ([]ELBListener, error) {
	if err := f.err("DescribeListeners"); err != nil {
		return nil, err
	}
	return f.net.listeners[lb], nil
}
func (f *fakeAWS) DescribeTargetGroups(_ context.Context, lb string) ([]ELBTargetGroup, error) {
	if err := f.err("DescribeTargetGroups"); err != nil {
		return nil, err
	}
	return f.net.tgs[lb], nil
}
func (f *fakeAWS) DescribeTargetHealth(_ context.Context, tg string) ([]ELBTarget, error) {
	if err := f.err("DescribeTargetHealth"); err != nil {
		return nil, err
	}
	return f.net.targets[tg], nil
}

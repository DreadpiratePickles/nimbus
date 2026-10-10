package aws

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/smithy-go"
)

// ELBLoadBalancer is one Elastic Load Balancing v2 load balancer (ALB / NLB / GWLB).
type ELBLoadBalancer struct {
	ARN, Name, DNSName string
	Scheme             string // internet-facing | internal
	Type               string // application | network | gateway
	VPCID              string
	Subnets            []string
	SecurityGroups     []string
}

// ELBListener is one listener with the target groups its default actions forward to.
type ELBListener struct {
	ARN, Protocol string
	Port          int
	TargetGroups  []string
}

// ELBTargetGroup is one target group of a load balancer.
type ELBTargetGroup struct {
	ARN, Name, Protocol string
	TargetType          string // instance | ip | lambda | alb
	Port                int
}

// ELBTarget is one registered target (instance id, IP, Lambda ARN or ALB ARN) and its port.
type ELBTarget struct {
	ID   string
	Port int
}

// ELBv2API is the read-only subset of Elastic Load Balancing v2 the reachability model needs
// (elasticloadbalancing:Describe*). The SDK module is not a dependency: sdkELBv2 calls the
// query API with SigV4, like s3control.go / scp.go.
type ELBv2API interface {
	DescribeLoadBalancers(ctx context.Context) ([]ELBLoadBalancer, error)
	DescribeListeners(ctx context.Context, loadBalancerARN string) ([]ELBListener, error)
	DescribeTargetGroups(ctx context.Context, loadBalancerARN string) ([]ELBTargetGroup, error)
	DescribeTargetHealth(ctx context.Context, targetGroupARN string) ([]ELBTarget, error)
}

type sdkELBv2 struct {
	cfg awssdk.Config
	// endpoint overrides https://elasticloadbalancing.{region}.amazonaws.com (tests).
	endpoint string
}

const elbv2Version = "2015-12-01"

func (c *sdkELBv2) call(ctx context.Context, action string, params url.Values, out any) error {
	region := c.cfg.Region
	if region == "" {
		region = "us-east-1"
	}
	base := c.endpoint
	if base == "" {
		base = fmt.Sprintf("https://elasticloadbalancing.%s.amazonaws.com/", region)
	}
	if params == nil {
		params = url.Values{}
	}
	params.Set("Action", action)
	params.Set("Version", elbv2Version)
	body := params.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base, strings.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	sum := sha256.Sum256([]byte(body))
	hash := hex.EncodeToString(sum[:])
	if c.cfg.Credentials == nil {
		return fmt.Errorf("elasticloadbalancing: no credentials")
	}
	creds, err := c.cfg.Credentials.Retrieve(ctx)
	if err != nil {
		return err
	}
	if err := v4.NewSigner().SignHTTP(ctx, creds, req, hash, "elasticloadbalancing", region, time.Now().UTC()); err != nil {
		return err
	}
	resp, err := signedDoer(c.cfg.HTTPClient).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	return decodeELBv2(resp.StatusCode, raw, out)
}

// decodeELBv2 turns a query-API response into out, or an API error carrying the AWS code
// (AccessDenied, Throttling, ...) so coverage rows classify it.
func decodeELBv2(status int, raw []byte, out any) error {
	if status != http.StatusOK {
		var e struct {
			Error struct {
				Code    string `xml:"Code"`
				Message string `xml:"Message"`
			} `xml:"Error"`
		}
		_ = xml.Unmarshal(raw, &e)
		code := e.Error.Code
		if code == "" {
			code = http.StatusText(status)
		}
		return &smithy.GenericAPIError{Code: code, Message: fmt.Sprintf("HTTP %d: %s", status, e.Error.Message)}
	}
	if err := xml.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("elasticloadbalancing: decode: %w", err)
	}
	return nil
}

func (c *sdkELBv2) DescribeLoadBalancers(ctx context.Context) ([]ELBLoadBalancer, error) {
	var out []ELBLoadBalancer
	marker := ""
	var pages pageTokens
	for {
		p := url.Values{}
		if marker != "" {
			p.Set("Marker", marker)
		}
		var r struct {
			LBs []struct {
				ARN     string `xml:"LoadBalancerArn"`
				Name    string `xml:"LoadBalancerName"`
				DNS     string `xml:"DNSName"`
				Scheme  string `xml:"Scheme"`
				Type    string `xml:"Type"`
				VPC     string `xml:"VpcId"`
				Subnets []struct {
					SubnetID string `xml:"SubnetId"`
				} `xml:"AvailabilityZones>member"`
				SGs []string `xml:"SecurityGroups>member"`
			} `xml:"DescribeLoadBalancersResult>LoadBalancers>member"`
			Next string `xml:"DescribeLoadBalancersResult>NextMarker"`
		}
		if err := c.call(ctx, "DescribeLoadBalancers", p, &r); err != nil {
			return out, err
		}
		for _, lb := range r.LBs {
			x := ELBLoadBalancer{ARN: lb.ARN, Name: lb.Name, DNSName: lb.DNS, Scheme: lb.Scheme, Type: lb.Type, VPCID: lb.VPC, SecurityGroups: lb.SGs}
			if x.SecurityGroups == nil {
				x.SecurityGroups = []string{}
			}
			for _, s := range lb.Subnets {
				x.Subnets = append(x.Subnets, s.SubnetID)
			}
			out = append(out, x)
		}
		if r.Next == "" {
			return out, nil
		}
		if err := pages.next("elasticloadbalancing:DescribeLoadBalancers", r.Next); err != nil {
			return out, err
		}
		marker = r.Next
	}
}

func (c *sdkELBv2) DescribeListeners(ctx context.Context, lbARN string) ([]ELBListener, error) {
	var out []ELBListener
	marker := ""
	var pages pageTokens
	for {
		p := url.Values{"LoadBalancerArn": {lbARN}}
		if marker != "" {
			p.Set("Marker", marker)
		}
		var r struct {
			Listeners []struct {
				ARN      string `xml:"ListenerArn"`
				Protocol string `xml:"Protocol"`
				Port     int    `xml:"Port"`
				Actions  []struct {
					TG  string   `xml:"TargetGroupArn"`
					TGs []string `xml:"ForwardConfig>TargetGroups>member>TargetGroupArn"`
				} `xml:"DefaultActions>member"`
			} `xml:"DescribeListenersResult>Listeners>member"`
			Next string `xml:"DescribeListenersResult>NextMarker"`
		}
		if err := c.call(ctx, "DescribeListeners", p, &r); err != nil {
			return out, err
		}
		for _, l := range r.Listeners {
			x := ELBListener{ARN: l.ARN, Protocol: l.Protocol, Port: l.Port}
			for _, a := range l.Actions {
				if a.TG != "" {
					x.TargetGroups = append(x.TargetGroups, a.TG)
				}
				x.TargetGroups = append(x.TargetGroups, a.TGs...)
			}
			x.TargetGroups = dedupe(x.TargetGroups)
			out = append(out, x)
		}
		if r.Next == "" {
			return out, nil
		}
		if err := pages.next("elasticloadbalancing:DescribeListeners", r.Next); err != nil {
			return out, err
		}
		marker = r.Next
	}
}

func (c *sdkELBv2) DescribeTargetGroups(ctx context.Context, lbARN string) ([]ELBTargetGroup, error) {
	var out []ELBTargetGroup
	marker := ""
	var pages pageTokens
	for {
		p := url.Values{"LoadBalancerArn": {lbARN}}
		if marker != "" {
			p.Set("Marker", marker)
		}
		var r struct {
			TGs []struct {
				ARN        string `xml:"TargetGroupArn"`
				Name       string `xml:"TargetGroupName"`
				Protocol   string `xml:"Protocol"`
				Port       int    `xml:"Port"`
				TargetType string `xml:"TargetType"`
			} `xml:"DescribeTargetGroupsResult>TargetGroups>member"`
			Next string `xml:"DescribeTargetGroupsResult>NextMarker"`
		}
		if err := c.call(ctx, "DescribeTargetGroups", p, &r); err != nil {
			return out, err
		}
		for _, t := range r.TGs {
			out = append(out, ELBTargetGroup{ARN: t.ARN, Name: t.Name, Protocol: t.Protocol, Port: t.Port, TargetType: t.TargetType})
		}
		if r.Next == "" {
			return out, nil
		}
		if err := pages.next("elasticloadbalancing:DescribeTargetGroups", r.Next); err != nil {
			return out, err
		}
		marker = r.Next
	}
}

func (c *sdkELBv2) DescribeTargetHealth(ctx context.Context, tgARN string) ([]ELBTarget, error) {
	var r struct {
		Targets []struct {
			ID   string `xml:"Target>Id"`
			Port int    `xml:"Target>Port"`
		} `xml:"DescribeTargetHealthResult>TargetHealthDescriptions>member"`
	}
	if err := c.call(ctx, "DescribeTargetHealth", url.Values{"TargetGroupArn": {tgARN}}, &r); err != nil {
		return nil, err
	}
	out := make([]ELBTarget, 0, len(r.Targets))
	for _, t := range r.Targets {
		out = append(out, ELBTarget{ID: t.ID, Port: t.Port})
	}
	return out, nil
}

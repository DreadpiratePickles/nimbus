package cost

import (
	"encoding/json"
	"math"
	"strings"
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/collector/core"
	"github.com/DreadpiratePickles/nimbus/internal/graph"
	"github.com/DreadpiratePickles/nimbus/internal/model"
)

func TestPriceLookup(t *testing.T) {
	cases := []struct {
		provider, typ string
		want          float64
		ok            bool
	}{
		{"aws", "t3.micro", 0.0104, true},
		{"AWS", "m5.2xlarge", 0.384, true},
		{"azure", "standard_d4s_v5", 0.192, true},
		{"gcp", "e2-standard-4", 0.134, true},
		{"gcp", "https://www.googleapis.com/compute/v1/projects/p/zones/us-central1-a/machineTypes/n1-standard-2", 0.095, true},
		{"aws", "x9.mega", 0, false},
	}
	for _, c := range cases {
		got, ok := Price(c.provider, c.typ)
		if ok != c.ok || got != c.want {
			t.Errorf("Price(%s,%s)=%v,%v want %v,%v", c.provider, c.typ, got, ok, c.want, c.ok)
		}
	}
}

func TestStorageAndIPPrices(t *testing.T) {
	p := DefaultPricing()
	cases := []struct {
		name string
		got  float64
		want float64
	}{
		{"gp3", p.StorageGB("aws", "gp3"), 0.08},
		{"aws default gp2", p.StorageGB("aws", ""), 0.10},
		{"aws unknown class -> default", p.StorageGB("aws", "weird"), 0.10},
		{"azure premium", p.StorageGB("azure", "Premium_LRS"), 0.15},
		{"azure default", p.StorageGB("azure", ""), 0.075},
		{"gcp pd-ssd", p.StorageGB("gcp", "pd-ssd"), 0.17},
		{"gcp default", p.StorageGB("gcp", ""), 0.04},
		{"aws eip", p.IP("aws"), 3.60},
		{"azure ip", p.IP("azure"), 3.65},
		{"gcp ip", p.IP("gcp"), 7.30},
		{"gcp egress", p.Egress("gcp"), 0.12},
	}
	for _, c := range cases {
		if math.Abs(c.got-c.want) > 1e-9 {
			t.Errorf("%s: got %v want %v", c.name, c.got, c.want)
		}
	}
}

func TestDownsize(t *testing.T) {
	cases := []struct {
		provider, typ, want string
		ok                  bool
	}{
		{"aws", "t3.large", "t3.medium", true},
		{"aws", "m5.2xlarge", "m5.xlarge", true},
		{"aws", "c5.12xlarge", "c5.9xlarge", true},
		{"aws", "t3.nano", "", false},
		{"azure", "Standard_D4s_v5", "Standard_D2s_v5", true},
		{"azure", "Standard_B2ms", "Standard_B1ms", true},
		{"azure", "Standard_E8s_v3", "Standard_E4s_v3", true},
		{"gcp", "e2-standard-2", "e2-medium", true},
		{"gcp", "n2-standard-8", "n2-standard-4", true},
		{"gcp", "n1-standard-1", "", false},
		{"aws", "unknown.large", "", false},
	}
	p := DefaultPricing()
	for _, c := range cases {
		got, _, ok := p.Downsize(c.provider, c.typ)
		if got != c.want || ok != c.ok {
			t.Errorf("Downsize(%s,%s)=%q,%v want %q,%v", c.provider, c.typ, got, ok, c.want, c.ok)
		}
	}
}

func TestItemPricing(t *testing.T) {
	cases := []struct {
		name     string
		sig      core.CostSignal
		category string
		savings  float64
	}{
		{"ebs gp2 100GB", core.CostSignal{Provider: "aws", Kind: core.KindUnattachedVolume, SizeGB: 100, Attributes: map[string]any{"volume_type": "gp2"}}, CategoryZombie, 10},
		{"ebs gp3 default attr", core.CostSignal{Provider: "aws", Kind: core.KindUnattachedVolume, SizeGB: 50, Attributes: map[string]any{"volume_type": "gp3"}}, CategoryZombie, 4},
		{"azure disk sku", core.CostSignal{Provider: "azure", Kind: core.KindUnattachedVolume, SizeGB: 128, Attributes: map[string]any{"sku": "Premium_LRS"}}, CategoryZombie, 19.2},
		{"gcp disk_type", core.CostSignal{Provider: "gcp", Kind: core.KindUnattachedVolume, SizeGB: 100, Attributes: map[string]any{"disk_type": "pd-ssd"}}, CategoryZombie, 17},
		{"eip", core.CostSignal{Provider: "aws", Kind: core.KindUnassociatedIP}, CategoryZombie, 3.6},
		{"gcp static ip", core.CostSignal{Provider: "gcp", Kind: core.KindUnassociatedIP}, CategoryZombie, 7.3},
		{"stopped w/ volume_gb", core.CostSignal{Provider: "aws", Kind: core.KindStoppedInstance, InstanceType: "m5.large", Attributes: map[string]any{"volume_gb": 200}}, CategoryZombie, 20},
		{"stopped default 8GB", core.CostSignal{Provider: "aws", Kind: core.KindStoppedInstance}, CategoryZombie, 0.8},
		{"idle t3.large", core.CostSignal{Provider: "aws", Kind: core.KindIdleInstance, InstanceType: "t3.large", AvgCPU: 1.2}, CategoryZombie, 60.74},
		{"idle uses MonthlySpend", core.CostSignal{Provider: "aws", Kind: core.KindIdleInstance, InstanceType: "t3.large", MonthlySpend: 99}, CategoryZombie, 99},
		{"oversized m5.2xlarge", core.CostSignal{Provider: "aws", Kind: core.KindOversizedInstance, InstanceType: "m5.2xlarge", AvgCPU: 9}, CategoryRightsizing, 140.16},
		{"oversized azure D4s", core.CostSignal{Provider: "azure", Kind: core.KindOversizedInstance, InstanceType: "Standard_D4s_v5"}, CategoryRightsizing, 70.08},
		{"oversized unknown family halves spend", core.CostSignal{Provider: "aws", Kind: core.KindOversizedInstance, InstanceType: "x1e.32xlarge", MonthlySpend: 1000}, CategoryRightsizing, 500},
		{"oversized smallest halves", core.CostSignal{Provider: "gcp", Kind: core.KindOversizedInstance, InstanceType: "n1-standard-1"}, CategoryRightsizing, 17.34},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := Analyze([]core.CostSignal{c.sig}, nil, nil, Options{})
			items := append(r.Zombies, r.Rightsizing...)
			if len(items) != 1 {
				t.Fatalf("want 1 item, got %d", len(items))
			}
			if items[0].Category != c.category {
				t.Errorf("category %s want %s", items[0].Category, c.category)
			}
			if math.Abs(items[0].MonthlySavings-c.savings) > 0.01 {
				t.Errorf("savings %v want %v", items[0].MonthlySavings, c.savings)
			}
			if math.Abs(r.TotalMonthlySavings-c.savings) > 0.01 {
				t.Errorf("total %v want %v", r.TotalMonthlySavings, c.savings)
			}
		})
	}
}

func TestBreachProbability(t *testing.T) {
	cases := []struct{ score, want float64 }{
		{0, 0}, {-5, 0}, {50, 1 - math.Exp(-1)}, {100, 1 - math.Exp(-2)},
	}
	for _, c := range cases {
		if got := BreachProbability(c.score); math.Abs(got-c.want) > 1e-12 {
			t.Errorf("p(%v)=%v want %v", c.score, got, c.want)
		}
	}
}

func TestMoney(t *testing.T) {
	cases := map[float64]string{0: "$0", 10.8: "$11", 2340.4: "$2,340", 8900: "$8,900", 1234567.6: "$1,234,568", 999.5: "$1,000", -42: "-$42"}
	for in, want := range cases {
		if got := Money(in); got != want {
			t.Errorf("Money(%v)=%s want %s", in, got, want)
		}
	}
}

// fixture: 5 public S3 buckets, one with 340/month egress; two attack paths totalling score 50.
func fixture() ([]core.CostSignal, *graph.Graph, []model.AttackPath, []model.Finding) {
	g := graph.New()
	var findings []model.Finding
	for i, b := range []string{"b1", "b2", "b3", "b4", "b5"} {
		id := "arn:aws:s3:::" + b
		fid := "f" + string(rune('1'+i))
		g.AddNode(&graph.Node{ID: id, Type: "aws_s3_bucket", Provider: "aws", Account: "111", FindingIDs: []string{fid}, Weaknesses: []string{"PUBLIC_DATA_STORE"}})
		g.AddEdge(graph.InternetNodeID, id, graph.EdgeExposes, nil)
		findings = append(findings, model.Finding{ID: fid, CanonicalID: "S3_PUBLIC_BUCKET", Status: model.Fail, Resource: model.Resource{ID: id}})
	}
	g.AddNode(&graph.Node{ID: "i-1", Type: "aws_instance", Provider: "aws", Account: "111"}) // private: no win
	findings = append(findings, model.Finding{ID: "x1", CanonicalID: "EC2_IMDSV1", Status: model.Fail, Resource: model.Resource{ID: "i-1"}})
	paths := []model.AttackPath{
		{ID: "p1", Score: 42, FindingIDs: []string{"f1", "x1"}},
		{ID: "p2", Score: 8, Steps: []model.Step{{FindingID: "x2", Weakness: "NO_MFA", Resource: "arn:aws:iam::111:user/bob"}}},
	}
	signals := []core.CostSignal{
		{Provider: "aws", Account: "111", ResourceID: "vol-1", Kind: core.KindUnattachedVolume, SizeGB: 100, Attributes: map[string]any{"volume_type": "gp2"}},
		{Provider: "aws", Account: "111", ResourceID: "vol-2", Kind: core.KindUnattachedVolume, SizeGB: 100, Attributes: map[string]any{"volume_type": "gp2"}},
		{Provider: "aws", Account: "111", ResourceID: "i-big", Kind: core.KindOversizedInstance, InstanceType: "m5.2xlarge", AvgCPU: 7},
		{Provider: "aws", Account: "111", ResourceID: "eip-1", Kind: core.KindUnassociatedIP},
		{Provider: "aws", Account: "111", ResourceID: "eip-2", Kind: core.KindUnassociatedIP},
		{Provider: "aws", Account: "111", ResourceID: "eip-3", Kind: core.KindUnassociatedIP},
		{Provider: "azure", Account: "sub", ResourceID: "/disk/1", Kind: core.KindUnattachedVolume, SizeGB: 128, Attributes: map[string]any{"sku": "Premium_LRS"}},
		{Provider: "aws", Account: "111", ResourceID: "arn:aws:s3:::b1", Kind: core.KindPublicEgress, MonthlySpend: 340},
		{Provider: "aws", Account: "111", ResourceID: "AmazonEC2", Kind: core.KindServiceSpend, MonthlySpend: 1234.5, Attributes: map[string]any{"service": "Amazon Elastic Compute Cloud - Compute"}},
	}
	return signals, g, paths, findings
}

func TestAnalyzeTextExact(t *testing.T) {
	signals, g, paths, findings := fixture()
	r := Analyze(signals, g, paths, Options{Findings: findings})
	text := r.Text()
	lossS3 := Money(DefaultBreachCostUSD * BreachProbability(50) * 0.84)
	wantLines := []string{
		"💰 Cost Optimization Opportunities:",
		"- 2 orphaned EBS volumes → $20/month savings",
		"- 1 orphaned Azure managed disk → $19/month savings",
		"- 1 oversized EC2 instance → $140/month savings (rightsizing)",
		"- 3 unused Elastic IPs → $11/month savings",
		"",
		"🔒 Security + Cost Wins:",
		"- Removing public access from these 5 S3 buckets:",
		"  - Reduces breach risk by 84%",
		"  - Saves $340/month (data transfer costs)",
		"",
		"📈 ROI:",
		"- Breach probability 63.2% × breach cost $4,880,000 = " + Money(DefaultBreachCostUSD*BreachProbability(50)) + " expected annual loss",
		"- Fix EC2_IMDSV1: breaks 1 attack path, reduces risk by 84%, avoids " + lossS3 + "/year expected loss",
		"- Fix S3_PUBLIC_BUCKET: breaks 1 attack path, reduces risk by 84%, avoids " + lossS3 + "/year expected loss, saves $340/month",
		"- Fix NO_MFA: breaks 1 attack path, reduces risk by 16%, avoids " + Money(DefaultBreachCostUSD*BreachProbability(50)*0.16) + "/year expected loss",
		"",
		"Total potential savings: $530/month",
	}
	got := strings.Split(strings.TrimRight(text, "\n"), "\n")
	if len(got) != len(wantLines) {
		t.Fatalf("line count %d want %d:\n%s", len(got), len(wantLines), text)
	}
	for i := range wantLines {
		if got[i] != wantLines[i] {
			t.Errorf("line %d:\n got %q\nwant %q", i, got[i], wantLines[i])
		}
	}
}

func TestROIMath(t *testing.T) {
	signals, g, paths, findings := fixture()
	r := Analyze(signals, g, paths, Options{Findings: findings, BreachCostUSD: 1_000_000})
	if r.ROI.TotalPathScore != 50 {
		t.Fatalf("total score %v", r.ROI.TotalPathScore)
	}
	p := 1 - math.Exp(-1)
	if math.Abs(r.ROI.BreachProbability-p) > 1e-12 {
		t.Fatalf("p=%v", r.ROI.BreachProbability)
	}
	byID := map[string]Fix{}
	for _, f := range r.ROI.Fixes {
		byID[f.CanonicalID] = f
	}
	cases := []struct {
		id    string
		pct   float64
		paths int
		ids   int
	}{
		{"S3_PUBLIC_BUCKET", 84, 1, 1},
		{"EC2_IMDSV1", 84, 1, 1},
		{"NO_MFA", 16, 1, 1},
	}
	for _, c := range cases {
		f, ok := byID[c.id]
		if !ok {
			t.Fatalf("missing fix %s", c.id)
		}
		if f.RiskReductionPct != c.pct || f.PathsBroken != c.paths || len(f.FindingIDs) != c.ids {
			t.Errorf("%s: %+v", c.id, f)
		}
		want := math.Round(1_000_000*p*c.pct/100*100) / 100
		if math.Abs(f.ExpectedAnnualLossAvoided-want) > 0.01 {
			t.Errorf("%s loss %v want %v", c.id, f.ExpectedAnnualLossAvoided, want)
		}
	}
	if r.ROI.Fixes[len(r.ROI.Fixes)-1].CanonicalID != "NO_MFA" {
		t.Errorf("fixes not sorted by loss avoided: %+v", r.ROI.Fixes)
	}
}

func TestWinsGrouping(t *testing.T) {
	g := graph.New()
	g.AddNode(&graph.Node{ID: "sg-1", Type: "aws_security_group", Provider: "aws", Weaknesses: []string{"PUBLIC_NETWORK_EXPOSURE"}, FindingIDs: []string{"s1"}})
	g.AddNode(&graph.Node{ID: "sg-2", Type: "aws_security_group", Provider: "aws"}) // not open
	g.AddNode(&graph.Node{ID: "i-1", Type: "aws_instance", Provider: "aws"})
	g.AddEdge(graph.InternetNodeID, "i-1", graph.EdgeExposes, nil)
	g.AddNode(&graph.Node{ID: "//storage.googleapis.com/a", Type: "gcp_storage_bucket", Provider: "gcp", Weaknesses: []string{"PUBLIC_DATA_STORE"}})
	g.AddNode(&graph.Node{ID: "//storage.googleapis.com/b", Type: "gcp_storage_bucket", Provider: "gcp", Weaknesses: []string{"PUBLIC_DATA_STORE"}})
	paths := []model.AttackPath{{ID: "p", Score: 10, FindingIDs: []string{"s1"}}}
	r := Analyze(nil, g, paths, Options{})
	titles := map[string]float64{}
	for _, w := range r.SecurityCostWins {
		titles[w.Title] = w.RiskReductionPct
	}
	want := map[string]float64{
		"Closing internet-open ports on this security group":       100,
		"Removing direct internet exposure from this EC2 instance": 0,
		"Removing public access from these 2 GCS buckets":          0,
	}
	if len(titles) != len(want) {
		t.Fatalf("wins %v", titles)
	}
	for k, v := range want {
		if got, ok := titles[k]; !ok || got != v {
			t.Errorf("win %q = %v,%v want %v", k, got, ok, v)
		}
	}
	if r.SecurityCostWins[0].Title != "Closing internet-open ports on this security group" {
		t.Errorf("highest risk reduction should be first: %+v", r.SecurityCostWins[0])
	}
}

func TestEmptyReportAndJSON(t *testing.T) {
	r := Analyze(nil, nil, nil, Options{})
	if r.ROI.BreachCostUSD != DefaultBreachCostUSD {
		t.Errorf("breach default %v", r.ROI.BreachCostUSD)
	}
	if !strings.Contains(r.Text(), "No zombie or oversized resources detected") {
		t.Error(r.Text())
	}
	signals, g, paths, findings := fixture()
	full := Analyze(signals, g, paths, Options{Findings: findings})
	b, err := full.JSON()
	if err != nil {
		t.Fatal(err)
	}
	var back map[string]any
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"zombies", "rightsizing", "security_cost_wins", "roi", "spend", "total_monthly_savings"} {
		if _, ok := back[k]; !ok {
			t.Errorf("json missing %s", k)
		}
	}
	if len(full.Spend) != 1 || full.Spend[0].Service != "Amazon Elastic Compute Cloud - Compute" {
		t.Errorf("spend %+v", full.Spend)
	}
}

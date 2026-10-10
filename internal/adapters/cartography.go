package adapters

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// CartographySupportedVersion: a Neo4j dump of a Cartography 0.9x graph exported with APOC
// (`CALL apoc.export.json.all(null, {stream: true})`, JSON lines of node / relationship
// records), or the same records as {"nodes": [...], "relationships": [...]} or a JSON array.
const CartographySupportedVersion = "cartography 0.9x graph via APOC apoc.export.json.all (JSON lines or {nodes, relationships})"

// Cartography turns a Cartography graph export into inventory records plus typed relations.
//
//   - every node -> PASS / INFO finding, CheckID "inventory:<PrimaryLabel>", attributes = node
//     properties; resource ID = the ID the native collectors use where one exists
//     ("aws:account:<id>", EC2 ARNs built from region/account, "<ns>/pod/<name>"), else
//     properties.arn, properties.id, or "cartography:node/<export id>";
//   - relationships become typed relations on the start node (see cartographyRelKind); unknown
//     relationship labels are skipped and counted per start node in the attribute
//     "cartography_unmapped_relationships";
//   - exposed_internet=true adds an exposed_to_internet relation; on an EC2Instance it also
//     yields a FAIL finding for check ec2_instance_public_ip (catalog EC2_PUBLIC_IP), the only
//     public-exposure canonical ID whose meaning matches. Other exposed nodes keep it as an
//     attribute and relation only.
type Cartography struct{}

func (Cartography) Name() string             { return "cartography" }
func (Cartography) SupportedVersion() string { return CartographySupportedVersion }

// cartoID accepts APOC ids as strings or numbers.
type cartoID string

func (c *cartoID) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) > 0 && b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		*c = cartoID(s)
		return nil
	}
	if bytes.Equal(b, []byte("null")) {
		*c = ""
		return nil
	}
	*c = cartoID(b)
	return nil
}

type cartoRef struct {
	ID         cartoID        `json:"id"`
	Labels     []string       `json:"labels"`
	Properties map[string]any `json:"properties"`
}

type cartoRecord struct {
	Type       string         `json:"type"`
	ID         cartoID        `json:"id"`
	Labels     []string       `json:"labels"`
	Label      string         `json:"label"`
	Properties map[string]any `json:"properties"`
	Start      cartoRef       `json:"start"`
	End        cartoRef       `json:"end"`
}

func (Cartography) Detect(filename string, data []byte) bool {
	trim := bytes.TrimSpace(data)
	if len(trim) == 0 {
		return false
	}
	head := trim[:min(len(trim), 4096)]
	if trim[0] == '{' && bytes.Contains(head, []byte(`"nodes"`)) && bytes.Contains(trim, []byte(`"relationships"`)) {
		return bytes.Contains(head, []byte(`"labels"`))
	}
	// JSON lines (or an array) of APOC records: probe the first record.
	if trim[0] == '[' {
		trim = bytes.TrimSpace(trim[1:])
	}
	var rec cartoRecord
	if err := json.NewDecoder(bytes.NewReader(trim)).Decode(&rec); err != nil {
		return false
	}
	return (rec.Type == "node" && len(rec.Labels) > 0) || (rec.Type == "relationship" && rec.Label != "" && rec.Start.ID != "")
}

func (c Cartography) Parse(data []byte, opts Options) ([]model.Finding, error) {
	nodes, rels, err := c.records(data)
	if err != nil {
		return nil, err
	}
	g := newCartoGraph(nodes, rels)
	var out []model.Finding
	for _, n := range nodes {
		inv := g.inventory(n)
		out = append(out, inv)
		if exposed, _ := n.Properties["exposed_internet"].(bool); exposed && g.primary[n.ID] == "EC2Instance" {
			out = append(out, g.exposure(n, inv))
		}
	}
	return out, nil
}

func (Cartography) records(data []byte) (nodes, rels []cartoRecord, err error) {
	trim := bytes.TrimSpace(data)
	var obj struct {
		Nodes         []cartoRecord `json:"nodes"`
		Relationships []cartoRecord `json:"relationships"`
	}
	if len(trim) > 0 && trim[0] == '{' && json.Unmarshal(trim, &obj) == nil && len(obj.Nodes)+len(obj.Relationships) > 0 {
		for _, n := range obj.Nodes {
			n.Type = "node"
			nodes = append(nodes, n)
		}
		for _, r := range obj.Relationships {
			r.Type = "relationship"
			rels = append(rels, r)
		}
		return nodes, rels, nil
	}
	var recs []cartoRecord
	if len(trim) > 0 && trim[0] == '[' {
		if err := json.Unmarshal(trim, &recs); err != nil {
			return nil, nil, err
		}
	} else {
		dec := json.NewDecoder(bytes.NewReader(trim))
		for {
			var r cartoRecord
			if err := dec.Decode(&r); err == io.EOF {
				break
			} else if err != nil {
				return nil, nil, fmt.Errorf("bad APOC record: %w", err)
			}
			recs = append(recs, r)
		}
	}
	for _, r := range recs {
		switch r.Type {
		case "node":
			nodes = append(nodes, r)
		case "relationship":
			rels = append(rels, r)
		}
	}
	if len(nodes) == 0 {
		return nil, nil, fmt.Errorf("no Cartography nodes found")
	}
	return nodes, rels, nil
}

// cartoLabelTypes maps Cartography node labels to nimbus resource types (the types the native
// collectors use) and providers. Unmapped labels become "cartography:<Label>".
var cartoLabelTypes = map[string][2]string{
	"AWSAccount":           {"aws_account", model.ProviderAWS},
	"EC2Instance":          {"aws_instance", model.ProviderAWS},
	"S3Bucket":             {"aws_s3_bucket", model.ProviderAWS},
	"AWSRole":              {"aws_iam_role", model.ProviderAWS},
	"AWSUser":              {"aws_iam_user", model.ProviderAWS},
	"AWSGroup":             {"aws_iam_group", model.ProviderAWS},
	"AWSPolicy":            {"aws_iam_policy", model.ProviderAWS},
	"EC2SecurityGroup":     {"aws_security_group", model.ProviderAWS},
	"AWSLambda":            {"aws_lambda_function", model.ProviderAWS},
	"RDSInstance":          {"aws_db_instance", model.ProviderAWS},
	"EKSCluster":           {"aws_eks_cluster", model.ProviderAWS},
	"KMSKey":               {"aws_kms_key", model.ProviderAWS},
	"SecretsManagerSecret": {"aws_secretsmanager_secret", model.ProviderAWS},
	"EBSVolume":            {"aws_ebs_volume", model.ProviderAWS},
	"ElasticIPAddress":     {"aws_eip", model.ProviderAWS},
	"LoadBalancer":         {"aws_elb", model.ProviderAWS},
	"LoadBalancerV2":       {"aws_lb", model.ProviderAWS},
	"EC2Subnet":            {"aws_subnet", model.ProviderAWS},
	"AWSVpc":               {"aws_vpc", model.ProviderAWS},
	"AWSPrincipal":         {"aws_iam_principal", model.ProviderAWS},
	"KubernetesCluster":    {"k8s_cluster", model.ProviderKubernetes},
	"KubernetesNamespace":  {"k8s_namespace", model.ProviderKubernetes},
	"KubernetesPod":        {"k8s_pod", model.ProviderKubernetes},
	"KubernetesContainer":  {"k8s_container", model.ProviderKubernetes},
	"KubernetesService":    {"k8s_service", model.ProviderKubernetes},
	"KubernetesSecret":     {"k8s_secret", model.ProviderKubernetes},
}

// cartoGenericLabels are secondary labels Cartography adds next to the specific one.
var cartoGenericLabels = map[string]bool{"AWSPrincipal": true, "Resource": true}

// cartoK8sNamespaced: Kubernetes labels whose nodes get native collector IDs <ns>/<kind>/<name>.
var cartoK8sNamespaced = map[string]string{"KubernetesPod": "pod", "KubernetesService": "service", "KubernetesSecret": "secret", "KubernetesServiceAccount": "serviceaccount"}

// cartographyRelKind maps a Cartography relationship (start node -> end node) to a relation
// kind declared on the start node. Directions follow Cartography's schema:
//
//	(AWSAccount)-[:RESOURCE]->(X), (KubernetesCluster)-[:RESOURCE]->(KubernetesNamespace) -> contains
//	(X)-[:CONTAINS]->(Y)                                  -> contains
//	(AWSPrincipal)-[:STS_ASSUMEROLE_ALLOW]->(AWSRole)     -> can_assume (the start node is the
//	    principal, so the forward edge; the sts_assume_role_allows alias is declared on the role)
//	(EC2Instance|AWSLambda)-[:STS_ASSUMEROLE_ALLOW]->(AWSRole), (EC2Instance)-[:INSTANCE_PROFILE]->(X),
//	    (AWSInstanceProfile)-[:ASSOCIATED_WITH]->(AWSRole)  -> runs_as (execution identity)
//	(AWSRole)-[:TRUSTS_AWS_PRINCIPAL]->(AWSPrincipal)     -> trusts (graph derives can_assume)
//	(AWSPrincipal)-[:POLICY]->(AWSPolicy)                 -> has_policy
//	(AWSUser)-[:MEMBER_AWS_GROUP]->(AWSGroup)             -> member_of
//	(EC2Instance)-[:MEMBER_OF_EC2_SECURITY_GROUP]->(EC2SecurityGroup) -> attached_to
//	(X)-[:PART_OF_SUBNET|MEMBER_OF_EC2_SUBNET]->(EC2Subnet) -> member_of
//	(LoadBalancer|LoadBalancerV2)-[:EXPOSE]->(EC2Instance) -> allows_traffic_to
func cartographyRelKind(label, startPrimary, endPrimary string) string {
	switch label {
	case "RESOURCE", "CONTAINS":
		return "contains"
	case "STS_ASSUMEROLE_ALLOW":
		if startPrimary == "EC2Instance" || startPrimary == "AWSLambda" || startPrimary == "ECSTaskDefinition" {
			return "runs_as"
		}
		return "can_assume"
	case "INSTANCE_PROFILE":
		return "runs_as"
	case "ASSOCIATED_WITH":
		if startPrimary == "AWSInstanceProfile" && endPrimary == "AWSRole" {
			return "runs_as"
		}
	case "TRUSTS_AWS_PRINCIPAL":
		return "trusts"
	case "POLICY":
		return "has_policy"
	case "MEMBER_AWS_GROUP":
		return "member_of"
	case "MEMBER_OF_EC2_SECURITY_GROUP":
		return "attached_to"
	case "PART_OF_SUBNET", "MEMBER_OF_EC2_SUBNET":
		return "member_of"
	case "EXPOSE":
		return "allows_traffic_to"
	}
	return ""
}

type cartoGraph struct {
	byID     map[cartoID]cartoRecord
	primary  map[cartoID]string
	account  map[cartoID]string
	resID    map[cartoID]string
	outgoing map[cartoID][]cartoRecord
}

func newCartoGraph(nodes, rels []cartoRecord) *cartoGraph {
	g := &cartoGraph{byID: map[cartoID]cartoRecord{}, primary: map[cartoID]string{}, account: map[cartoID]string{}, resID: map[cartoID]string{}, outgoing: map[cartoID][]cartoRecord{}}
	for _, n := range nodes {
		g.byID[n.ID] = n
		g.primary[n.ID] = cartoPrimaryLabel(n.Labels)
	}
	for _, r := range rels {
		g.outgoing[r.Start.ID] = append(g.outgoing[r.Start.ID], r)
	}
	// Account: an AWSAccount node is its own account; (AWSAccount)-[:RESOURCE]->(X) sets X's;
	// otherwise the ARN's account field.
	for _, n := range nodes {
		if g.primary[n.ID] == "AWSAccount" {
			g.account[n.ID] = str(n.Properties, "id")
		}
	}
	for _, r := range rels {
		if r.Label == "RESOURCE" && g.primary[r.Start.ID] == "AWSAccount" {
			if acct := g.account[r.Start.ID]; acct != "" {
				g.account[r.End.ID] = acct
			}
		}
	}
	for _, n := range nodes {
		if g.account[n.ID] == "" {
			g.account[n.ID] = arnAccount(str(n.Properties, "arn"))
		}
		g.resID[n.ID] = g.resourceID(n)
	}
	return g
}

func cartoPrimaryLabel(labels []string) string {
	for _, l := range labels {
		if _, ok := cartoLabelTypes[l]; ok && !cartoGenericLabels[l] {
			return l
		}
	}
	for _, l := range labels {
		if !cartoGenericLabels[l] {
			return l
		}
	}
	if len(labels) > 0 {
		return labels[0]
	}
	return "Unknown"
}

// arnAccount returns the account field of arn:partition:service:region:account:resource.
func arnAccount(arn string) string {
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) == 6 && parts[0] == "arn" {
		return parts[4]
	}
	return ""
}

func (g *cartoGraph) resourceID(n cartoRecord) string {
	p := n.Properties
	label := g.primary[n.ID]
	switch label {
	case "AWSAccount":
		if id := str(p, "id"); id != "" {
			return "aws:account:" + id
		}
	case "EC2Instance", "EC2SecurityGroup":
		if arn := str(p, "arn"); arn != "" {
			return arn
		}
		kind := map[string]string{"EC2Instance": "instance", "EC2SecurityGroup": "security-group"}[label]
		if region, acct, id := str(p, "region"), g.account[n.ID], str(p, "id"); region != "" && acct != "" && id != "" {
			return fmt.Sprintf("arn:aws:ec2:%s:%s:%s/%s", region, acct, kind, id)
		}
	case "KubernetesNamespace":
		if name := str(p, "name"); name != "" {
			return k8sResourceID("Namespace", "", name)
		}
	default:
		if kind, ok := cartoK8sNamespaced[label]; ok {
			if name, ns := str(p, "name"), str(p, "namespace"); name != "" && ns != "" {
				return k8sResourceID(kind, ns, name)
			}
		}
	}
	if id := firstNonEmpty(str(p, "arn"), str(p, "id")); id != "" {
		return id
	}
	return "cartography:node/" + string(n.ID)
}

func (g *cartoGraph) provider(n cartoRecord) string {
	label := g.primary[n.ID]
	if t, ok := cartoLabelTypes[label]; ok {
		return t[1]
	}
	if strings.HasPrefix(str(n.Properties, "arn"), "arn:aws") {
		return model.ProviderAWS
	}
	for prefix, p := range map[string]string{"AWS": model.ProviderAWS, "EC2": model.ProviderAWS, "GCP": model.ProviderGCP, "Azure": model.ProviderAzure, "Kubernetes": model.ProviderKubernetes, "GitHub": model.ProviderGitHub, "Okta": model.ProviderOkta} {
		if strings.HasPrefix(label, prefix) {
			return p
		}
	}
	return model.ProviderUnknown
}

func (g *cartoGraph) baseResource(n cartoRecord) model.Resource {
	label := g.primary[n.ID]
	typ := "cartography:" + label
	if t, ok := cartoLabelTypes[label]; ok {
		typ = t[0]
	}
	p := n.Properties
	id := g.resID[n.ID]
	attrs := map[string]any{}
	for k, v := range p {
		attrs[k] = v
	}
	attrs["cartography_labels"] = n.Labels
	attrs["cartography_node_id"] = string(n.ID)
	return model.Resource{
		ID:         id,
		Type:       typ,
		Name:       firstNonEmpty(str(p, "name"), str(p, "db_instance_identifier"), str(p, "instanceid"), str(p, "id"), id),
		Attributes: attrs,
	}
}

func (g *cartoGraph) inventory(n cartoRecord) model.Finding {
	label := g.primary[n.ID]
	res := g.baseResource(n)
	unmapped := map[string]any{}
	for _, r := range g.outgoing[n.ID] {
		kind := cartographyRelKind(r.Label, label, g.primary[r.End.ID])
		if kind == "" {
			c, _ := unmapped[r.Label].(int)
			unmapped[r.Label] = c + 1
			continue
		}
		target, ok := g.resID[r.End.ID]
		if !ok {
			// End node not in the export: fall back to the reference's own properties.
			target = firstNonEmpty(str(r.End.Properties, "arn"), str(r.End.Properties, "id"), "cartography:node/"+string(r.End.ID))
		}
		addRelation(&res, target, kind, map[string]any{"cartography_rel": r.Label})
	}
	if len(unmapped) > 0 {
		res.Attributes["cartography_unmapped_relationships"] = unmapped
	}
	if exposed, _ := n.Properties["exposed_internet"].(bool); exposed {
		addRelation(&res, "internet", "exposed_to_internet", map[string]any{"cartography_property": "exposed_internet"})
	}
	return model.Finding{
		Source:   "cartography",
		CheckID:  "inventory:" + label,
		Title:    fmt.Sprintf("Inventory: %s %s", label, res.Name),
		Severity: model.Info,
		Status:   model.Pass,
		Provider: g.provider(n),
		Account:  g.account[n.ID],
		Region:   str(n.Properties, "region"),
		Resource: res,
		Tags:     map[string]string{"cartography_label": label},
		Raw:      rawOf(n),
	}
}

// exposure is the FAIL finding for an EC2 instance Cartography marks exposed_internet.
func (g *cartoGraph) exposure(n cartoRecord, inv model.Finding) model.Finding {
	res := g.baseResource(n)
	var how []string
	for _, x := range list(n.Properties, "exposed_internet_type") {
		if s, ok := x.(string); ok {
			how = append(how, s)
		}
	}
	desc := "Cartography marks this EC2 instance exposed_internet=true (reachable from 0.0.0.0/0 through its security groups and a public address or internet-facing load balancer)."
	if len(how) > 0 {
		desc += " Exposure type: " + strings.Join(how, ", ") + "."
	}
	return model.Finding{
		Source:      "cartography",
		CheckID:     "ec2_instance_public_ip",
		Title:       "EC2 instance is exposed to the internet",
		Description: desc,
		Status:      model.Fail,
		Provider:    inv.Provider,
		Account:     inv.Account,
		Region:      inv.Region,
		Resource:    res,
		Tags:        map[string]string{"cartography_label": inv.Tags["cartography_label"], "derived_from": "exposed_internet"},
		Raw:         rawOf(n),
	}
}

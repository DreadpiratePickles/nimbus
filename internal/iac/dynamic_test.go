package iac

import (
	"strings"
	"testing"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// D6 (open since Verification 2; Verification 3 addendum a): `dynamic "ingress"` blocks were not
// evaluated, so a world-open port behind a dynamic block passed, and `fix --patch` reported
// EC2_SG_OPEN_RDP fixed while 3389 stayed open (scratchpad verify-3/me/fixv). Dynamic ingress
// blocks with a statically known for_each are expanded; an unknown for_each is SKIP with a reason.
func TestDynamicIngressWithOpenCIDRFails(t *testing.T) {
	sg := func(body string) string {
		return "resource \"aws_security_group\" \"web\" {\n  name = \"web\"\n" + body + "}\n"
	}
	dyn := func(forEach, content string, extra ...string) string {
		return "  dynamic \"ingress\" {\n    for_each = " + forEach + "\n" + strings.Join(extra, "") + "    content {\n" + content + "    }\n  }\n"
	}
	open := "      from_port   = ingress.value\n      to_port     = ingress.value\n      protocol    = \"tcp\"\n      cidr_blocks = [\"0.0.0.0/0\"]\n"
	cases := []struct {
		name, src string
		want      model.Status
		detail    string
	}{
		{"fixv: static 22 narrowed, dynamic 3389 open", sg("  ingress {\n    from_port = 22\n    to_port = 22\n    protocol = \"tcp\"\n    cidr_blocks = var.allowed_cidrs\n  }\n" + dyn("[3389]", open)), model.Fail, "dynamic ingress 3389-3389 from 0.0.0.0/0"},
		{"literal list", sg(dyn("[3389]", open)), model.Fail, "3389-3389"},
		{"toset", sg(dyn("toset([22, 3389])", open)), model.Fail, "0.0.0.0/0"},
		{"objects via iterator", sg(dyn(`[{ port = 22, cidr = "10.0.0.0/8" }, { port = 3389, cidr = "0.0.0.0/0" }]`,
			"      from_port   = rule.value.port\n      to_port     = rule.value.port\n      protocol    = \"tcp\"\n      cidr_blocks = [rule.value.cidr]\n", "    iterator = rule\n")), model.Fail, "3389-3389 from 0.0.0.0/0"},
		{"map key/value ipv6", sg(dyn(`{ ssh = "::/0" }`, "      from_port = 22\n      to_port = 22\n      protocol = \"tcp\"\n      ipv6_cidr_blocks = [ingress.value]\n      description = ingress.key\n")), model.Fail, "from ::/0"},
		{"closed dynamic", sg(dyn(`[{ port = 22, cidr = "10.0.0.0/8" }]`, "      from_port = ingress.value.port\n      to_port = ingress.value.port\n      protocol = \"tcp\"\n      cidr_blocks = [ingress.value.cidr]\n")), model.Pass, ""},
		{"empty for_each", sg(dyn("[]", open)), model.Pass, ""},
		{"unknown for_each", sg(dyn("var.ports", open)), model.Skip, "for_each"},
		{"unknown content", sg(dyn("[22]", "      from_port = 22\n      to_port = 22\n      protocol = \"tcp\"\n      cidr_blocks = var.cidrs\n")), model.Skip, "dynamic ingress"},
		{"static open wins over unknown dynamic", sg("  ingress {\n    from_port = 22\n    to_port = 22\n    protocol = \"tcp\"\n    cidr_blocks = [\"0.0.0.0/0\"]\n  }\n" + dyn("var.ports", open)), model.Fail, "22-22"},
		{"egress dynamic ignored", sg("  dynamic \"egress\" {\n    for_each = [0]\n    content {\n      from_port = 0\n      to_port = 0\n      protocol = \"-1\"\n      cidr_blocks = [\"0.0.0.0/0\"]\n    }\n  }\n"), model.Pass, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fs, err := ScanHCL([]byte(c.src), "main.tf", time.Unix(0, 0))
			if err != nil {
				t.Fatalf("scan: %v\n%s", err, c.src)
			}
			var got *model.Finding
			for i := range fs {
				if fs[i].CheckID == "NIMBUS_TF_SG_OPEN" {
					got = &fs[i]
				}
			}
			if got == nil {
				t.Fatalf("no NIMBUS_TF_SG_OPEN result: %+v", fs)
			}
			if got.Status != c.want || !strings.Contains(got.Description, c.detail) {
				t.Errorf("status %s detail %q, want %s containing %q", got.Status, got.Description, c.want, c.detail)
			}
		})
	}
}

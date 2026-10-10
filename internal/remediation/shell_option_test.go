package remediation

import (
	"os/exec"
	"strings"
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// Verification 2 defect 6 (D4): a resource name starting with '-' became a kubectl/az option
// (`--server=https://evil` sends the kubeconfig credentials there). Derived from the verifier probe
// zz_verify_shell_test.go. Every generated command is run through bash with stub kubectl/az/aws/
// terraform functions that print their argv; no argument before a `--` may carry the hostile name.
func TestGeneratedCommandsResistOptionInjection(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	stub := `kubectl(){ printf '%s\n' "$@"; }; az(){ printf '%s\n' "$@"; }; aws(){ printf '%s\n' "$@"; }; terraform(){ printf '%s\n' "$@"; }; `
	hostile := []string{"-n evil", "--namespace=x", "--server=https://evil.example", "-n=kube-system", "--kubeconfig=/tmp/evil", "-oyaml"}
	for _, n := range hostile {
		cases := []struct {
			id  string
			fm  Format
			res model.Resource
		}{
			{"K8S_PRIVILEGED_CONTAINER", Kubernetes, model.Resource{ID: "Deployment/" + n, Name: n, Type: "kubernetes_deployment", Attributes: map[string]any{"namespace": "default"}}},
			{"K8S_PRIVILEGED_CONTAINER", Kubernetes, model.Resource{ID: "Deployment/web", Name: "web", Type: "kubernetes_deployment", Attributes: map[string]any{"namespace": n}}},
			{"K8S_PRIVILEGED_CONTAINER", Kubernetes, model.Resource{ID: "Deployment/web", Name: "web", Type: "kubernetes_deployment", Attributes: map[string]any{"namespace": "default", "kind": n}}},
			{"AZ_STORAGE_PUBLIC_BLOB", Bicep, model.Resource{ID: "/subscriptions/s/resourceGroups/rg/x", Name: "st", Type: "azurerm_storage_account", Attributes: map[string]any{"resource_group": n}}},
			{"S3_PUBLIC_BUCKET", CloudFormation, model.Resource{ID: "arn:aws:s3:::" + n, Name: n, Type: "aws_s3_bucket"}},
			{"S3_PUBLIC_BUCKET", Terraform, model.Resource{ID: "arn:aws:s3:::" + n, Name: n, Type: "aws_s3_bucket"}},
			// generic stub path: the canonical ID flows into the file name
			{n, Kubernetes, model.Resource{ID: "Deployment/web", Name: "web", Type: "kubernetes_deployment"}},
		}
		for _, tc := range cases {
			fx, err := Generate(model.Finding{CanonicalID: tc.id, Resource: tc.res}, tc.fm)
			if err != nil {
				t.Logf("%s %q: %v", tc.fm, n, err)
				continue
			}
			for _, s := range append([]string{fx.Apply}, fx.Steps...) {
				if !strings.HasPrefix(s, "kubectl") && !strings.HasPrefix(s, "az ") && !strings.HasPrefix(s, "aws ") && !strings.HasPrefix(s, "terraform") {
					continue // review prose or a refusal comment
				}
				if strings.Contains(s, "<") {
					continue // a human placeholder such as <resource-group>: not runnable as is
				}
				cmd := s
				if j := strings.Index(cmd, "   #"); j >= 0 {
					cmd = cmd[:j]
				}
				out, err := exec.Command("bash", "-c", stub+cmd).CombinedOutput()
				if err != nil {
					t.Errorf("%s %q: command does not run: %s: %v", tc.fm, n, cmd, err)
					continue
				}
				for _, arg := range strings.Split(strings.TrimRight(string(out), "\n"), "\n") {
					if arg == "--" {
						break // everything after `--` is positional
					}
					if strings.HasPrefix(arg, n) {
						t.Errorf("%s %q: hostile name became an option: %s\n  argv arg %q", tc.fm, n, cmd, arg)
					}
				}
			}
		}
	}
}

// Option values are bound with --flag=value and positional names follow `--`, so a hostile value
// can neither become an option nor be split: check the exact argv kubectl and az would receive.
func TestKubectlArgvBindsHostileValues(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	fx, err := Generate(model.Finding{CanonicalID: "K8S_PRIVILEGED_CONTAINER", Resource: model.Resource{ID: "Deployment/x", Name: "--server=https://evil.example", Type: "kubernetes_deployment", Attributes: map[string]any{"namespace": "-n evil"}}}, Kubernetes)
	if err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("bash", "-c", `kubectl(){ printf '%s\n' "$@"; }; `+fx.Apply).CombinedOutput()
	if err != nil {
		t.Fatal(err)
	}
	argv := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
	want := []string{"patch", "--namespace=-n evil", "--type=strategic", "--patch-file=" + fx.FileName, "--dry-run=server", "--output=yaml", "--", "deployment", "--server=https://evil.example"}
	if strings.Join(argv, "|") != strings.Join(want, "|") {
		t.Errorf("argv\n got %q\nwant %q", argv, want)
	}
}

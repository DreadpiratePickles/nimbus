package adapters

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// Integration pass 3 item #10: Trivy 0.75 ids ("AWS-0028", "KSV-0111", no AVDID) map through the
// catalog, and `trivy k8s` findings carry the <ns>/<kind>/<name> resource id the k8s collector
// and the trivy-operator / kubescape adapters use.

func TestTrivy075IDsMapToCanonical(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "lab", "golden", "trivy", "0.75.0", "aws.json"))
	if err != nil {
		t.Fatal(err)
	}
	fs, err := Trivy{}.Parse(data, Options{})
	if err != nil {
		t.Fatal(err)
	}
	Finalize(fs, Options{})
	got := map[string]string{}
	for _, f := range fs {
		if f.Status == model.Fail {
			got[f.CheckID+"|"+f.Resource.ID] = f.CanonicalID
		}
	}
	for k, want := range map[string]string{
		"AWS-0028|aws_instance.web":                      "EC2_IMDSV1",
		"AWS-0180|aws_db_instance.orders[0]":             "RDS_PUBLIC",
		"AWS-0087|aws_s3_bucket_public_access_block.pii": "S3_PUBLIC_BUCKET",
		"KSV-0111|": "K8S_CLUSTER_ADMIN_BINDING",
		"KSV-0012|": "K8S_RUN_AS_ROOT",
	} {
		if got[k] != want {
			t.Errorf("%s → %q, want %q", k, got[k], want)
		}
	}
	for _, f := range fs {
		if f.CheckID == "AWS-0028" && f.Provider != model.ProviderAWS {
			t.Errorf("provider of AWS-0028: %q", f.Provider)
		}
	}
}

func TestTrivyK8sResourceIDFromWrapper(t *testing.T) {
	doc := `{"ClusterName":"lab","Resources":[
	 {"Namespace":"ci","Kind":"Pod","Name":"build-runner-0","Results":[{"Target":"Pod/build-runner-0","Class":"config","Type":"kubernetes",
	   "Misconfigurations":[{"Type":"Kubernetes Security Check","ID":"KSV-0012","Title":"Runs as root user","Severity":"MEDIUM","Status":"FAIL",
	     "CauseMetadata":{"Provider":"Kubernetes","Service":"general"}}]}]},
	 {"Namespace":"","Kind":"ClusterRoleBinding","Name":"ci-deployer-admin","Results":[{"Target":"ClusterRoleBinding/ci-deployer-admin","Class":"config","Type":"kubernetes",
	   "Misconfigurations":[{"Type":"Kubernetes Security Check","ID":"KSV-0111","Title":"User with admin access","Severity":"MEDIUM","Status":"FAIL",
	     "CauseMetadata":{"Provider":"Kubernetes","Service":"general"}}]}]},
	 {"Namespace":"web","Kind":"Deployment","Name":"api","Results":[{"Target":"Deployment/api","Class":"config","Type":"kubernetes",
	   "Misconfigurations":[{"Type":"Kubernetes Security Check","ID":"KSV-0017","Title":"Privileged","Severity":"HIGH","Status":"FAIL",
	     "CauseMetadata":{"Resource":"Deployment/api","Provider":"Kubernetes","Service":"general"}}]}]}]}`
	fs, err := Trivy{}.Parse([]byte(doc), Options{})
	if err != nil {
		t.Fatal(err)
	}
	Finalize(fs, Options{})
	if len(fs) != 3 {
		t.Fatalf("want 3 findings, got %d", len(fs))
	}
	pod := findCheck(fs, "KSV-0012", "ci/pod/build-runner-0")
	if pod == nil || pod.Resource.Type != "k8s_pod" || pod.Resource.Name != "build-runner-0" || !hasRelation(pod.Resource, "namespace/ci", "member_of") || pod.CanonicalID != "K8S_RUN_AS_ROOT" {
		t.Errorf("pod: %+v", pod)
	}
	crb := findCheck(fs, "KSV-0111", "cluster/clusterrolebinding/ci-deployer-admin")
	if crb == nil || crb.Resource.Type != "k8s_cluster_role_binding" || crb.CanonicalID != "K8S_CLUSTER_ADMIN_BINDING" {
		t.Errorf("cluster role binding: %+v", crb)
	}
	// A CauseMetadata.Resource Trivy did give is kept (IaC scans join on it).
	if dep := findCheck(fs, "KSV-0017", "Deployment/api"); dep == nil || dep.CanonicalID != "K8S_PRIVILEGED_CONTAINER" {
		t.Errorf("deployment: %+v", dep)
	}
}

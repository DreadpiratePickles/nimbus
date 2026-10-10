package adapters

// Supported upstream output versions of the pre-existing adapters (P1-INTEROP: every adapter
// marks the version it parses; the golden or fixture test named alongside covers it).
func (Prowler) SupportedVersion() string {
	return "prowler v4/v5 json-ocsf (OCSF Detection Finding) and v3 json (testdata/prowler.ocsf.json)"
}
func (Checkov) SupportedVersion() string {
	return "checkov v2/v3 -o json, single report or list (testdata/checkov.json)"
}
func (Trivy) SupportedVersion() string {
	return "trivy -f json SchemaVersion 2 (config|k8s|image|fs) (testdata/trivy.json)"
}
func (Steampipe) SupportedVersion() string {
	return "steampipe check --export json / powerpipe benchmark run --export json (testdata/steampipe.json)"
}
func (ScoutSuite) SupportedVersion() string {
	return "scoutsuite v5 scoutsuite_results_<provider>-<account>.js (testdata/scoutsuite_results_azure.js)"
}
func (Native) SupportedVersion() string {
	return "nimbus finding contract 1.x (docs/spec/finding-v1.md)"
}

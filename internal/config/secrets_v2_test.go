package config

import (
	"errors"
	"strings"
	"testing"
)

// V2 defect 8: secret-bearing fields beyond token/password (webhook URLs, URL query
// tokens, credential headers, DSNs with passwords). Adapted from the verifier probe.
const secretSample = "S3CR3T-xyz-123"

func TestSecretBearingFieldsRejected(t *testing.T) {
	cases := []struct {
		name   string
		body   string
		reject bool
	}{
		{"slack token", "integrations:\n  slack: {token: " + secretSample + "}\n", true},
		{"jira token", "integrations:\n  jira: {url: https://x.atlassian.net, token: " + secretSample + "}\n", true},
		{"datadog token", "integrations:\n  datadog: {token: " + secretSample + "}\n", true},
		{"datadog api_key raw", "integrations:\n  datadog: {api_key: " + secretSample + "}\n", true},
		{"sentinel key raw", "integrations:\n  sentinel: {key: " + secretSample + "}\n", true},
		{"neo4j password", "neo4j:\n  password: " + secretSample + "\n", true},
		{"server token raw", "server:\n  token: " + secretSample + "\n", true},
		{"uppercase TOKEN", "integrations:\n  slack: {TOKEN: " + secretSample + "}\n", true},
		{"slack webhook URL literal", "integrations:\n  slack: {url: https://hooks.slack.com/services/T000/B000/" + secretSample + "}\n", true},
		{"teams webhook URL literal", "integrations:\n  teams: {url: https://x.webhook.office.com/webhookb2/" + secretSample + "}\n", true},
		{"siem url with token in query", "integrations:\n  siem: {type: webhook, url: \"https://siem.example.com/in?token=" + secretSample + "\"}\n", true},
		{"siem Authorization header", "integrations:\n  siem: {type: webhook, url_env: X, headers: {Authorization: \"Bearer " + secretSample + "\"}}\n", true},
		{"neo4j uri with creds", "neo4j:\n  uri: \"neo4j://neo4j:" + secretSample + "@db:7687\"\n", true},
		{"bot_token key", "integrations:\n  slack: {bot_token: " + secretSample + "}\n", true},
		{"access_token key", "integrations:\n  github: {access_token: " + secretSample + "}\n", true},
		{"scalar alias into token (struct)", "x-tok: &t " + secretSample + "\nintegrations:\n  slack: {token: *t}\n", true},
		{"scalar alias into raw secret key", "x-tok: &t " + secretSample + "\naccounts:\n  m365:\n    provider: m365\n    client_secret: *t\n", true},
		{"merge key with token", "x-base: &b {token: " + secretSample + "}\nintegrations:\n  slack:\n    <<: *b\n", true},
		{"token_env holding a literal secret", "integrations:\n  slack: {token_env: " + secretSample + "}\n", true /* not a valid environment variable name */},
		{"token_env holding a variable name", "integrations:\n  slack: {token_env: SLACK_TOKEN}\n", false},
		{"token_env holding value-like secret xoxb", "integrations:\n  slack: {token_env: xoxb-1234-5678-abcdefSECRET}\n", true},
		{"plain siem url is fine", "integrations:\n  siem: {type: webhook, url: \"https://siem.example.com/in\"}\n", false},
		{"jira site url is fine", "integrations:\n  jira: {url: https://x.atlassian.net, token_env: JIRA_API_TOKEN}\n", false},
		{"non-credential header is fine", "integrations:\n  siem: {type: webhook, url_env: X, headers: {X-Source: nimbus}}\n", false},
		{"neo4j uri without password is fine", "neo4j:\n  uri: \"neo4j://db:7687\"\n", false},
		{"url with api key in query", "integrations:\n  siem: {type: webhook, url: \"https://siem.example.com/in?api_key=" + secretSample + "\"}\n", true},
		{"url with userinfo password", "integrations:\n  siem: {type: elastic, url: \"https://u:" + secretSample + "@es.example.com\"}\n", true},
		{"x-api-key header", "integrations:\n  siem: {type: webhook, url_env: X, headers: {X-API-Key: " + secretSample + "}}\n", true},
		{"block scalar token", "integrations:\n  slack:\n    token: |\n      " + secretSample + "\n", true},
	}
	for _, c := range cases {
		_, err := Load(writeCfg(t, c.body))
		rejected := errors.Is(err, ErrPlaintextSecret)
		leak := err != nil && strings.Contains(err.Error(), secretSample)
		if leak {
			t.Errorf("LEAK %s: error echoes secret: %v", c.name, err)
		}
		if rejected != c.reject {
			t.Errorf("MISMATCH %s: rejected=%v want %v (err=%v)", c.name, rejected, c.reject, err)
		}
	}
}

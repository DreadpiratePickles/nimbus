# Configuration

`cloud-posture onboard` writes `cloud-posture.yaml` for you. You can also copy the example below to the repo root or to `~/.cloud-posture/cloud-posture.yaml` and edit it.

- **accounts**: one entry per account, subscription, project, cluster or SaaS tenant. Each sets a `provider`, how to reach it (profile, `role_arn`, `subscription_id`, `project_id`, `kube_context`, org or domain), and which `tools` to run (`native`, `python-checks`, `prowler`, `scoutsuite`, `checkov`, `trivy`, `steampipe`). `criticality` feeds the risk score.
- **scan**: IaC paths, parallelism, custom attack rules, and `crown_jewels` overrides (glob `pattern` → `criticality` 1–4) for the attack-path engine.
- **integrations**: alert sinks with a minimum severity each.
- **plugins**: external commands that print native findings.
- **python**: whether to use the Python intelligence layer.
- **neo4j**: where `graph push` sends the graph.

Secrets never go in this file. Every token is named by an environment variable (`token_env`, `url_env`, `key_env`…). A `.env` or `nimbus.env` in the working directory is loaded automatically and is git-ignored.

## Example

```yaml
<!-- include: cloud-posture.example.yaml -->
```

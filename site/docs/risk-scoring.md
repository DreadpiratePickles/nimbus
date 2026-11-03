# Risk scoring

Every open finding gets a score and the reasons behind it, so the top of the list explains itself. The weights are published in the repo, unlike the closed scoring of the big commercial platforms.

There are two implementations with the same inputs. The Python model is used when the Python layer is installed, and the Go engine is the fallback built into the binary.

## The Go engine (`cloud-posture prioritize`)

```text
base    = severity weight      CRITICAL 1.0 · HIGH 0.8 · MEDIUM 0.55 · LOW 0.3 · INFO 0.1
context = Σ weight_i × feature_i
x       = 0.45 × base + 0.55 × context
score   = 1 + 9 × sigmoid(7 × (x − 0.42))       → 1.0–10.0, one decimal
```

| Feature | Weight | Fires when |
|---|---|---|
| exposure | 0.22 | the finding is public or the resource has an inbound edge from the internet |
| identity | 0.16 | admin privileges (1.0); weak or long-lived identity (0.7); a credential-theft vector such as IMDSv1 (0.5) |
| data sensitivity | 0.16 | sensitive data, PII/PHI/PCI tags or a production DB (1.0); unencrypted or exposed secrets (0.5) |
| criticality | 0.12 | production (1.0), staging (0.6), unknown (0.5), dev (0.3) |
| vulnerabilities | 0.08 | CVE count on the resource (up to 5), or an exploitable vulnerability |
| compliance scope | 0.06 | PCI DSS / HIPAA (1.0), SOC 2 / GDPR (0.8), others (0.6) |
| recent change | 0.05 | resource changed or first seen in the last 24h |
| orphaned | 0.03 | no owner |
| attack paths | 0.12 | the finding sits on attack paths (count and max path score) |

Bands and SLAs:

| Band | Score | SLA |
|---|---|---|
| <span class="sev critical">Critical</span> | ≥ 9.0 | 7 days |
| <span class="sev high">High</span> | ≥ 7.0 | 30 days |
| <span class="sev medium">Medium</span> | ≥ 4.0 | 90 days |
| <span class="sev low">Low</span> | < 4.0 | 180 days |

Source: [`internal/risk/risk.go`](https://github.com/DreadpiratePickles/nimbus/blob/main/internal/risk/risk.go).

## The Python model (`nimbus risk`)

The Python layer normalises the same signals to `[0, 1]` and combines them through a logistic function:

```text
z          = bias + Σ weight_i × feature_i
risk_score = 100 / (1 + e^(−z))                 → 0–100, one decimal
```

| Feature | Weight |
|---|---|
| bias | −4.2 |
| severity | 3.0 |
| attack_path | 2.2 |
| exposure | 1.8 |
| data_sensitivity | 1.4 |
| identity_risk | 1.2 |
| criticality | 0.9 |
| vulnerability_count | 0.8 |
| compliance_weight | 0.6 |
| recent_change | 0.5 |
| ownership | 0.4 |

Every feature is defined in [`python/nimbus/risk_weights.json`](https://github.com/DreadpiratePickles/nimbus/blob/main/python/nimbus/risk_weights.json). You can replace the weights with your own linear model as JSON (`--model FILE` or `NIMBUS_RISK_MODEL`); pickle files are never loaded.

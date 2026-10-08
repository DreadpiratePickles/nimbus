-- Accounts ranked by severity-weighted open findings plus attack paths.
SELECT f.provider, f.account,
       SUM(CASE f.severity WHEN 'CRITICAL' THEN 10 WHEN 'HIGH' THEN 5 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 1 ELSE 0 END) AS risk_points,
       COUNT(*) AS open_findings,
       SUM(f.severity = 'CRITICAL') AS critical,
       SUM(f.severity = 'HIGH') AS high,
       (SELECT COUNT(*) FROM attack_paths ap WHERE ap.account = f.account) AS attack_paths
FROM findings f
WHERE f.status = 'FAIL'
GROUP BY f.provider, f.account
ORDER BY risk_points + 20 * attack_paths DESC

-- CIS benchmark control status across every CIS pack (AWS, Azure, GCP, Kubernetes, GitHub).
SELECT framework, control_id, provider, account, status, failed, passed, reason
FROM compliance_controls
WHERE framework LIKE 'cis%'
ORDER BY framework, CASE status WHEN 'FAIL' THEN 0 WHEN 'PASS' THEN 1 ELSE 2 END, control_id

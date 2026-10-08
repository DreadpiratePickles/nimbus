-- Public storage buckets that the security graph marks as holding sensitive data (PII, secrets, prod data).
SELECT f.resource_id, f.resource_name, f.provider, f.account, f.region, f.canonical_id, f.severity,
       COALESCE(g.sensitive, 0) AS sensitive, g.criticality, g.owner
FROM findings f
JOIN graph_nodes g ON g.id = f.resource_id
WHERE f.status = 'FAIL'
  AND f.weaknesses LIKE '%"PUBLIC_DATA_STORE"%'
  AND (g.sensitive = 1 OR lower(f.resource_name) LIKE '%pii%' OR lower(f.resource_name) LIKE '%customer%')
ORDER BY CASE f.severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 ELSE 3 END, f.account

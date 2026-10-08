-- Unencrypted data stores (buckets, databases, disks, volumes) per provider and type.
SELECT provider, resource_type, COUNT(DISTINCT resource_id) AS resources, group_concat(DISTINCT resource_name) AS names
FROM findings
WHERE status = 'FAIL' AND weaknesses LIKE '%"UNENCRYPTED_AT_REST"%'
GROUP BY provider, resource_type
ORDER BY resources DESC

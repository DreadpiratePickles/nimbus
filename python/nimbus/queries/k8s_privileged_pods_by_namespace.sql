-- Kubernetes pods with privileged containers / host access, counted per namespace.
SELECT COALESCE(json_extract(doc, '$.resource.attributes.namespace'), 'default') AS namespace,
       account AS cluster, COUNT(DISTINCT resource_id) AS pods,
       group_concat(DISTINCT resource_name) AS pod_names,
       SUM(weaknesses LIKE '%"PRIVILEGED_CONTAINER"%') AS privileged_findings,
       SUM(weaknesses LIKE '%"HOST_ACCESS"%') AS host_access_findings
FROM findings
WHERE status = 'FAIL' AND provider = 'kubernetes'
  AND (weaknesses LIKE '%"PRIVILEGED_CONTAINER"%' OR weaknesses LIKE '%"HOST_ACCESS"%')
GROUP BY namespace, account
ORDER BY pods DESC

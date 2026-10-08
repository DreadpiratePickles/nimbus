-- Internet-exposed compute across AWS, Azure and GCP (one UNION ALL branch per cloud).
-- Uses the resources table with the same EXISTS expression as the <type>s inventory views'
-- internet_exposed column, so it works whether or not a given cloud's view exists yet.
SELECT 'aws' AS cloud, r.id, r.name, r.type, r.account, r.region
FROM resources r
WHERE r.provider = 'aws' AND (r.type LIKE 'aws_instance%' OR r.type LIKE 'aws_lambda%' OR r.type LIKE 'aws_ecs%' OR r.type LIKE 'aws_eks%')
  AND EXISTS (SELECT 1 FROM findings f WHERE f.resource_id = r.id AND f.status = 'FAIL' AND f.weaknesses LIKE '%"PUBLIC_NETWORK_EXPOSURE"%')
UNION ALL
SELECT 'azure', r.id, r.name, r.type, r.account, r.region
FROM resources r
WHERE r.provider = 'azure' AND (r.type LIKE '%virtual_machine%' OR r.type LIKE '%vm%' OR r.type LIKE '%function%' OR r.type LIKE '%kubernetes_cluster%')
  AND EXISTS (SELECT 1 FROM findings f WHERE f.resource_id = r.id AND f.status = 'FAIL' AND f.weaknesses LIKE '%"PUBLIC_NETWORK_EXPOSURE"%')
UNION ALL
SELECT 'gcp', r.id, r.name, r.type, r.account, r.region
FROM resources r
WHERE r.provider = 'gcp' AND (r.type LIKE 'gcp_compute_instance%' OR r.type LIKE '%cloudfunction%' OR r.type LIKE 'gcp_container_cluster%')
  AND EXISTS (SELECT 1 FROM findings f WHERE f.resource_id = r.id AND f.status = 'FAIL' AND f.weaknesses LIKE '%"PUBLIC_NETWORK_EXPOSURE"%')
ORDER BY cloud, account, name

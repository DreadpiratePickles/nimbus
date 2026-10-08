// nimbus / cloud-posture — Neo4j attack-graph queries
// Load the graph with:  cloud-posture graph push --neo4j-uri neo4j://localhost:7687
// Schema (Cartography / BloodHound style): every node has :Resource plus a primary label
// (AWSAccount, EC2Instance, S3Bucket, IAMRole, IAMUser, IAMPolicy, SecurityGroup, RDSInstance,
// LambdaFunction, EKSCluster, EBSVolume, AzureVM, AzureStorageAccount, AzureNSG, AzureSQLServer,
// KeyVault, GCEInstance, GCSBucket, GCPFirewall, CloudSQLInstance, KubernetesPod,
// KubernetesNamespace, KubernetesServiceAccount, ClusterRoleBinding, GitHubRepository,
// GitHubOrganization, OktaUser, Internet). Relationships: RESOURCE, MEMBER_OF_SECURITY_GROUP,
// ATTACHED_TO, STS_ASSUME_ROLE_ALLOWS, POLICY, GRANTS_ACCESS_TO, ALLOWS_TRAFFIC_TO,
// EXPOSED_TO_INTERNET, RUNS_AS, BOUND_TO, MEMBER_OF, TRUSTS, RUNS_ON.
// Node properties: id, name, type, class, provider, account, region, sensitive, criticality,
// owner, weaknesses[], finding_ids[], cve_count, monthly_cost, lastupdated.
// RESOURCE edges are excluded from path queries: account containment is not an attack step.

// ---------------------------------------------------------------------------------------------
// 1. Internet -> sensitive (PII) S3 bucket attack paths, shortest first
// ---------------------------------------------------------------------------------------------
MATCH path = (i:Internet)-[*1..6]->(b:S3Bucket)
WHERE b.sensitive = true
  AND none(r IN relationships(path) WHERE type(r) = 'RESOURCE')
RETURN path, length(path) AS hops
ORDER BY hops
LIMIT 25;

// 1b. Same for every cloud's object / database stores (GCS, Azure Storage, RDS, Cloud SQL, Azure SQL)
MATCH path = (i:Internet)-[*1..6]->(d)
WHERE (d:S3Bucket OR d:GCSBucket OR d:AzureStorageAccount OR d:RDSInstance OR d:CloudSQLInstance OR d:AzureSQLServer OR d:KeyVault)
  AND d.sensitive = true
  AND none(r IN relationships(path) WHERE type(r) = 'RESOURCE')
RETURN d.provider AS provider, d.name AS target, labels(d) AS labels, length(path) AS hops, path
ORDER BY hops, provider
LIMIT 50;

// ---------------------------------------------------------------------------------------------
// 2. All public-facing resources
// ---------------------------------------------------------------------------------------------
MATCH (:Internet)-[e:EXPOSED_TO_INTERNET]->(r:Resource)
RETURN r.provider AS provider, r.account AS account, [l IN labels(r) WHERE l <> 'Resource'][0] AS kind,
       r.name AS name, r.id AS id, e.via AS via, e.ports AS ports, r.criticality AS criticality, r.weaknesses AS weaknesses
ORDER BY provider, account, kind, name;

// 2b. Public-facing compute that can reach a sensitive store through its identity
MATCH (:Internet)-[:EXPOSED_TO_INTERNET]->(c)-[:RUNS_AS|ATTACHED_TO*1..2]->(id)-[:POLICY|GRANTS_ACCESS_TO*1..2]->(d)
WHERE (c:EC2Instance OR c:AzureVM OR c:GCEInstance OR c:LambdaFunction OR c:KubernetesPod) AND d.sensitive = true
RETURN DISTINCT c.name AS entry, id.name AS identity, d.name AS crown_jewel, d.type AS store_type;

// ---------------------------------------------------------------------------------------------
// 3. Blast radius of a compromised IAM role ($role = role name or ARN)
//    Datastores reachable through policies, grants and role chaining within 4 hops.
// ---------------------------------------------------------------------------------------------
MATCH (r:IAMRole)
WHERE r.name = $role OR r.id = $role
MATCH p = (r)-[:POLICY|GRANTS_ACCESS_TO|STS_ASSUME_ROLE_ALLOWS*1..4]->(d)
WHERE d:S3Bucket OR d:RDSInstance OR d:EBSVolume OR d:KeyVault OR d:GCSBucket OR d:CloudSQLInstance
   OR d:AzureStorageAccount OR d:AzureSQLServer OR d.class = 'datastore'
RETURN DISTINCT d.type AS type, d.name AS datastore, d.sensitive AS sensitive, min(length(p)) AS hops
ORDER BY sensitive DESC, hops;

// ---------------------------------------------------------------------------------------------
// 4. Choke points: intermediate nodes that appear on the most internet -> sensitive paths.
//    Fixing (or isolating) the top node breaks the most attack paths at once.
// ---------------------------------------------------------------------------------------------
MATCH path = (:Internet)-[*1..6]->(t)
WHERE t.sensitive = true
  AND none(r IN relationships(path) WHERE type(r) = 'RESOURCE')
UNWIND nodes(path)[1..-1] AS n
WITH n, count(DISTINCT path) AS paths, collect(DISTINCT t.name)[0..10] AS targets
RETURN [l IN labels(n) WHERE l <> 'Resource'][0] AS kind, n.name AS choke_point, n.id AS id,
       paths, targets, n.weaknesses AS weaknesses
ORDER BY paths DESC
LIMIT 20;

// ---------------------------------------------------------------------------------------------
// 5. BloodHoundAz-style: shortest path from any foothold to any admin identity
// ---------------------------------------------------------------------------------------------
MATCH (s), (a)
WHERE (s:Internet OR s:IAMUser OR s:OktaUser OR s:KubernetesPod OR s:GitHubRepository)
  AND (a:IAMRole OR a:IAMUser OR a:IAMPolicy OR a:KubernetesServiceAccount OR a:ClusterRoleBinding OR a.class = 'identity')
  AND ('OVERPRIVILEGED_IDENTITY' IN a.weaknesses OR 'CLUSTER_ADMIN' IN a.weaknesses OR a.name =~ '(?i).*admin.*')
  AND s <> a
MATCH p = shortestPath((s)-[*1..8]->(a))
WHERE none(r IN relationships(p) WHERE type(r) = 'RESOURCE')
RETURN s.name AS start, a.name AS admin, length(p) AS hops, [n IN nodes(p) | n.name] AS route
ORDER BY hops
LIMIT 25;

// ---------------------------------------------------------------------------------------------
// Extras
// ---------------------------------------------------------------------------------------------

// 6. Cross-account / external trust relationships (who can assume into us)
MATCH (role:IAMRole)-[:TRUSTS]->(ext)
WHERE ext.account IS NULL OR ext.account <> role.account
RETURN role.account AS account, role.name AS role, ext.id AS trusted_principal, role.weaknesses AS weaknesses
ORDER BY account, role;

// 6b. Principals that can assume a role which reaches sensitive data
MATCH (p)-[:STS_ASSUME_ROLE_ALLOWS]->(r:IAMRole)-[:POLICY]->(:IAMPolicy)-[:GRANTS_ACCESS_TO]->(d)
WHERE d.sensitive = true
RETURN DISTINCT p.id AS principal, r.name AS role, d.name AS data;

// 7. Kubernetes pods that run as a service account bound to cluster-admin / wildcard roles
MATCH (pod:KubernetesPod)-[:RUNS_AS]->(sa:KubernetesServiceAccount)-[:BOUND_TO]->(role)
WHERE role.name = 'cluster-admin' OR 'CLUSTER_ADMIN' IN role.weaknesses OR 'CLUSTER_ADMIN' IN sa.weaknesses
OPTIONAL MATCH (pod)-[:MEMBER_OF]->(ns:KubernetesNamespace)
RETURN ns.name AS namespace, pod.name AS pod, sa.name AS service_account, role.name AS role, pod.weaknesses AS pod_weaknesses;

// 8. Sensitive data stores without encryption at rest
MATCH (d:Resource)
WHERE d.sensitive = true AND 'UNENCRYPTED_AT_REST' IN d.weaknesses
RETURN d.provider AS provider, d.account AS account, d.type AS type, d.name AS name, d.owner AS owner
ORDER BY provider, account;

// 9. Security groups / NSGs / firewalls open to the internet and what they protect
MATCH (sg)-[t:ALLOWS_TRAFFIC_TO]->(target)
WHERE (sg:SecurityGroup OR sg:AzureNSG OR sg:GCPFirewall) AND 'PUBLIC_NETWORK_EXPOSURE' IN sg.weaknesses
RETURN sg.name AS rule_set, t.ports AS ports, target.name AS target, target.type AS target_type
ORDER BY rule_set;

// 10. Stale nodes not refreshed by the latest sync (pass $update_tag from the push)
MATCH (n:Resource) WHERE n.lastupdated < $update_tag
RETURN n.provider, n.account, n.type, count(*) AS stale ORDER BY stale DESC;

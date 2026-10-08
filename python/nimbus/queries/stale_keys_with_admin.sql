-- Stale credentials whose owning identity (same resource, related resource or same account user) is over-privileged.
SELECT s.resource_id AS credential, s.resource_name, s.provider, s.account, s.canonical_id AS stale_check,
       a.resource_id AS admin_identity, a.canonical_id AS admin_check
FROM findings s
JOIN findings a ON a.account = s.account AND a.provider = s.provider AND a.status = 'FAIL'
  AND a.weaknesses LIKE '%"OVERPRIVILEGED_IDENTITY"%'
  AND (a.resource_id = s.resource_id
       OR s.doc LIKE '%' || a.resource_id || '%'
       OR a.doc LIKE '%' || s.resource_id || '%'
       OR instr(s.resource_id, a.resource_name) > 0)
WHERE s.status = 'FAIL' AND s.weaknesses LIKE '%"STALE_CREDENTIALS"%'
ORDER BY s.account, s.resource_id

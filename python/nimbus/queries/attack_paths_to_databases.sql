-- Attack paths whose chain touches a database (RDS, Cloud SQL, Azure SQL ...), highest score first.
SELECT ap.id, ap.rule_id, ap.name, json_extract(ap.doc, '$.impact') AS impact, ap.provider, ap.account,
       ap.severity, ap.score, json_array_length(ap.doc, '$.steps') AS steps,
       json_extract(ap.doc, '$.steps[#-1].resource') AS target
FROM attack_paths ap
WHERE lower(ap.doc) LIKE '%database%' OR lower(ap.doc) LIKE '%rds%' OR lower(ap.doc) LIKE '%db_instance%'
   OR lower(ap.doc) LIKE '%sql%'
ORDER BY ap.score DESC

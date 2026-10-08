-- Findings trend per scan (from scan summaries) with the number of findings last seen in that scan.
SELECT s.id AS scan_id, s.started_at, s.finished_at,
       json_extract(s.doc, '$.total') AS total, json_extract(s.doc, '$.failed') AS failed,
       json_extract(s.doc, '$.attack_paths') AS attack_paths,
       (SELECT COUNT(*) FROM findings f WHERE f.scan_id = s.id) AS findings_last_seen_in_scan
FROM scans s
ORDER BY s.started_at

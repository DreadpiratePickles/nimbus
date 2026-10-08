-- Share of assessed controls passing, per framework (from the compliance_controls view).
SELECT framework,
       COUNT(DISTINCT control_id) AS controls,
       COUNT(DISTINCT CASE WHEN status = 'FAIL' THEN control_id END) AS failing,
       COUNT(DISTINCT control_id) - COUNT(DISTINCT CASE WHEN status = 'FAIL' THEN control_id END) AS passing,
       ROUND(100.0 * (COUNT(DISTINCT control_id) - COUNT(DISTINCT CASE WHEN status = 'FAIL' THEN control_id END))
             / MAX(COUNT(DISTINCT control_id), 1), 1) AS score_percent
FROM compliance_controls
GROUP BY framework
ORDER BY score_percent

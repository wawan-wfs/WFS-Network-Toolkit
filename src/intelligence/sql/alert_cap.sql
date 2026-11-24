DELETE FROM collector_alerts WHERE id IN (
 SELECT id FROM collector_alerts ORDER BY last_seen DESC,id DESC LIMIT -1 OFFSET ?1
);

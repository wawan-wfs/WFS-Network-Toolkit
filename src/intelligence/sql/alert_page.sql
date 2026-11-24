SELECT id,session,serial,scope,signal,opened,last_seen,total,acknowledged,recovered
FROM collector_alerts
WHERE (?1 = '' OR instr(lower(scope || ' ' || signal || ' ' || session),lower(?1)) > 0)
AND (?2 = 'all' OR (?2 = 'open' AND recovered IS NULL AND acknowledged IS NULL)
 OR (?2 = 'ack' AND recovered IS NULL AND acknowledged IS NOT NULL)
 OR (?2 = 'recovered' AND recovered IS NOT NULL))
ORDER BY last_seen DESC,id DESC LIMIT ?3;

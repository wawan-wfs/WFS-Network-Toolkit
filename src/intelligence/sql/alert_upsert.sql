INSERT INTO collector_alerts(session,serial,scope,signal,opened,last_seen,total,recovered)
VALUES(?1,?2,?3,?4,?5,?6,?7,?8)
ON CONFLICT(session,serial) DO UPDATE SET
 last_seen = CASE WHEN collector_alerts.recovered IS NULL THEN max(collector_alerts.last_seen,excluded.last_seen) ELSE collector_alerts.last_seen END,
 total = CASE WHEN collector_alerts.recovered IS NULL THEN max(collector_alerts.total,excluded.total) ELSE collector_alerts.total END,
 recovered = CASE WHEN collector_alerts.recovered IS NULL AND excluded.recovered >= collector_alerts.last_seen THEN excluded.recovered ELSE collector_alerts.recovered END
WHERE collector_alerts.scope = excluded.scope AND collector_alerts.signal = excluded.signal AND collector_alerts.opened = excluded.opened;

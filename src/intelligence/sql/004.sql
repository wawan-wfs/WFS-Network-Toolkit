CREATE TABLE collector_alerts (
 id INTEGER PRIMARY KEY,
 session TEXT NOT NULL,
 serial INTEGER NOT NULL,
 scope TEXT NOT NULL,
 signal TEXT NOT NULL,
 opened INTEGER NOT NULL,
 last_seen INTEGER NOT NULL,
 total INTEGER NOT NULL,
 acknowledged INTEGER,
 recovered INTEGER,
 UNIQUE(session,serial),
 CHECK(serial > 0 AND total >= 0 AND last_seen >= opened),
 CHECK(recovered IS NULL OR recovered >= opened),
 CHECK(acknowledged IS NULL OR acknowledged >= opened)
);
CREATE INDEX collector_alerts_recent ON collector_alerts(last_seen DESC,id DESC);
PRAGMA user_version=4;

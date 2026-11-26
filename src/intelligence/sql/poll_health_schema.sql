CREATE TABLE poll_health (
 id INTEGER PRIMARY KEY,
 authority TEXT NOT NULL CHECK(length(authority) BETWEEN 1 AND 512),
 stamp INTEGER NOT NULL CHECK(stamp >= 0),
 elapsed_ms INTEGER NOT NULL CHECK(elapsed_ms BETWEEN 0 AND 3600000),
 outcome INTEGER NOT NULL CHECK(outcome BETWEEN 0 AND 7),
 archive_state INTEGER NOT NULL CHECK(archive_state BETWEEN 0 AND 2),
 CHECK((outcome IN (0,1) AND archive_state IN (1,2)) OR
       (outcome BETWEEN 2 AND 7 AND archive_state=0))
);
CREATE INDEX poll_health_scope ON poll_health(authority,id DESC);
PRAGMA application_id=1464742224;
PRAGMA user_version=1;

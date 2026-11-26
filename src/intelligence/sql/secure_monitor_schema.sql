CREATE TABLE secure_observation (
 id INTEGER PRIMARY KEY,
 scope TEXT NOT NULL CHECK(length(scope) BETWEEN 1 AND 128),
 stamp INTEGER NOT NULL CHECK(stamp >= 0),
 report TEXT NOT NULL CHECK(length(CAST(report AS BLOB)) BETWEEN 1 AND 16384)
);
CREATE INDEX secure_observation_scope ON secure_observation(scope,id DESC);
PRAGMA application_id=1464742225;
PRAGMA user_version=1;

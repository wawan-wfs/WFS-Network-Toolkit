CREATE TABLE ipam_evidence (
 scope TEXT NOT NULL CHECK(length(scope)=73 AND substr(scope,1,9)='scope:v1:'),
 cidr TEXT NOT NULL CHECK(length(cidr) BETWEEN 1 AND 64),
 observed_at INTEGER NOT NULL CHECK(observed_at>0),
 recorded_at INTEGER NOT NULL CHECK(recorded_at>=observed_at),
 configured INTEGER NOT NULL CHECK(configured BETWEEN 1 AND 1000000),
 observed INTEGER NOT NULL CHECK(observed BETWEEN 0 AND 1000000),
 partial INTEGER NOT NULL CHECK(partial IN (0,1)),
 PRIMARY KEY(scope,cidr,observed_at)
) WITHOUT ROWID;
CREATE INDEX ipam_evidence_retention ON ipam_evidence(recorded_at,scope,cidr,observed_at);
PRAGMA application_id=1464742227;
PRAGMA user_version=1;

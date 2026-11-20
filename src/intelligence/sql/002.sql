CREATE TABLE router_samples (
 authority TEXT NOT NULL,
 received INTEGER NOT NULL,
 payload TEXT NOT NULL,
 PRIMARY KEY(authority,received)
) WITHOUT ROWID;
CREATE INDEX router_samples_retention ON router_samples(received);
PRAGMA user_version=2;

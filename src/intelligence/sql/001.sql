CREATE TABLE flow (
 id INTEGER PRIMARY KEY,
 fingerprint BLOB NOT NULL UNIQUE,
 profile TEXT NOT NULL,
 site TEXT NOT NULL,
 vrf TEXT,
 exporter TEXT NOT NULL,
 domain INTEGER NOT NULL,
 version INTEGER NOT NULL,
 received INTEGER NOT NULL,
 source TEXT NOT NULL,
 destination TEXT NOT NULL,
 protocol INTEGER,
 ingress INTEGER,
 egress INTEGER,
 data TEXT NOT NULL
);
CREATE INDEX flow_recent ON flow(received DESC,id DESC);
CREATE INDEX flow_src ON flow(source,received DESC,id DESC);
CREATE INDEX flow_dst ON flow(destination,received DESC,id DESC);
CREATE INDEX flow_scope ON flow(site,vrf,received DESC,id DESC);
CREATE TABLE snapshots (id INTEGER PRIMARY KEY, fingerprint BLOB UNIQUE NOT NULL, source TEXT NOT NULL, observed INTEGER NOT NULL, data TEXT NOT NULL);
CREATE INDEX snapshot_time ON snapshots(observed DESC,id DESC);
PRAGMA application_id=1464226638;
PRAGMA user_version=1;

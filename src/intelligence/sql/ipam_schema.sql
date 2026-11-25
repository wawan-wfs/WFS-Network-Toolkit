CREATE TABLE ipam_revision (
 scope TEXT NOT NULL CHECK(length(scope) BETWEEN 1 AND 160),
 cidr TEXT NOT NULL CHECK(length(cidr) BETWEEN 1 AND 64),
 revision INTEGER NOT NULL CHECK(revision BETWEEN 1 AND 16384),
 recorded INTEGER NOT NULL CHECK(recorded >= 0),
 active INTEGER NOT NULL CHECK(active IN (0,1)),
 reserved INTEGER NOT NULL CHECK(reserved IN (0,1)),
 alias TEXT NOT NULL CHECK(length(alias) <= 80),
 tags TEXT NOT NULL CHECK(length(tags) <= 120),
 note TEXT NOT NULL CHECK(length(note) <= 240),
 PRIMARY KEY(scope,cidr,revision)
) WITHOUT ROWID;
PRAGMA application_id=1464742221;
PRAGMA user_version=1;

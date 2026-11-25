CREATE TABLE dhcp6_sample (
 authority TEXT NOT NULL CHECK(length(authority) BETWEEN 1 AND 512),
 stamp INTEGER NOT NULL CHECK(stamp >= 0),
 payload TEXT NOT NULL CHECK(length(CAST(payload AS BLOB)) BETWEEN 1 AND 262144),
 PRIMARY KEY(authority,stamp)
) WITHOUT ROWID;
PRAGMA application_id=1464742214;
PRAGMA user_version=1;

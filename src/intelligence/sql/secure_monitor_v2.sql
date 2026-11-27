CREATE TABLE secure_poll_attempt (
 id INTEGER PRIMARY KEY,
 target TEXT NOT NULL CHECK(length(target) BETWEEN 1 AND 128),
 stamp INTEGER NOT NULL CHECK(stamp >= 0),
 elapsed_ms INTEGER NOT NULL CHECK(elapsed_ms BETWEEN 0 AND 60000),
 success INTEGER NOT NULL CHECK(success IN (0,1))
);
CREATE INDEX secure_poll_attempt_target ON secure_poll_attempt(target,id DESC);
PRAGMA user_version=2;

-- Sessions are short-lived, so rebuild the table rather than migrating rows:
-- expires_at becomes an integer unix timestamp (comparable without relying on
-- text ordering of RFC 3339 strings) and gains an index so expired rows can be
-- pruned cheaply. Existing sessions are dropped; users simply log in again.
DROP TABLE sessions;
CREATE TABLE sessions (
    id          INTEGER PRIMARY KEY,
    token_hash  TEXT NOT NULL UNIQUE,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at  INTEGER NOT NULL
);
CREATE INDEX sessions_user_id ON sessions(user_id);
CREATE INDEX sessions_expires_at ON sessions(expires_at);

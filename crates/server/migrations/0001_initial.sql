CREATE TABLE users (
    id                     INTEGER PRIMARY KEY,
    email                  TEXT NOT NULL UNIQUE,
    auth_hash              TEXT NOT NULL,
    public_key             TEXT NOT NULL,
    encrypted_private_key  TEXT NOT NULL,
    created_at             TEXT NOT NULL
);

CREATE TABLE sessions (
    id          INTEGER PRIMARY KEY,
    token_hash  TEXT NOT NULL UNIQUE,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at  TEXT NOT NULL
);
CREATE INDEX sessions_user_id ON sessions(user_id);

CREATE TABLE secrets (
    id          INTEGER PRIMARY KEY,
    owner_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    payload     TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);
CREATE INDEX secrets_owner_id ON secrets(owner_id);

-- A row here means user_id may read secret_id. wrapped_key is the secret's
-- AES key sealed to that user's public key.
CREATE TABLE secret_keys (
    secret_id    INTEGER NOT NULL REFERENCES secrets(id) ON DELETE CASCADE,
    user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    wrapped_key  TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    PRIMARY KEY (secret_id, user_id)
);
CREATE INDEX secret_keys_user_id ON secret_keys(user_id);

CREATE TABLE invites (
    id           INTEGER PRIMARY KEY,
    secret_id    INTEGER NOT NULL REFERENCES secrets(id) ON DELETE CASCADE,
    inviter_id   INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    invitee_id   INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    wrapped_key  TEXT NOT NULL,
    message      TEXT NOT NULL DEFAULT '',
    created_at   TEXT NOT NULL,
    UNIQUE (secret_id, invitee_id)
);
CREATE INDEX invites_invitee_id ON invites(invitee_id);

CREATE TABLE users (
    id                     INTEGER PRIMARY KEY,
    email                  TEXT NOT NULL UNIQUE,
    auth_hash              TEXT NOT NULL,
    -- Whether auth_hash is a credential anyone holds. Accounts created through
    -- Google store a hash of random bytes instead, so that password login
    -- fails through the ordinary code path with the ordinary timing. This flag
    -- is what stops a passphrase change from turning that into a working
    -- password login and quietly adding a second way into the account.
    password_login         INTEGER NOT NULL DEFAULT 1,
    public_key             TEXT NOT NULL,
    encrypted_private_key  TEXT NOT NULL,
    created_at             TEXT NOT NULL
);

-- expires_at is a unix timestamp in seconds, so it compares without relying
-- on the text ordering of RFC 3339 strings, and is indexed so expired rows
-- can be pruned cheaply.
CREATE TABLE sessions (
    id          INTEGER PRIMARY KEY,
    token_hash  TEXT NOT NULL UNIQUE,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at  INTEGER NOT NULL
);
CREATE INDEX sessions_user_id ON sessions(user_id);
CREATE INDEX sessions_expires_at ON sessions(expires_at);

-- key_version is bumped by every key rotation. Writes that depend on the
-- current key (update, invite, revoke) carry the version the client last saw,
-- so a device holding a stale key gets a 409 instead of re-encrypting under a
-- key a revoked member still holds.
CREATE TABLE secrets (
    id           INTEGER PRIMARY KEY,
    owner_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    payload      TEXT NOT NULL,
    key_version  INTEGER NOT NULL DEFAULT 0,
    created_at   TEXT NOT NULL,
    updated_at   TEXT NOT NULL
);
CREATE INDEX secrets_owner_id ON secrets(owner_id);

-- A row here means user_id may read secret_id. wrapped_key is the secret's
-- AES key, self-wrapped for the owner and sealed to a public key for everyone
-- else.
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

-- Google (OpenID Connect) identities bound to accounts.
--
-- `subject` is the provider's stable user id and is the only thing a sign-in
-- is resolved by. The email is kept for display and is deliberately NOT used
-- for lookup: a provider email can be reassigned, and matching on it would let
-- whoever holds an address today claim an account created by whoever held it
-- before.
CREATE TABLE oauth_identities (
    provider   TEXT    NOT NULL,
    subject    TEXT    NOT NULL,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    email      TEXT    NOT NULL,
    linked_at  INTEGER NOT NULL,
    PRIMARY KEY (provider, subject)
);

-- At most one identity per provider per account, so a sign-in resolves to
-- exactly one user and an account cannot accumulate sign-in paths silently.
CREATE UNIQUE INDEX oauth_identities_user ON oauth_identities(provider, user_id);

-- Authorization requests that are in flight. Only the digest of the state is
-- stored, so a leaked database cannot be used to complete someone's sign-in.
-- `purpose` keeps a flow started to link an identity from being completed as a
-- sign-in, and the reverse. Rows are consumed on use and pruned by expiry.
CREATE TABLE oauth_attempts (
    state_hash       TEXT    PRIMARY KEY,
    purpose          TEXT    NOT NULL,
    -- Digest of a secret handed only to the client that started the flow, over
    -- that client's own connection, and never put in the authorization URL.
    -- Redeeming an attempt needs it, so a (state, code) pair read out of a
    -- browser is not enough to complete someone else's sign-in.
    app_secret_hash  TEXT    NOT NULL,
    -- The account a link flow was started from. NULL for a sign-in, which has
    -- no account yet. A link may only be completed by the session that began
    -- it, so an identity cannot be bound to an account from elsewhere.
    user_id          INTEGER REFERENCES users(id) ON DELETE CASCADE,
    code_verifier    TEXT    NOT NULL,
    nonce            TEXT    NOT NULL,
    redirect_uri     TEXT    NOT NULL,
    expires_at       INTEGER NOT NULL
);
CREATE INDEX oauth_attempts_expires_at ON oauth_attempts(expires_at);

-- A verified identity with no account yet. The client has to prompt for a new
-- passphrase and generate a key pair before the account can exist, because the
-- server cannot produce either; this row holds the verified identity in the
-- meantime. Short-lived, and the ticket is digested like the state above.
CREATE TABLE oauth_pending_registrations (
    ticket_hash  TEXT    PRIMARY KEY,
    provider     TEXT    NOT NULL,
    subject      TEXT    NOT NULL,
    email        TEXT    NOT NULL,
    expires_at   INTEGER NOT NULL
);
CREATE INDEX oauth_pending_registrations_expires_at ON oauth_pending_registrations(expires_at);

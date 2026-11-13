-- Projects: a heading an owner files their own secrets under.
--
-- The name is stored in plaintext, like a secret's name and for the same
-- reason: it is a label the interface has to draw, and the server cannot
-- draw what it cannot read. That is new metadata and worth naming plainly --
-- an operator reading this table learns that an account keeps a project
-- called Perspectiv and which of its secrets sit together. Nothing about the
-- credentials changes: payloads stay sealed and keys stay wrapped.
CREATE TABLE projects (
    id          INTEGER PRIMARY KEY,
    owner_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    created_at  TEXT NOT NULL
);

-- One name per account. Two projects called Perspectiv would draw two
-- identical headings over different secrets, which is a state the owner
-- cannot tell apart and so cannot fix. The index rather than a SELECT first,
-- so two devices creating the same project at once cannot both win.
--
-- NOCASE folds ASCII only, so `Perspectiv` and `perspectiv` collide while
-- two spellings that differ beyond ASCII do not. That is the same collation
-- the secret list is already ordered by, and the looser half costs a
-- duplicate heading rather than access to anything.
CREATE UNIQUE INDEX projects_owner_name ON projects(owner_id, name COLLATE NOCASE);

-- SET NULL, never CASCADE: deleting a project must never delete the
-- credentials filed under it. They become unfiled, and nothing else changes.
ALTER TABLE secrets ADD COLUMN project_id INTEGER REFERENCES projects(id) ON DELETE SET NULL;
CREATE INDEX secrets_project_id ON secrets(project_id);

-- Whether one member may see which project a secret is filed under.
--
-- Per membership rather than per secret, because it is a decision about a
-- person: an owner may want a colleague on the project to see the grouping
-- and a one-off recipient not to. Default 0 on both tables, so every
-- membership that exists today, and every invite from a client that has
-- never heard of projects, shares the credential and nothing more.
ALTER TABLE secret_keys ADD COLUMN share_project INTEGER NOT NULL DEFAULT 0;
ALTER TABLE invites ADD COLUMN share_project INTEGER NOT NULL DEFAULT 0;

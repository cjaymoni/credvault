-- Every key rotation bumps key_version. Writes that depend on the current key
-- (update, invite, revoke) carry the version the client last saw, so a device
-- holding a stale key gets a 409 instead of re-encrypting under a revoked key.
ALTER TABLE secrets ADD COLUMN key_version INTEGER NOT NULL DEFAULT 0;

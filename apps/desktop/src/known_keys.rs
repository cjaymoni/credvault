//! Trust-on-first-use pinning of other users' public keys.
//!
//! The server tells us which public key belongs to an email address. A
//! malicious server could lie and hand us its own key, so the first time we
//! see a key for someone we show its fingerprint for the user to confirm out
//! of band and remember it here. If the server later returns a different key
//! for the same person, that is surfaced as a change rather than silently
//! accepted.

use std::collections::HashMap;
use std::io;
use std::path::Path;

use klavyn_core::PublicKey;
use serde::{Deserialize, Serialize};

/// Keys pinned so far, keyed by server URL and then by email.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct KnownKeys {
    servers: HashMap<String, HashMap<String, String>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum KeyStatus {
    /// Never seen a key for this person on this server.
    New,
    /// Matches the pinned key.
    Known,
    /// Differs from the pinned key: either they re-created their account or
    /// the server is lying. The user must decide.
    Changed { pinned_fingerprint: String },
}

impl KnownKeys {
    /// Load the store; a missing file is simply an empty store.
    pub fn load(path: &Path) -> io::Result<Self> {
        match std::fs::read(path) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e),
        }
    }

    /// Write atomically (temp file + rename) with owner-only permissions.
    pub fn save(&self, path: &Path) -> io::Result<()> {
        let json = serde_json::to_vec_pretty(self).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let tmp = path.with_extension("json.tmp");
        write_private(&tmp, &json)?;
        std::fs::rename(&tmp, path)
    }

    pub fn check(&self, server: &str, email: &str, key: &PublicKey) -> KeyStatus {
        let Some(pinned) = self.servers.get(server).and_then(|users| users.get(email)) else {
            return KeyStatus::New;
        };
        if *pinned == key.to_base64() {
            return KeyStatus::Known;
        }
        let pinned_fingerprint =
            PublicKey::from_base64(pinned).map(|k| k.fingerprint()).unwrap_or_else(|_| "<unreadable>".into());
        KeyStatus::Changed { pinned_fingerprint }
    }

    /// The key pinned for `email` on `server`, if one was pinned and still
    /// parses. Used to ask the server about someone we have shared with
    /// before without making the user read their fingerprint out again.
    pub fn pinned_key(&self, server: &str, email: &str) -> Option<PublicKey> {
        let pinned = self.servers.get(server)?.get(email)?;
        PublicKey::from_base64(pinned).ok()
    }

    pub fn pin(&mut self, server: &str, email: &str, key: &PublicKey) {
        self.servers.entry(server.to_string()).or_default().insert(email.to_string(), key.to_base64());
    }
}

fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(path)?;
        file.write_all(bytes)
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, bytes)
    }
}

#[cfg(test)]
mod tests {
    use klavyn_core::Identity;

    use super::*;

    const SERVER: &str = "https://vault.example.com";

    #[test]
    fn new_then_known_then_changed() {
        let bob = Identity::generate();
        let bob_again = Identity::generate();
        let mut keys = KnownKeys::default();
        assert_eq!(keys.check(SERVER, "bob@example.com", bob.public_key()), KeyStatus::New);
        keys.pin(SERVER, "bob@example.com", bob.public_key());
        assert_eq!(keys.check(SERVER, "bob@example.com", bob.public_key()), KeyStatus::Known);
        assert_eq!(
            keys.check(SERVER, "bob@example.com", bob_again.public_key()),
            KeyStatus::Changed { pinned_fingerprint: bob.public_key().fingerprint() }
        );
        // The pinned key can be read back, to look Bob up again without
        // making the user read his fingerprint out a second time.
        assert_eq!(keys.pinned_key(SERVER, "bob@example.com").as_ref(), Some(bob.public_key()));
        assert_eq!(keys.pinned_key(SERVER, "nobody@example.com"), None);
        assert_eq!(keys.pinned_key("https://other.example.com", "bob@example.com"), None);

        // Pins are per server.
        assert_eq!(keys.check("https://other.example.com", "bob@example.com", bob.public_key()), KeyStatus::New);
        // Re-pinning replaces.
        keys.pin(SERVER, "bob@example.com", bob_again.public_key());
        assert_eq!(keys.check(SERVER, "bob@example.com", bob_again.public_key()), KeyStatus::Known);
    }

    #[test]
    fn round_trips_through_disk_and_tolerates_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_keys.json");
        assert!(KnownKeys::load(&path).unwrap().servers.is_empty());

        let bob = Identity::generate();
        let mut keys = KnownKeys::default();
        keys.pin(SERVER, "bob@example.com", bob.public_key());
        keys.save(&path).unwrap();

        let loaded = KnownKeys::load(&path).unwrap();
        assert_eq!(loaded.check(SERVER, "bob@example.com", bob.public_key()), KeyStatus::Known);
        assert!(!path.with_extension("json.tmp").exists());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        }
    }

    #[test]
    fn corrupt_file_is_an_error_not_an_empty_store() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_keys.json");
        std::fs::write(&path, b"{not json").unwrap();
        assert!(KnownKeys::load(&path).is_err());
    }
}

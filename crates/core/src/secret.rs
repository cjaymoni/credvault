//! Per-secret encryption and key wrapping for sharing.

use std::fmt;

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::aead::{self, Context, Sealed, KEY_LEN};
use crate::identity::{self, Identity, PublicKey, SealedBox};
use crate::{CryptoError, Result};

pub const MAX_FIELD_LEN: usize = 4096;
pub const MAX_NAME_LEN: usize = 200;
/// How many extra details one secret may carry. Enough for the recovery
/// codes, PINs and account numbers people keep alongside a login, bounded so
/// one secret cannot grow without limit.
pub const MAX_CUSTOM_FIELDS: usize = 20;
pub const MAX_LABEL_LEN: usize = 100;
/// Field ids are generated as 16 hex characters; this leaves a little room.
pub const MAX_FIELD_ID_LEN: usize = 64;
/// Largest serialised payload that will be encrypted. Kept under the server's
/// blob limit with room to spare for the AEAD tag, so a payload accepted here
/// is never rejected after encryption, where the error would be far less clear.
pub const MAX_PLAINTEXT_BYTES: usize = 48 * 1024;

/// Anything that encrypts has to fit the blob the server will accept. Checked
/// when this crate is built, so the two limits cannot drift apart unnoticed.
const _: () = assert!(MAX_PLAINTEXT_BYTES + 64 <= crate::api::MAX_BLOB_BYTES);

const SELF_WRAP: Context = Context::new("copy of a secret's key", b"credvault/aead/self-wrap");
/// Bound to the secret's plaintext name as well as its purpose, so the server
/// cannot present one secret's ciphertext under another's name.
const SECRET_PAYLOAD: Context = Context::new("secret", b"credvault/aead/secret-payload");

/// Format of the JSON that goes inside a secret's ciphertext.
///
/// It is written into the plaintext, so it is covered by the AEAD tag and a
/// server cannot change it. Its job is forward-looking: a build that meets a
/// payload written by a *newer* build must refuse it loudly rather than parse
/// what it recognises and silently drop the rest — a client that dropped a
/// field and then saved the secret back would destroy data it never showed.
///
/// Bump it when the meaning of a field changes or a field becomes required.
/// Adding an optional field that older builds can ignore does not need a bump;
/// that is what `serde(default)` on [`SecretPayload::fields`] already covers.
pub const PAYLOAD_FORMAT: u32 = 1;

/// What is actually encrypted: the payload, tagged with the format it was
/// written in.
#[derive(Serialize)]
struct TaggedPayload<'a> {
    v: u32,
    #[serde(flatten)]
    payload: &'a SecretPayload,
}

/// Reads the format tag and nothing else.
///
/// Deliberately a separate pass over the plaintext rather than a `flatten` on
/// the way in: flattening makes serde buffer every field into an intermediate
/// map it owns, which would put the password in an allocation this crate does
/// not wipe. Skipping the other fields costs one more parse of at most
/// [`MAX_PLAINTEXT_BYTES`] and keeps the plaintext in buffers that zeroise.
#[derive(Deserialize)]
struct FormatTag {
    v: u32,
}

/// A secret's key wrapped for one person. The two forms differ in who could
/// have produced them: anyone can seal a box to a public key, but only the
/// owner can derive the self-wrap key, so an `Owner` copy proves the owner
/// made it and the server cannot swap in a key it knows.
///
/// Tagged, so which form a copy takes is stated rather than inferred from
/// which fields happen to be present. A copy of the wrong form is then a
/// parse failure, not something that quietly reads as the other one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "wrap", content = "key", rename_all = "snake_case")]
pub enum WrappedKey {
    /// Sealed to a member's X25519 public key.
    Shared(SealedBox),
    /// Encrypted under the owner's self-wrap key (see `MasterKey::self_wrap_key`).
    Owner(Sealed),
}

impl WrappedKey {
    pub fn ciphertext_len(&self) -> usize {
        match self {
            Self::Shared(boxed) => boxed.sealed.ciphertext.len(),
            Self::Owner(sealed) => sealed.ciphertext.len(),
        }
    }
}

/// One extra detail stored alongside a credential: a recovery code, a PIN, an
/// account number, a security answer. `secret` marks a value that should be
/// masked and revealed deliberately, the way the password is.
#[derive(Clone, PartialEq, Eq, Default, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct CustomField {
    /// Stable identity, assigned once when the field is created.
    ///
    /// An edit says "keep the value I was not shown" by naming the field it
    /// means. A label cannot name it, because several fields may share one; a
    /// position cannot either, because another device may have reordered or
    /// deleted rows since this form was rendered, and a position that still
    /// holds a same-named field would pass a check it should fail. An id is
    /// the only thing that still means the same field afterwards.
    pub id: String,
    pub label: String,
    pub value: String,
    #[serde(default)]
    pub secret: bool,
}

/// A fresh field id. Random rather than sequential so two devices adding a
/// field at the same time cannot produce the same one.
pub fn new_field_id() -> String {
    aead::random_bytes::<8>().iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Print a masked value only when it was marked secret; a label is not
/// sensitive and is what makes the output worth reading at all.
impl fmt::Debug for CustomField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value: &dyn fmt::Debug = if self.secret { &"<redacted>" } else { &self.value };
        f.debug_struct("CustomField").field("label", &self.label).field("value", value).finish()
    }
}

/// The sensitive fields of a credential. Encrypted as one JSON blob so the
/// server cannot tell which fields are present.
#[derive(Clone, PartialEq, Eq, Default, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct SecretPayload {
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub notes: String,
    /// Extra details the fixed fields do not cover. `default` so a payload
    /// without the key still decrypts, and `skip_serializing_if` so one with
    /// no extras is written without it. Together they are what lets a field be
    /// added here without the addition being a break.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<CustomField>,
}

/// Never print the password or notes, even in debug output.
impl fmt::Debug for SecretPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretPayload")
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .field("url", &self.url)
            .field("notes", &"<redacted>")
            .field("fields", &self.fields)
            .finish()
    }
}

impl SecretPayload {
    pub fn validate(&self) -> Result<()> {
        if self.password.is_empty() {
            return Err(CryptoError::InvalidInput("password must not be empty".into()));
        }
        for (label, value) in
            [("username", &self.username), ("password", &self.password), ("url", &self.url), ("notes", &self.notes)]
        {
            if value.len() > MAX_FIELD_LEN {
                return Err(CryptoError::InvalidInput(format!("{label} is longer than {MAX_FIELD_LEN} bytes")));
            }
        }
        if self.fields.len() > MAX_CUSTOM_FIELDS {
            return Err(CryptoError::InvalidInput(format!(
                "a secret may have at most {MAX_CUSTOM_FIELDS} extra fields"
            )));
        }
        let mut seen = std::collections::HashSet::with_capacity(self.fields.len());
        for field in &self.fields {
            validate_label(&field.label)?;
            // Bounded like every other stored string: ids are generated as
            // 16 hex characters, and nothing else should be storing one.
            if field.id.is_empty()
                || field.id.len() > MAX_FIELD_ID_LEN
                || !field.id.chars().all(|c| c.is_ascii_hexdigit())
            {
                return Err(CryptoError::InvalidInput("an extra field has an invalid id".into()));
            }
            // The desktop client catches this earlier, with a better message.
            // This one guards anything else calling the crate directly.
            if !seen.insert(field.id.as_str()) {
                return Err(CryptoError::InvalidInput("two extra fields share an id".into()));
            }
            // Characters, like the label, so the limit matches the one the
            // input box appears to enforce. `MAX_PLAINTEXT_BYTES` still
            // backstops the real encoded size.
            if field.value.chars().count() > MAX_FIELD_LEN {
                return Err(CryptoError::InvalidInput(format!(
                    "the value of \"{}\" is longer than {MAX_FIELD_LEN} characters",
                    field.label.trim()
                )));
            }
        }
        Ok(())
    }
}

/// Validate the label of one custom field, returning it trimmed.
///
/// `SecretPayload::validate` takes `&self` and so can only use this to
/// reject, never to normalise. The desktop client trims on the way in, via
/// `resolve_fields`; a direct caller of this crate that does not will have
/// its untrimmed label stored as given. A blank label is refused rather than
/// stored, because an edit names the field it could not keep a value for.
pub fn validate_label(label: &str) -> Result<String> {
    let trimmed = label.trim();
    if trimmed.is_empty() {
        return Err(CryptoError::InvalidInput("every extra field needs a label".into()));
    }
    // Counted in characters, not bytes, so the limit matches the one the
    // input box appears to enforce and a non-ASCII label is not cut short.
    if trimmed.chars().count() > MAX_LABEL_LEN {
        return Err(CryptoError::InvalidInput(format!("a field label is longer than {MAX_LABEL_LEN} characters")));
    }
    Ok(trimmed.to_string())
}

/// Validate the plaintext display name stored alongside the ciphertext.
pub fn validate_name(name: &str) -> Result<String> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err(CryptoError::InvalidInput("name must not be empty".into()));
    }
    if trimmed.len() > MAX_NAME_LEN {
        return Err(CryptoError::InvalidInput(format!("name is longer than {MAX_NAME_LEN} bytes")));
    }
    Ok(trimmed.to_string())
}

/// The random key that encrypts one secret's payload.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretKey([u8; KEY_LEN]);

impl SecretKey {
    pub fn generate() -> Self {
        Self(aead::random_bytes())
    }

    /// Encrypt `payload` under this key. The (trimmed) `name` is authenticated
    /// as associated data, so the server cannot present this ciphertext under
    /// a different name. Renaming a secret therefore re-encrypts it.
    pub fn encrypt(&self, name: &str, payload: &SecretPayload) -> Result<Sealed> {
        let name = validate_name(name)?;
        payload.validate()?;
        // The serialised plaintext is wiped as soon as it has been encrypted.
        let tagged = TaggedPayload { v: PAYLOAD_FORMAT, payload };
        let json =
            zeroize::Zeroizing::new(serde_json::to_vec(&tagged).map_err(|e| CryptoError::Encoding(e.to_string()))?);
        // Per-field limits cannot catch every combination that adds up to too
        // much, so the total is checked once here, where the real size is known.
        if json.len() > MAX_PLAINTEXT_BYTES {
            return Err(CryptoError::InvalidInput(format!(
                "this secret's details come to {} bytes, over the {MAX_PLAINTEXT_BYTES} byte limit; shorten the \
                 notes or remove an extra field",
                json.len()
            )));
        }
        Ok(aead::encrypt(&self.0, &json, &SECRET_PAYLOAD.bound_to(name.as_bytes())))
    }

    /// Decrypt a payload that was encrypted under `name`.
    ///
    /// # Errors
    ///
    /// [`CryptoError::Decrypt`] if the key, the name, or the ciphertext is
    /// wrong; [`CryptoError::UnsupportedPayloadFormat`] if the payload was
    /// written by a newer build than this one; [`CryptoError::Encoding`] if
    /// the plaintext is not a payload at all.
    pub fn decrypt(&self, name: &str, sealed: &Sealed) -> Result<SecretPayload> {
        let name = validate_name(name)?;
        let json = zeroize::Zeroizing::new(aead::decrypt(&self.0, sealed, &SECRET_PAYLOAD.bound_to(name.as_bytes()))?);
        let tag: FormatTag = serde_json::from_slice(&json)
            .map_err(|e| CryptoError::Encoding(format!("payload has no readable format tag: {e}")))?;
        // No format below the current one has ever shipped, so an unfamiliar
        // tag is not old data to migrate; it is a payload this build cannot
        // account for, and guessing at it would be worse than stopping.
        crate::check_format(SECRET_PAYLOAD.what(), tag.v, PAYLOAD_FORMAT)?;
        serde_json::from_slice(&json).map_err(|e| CryptoError::Encoding(format!("payload: {e}")))
    }

    /// Wrap this key for another user so they can read the secret.
    pub fn wrap_for(&self, recipient: &PublicKey) -> Result<SealedBox> {
        identity::seal(recipient, &self.0)
    }

    /// Wrap this key for its owner under their self-wrap key.
    pub fn wrap_for_owner(&self, self_wrap_key: &[u8; KEY_LEN]) -> Sealed {
        aead::encrypt(self_wrap_key, &self.0, &SELF_WRAP)
    }

    /// Recover the key from the owner's own copy.
    pub fn unwrap_owner(self_wrap_key: &[u8; KEY_LEN], sealed: &Sealed) -> Result<Self> {
        let bytes = zeroize::Zeroizing::new(aead::decrypt(self_wrap_key, sealed, &SELF_WRAP)?);
        Self::from_bytes(&bytes)
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let array: zeroize::Zeroizing<[u8; KEY_LEN]> = zeroize::Zeroizing::new(
            bytes.try_into().map_err(|_| CryptoError::Encoding("secret key must be 32 bytes".into()))?,
        );
        Ok(Self(*array))
    }

    /// Recover the key from a copy sealed to `me`.
    pub fn unwrap_with(me: &Identity, wrapped: &SealedBox) -> Result<Self> {
        let bytes = zeroize::Zeroizing::new(me.open(wrapped)?);
        Self::from_bytes(&bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NAME: &str = "GitHub";

    fn payload() -> SecretPayload {
        SecretPayload {
            username: "jüde".into(),
            password: "pässwörd🔐".into(),
            url: "https://example.com".into(),
            notes: "".into(),
            fields: Vec::new(),
        }
    }

    #[test]
    fn owner_and_shared_user_can_both_decrypt() {
        let owner = Identity::generate();
        let friend = Identity::generate();
        let key = SecretKey::generate();
        let sealed = key.encrypt(NAME, &payload()).unwrap();

        let for_owner = key.wrap_for(owner.public_key()).unwrap();
        let for_friend = key.wrap_for(friend.public_key()).unwrap();

        let owner_key = SecretKey::unwrap_with(&owner, &for_owner).unwrap();
        let friend_key = SecretKey::unwrap_with(&friend, &for_friend).unwrap();
        assert_eq!(owner_key.decrypt(NAME, &sealed).unwrap(), payload());
        assert_eq!(friend_key.decrypt(NAME, &sealed).unwrap(), payload());
    }

    #[test]
    fn name_is_authenticated_but_whitespace_insensitive() {
        let key = SecretKey::generate();
        let sealed = key.encrypt("  GitHub ", &payload()).unwrap();
        assert_eq!(key.decrypt("GitHub", &sealed).unwrap(), payload());
        assert!(key.decrypt("GitLab", &sealed).is_err());
        assert!(key.encrypt("   ", &payload()).is_err());
    }

    #[test]
    fn owner_copy_round_trips_and_needs_the_owners_key() {
        let key = SecretKey::generate();
        let self_wrap = aead::random_bytes::<KEY_LEN>();
        let other = aead::random_bytes::<KEY_LEN>();
        let wrapped = key.wrap_for_owner(&self_wrap);
        let restored = SecretKey::unwrap_owner(&self_wrap, &wrapped).unwrap();
        let sealed = key.encrypt(NAME, &payload()).unwrap();
        assert_eq!(restored.decrypt(NAME, &sealed).unwrap(), payload());
        assert!(SecretKey::unwrap_owner(&other, &wrapped).is_err());
        // An owner copy is not a sealed box, so nobody's identity opens it.
        let me = Identity::generate();
        let as_box = SealedBox { ephemeral_public: me.public_key().clone(), sealed: wrapped };
        assert!(SecretKey::unwrap_with(&me, &as_box).is_err());
    }

    #[test]
    fn wrapped_key_json_states_which_form_it_is() {
        let key = SecretKey::generate();
        let me = Identity::generate();
        let shared = WrappedKey::Shared(key.wrap_for(me.public_key()).unwrap());
        let owner = WrappedKey::Owner(key.wrap_for_owner(&aead::random_bytes::<KEY_LEN>()));
        for original in [&shared, &owner] {
            let json = serde_json::to_string(original).unwrap();
            assert_eq!(&serde_json::from_str::<WrappedKey>(&json).unwrap(), original);
        }
        // The form is named, not guessed at from the fields present. Note
        // the guarantee is one-way: `Sealed` cannot use `deny_unknown_fields`
        // alongside `SealedBox`'s `flatten`, so a sealed box labelled as an
        // owner copy parses, dropping `ephemeral_public`. Nothing is exposed
        // by that — unwrapping it is an AES-GCM open that fails — but it
        // surfaces as a decrypt error rather than an explicit refusal.
        assert!(serde_json::to_string(&owner).unwrap().contains(r#""wrap":"owner""#));
        assert!(serde_json::to_string(&shared).unwrap().contains(r#""wrap":"shared""#));
        // An untagged sealed box is no longer a wrapped key of either form.
        let untagged = serde_json::to_string(&key.wrap_for(me.public_key()).unwrap()).unwrap();
        assert!(serde_json::from_str::<WrappedKey>(&untagged).is_err());
        // The other direction is not a parse failure: a sealed box labelled
        // as an owner copy reads as one, with `ephemeral_public` ignored.
        // Pinned here so the asymmetry is recorded rather than assumed away.
        let mislabelled = format!(r#"{{"wrap":"owner","key":{untagged}}}"#);
        let parsed = serde_json::from_str::<WrappedKey>(&mislabelled).unwrap();
        assert!(matches!(parsed, WrappedKey::Owner(_)));
        // It opens nothing: unwrapping is an authenticated decrypt that fails.
        let WrappedKey::Owner(sealed) = parsed else { unreachable!() };
        assert!(SecretKey::unwrap_owner(&aead::random_bytes::<KEY_LEN>(), &sealed).is_err());
        // Nor is an owner copy wearing the other form's tag.
        let mistagged = serde_json::to_string(&owner).unwrap().replace("owner", "shared");
        assert!(serde_json::from_str::<WrappedKey>(&mistagged).is_err());
    }

    #[test]
    fn stranger_cannot_unwrap() {
        let owner = Identity::generate();
        let stranger = Identity::generate();
        let key = SecretKey::generate();
        let for_owner = key.wrap_for(owner.public_key()).unwrap();
        assert!(SecretKey::unwrap_with(&stranger, &for_owner).is_err());
    }

    /// The tag travels inside the ciphertext, so it is covered by the AEAD tag
    /// and the server can neither read nor change it.
    #[test]
    fn the_format_tag_is_written_inside_the_ciphertext() {
        let key = SecretKey::generate();
        let sealed = key.encrypt(NAME, &payload()).unwrap();
        let plaintext = aead::decrypt(&key.0, &sealed, &SECRET_PAYLOAD.bound_to(NAME.as_bytes())).unwrap();
        let json = String::from_utf8(plaintext).unwrap();
        assert!(json.contains(r#""v":1"#), "{json}");
        // The two tags are different things and only one of them is visible.
        // What the server stores is the envelope: its own scheme version, the
        // nonce and the ciphertext. The payload's tag is inside that
        // ciphertext, along with every field it describes.
        let stored = serde_json::to_string(&sealed).unwrap();
        assert!(stored.starts_with(r#"{"v":1,"nonce":""#), "{stored}");
        for field in ["username", "password", "notes", "fields"] {
            assert!(!stored.contains(field), "{field} is visible in {stored}");
        }
    }

    /// The reason the tag exists: refuse a payload from a newer build rather
    /// than parse the fields this one knows and drop the rest.
    #[test]
    fn a_payload_from_a_newer_build_is_refused_not_half_read() {
        let key = SecretKey::generate();
        let from_the_future = format!(
            r#"{{"v":{},"username":"jude","password":"hunter2","something_new":"must not be dropped"}}"#,
            PAYLOAD_FORMAT + 1
        );
        let sealed = aead::encrypt(&key.0, from_the_future.as_bytes(), &SECRET_PAYLOAD.bound_to(NAME.as_bytes()));
        let error = key.decrypt(NAME, &sealed).unwrap_err();
        assert!(matches!(error, CryptoError::NewerFormat { found, .. } if found == PAYLOAD_FORMAT + 1), "{error:?}");
        assert!(error.to_string().contains("this secret was saved by a newer version"), "{error}");
    }

    #[test]
    fn an_untagged_or_unknown_payload_is_refused() {
        let key = SecretKey::generate();
        // No tag at all is a payload this build cannot account for...
        let untagged = r#"{"username":"jude","password":"hunter2"}"#;
        let sealed = aead::encrypt(&key.0, untagged.as_bytes(), &SECRET_PAYLOAD.bound_to(NAME.as_bytes()));
        assert!(matches!(key.decrypt(NAME, &sealed), Err(CryptoError::Encoding(_))));
        // ...and nor is a format number that never existed.
        let zero = r#"{"v":0,"username":"j","password":"h"}"#;
        let sealed = aead::encrypt(&key.0, zero.as_bytes(), &SECRET_PAYLOAD.bound_to(NAME.as_bytes()));
        assert!(matches!(key.decrypt(NAME, &sealed), Err(CryptoError::UnknownFormat { found: 0, .. })));
    }

    #[test]
    fn empty_password_and_oversized_fields_rejected() {
        let key = SecretKey::generate();
        let mut bad = payload();
        bad.password = String::new();
        assert!(key.encrypt(NAME, &bad).is_err());
        let mut big = payload();
        big.notes = "n".repeat(MAX_FIELD_LEN + 1);
        assert!(key.encrypt(NAME, &big).is_err());
    }

    #[test]
    fn custom_fields_round_trip_and_keep_their_order() {
        let key = SecretKey::generate();
        let mut with_extras = payload();
        with_extras.fields = vec![
            CustomField { id: new_field_id(), label: "Account number".into(), value: "12345678".into(), secret: false },
            CustomField { id: new_field_id(), label: "Recovery code".into(), value: "aaaa-bbbb".into(), secret: true },
            // Two fields may share a label; people really do keep several
            // recovery codes, and they are told apart by id.
            CustomField { id: new_field_id(), label: "Recovery code".into(), value: "cccc-dddd".into(), secret: true },
        ];
        let sealed = key.encrypt(NAME, &with_extras).unwrap();
        let back = key.decrypt(NAME, &sealed).unwrap();
        assert_eq!(back, with_extras);
        assert_eq!(back.fields[2].value, "cccc-dddd");
        assert!(back.fields[1].secret && !back.fields[0].secret);
    }

    /// Characterises the `default` / `skip_serializing_if` pair: a payload
    /// without the key reads as one with no extra fields, and one with no
    /// extra fields is written without the key. This works on the struct
    /// alone, not the encrypted form, which also carries the `v` tag that
    /// [`SecretKey::encrypt`] adds. It is what keeps a field added here from
    /// being a breaking change.
    #[test]
    fn an_absent_field_list_reads_and_writes_as_no_extra_fields() {
        let older = r#"{"username":"jude","password":"hunter2","url":"","notes":"note"}"#;
        let restored: SecretPayload = serde_json::from_str(older).unwrap();
        assert_eq!(restored.username, "jude");
        assert_eq!(restored.notes, "note");
        assert!(restored.fields.is_empty(), "a missing list must read as no extra fields, not fail");

        // And a payload with no extras serialises without the key at all, so
        // nothing already stored changes shape when it is next written.
        let json = serde_json::to_string(&restored).unwrap();
        assert!(!json.contains("fields"), "{json}");
    }

    #[test]
    fn custom_fields_are_validated() {
        let key = SecretKey::generate();
        let with_fields = |fields: Vec<CustomField>| {
            let mut p = payload();
            p.fields = fields;
            p
        };
        let field = |label: &str, value: &str| CustomField {
            id: new_field_id(),
            label: label.into(),
            value: value.into(),
            secret: false,
        };

        // Labels are required and are stored trimmed.
        assert!(key.encrypt(NAME, &with_fields(vec![field("   ", "x")])).is_err());
        assert_eq!(validate_label("  PIN  ").unwrap(), "PIN");
        assert!(validate_label(&"l".repeat(MAX_LABEL_LEN + 1)).is_err());

        // Too many fields, and an oversized value, are both refused.
        let many = (0..=MAX_CUSTOM_FIELDS).map(|i| field(&format!("f{i}"), "v")).collect();
        assert!(key.encrypt(NAME, &with_fields(many)).is_err());
        assert!(key.encrypt(NAME, &with_fields(vec![field("PIN", &"v".repeat(MAX_FIELD_LEN + 1))])).is_err());

        // A value may be empty: the label alone is still worth keeping.
        assert!(key.encrypt(NAME, &with_fields(vec![field("PIN", "")])).is_ok());
    }

    #[test]
    fn a_payload_that_is_too_big_overall_is_refused_before_encryption() {
        let key = SecretKey::generate();
        let mut big = payload();
        // Each field is within its own limit; together they are not.
        big.fields = (0..MAX_CUSTOM_FIELDS)
            .map(|i| CustomField {
                id: new_field_id(),
                label: format!("f{i}"),
                value: "v".repeat(MAX_FIELD_LEN),
                secret: false,
            })
            .collect();
        assert!(big.validate().is_ok(), "every field is individually legal");
        let error = key.encrypt(NAME, &big).unwrap_err();
        assert!(error.to_string().contains("over the"), "{error}");
    }

    #[test]
    fn debug_redacts_secret_field_values_but_not_labels() {
        let mut p = payload();
        p.fields = vec![
            CustomField { id: new_field_id(), label: "Recovery code".into(), value: "top-secret".into(), secret: true },
            CustomField { id: new_field_id(), label: "Account number".into(), value: "12345678".into(), secret: false },
        ];
        let text = format!("{p:?}");
        assert!(text.contains("Recovery code"), "{text}");
        assert!(!text.contains("top-secret"), "{text}");
        // A value the user did not mark sensitive is shown, like the username.
        assert!(text.contains("12345678"), "{text}");
    }

    #[test]
    fn name_validation() {
        assert_eq!(validate_name("  GitHub ").unwrap(), "GitHub");
        assert!(validate_name("   ").is_err());
        assert!(validate_name(&"x".repeat(MAX_NAME_LEN + 1)).is_err());
    }

    #[test]
    fn debug_output_redacts_password_and_notes() {
        let mut p = payload();
        p.notes = "very private".into();
        let text = format!("{p:?}");
        assert!(text.contains("jüde"));
        assert!(!text.contains("pässwörd"));
        assert!(!text.contains("very private"));
    }
}

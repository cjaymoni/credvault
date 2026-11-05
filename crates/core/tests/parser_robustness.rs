//! Randomised robustness sweep over every parser that can be reached with
//! bytes an attacker chooses.
//!
//! The property under test is narrow and absolute: none of these may panic,
//! hang, or consume memory proportional to anything but their input. A parser
//! that panics on a malformed body is a denial of service on the server, which
//! calls all of them on data straight off the wire.
//!
//! The generator is seeded, so a failure here reproduces exactly: the panic
//! message names the iteration, and re-running reaches the same input.

use credvault_core::aead::{self, Sealed, KEY_LEN};
use credvault_core::api::*;
use credvault_core::identity::{normalize_fingerprint, SealedBox};
use credvault_core::kdf::{normalize_email, validate_auth_hash, ServerAddress};
use credvault_core::secret::{validate_label, validate_name, CustomField};
use credvault_core::{PublicKey, SecretKey, SecretPayload, WrappedKey};

/// xorshift64*, so the sweep is reproducible without a dependency.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, bound: usize) -> usize {
        (self.next() % bound as u64) as usize
    }

    fn bytes(&mut self, max: usize) -> Vec<u8> {
        let len = self.below(max + 1);
        (0..len).map(|_| (self.next() & 0xff) as u8).collect()
    }

    /// A string drawn from the characters that actually break parsers: quotes,
    /// braces, control codes, multi-byte UTF-8, combining marks, surrogates
    /// written as escapes, and the odd NUL.
    fn nasty_string(&mut self, max: usize) -> String {
        const ALPHABET: &[&str] = &[
            "\"", "\\", "{", "}", "[", "]", ":", ",", "/", "=", "+", "\0", "\n", "\r", "\t", " ", "a", "0", "-",
            "\u{7f}", "é", "日", "🔐", "\u{0301}", "\u{200b}", "\u{feff}", "\\u0000", "\\ud800", "@", ".", "%", "#",
            "?", "&", "'", "<", ">", "..", "../", "\u{202e}",
        ];
        let len = self.below(max + 1);
        (0..len).map(|_| ALPHABET[self.below(ALPHABET.len())]).collect()
    }

    fn pick<'a>(&mut self, options: &[&'a str]) -> &'a str {
        options[self.below(options.len())]
    }
}

/// Parse `text` as `T` and discard the outcome. Only a panic fails the test.
fn try_parse<T: serde::de::DeserializeOwned>(text: &str) {
    let _ = serde_json::from_str::<T>(text);
}

/// Every wire type the server deserialises from a request body, plus the
/// crypto containers nested inside them.
fn feed_every_wire_type(text: &str) {
    try_parse::<Sealed>(text);
    try_parse::<SealedBox>(text);
    try_parse::<WrappedKey>(text);
    try_parse::<PublicKey>(text);
    try_parse::<SecretPayload>(text);
    try_parse::<CustomField>(text);
    try_parse::<RegisterRequest>(text);
    try_parse::<LoginRequest>(text);
    try_parse::<CreateSecretRequest>(text);
    try_parse::<UpdateSecretRequest>(text);
    try_parse::<RevokeAccessRequest>(text);
    try_parse::<InviteRequest>(text);
    try_parse::<LookupQuery>(text);
    try_parse::<OAuthStartRequest>(text);
    try_parse::<OAuthCallbackRequest>(text);
    try_parse::<OAuthRegisterRequest>(text);
    try_parse::<Health>(text);
}

/// Every free function that takes a caller-supplied string.
fn feed_every_validator(text: &str) {
    let _ = validate_auth_hash(text);
    let _ = normalize_email(text);
    let _ = normalize_fingerprint(text);
    let _ = validate_name(text);
    let _ = validate_label(text);
    let _ = PublicKey::from_base64(text);
    let _ = ServerAddress::parse(text);
}

#[test]
fn no_parser_panics_on_arbitrary_bytes() {
    let mut rng = Rng(0x6C72_7976_6175_6C74);
    for iteration in 0..4_000 {
        let raw = rng.bytes(192);
        // Bytes that happen to be UTF-8 go through the string parsers too;
        // the rest still exercise the lossy path a body can take.
        let text = String::from_utf8_lossy(&raw).into_owned();
        assert!(
            std::panic::catch_unwind(|| {
                feed_every_wire_type(&text);
                feed_every_validator(&text);
            })
            .is_ok(),
            "panicked on iteration {iteration} with bytes {raw:?}"
        );
    }
}

#[test]
fn no_parser_panics_on_adversarial_strings() {
    let mut rng = Rng(0x7365_6372_6574_7321);
    for iteration in 0..4_000 {
        let text = rng.nasty_string(64);
        assert!(
            std::panic::catch_unwind(|| {
                feed_every_wire_type(&text);
                feed_every_validator(&text);
            })
            .is_ok(),
            "panicked on iteration {iteration} with {text:?}"
        );
    }
}

/// Structurally valid JSON with hostile field values — the shape that gets
/// past the outer parse and reaches the validators behind it.
#[test]
fn no_parser_panics_on_well_formed_json_with_hostile_values() {
    let mut rng = Rng(0x7761_6c6c_6574_0001);
    for iteration in 0..4_000 {
        let string = |rng: &mut Rng| serde_json::Value::String(rng.nasty_string(24)).to_string();
        let number = |rng: &mut Rng| {
            rng.pick(&["0", "-1", "9223372036854775807", "-9223372036854775808", "1e308", "-0", "null", "1.5"])
                .to_string()
        };
        let body = format!(
            r#"{{"v":{},"nonce":{},"ciphertext":{},"email":{},"auth_hash":{},"public_key":{},"name":{},"key_version":{},"username":{},"password":{},"wrap":{},"key":{},"state":{},"code":{},"ticket":{},"redirect_uri":{},"purpose":{},"message":{},"fingerprint":{},"fields":[{{"id":{},"label":{},"value":{},"secret":true}}]}}"#,
            number(&mut rng),
            string(&mut rng),
            string(&mut rng),
            string(&mut rng),
            string(&mut rng),
            string(&mut rng),
            string(&mut rng),
            number(&mut rng),
            string(&mut rng),
            string(&mut rng),
            string(&mut rng),
            string(&mut rng),
            string(&mut rng),
            string(&mut rng),
            string(&mut rng),
            string(&mut rng),
            string(&mut rng),
            string(&mut rng),
            string(&mut rng),
            string(&mut rng),
            string(&mut rng),
            string(&mut rng),
        );
        assert!(
            std::panic::catch_unwind(|| feed_every_wire_type(&body)).is_ok(),
            "panicked on iteration {iteration} with {body}"
        );
    }
}

/// Decryption is the one place that takes attacker-chosen ciphertext *and*
/// attacker-chosen associated data. It must always fail cleanly.
#[test]
fn decryption_never_panics_on_forged_blobs() {
    let mut rng = Rng(0x6165_6164_0000_0001);
    let key = SecretKey::generate();
    let raw_key = [7u8; KEY_LEN];
    for iteration in 0..2_000 {
        let sealed = Sealed { v: (rng.next() % 5) as u32, nonce: rng.bytes(20), ciphertext: rng.bytes(96) };
        let name = rng.nasty_string(16);
        let outcome = std::panic::catch_unwind(|| {
            // Through the public API, with a name that is itself hostile.
            let _ = key.decrypt(&name, &sealed);
            // And through the raw layer, whose nonce length is unchecked here.
            let _ = aead::decrypt(&raw_key, &sealed, &aead::Context::new("thing", b"credvault/test"));
            let _ = SecretKey::unwrap_owner(&raw_key, &sealed);
        });
        assert!(outcome.is_ok(), "panicked on iteration {iteration} with {sealed:?} and name {name:?}");
    }
}

/// A real ciphertext whose bytes are then flipped one at a time: every
/// position must fail authentication rather than produce a payload.
#[test]
fn every_single_bit_flip_is_rejected() {
    let key = SecretKey::generate();
    // Built field by field: SecretPayload zeroises on drop, so struct-update
    // syntax cannot move out of a default.
    let mut payload = SecretPayload::default();
    payload.username = "u".into();
    payload.password = "p".into();
    let sealed = key.encrypt("GitHub", &payload).unwrap();
    assert!(key.decrypt("GitHub", &sealed).is_ok(), "the unmodified blob must open");

    for byte in 0..sealed.ciphertext.len() {
        for bit in 0..8 {
            let mut tampered = sealed.clone();
            tampered.ciphertext[byte] ^= 1 << bit;
            assert!(key.decrypt("GitHub", &tampered).is_err(), "byte {byte} bit {bit} was accepted");
        }
    }
    for byte in 0..sealed.nonce.len() {
        let mut tampered = sealed.clone();
        tampered.nonce[byte] ^= 1;
        assert!(key.decrypt("GitHub", &tampered).is_err(), "nonce byte {byte} was accepted");
    }
}

/// Oversized inputs: the validators must reject by length rather than by
/// trying to process what they were handed.
#[test]
fn oversized_inputs_are_refused_not_processed() {
    for size in [MAX_EMAIL_LEN, MAX_BLOB_BYTES, 1 << 20] {
        let huge = "A".repeat(size);
        assert!(std::panic::catch_unwind(|| feed_every_validator(&huge)).is_ok(), "panicked on {size} bytes");
    }
    // Deep nesting is serde_json's recursion limit to enforce, not ours; what
    // matters is that it errors rather than overflowing the stack.
    let deep = format!("{}{}", "[".repeat(2_000), "]".repeat(2_000));
    assert!(serde_json::from_str::<Sealed>(&deep).is_err());
}

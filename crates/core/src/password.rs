//! Random password generation from the OS entropy source.

use rand::seq::SliceRandom;

use crate::{CryptoError, Result};

pub const DEFAULT_LENGTH: usize = 20;
pub const MIN_LENGTH: usize = 8;
pub const MAX_LENGTH: usize = 128;

const LETTERS_AND_DIGITS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const SYMBOLS: &[u8] = b"!@#$%^&*()-_=+[]{};:,.?";

pub fn generate(length: usize, symbols: bool) -> Result<String> {
    if !(MIN_LENGTH..=MAX_LENGTH).contains(&length) {
        return Err(CryptoError::InvalidInput(format!("length must be between {MIN_LENGTH} and {MAX_LENGTH}")));
    }
    let mut alphabet = LETTERS_AND_DIGITS.to_vec();
    if symbols {
        alphabet.extend_from_slice(SYMBOLS);
    }
    let mut rng = rand::rngs::OsRng;
    Ok((0..length).map(|_| *alphabet.choose(&mut rng).expect("alphabet is non-empty") as char).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn length_and_alphabet() {
        let p = generate(32, false).unwrap();
        assert_eq!(p.len(), 32);
        assert!(p.bytes().all(|b| LETTERS_AND_DIGITS.contains(&b)));
    }

    #[test]
    fn rejects_bad_lengths_and_is_random() {
        assert!(generate(4, true).is_err());
        assert!(generate(MAX_LENGTH + 1, true).is_err());
        assert_ne!(generate(20, true).unwrap(), generate(20, true).unwrap());
    }
}

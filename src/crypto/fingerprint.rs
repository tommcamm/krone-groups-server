//! BIP-39 fingerprint encoding per design-spec §4.1/§8.3.
//!
//! Takes a public key, hashes with SHA-256, truncates to 88 bits, and encodes as 8 BIP-39
//! English words. 88 bits = 8 × 11 bit indexes into the 2048-word list.

use bip39::Language;
use sha2::{Digest, Sha256};

/// Compute the 8-word fingerprint of an Ed25519 public key per design-spec §4.1:
/// SHA-256 of the pubkey, truncated to 88 bits, encoded as 8 BIP-39 English words.
pub fn bip39_fingerprint(public_key: &[u8; 32]) -> String {
    let digest = Sha256::digest(public_key);
    encode_88_bits(&digest[..11])
}

fn encode_88_bits(bytes_11: &[u8]) -> String {
    assert_eq!(bytes_11.len(), 11, "need exactly 11 bytes (88 bits)");
    let wordlist = Language::English.word_list();

    // Treat the 11 bytes as a big-endian 88-bit integer and chop into 8 × 11-bit indexes.
    // 88 = 8 * 11.
    let mut acc: u128 = 0;
    for &b in bytes_11 {
        acc = (acc << 8) | b as u128;
    }

    let mut words = Vec::with_capacity(8);
    for i in 0..8 {
        let shift = (7 - i) * 11;
        let idx = ((acc >> shift) & 0x7FF) as usize;
        words.push(wordlist[idx]);
    }
    words.join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic() {
        let pk = [0u8; 32];
        let fp = bip39_fingerprint(&pk);
        assert_eq!(fp.split_whitespace().count(), 8);
        assert_eq!(fp, bip39_fingerprint(&pk));
    }

    #[test]
    fn differs_for_different_keys() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        a[0] = 1;
        b[0] = 2;
        assert_ne!(bip39_fingerprint(&a), bip39_fingerprint(&b));
    }

    #[test]
    fn all_words_valid_bip39() {
        let pk = [0xAB; 32];
        let fp = bip39_fingerprint(&pk);
        let wordlist = Language::English.word_list();
        for w in fp.split_whitespace() {
            assert!(wordlist.contains(&w), "non-bip39 word: {w}");
        }
    }
}

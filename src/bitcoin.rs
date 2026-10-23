//! Bitcoin consensus primitives (80-byte header hashing, Merkle roots and
//! compact-target math). Block production currently only consumes `sha256d`,
//! `merkle_root` and `display_hash`; the remaining header/target helpers are
//! staged for a future protocol upgrade and are intentionally not wired in
//! yet, so dead-code lints are allowed for this module.
#![allow(dead_code)]

use anyhow::{anyhow, Result};
use sha2::{Digest, Sha256};

pub const BITCOIN_GENESIS_BITS: u32 = 0x1d00ffff;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitcoinBlockHeader {
    pub version: i32,
    /// Internal hash byte order, exactly as serialized in a Bitcoin header.
    pub previous_block_hash: [u8; 32],
    /// Internal hash byte order, exactly as serialized in a Bitcoin header.
    pub merkle_root: [u8; 32],
    pub time: u32,
    pub bits: u32,
    pub nonce: u32,
}

impl BitcoinBlockHeader {
    pub fn serialize(&self) -> [u8; 80] {
        let mut out = [0_u8; 80];
        out[0..4].copy_from_slice(&self.version.to_le_bytes());
        out[4..36].copy_from_slice(&self.previous_block_hash);
        out[36..68].copy_from_slice(&self.merkle_root);
        out[68..72].copy_from_slice(&self.time.to_le_bytes());
        out[72..76].copy_from_slice(&self.bits.to_le_bytes());
        out[76..80].copy_from_slice(&self.nonce.to_le_bytes());
        out
    }

    pub fn hash(&self) -> [u8; 32] {
        sha256d(&self.serialize())
    }

    pub fn display_hash(&self) -> String {
        display_hash(&self.hash())
    }

    pub fn meets_target(&self) -> Result<bool> {
        hash_meets_compact_target(&self.hash(), self.bits)
    }
}

pub fn sha256d(bytes: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(bytes);
    let second = Sha256::digest(first);
    let mut out = [0_u8; 32];
    out.copy_from_slice(&second);
    out
}

pub fn display_hash(internal_hash: &[u8; 32]) -> String {
    let mut display = *internal_hash;
    display.reverse();
    hex::encode(display)
}

pub fn internal_hash_from_display_hex(display_hex: &str) -> Result<[u8; 32]> {
    let mut bytes = decode_32_byte_hex(display_hex)?;
    bytes.reverse();
    Ok(bytes)
}

pub fn merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return [0_u8; 32];
    }

    let mut level = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            let left = pair[0];
            let right = if pair.len() == 2 { pair[1] } else { pair[0] };
            next.push(merkle_parent(&left, &right));
        }
        level = next;
    }
    level[0]
}

pub fn merkle_parent(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut preimage = Vec::with_capacity(64);
    preimage.extend_from_slice(left);
    preimage.extend_from_slice(right);
    sha256d(&preimage)
}

pub fn compact_target_to_be_bytes(bits: u32) -> Result<[u8; 32]> {
    let exponent = (bits >> 24) as usize;
    let mantissa = bits & 0x007f_ffff;
    let sign = bits & 0x0080_0000 != 0;

    if sign {
        return Err(anyhow!("compact target must not be negative"));
    }
    if mantissa == 0 {
        return Err(anyhow!("compact target mantissa must be non-zero"));
    }
    if exponent > 32 {
        return Err(anyhow!("compact target exponent exceeds 256-bit range"));
    }

    let mut target = [0_u8; 32];
    let mantissa_bytes = mantissa.to_be_bytes();
    let significant = &mantissa_bytes[1..4];

    if exponent <= 3 {
        let value = mantissa >> (8 * (3 - exponent));
        let value_bytes = value.to_be_bytes();
        target[28..32].copy_from_slice(&value_bytes);
    } else {
        let start = 32 - exponent;
        target[start..start + 3].copy_from_slice(significant);
    }

    Ok(target)
}

pub fn hash_meets_compact_target(internal_hash: &[u8; 32], bits: u32) -> Result<bool> {
    let target = compact_target_to_be_bytes(bits)?;
    let mut hash_be = *internal_hash;
    hash_be.reverse();
    Ok(hash_be <= target)
}

fn decode_32_byte_hex(hex_text: &str) -> Result<[u8; 32]> {
    let normalized = hex_text.trim();
    let bytes = hex::decode(normalized)?;
    if bytes.len() != 32 {
        return Err(anyhow!("hash must be exactly 32 bytes"));
    }
    let mut out = [0_u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bitcoin_genesis_header_hash_matches_reference_vector() {
        let header = BitcoinBlockHeader {
            version: 1,
            previous_block_hash: [0_u8; 32],
            merkle_root: internal_hash_from_display_hex(
                "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b",
            )
            .expect("merkle root"),
            time: 1_231_006_505,
            bits: BITCOIN_GENESIS_BITS,
            nonce: 2_083_236_893,
        };

        assert_eq!(
            header.display_hash(),
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
        );
        assert!(header.meets_target().expect("valid target"));
    }

    #[test]
    fn compact_bits_decode_bitcoin_genesis_target() {
        assert_eq!(
            hex::encode(compact_target_to_be_bytes(BITCOIN_GENESIS_BITS).expect("target")),
            "00000000ffff0000000000000000000000000000000000000000000000000000"
        );
    }

    #[test]
    fn merkle_root_duplicates_odd_leaf_like_bitcoin() {
        let a = sha256d(b"a");
        let b = sha256d(b"b");
        let c = sha256d(b"c");

        let left = merkle_parent(&a, &b);
        let right = merkle_parent(&c, &c);
        let expected = merkle_parent(&left, &right);

        assert_eq!(merkle_root(&[a, b, c]), expected);
    }

    #[test]
    fn hash_target_comparison_rejects_above_target_hashes() {
        let target = compact_target_to_be_bytes(BITCOIN_GENESIS_BITS).expect("target");
        let mut too_high_be = target;
        too_high_be[31] = too_high_be[31].saturating_add(1);
        let mut too_high_internal = too_high_be;
        too_high_internal.reverse();

        assert!(
            !hash_meets_compact_target(&too_high_internal, BITCOIN_GENESIS_BITS)
                .expect("target check")
        );
    }
}

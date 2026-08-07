//! Envelope header codec: canonical fields, per-build permutation and XOR mask
//! (FORMAT.md §2). The permutation/mask are computed once from `build_seed` and
//! cached in [`HeaderCodec`]; they are obfuscation, not a security pillar.

use crate::error::{Error, Result};
use crate::kdf::{blake3_keyed, blake3_xof, fisher_yates, K_HEADER, K_PERM};

pub const FORMAT_VERSION: u8 = 1;
pub const HEADER_LEN: usize = 28;
pub const TAG_LEN: usize = 16;

// Asset type / profile selectors (FORMAT.md §2, RFC §8.2).
pub const ASSET_HOT: u8 = 0; // profile A — sprite chunk
pub const ASSET_COLD: u8 = 1; // profile B — bytecode/.dat/.otb
pub const ASSET_STREAM: u8 = 2; // profile C — sound/music
pub const ASSET_UI: u8 = 3; // profile D — png/font/otui

/// Manifest-only flag OR'd into an asset's `profile` byte: the plaintext is a
/// LuaJIT dump whose opcodes were permuted by the packer (see `luajit.rs`). The
/// client un-permutes after decryption. It lives only in the (signed) manifest
/// entry — never in the envelope header — so it does not affect key derivation.
pub const PROFILE_FLAG_LUA: u8 = 0x80;
/// Low bits of `profile` = the real asset type once [`PROFILE_FLAG_LUA`] is masked.
pub const PROFILE_TYPE_MASK: u8 = 0x7F;

// Header flags.
pub const FLAG_COMPRESSED: u8 = 0b0000_0001; // payload zlib-compressed before encryption
pub const FLAG_CHUNK_PASSTHROUGH: u8 = 0b0000_0010; // chunk stores per-sprite ciphertexts verbatim

/// Canonical field order and sizes (FORMAT.md §2). Index = canonical field id.
/// 0 magic, 1 version, 2 asset_type, 3 cipher_id, 4 flags, 5 nonce, 6 payload_len
const FIELD_SIZES: [usize; 7] = [4, 1, 1, 1, 1, 16, 4];
const NUM_FIELDS: usize = 7;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    pub magic: [u8; 4],
    pub version: u8,
    pub asset_type: u8,
    pub cipher_id: u8,
    pub flags: u8,
    pub nonce: [u8; 16],
    pub payload_len: u32,
}

/// Precomputed permutation + mask + expected magic for one build.
pub struct HeaderCodec {
    /// `perm[k]` = canonical field id placed at output slot `k`.
    perm: [usize; NUM_FIELDS],
    /// Byte offset (in the 28-byte wire header) where output slot `k` starts.
    slot_off: [usize; NUM_FIELDS],
    mask: [u8; HEADER_LEN],
    pub magic: [u8; 4],
}

impl HeaderCodec {
    pub fn new(build_seed: &[u8; 32]) -> Self {
        let p = fisher_yates(NUM_FIELDS, build_seed, &K_PERM);
        let mut perm = [0usize; NUM_FIELDS];
        for (k, v) in p.iter().enumerate() {
            perm[k] = *v as usize;
        }
        let mut slot_off = [0usize; NUM_FIELDS];
        let mut off = 0usize;
        for k in 0..NUM_FIELDS {
            slot_off[k] = off;
            off += FIELD_SIZES[perm[k]];
        }
        debug_assert_eq!(off, HEADER_LEN);

        let mut mask = [0u8; HEADER_LEN];
        blake3_xof(build_seed, &K_HEADER).fill(&mut mask);

        let magic4 = blake3_keyed(&K_HEADER, build_seed);
        let mut magic = [0u8; 4];
        magic.copy_from_slice(&magic4[0..4]);

        HeaderCodec {
            perm,
            slot_off,
            mask,
            magic,
        }
    }

    /// Canonical bytes for field `id` extracted from `h`.
    fn field_bytes(h: &Header, id: usize, out: &mut [u8]) {
        match id {
            0 => out.copy_from_slice(&h.magic),
            1 => out[0] = h.version,
            2 => out[0] = h.asset_type,
            3 => out[0] = h.cipher_id,
            4 => out[0] = h.flags,
            5 => out.copy_from_slice(&h.nonce),
            6 => out.copy_from_slice(&h.payload_len.to_le_bytes()),
            _ => unreachable!(),
        }
    }

    /// Serialize `h` into a 28-byte permuted, XOR-masked wire header.
    pub fn encode(&self, h: &Header) -> [u8; HEADER_LEN] {
        let mut raw = [0u8; HEADER_LEN];
        for k in 0..NUM_FIELDS {
            let id = self.perm[k];
            let off = self.slot_off[k];
            Self::field_bytes(h, id, &mut raw[off..off + FIELD_SIZES[id]]);
        }
        for i in 0..HEADER_LEN {
            raw[i] ^= self.mask[i];
        }
        raw
    }

    /// Parse a 28-byte wire header. Verifies `magic` and `version`.
    pub fn decode(&self, wire: &[u8]) -> Result<Header> {
        if wire.len() < HEADER_LEN {
            return Err(Error::Truncated);
        }
        let mut raw = [0u8; HEADER_LEN];
        raw.copy_from_slice(&wire[..HEADER_LEN]);
        for i in 0..HEADER_LEN {
            raw[i] ^= self.mask[i];
        }
        let mut h = Header {
            magic: [0; 4],
            version: 0,
            asset_type: 0,
            cipher_id: 0,
            flags: 0,
            nonce: [0; 16],
            payload_len: 0,
        };
        for k in 0..NUM_FIELDS {
            let id = self.perm[k];
            let off = self.slot_off[k];
            let s = &raw[off..off + FIELD_SIZES[id]];
            match id {
                0 => h.magic.copy_from_slice(s),
                1 => h.version = s[0],
                2 => h.asset_type = s[0],
                3 => h.cipher_id = s[0],
                4 => h.flags = s[0],
                5 => h.nonce.copy_from_slice(s),
                6 => h.payload_len = u32::from_le_bytes(s.try_into().unwrap()),
                _ => unreachable!(),
            }
        }
        if h.magic != self.magic || h.version != FORMAT_VERSION {
            return Err(Error::BadFormat);
        }
        Ok(h)
    }
}

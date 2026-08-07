//! Key-derivation primitives (FORMAT.md §0, §1.3, §2.1). All domain-separated.
//!
//! These are the *only* KDFs in the system; both the packer and the client route
//! through them so a change here changes both sides at once.

use hkdf::Hkdf;
use sha2::{Digest, Sha256};

// ---- Domain-separation constants (FORMAT.md §0) -------------------------------
//
// Raw 32-byte values, NOT ASCII (hardening item B). The only requirements are that
// they are fixed and pairwise-distinct. Earlier revisions used self-describing
// strings ("czq.v1.share_mask", …) and then opaque ASCII-hex; both showed up in a
// `strings` dump as beacons in .rdata. Raw bytes do not — they are indistinguishable
// from any other binary constant. Each domain uses `keyed_hash(K_x, material)`
// (see below), so the constant is the BLAKE3 key, giving the same domain separation
// derive_key gave, with nothing greppable. The Rust identifiers are stripped.

pub const K_SEED_TERM: [u8; 32] = [
    0x2c, 0x91, 0x0d, 0xf4, 0x63, 0xa8, 0x1e, 0x57, 0xbb, 0x04, 0x9a, 0xe2, 0x38, 0x7f, 0xc5, 0x60,
    0x11, 0xd3, 0x4e, 0x86, 0xa0, 0x7c, 0x59, 0x0b, 0xe4, 0x92, 0x35, 0x6d, 0xc8, 0x1a, 0xf7, 0x83,
];
pub const K_SHARE_MASK: [u8; 32] = [
    0x9e, 0x40, 0xb7, 0x1c, 0x6a, 0xd5, 0x02, 0x88, 0x3f, 0xe1, 0x74, 0x9b, 0x2d, 0xc6, 0x50, 0xa9,
    0x07, 0x63, 0xbe, 0x14, 0x8c, 0x41, 0xf2, 0x5a, 0x99, 0x2b, 0xd0, 0x67, 0x35, 0xae, 0x18, 0xfc,
];
pub const K_COLD: [u8; 32] = [
    0x51, 0xc3, 0x2f, 0x9a, 0x08, 0x76, 0xed, 0x41, 0xb9, 0x1d, 0x84, 0x6f, 0xa2, 0x30, 0xdb, 0x57,
    0xe0, 0x4b, 0x93, 0x2c, 0x68, 0x0f, 0xd7, 0xa5, 0x12, 0x8e, 0x39, 0xc4, 0x7b, 0x50, 0xe6, 0x1f,
];
pub const K_CHUNK_MAC: [u8; 32] = [
    0xb4, 0x28, 0x7d, 0xf1, 0x5c, 0x03, 0x96, 0xea, 0x47, 0xbd, 0x11, 0x8a, 0x62, 0xd9, 0x35, 0x0e,
    0xa8, 0x54, 0xcf, 0x23, 0x79, 0x9e, 0x06, 0xb2, 0x4d, 0xe7, 0x1b, 0x80, 0x3a, 0xc1, 0x66, 0xfd,
];
pub const K_HEADER: [u8; 32] = [
    0x0a, 0x7f, 0xd2, 0x4b, 0x91, 0x26, 0xbc, 0x58, 0xe3, 0x0d, 0x74, 0xa1, 0x39, 0xce, 0x62, 0x8f,
    0x15, 0xb8, 0x43, 0xda, 0x2e, 0x97, 0x6b, 0x00, 0xc5, 0x51, 0xae, 0x38, 0x7c, 0xe9, 0x12, 0x9d,
];
pub const K_PERM: [u8; 32] = [
    0xe8, 0x35, 0x9c, 0x41, 0x0b, 0xf6, 0x7a, 0x2d, 0xd0, 0x64, 0xb3, 0x19, 0x8e, 0x52, 0xc7, 0x03,
    0x99, 0x2a, 0x46, 0xf1, 0x5d, 0xa0, 0x0c, 0xe5, 0x71, 0xbf, 0x38, 0x84, 0x1e, 0xca, 0x67, 0x2b,
];
/// Keys the per-build LuaJIT opcode permutation (see `luajit.rs`).
pub const K_LUA_OP: [u8; 32] = [
    0x6d, 0xf0, 0x1b, 0x84, 0x39, 0xa7, 0x5e, 0xc2, 0x08, 0x91, 0x4c, 0xda, 0x27, 0xb5, 0x60, 0x1f,
    0x83, 0x3e, 0xe1, 0x0a, 0x76, 0xcd, 0x45, 0x98, 0x22, 0xbf, 0x51, 0x0d, 0xea, 0x37, 0x9b, 0x64,
];
/// Keys the manifest confidentiality layer (see `manifest::xor_manifest`).
pub const K_MANIFEST: [u8; 32] = [
    0xf5, 0x1a, 0x87, 0x2e, 0xc0, 0x63, 0xba, 0x49, 0x0d, 0x96, 0x71, 0xdc, 0x28, 0x4f, 0xe3, 0x05,
    0x9b, 0x54, 0xa2, 0x3d, 0x68, 0x1f, 0xc7, 0x80, 0x36, 0xed, 0x12, 0xab, 0x74, 0x5c, 0x09, 0xbe,
];

// ---- Hashes -------------------------------------------------------------------

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

/// BLAKE3 `derive_key` mode: `context` is a literal ASCII string, `material` is
/// hashed under it. Used for masks, seed_term and the header magic.
pub fn blake3_derive_key(context: &str, material: &[u8]) -> [u8; 32] {
    blake3::derive_key(context, material)
}

/// BLAKE3 keyed hash (32-byte key). Used for per-sprite key, sprite IV and chunk MAC.
pub fn blake3_keyed(key: &[u8; 32], data: &[u8]) -> [u8; 32] {
    blake3::keyed_hash(key, data).into()
}

/// HKDF-SHA256 producing a 32-byte OKM (FORMAT.md §1.3).
pub fn hkdf_sha256_32(ikm: &[u8], salt: &[u8], info: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm).expect("32 bytes is within HKDF output limit");
    okm
}

// ---- Keyed XOF over an empty message (FORMAT.md §2.1) --------------------------

/// A deterministic byte stream keyed by `key` and separated by `ctx`. Drives the
/// header permutation and the header XOR mask. One reader per (key, ctx).
pub struct Xof(blake3::OutputReader);

pub fn blake3_xof(key: &[u8; 32], ctx: &[u8]) -> Xof {
    let mut h = blake3::Hasher::new_keyed(key);
    h.update(ctx);
    Xof(h.finalize_xof())
}

impl Xof {
    pub fn fill(&mut self, out: &mut [u8]) {
        self.0.fill(out);
    }
    pub fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.0.fill(&mut b);
        u32::from_le_bytes(b)
    }
}

/// Deterministic Fisher–Yates permutation of `n` elements, driven by a keyed XOF.
/// Identical on packer and client (both call this). For the small `n` used here
/// (7 header fields) the modulo bias is cryptographically irrelevant — this is a
/// header-obfuscation layer, never a security pillar (RFC §8.3).
pub fn fisher_yates(n: usize, key: &[u8; 32], ctx: &[u8]) -> Vec<u8> {
    let mut xof = blake3_xof(key, ctx);
    let mut p: Vec<u8> = (0..n as u8).collect();
    for i in (1..n).rev() {
        let j = (xof.next_u32() as usize) % (i + 1);
        p.swap(i, j);
    }
    p
}

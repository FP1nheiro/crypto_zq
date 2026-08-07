//! Signed manifest (FORMAT.md §5, RFC §12). Binary body + detached Ed25519
//! signature. The body hash is the `integrity_material` that binds `master'`
//! (FORMAT.md §1.2), so any tamper both fails the signature *and* corrupts the
//! reconstructed key — defense in depth (RFC §7.2).

use crate::cipher::aes_ctr_xor;
use crate::error::{Error, Result};
use crate::kdf::{blake3_xof, sha256, K_MANIFEST};
use crate::read::Reader;

use ed25519_dalek::{Signature, VerifyingKey};

pub const MANIFEST_MAGIC: &[u8; 4] = b"CZQM";
pub const SIG_LEN: usize = 64;

/// Confidentiality layer over the whole signed manifest (hardening item C): the
/// asset index (names + ids) is no longer readable at rest. Keyed by `build_seed`
/// — NOT `master'`, because the manifest hash feeds `master'`, so the manifest must
/// be decryptable before `master'` exists. AES-256-CTR, symmetric (same call both
/// ways). Integrity stays the inner Ed25519 signature: a wrong key yields garbage
/// that fails the signature, so `boot` fails (RFC §14). The packer applies this
/// right before writing `manifest.czq`; `Context::boot` reverses it before parsing.
pub fn xor_manifest(build_seed: &[u8; 32], buf: &mut [u8]) {
    let mut ks = [0u8; 48];
    blake3_xof(build_seed, &K_MANIFEST).fill(&mut ks);
    let key: [u8; 32] = ks[0..32].try_into().unwrap();
    let iv: [u8; 16] = ks[32..48].try_into().unwrap();
    aes_ctr_xor(&key, &iv, buf);
}

#[derive(Clone)]
pub struct AssetEntry {
    pub asset_id: u64,
    pub profile: u8,
    pub sha256: [u8; 32],
    pub name: String,
}

pub struct Manifest {
    pub dat_version: u16,
    pub spr_version: u16,
    pub feature_flags: u32,
    pub sprite_cipher: u8,
    pub chunk_size: u32,
    pub assets: Vec<AssetEntry>,
    pub pubkey: [u8; 32],
    /// SHA-256 of the signed body — becomes `integrity_material`.
    pub integrity_material: [u8; 32],
}

impl Manifest {
    /// Parse and verify. `embedded_pubkey` is the key compiled into the client;
    /// the manifest's own pubkey field must equal it (rejects key-swap) and the
    /// signature must verify under it.
    pub fn parse_and_verify(blob: &[u8], embedded_pubkey: &[u8; 32]) -> Result<Manifest> {
        if blob.len() < SIG_LEN {
            return Err(Error::Truncated);
        }
        let body = &blob[..blob.len() - SIG_LEN];
        let sig_bytes = &blob[blob.len() - SIG_LEN..];

        let vk = VerifyingKey::from_bytes(embedded_pubkey).map_err(|_| Error::BadSignature)?;
        let sig = Signature::from_bytes(sig_bytes.try_into().unwrap());
        vk.verify_strict(body, &sig).map_err(|_| Error::BadSignature)?;

        let mut r = Reader::new(body);
        r.expect_magic(MANIFEST_MAGIC)?;
        if r.u8()? != crate::format::FORMAT_VERSION {
            return Err(Error::Unsupported);
        }
        let dat_version = r.u16()?;
        let spr_version = r.u16()?;
        let feature_flags = r.u32()?;
        let sprite_cipher = r.u8()?;
        let chunk_size = r.u32()?;
        let asset_count = r.u32()? as usize;

        let mut assets = Vec::with_capacity(asset_count);
        for _ in 0..asset_count {
            let asset_id = r.u64()?;
            let profile = r.u8()?;
            let sha = r.arr32()?;
            let name_len = r.u16()? as usize;
            let name = String::from_utf8(r.take(name_len)?.to_vec()).map_err(|_| Error::BadFormat)?;
            assets.push(AssetEntry {
                asset_id,
                profile,
                sha256: sha,
                name,
            });
        }
        let pubkey = r.arr32()?;

        // The pubkey inside the signed body must match what we verified with.
        if &pubkey != embedded_pubkey {
            return Err(Error::BadSignature);
        }

        Ok(Manifest {
            dat_version,
            spr_version,
            feature_flags,
            sprite_cipher,
            chunk_size,
            assets,
            pubkey,
            integrity_material: sha256(body),
        })
    }

    pub fn asset_id_by_name(&self, name: &str) -> Option<u64> {
        self.assets
            .iter()
            .find(|a| a.name == name)
            .map(|a| a.asset_id)
    }
}

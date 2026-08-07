//! Build + sign the manifest (FORMAT.md §5, RFC §12). Mirror of the parser in
//! `crypto_core::manifest`; the two must stay in lockstep (same field order).

use czq_core::kdf::sha256;
use czq_core::read::Writer;
use ed25519_dalek::{Signer, SigningKey};

pub struct AssetRecord {
    pub asset_id: u64,
    pub profile: u8,
    pub sha256: [u8; 32],
    pub name: String,
}

pub struct BuiltManifest {
    pub blob: Vec<u8>,
    /// SHA-256 of the signed body — used as `integrity_material` for the shares.
    pub integrity_material: [u8; 32],
}

#[allow(clippy::too_many_arguments)]
pub fn build_and_sign(
    sk: &SigningKey,
    dat_version: u16,
    spr_version: u16,
    feature_flags: u32,
    sprite_cipher: u8,
    chunk_size: u32,
    assets: &[AssetRecord],
) -> BuiltManifest {
    let mut w = Writer::new();
    w.bytes(b"CZQM");
    w.u8(czq_core::FORMAT_VERSION);
    w.u16(dat_version);
    w.u16(spr_version);
    w.u32(feature_flags);
    w.u8(sprite_cipher);
    w.u32(chunk_size);
    w.u32(assets.len() as u32);
    for a in assets {
        w.u64(a.asset_id);
        w.u8(a.profile);
        w.bytes(&a.sha256);
        w.u16(a.name.len() as u16);
        w.bytes(a.name.as_bytes());
    }
    w.bytes(&sk.verifying_key().to_bytes());
    let body = w.into_vec();

    let integrity_material = sha256(&body);
    let sig = sk.sign(&body);

    let mut blob = body;
    blob.extend_from_slice(&sig.to_bytes());
    BuiltManifest {
        blob,
        integrity_material,
    }
}

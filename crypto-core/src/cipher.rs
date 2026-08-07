//! Symmetric ciphers (FORMAT.md §3). One place, used by both packer (seal) and
//! client (open). CTR/ChaCha are XOR streams (same call both directions); GCM is
//! AEAD with a detached 16-byte tag.

use crate::error::{Error, Result};

use aes::cipher::{KeyIvInit, StreamCipher};
use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::Aes256Gcm;
use chacha20::ChaCha20;

type Aes256Ctr = ctr::Ctr128BE<aes::Aes256>;

pub const CIPHER_AES_CTR: u8 = 0;
pub const CIPHER_AES_GCM: u8 = 1;
pub const CIPHER_CHACHA20: u8 = 2;

/// AES-256-CTR in place. `iv` is the full 16-byte initial counter block.
pub fn aes_ctr_xor(key: &[u8; 32], iv: &[u8; 16], buf: &mut [u8]) {
    let mut c = Aes256Ctr::new(key.into(), iv.into());
    c.apply_keystream(buf);
}

/// ChaCha20 (IETF, 96-bit nonce) in place. Uses `nonce[0:12]`.
pub fn chacha20_xor(key: &[u8; 32], nonce16: &[u8; 16], buf: &mut [u8]) {
    let nonce: [u8; 12] = nonce16[0..12].try_into().unwrap();
    let mut c = ChaCha20::new(key.into(), (&nonce).into());
    c.apply_keystream(buf);
}

/// Stream cipher dispatch for profiles A/C (per-sprite / per-block). GCM is not a
/// stream primitive and is rejected here.
pub fn stream_xor(cipher_id: u8, key: &[u8; 32], iv: &[u8; 16], buf: &mut [u8]) -> Result<()> {
    match cipher_id {
        CIPHER_AES_CTR => {
            aes_ctr_xor(key, iv, buf);
            Ok(())
        }
        CIPHER_CHACHA20 => {
            chacha20_xor(key, iv, buf);
            Ok(())
        }
        _ => Err(Error::Unsupported),
    }
}

/// AES-256-GCM seal in place; returns the detached 16-byte tag. `nonce` uses
/// `nonce[0:12]`.
pub fn gcm_seal(key: &[u8; 32], nonce16: &[u8; 16], aad: &[u8], buf: &mut [u8]) -> [u8; 16] {
    let nonce: [u8; 12] = nonce16[0..12].try_into().unwrap();
    let c = Aes256Gcm::new(key.into());
    let tag = c
        .encrypt_in_place_detached((&nonce).into(), aad, buf)
        .expect("gcm seal");
    let mut out = [0u8; 16];
    out.copy_from_slice(tag.as_slice());
    out
}

/// AES-256-GCM open in place; verifies the detached tag. Constant-time on the tag.
pub fn gcm_open(
    key: &[u8; 32],
    nonce16: &[u8; 16],
    aad: &[u8],
    buf: &mut [u8],
    tag: &[u8; 16],
) -> Result<()> {
    let nonce: [u8; 12] = nonce16[0..12].try_into().unwrap();
    let c = Aes256Gcm::new(key.into());
    c.decrypt_in_place_detached((&nonce).into(), aad, buf, tag.into())
        .map_err(|_| Error::AuthFailed)
}

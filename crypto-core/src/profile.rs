//! Envelope seal/open per profile (FORMAT.md §2, §3, §4). Seal = packer side,
//! open = client side; both live here so they cannot drift.

use subtle::ConstantTimeEq;

use crate::cipher::{gcm_open, gcm_seal, stream_xor, CIPHER_AES_GCM};
use crate::error::{Error, Result};
use crate::flate;
use crate::format::{
    Header, HeaderCodec, ASSET_HOT, FLAG_CHUNK_PASSTHROUGH, FLAG_COMPRESSED, FORMAT_VERSION,
    HEADER_LEN, TAG_LEN,
};
use crate::kdf::{blake3_keyed, hkdf_sha256_32, K_CHUNK_MAC, K_COLD};
use crate::sprite::{per_sprite_key, sprite_iv};

// Raw domain constant (hardening item B) — see kdf.rs. Not ASCII, so it does not
// surface in a `strings` dump.
const K_STREAM_MAC: [u8; 32] = [
    0x3b, 0xc7, 0x14, 0x8f, 0x50, 0xa2, 0xe9, 0x06, 0x7d, 0xd1, 0x4b, 0x93, 0x28, 0xbe, 0x65, 0x0c,
    0xa4, 0x1f, 0x82, 0x37, 0xcd, 0x59, 0x0e, 0xf6, 0x91, 0x23, 0xb8, 0x40, 0x6a, 0xdf, 0x15, 0x7c,
];

fn cold_key(master: &[u8; 32], build_salt: &[u8; 16], asset_type: u8, asset_id: u64) -> [u8; 32] {
    let mut info = Vec::with_capacity(K_COLD.len() + 9);
    info.extend_from_slice(&K_COLD);
    info.push(asset_type);
    info.extend_from_slice(&asset_id.to_le_bytes());
    hkdf_sha256_32(master, build_salt, &info)
}

fn stream_mac_key(master: &[u8; 32], build_salt: &[u8; 16], asset_id: u64) -> [u8; 32] {
    let mut info = Vec::with_capacity(K_STREAM_MAC.len() + 8);
    info.extend_from_slice(&K_STREAM_MAC);
    info.extend_from_slice(&asset_id.to_le_bytes());
    hkdf_sha256_32(master, build_salt, &info)
}

fn chunk_mac_key(master: &[u8; 32], build_salt: &[u8; 16], chunk_id: u32) -> [u8; 32] {
    let mut info = Vec::with_capacity(K_CHUNK_MAC.len() + 4);
    info.extend_from_slice(&K_CHUNK_MAC);
    info.extend_from_slice(&chunk_id.to_le_bytes());
    hkdf_sha256_32(master, build_salt, &info)
}

fn mac16(mac_key: &[u8; 32], header: &[u8], payload: &[u8]) -> [u8; 16] {
    let mut m = Vec::with_capacity(header.len() + payload.len());
    m.extend_from_slice(header);
    m.extend_from_slice(payload);
    let full = blake3_keyed(mac_key, &m);
    let mut t = [0u8; 16];
    t.copy_from_slice(&full[0..16]);
    t
}

// --- Cold / UI / Stream (profiles B, C, D) ------------------------------------

/// Seal a whole file into an envelope. B/D use AES-GCM; C uses a stream cipher +
/// BLAKE3 MAC. (packer side)
pub fn seal_cold(
    codec: &HeaderCodec,
    master: &[u8; 32],
    build_salt: &[u8; 16],
    asset_id: u64,
    asset_type: u8,
    cipher_id: u8,
    flags: u8,
    nonce: [u8; 16],
    plaintext: &[u8],
) -> Vec<u8> {
    let key = cold_key(master, build_salt, asset_type, asset_id);
    // Compress-then-encrypt if requested (and only if it shrinks) — FORMAT.md §2.
    let mut flags = flags;
    let payload: Vec<u8> = if flags & FLAG_COMPRESSED != 0 {
        let (c, did) = flate::maybe_compress(plaintext);
        if !did {
            flags &= !FLAG_COMPRESSED;
        }
        c
    } else {
        plaintext.to_vec()
    };
    let header = Header {
        magic: codec.magic,
        version: FORMAT_VERSION,
        asset_type,
        cipher_id,
        flags,
        nonce,
        payload_len: payload.len() as u32,
    };
    let wire = codec.encode(&header);
    let mut buf = payload;
    let tag = if cipher_id == CIPHER_AES_GCM {
        gcm_seal(&key, &nonce, &wire, &mut buf)
    } else {
        stream_xor(cipher_id, &key, &nonce, &mut buf).expect("stream cipher");
        mac16(&stream_mac_key(master, build_salt, asset_id), &wire, &buf)
    };
    let mut out = Vec::with_capacity(HEADER_LEN + buf.len() + TAG_LEN);
    out.extend_from_slice(&wire);
    out.extend_from_slice(&buf);
    out.extend_from_slice(&tag);
    out
}

/// Open a cold/ui/stream envelope. Verifies GCM tag or BLAKE3 MAC. (client side)
pub fn open_cold(
    codec: &HeaderCodec,
    master: &[u8; 32],
    build_salt: &[u8; 16],
    asset_id: u64,
    bytes: &[u8],
) -> Result<Vec<u8>> {
    if bytes.len() < HEADER_LEN + TAG_LEN {
        return Err(Error::Truncated);
    }
    let wire = &bytes[..HEADER_LEN];
    let h = codec.decode(wire)?;
    let plen = h.payload_len as usize;
    if bytes.len() != HEADER_LEN + plen + TAG_LEN {
        return Err(Error::Truncated);
    }
    let payload = &bytes[HEADER_LEN..HEADER_LEN + plen];
    let tag: [u8; 16] = bytes[HEADER_LEN + plen..].try_into().unwrap();
    let key = cold_key(master, build_salt, h.asset_type, asset_id);

    let mut buf = payload.to_vec();
    if h.cipher_id == CIPHER_AES_GCM {
        gcm_open(&key, &h.nonce, wire, &mut buf, &tag)?;
    } else {
        let expect = mac16(&stream_mac_key(master, build_salt, asset_id), wire, payload);
        if expect.ct_eq(&tag).unwrap_u8() != 1 {
            return Err(Error::AuthFailed);
        }
        stream_xor(h.cipher_id, &key, &h.nonce, &mut buf)?;
    }
    if h.flags & FLAG_COMPRESSED != 0 {
        buf = flate::decompress(&buf)?;
    }
    Ok(buf)
}

// --- Hot sprite chunk (profile A) ---------------------------------------------

/// Seal a chunk: `payload` is the concatenation of per-sprite ciphertexts (each
/// sprite already encrypted with its own key via [`encrypt_sprite`]). One MAC per
/// chunk (RFC §13). (packer side)
pub fn seal_chunk(
    codec: &HeaderCodec,
    master: &[u8; 32],
    build_salt: &[u8; 16],
    chunk_id: u32,
    sprite_cipher: u8,
    payload: &[u8],
) -> Vec<u8> {
    let header = Header {
        magic: codec.magic,
        version: FORMAT_VERSION,
        asset_type: ASSET_HOT,
        cipher_id: sprite_cipher,
        flags: FLAG_CHUNK_PASSTHROUGH,
        nonce: [0u8; 16], // per-sprite IVs are derived; chunk nonce unused
        payload_len: payload.len() as u32,
    };
    let wire = codec.encode(&header);
    let tag = mac16(&chunk_mac_key(master, build_salt, chunk_id), &wire, payload);
    let mut out = Vec::with_capacity(HEADER_LEN + payload.len() + TAG_LEN);
    out.extend_from_slice(&wire);
    out.extend_from_slice(payload);
    out.extend_from_slice(&tag);
    out
}

/// Verify a chunk MAC and return the `(header, payload)` view. (client side)
pub fn open_chunk<'a>(
    codec: &HeaderCodec,
    master: &[u8; 32],
    build_salt: &[u8; 16],
    chunk_id: u32,
    bytes: &'a [u8],
    verify: bool,
) -> Result<(Header, &'a [u8])> {
    if bytes.len() < HEADER_LEN + TAG_LEN {
        return Err(Error::Truncated);
    }
    let wire = &bytes[..HEADER_LEN];
    let h = codec.decode(wire)?;
    let plen = h.payload_len as usize;
    if bytes.len() != HEADER_LEN + plen + TAG_LEN {
        return Err(Error::Truncated);
    }
    let payload = &bytes[HEADER_LEN..HEADER_LEN + plen];
    if verify {
        let tag: [u8; 16] = bytes[HEADER_LEN + plen..].try_into().unwrap();
        let expect = mac16(&chunk_mac_key(master, build_salt, chunk_id), wire, payload);
        if expect.ct_eq(&tag).unwrap_u8() != 1 {
            return Err(Error::AuthFailed);
        }
    }
    Ok((h, payload))
}

/// Encrypt one sprite's pixels (packer side). Returns the per-sprite ciphertext
/// to be concatenated into a chunk payload.
pub fn encrypt_sprite(
    master: &[u8; 32],
    sprite_cipher: u8,
    category: u8,
    assembled_id: u32,
    sub_ids: &[u32],
    pixels: &[u8],
) -> Vec<u8> {
    let key = per_sprite_key(master, category, assembled_id, sub_ids);
    let iv = sprite_iv(&key, assembled_id);
    let mut buf = pixels.to_vec();
    stream_xor(sprite_cipher, &key, &iv, &mut buf).expect("stream cipher");
    buf
}

/// Decrypt one sprite's ciphertext (client side).
pub fn decrypt_sprite_ct(
    master: &[u8; 32],
    sprite_cipher: u8,
    category: u8,
    assembled_id: u32,
    sub_ids: &[u32],
    ct: &[u8],
) -> Result<Vec<u8>> {
    let key = per_sprite_key(master, category, assembled_id, sub_ids);
    let iv = sprite_iv(&key, assembled_id);
    let mut buf = ct.to_vec();
    stream_xor(sprite_cipher, &key, &iv, &mut buf)?;
    Ok(buf)
}

//! CZQ crypto-core — the single implementation of the CZQ asset format
//! (spec/FORMAT.md). Consumed by the packer (as a Rust `rlib`) and by the client
//! (as a `staticlib` through the C ABI below). One codebase → packer and client
//! agree byte-for-byte by construction, which is the load-bearing property of
//! RFC §6.
//!
//! Safety posture: this crate is the crypto boundary. It performs no I/O, keeps
//! `master'` in a `Zeroizing` buffer, and returns opaque errors so the client can
//! implement the delayed/non-obvious failure policy of RFC §14.

pub mod cipher;
pub mod context;
pub mod error;
pub mod flate;
pub mod format;
pub mod index;
pub mod kdf;
pub mod luajit;
pub mod manifest;
pub mod profile;
pub mod read;
pub mod shares;
pub mod sprite;

pub use context::{Context, MATERIAL_LEN};
pub use error::{Error, Result};

/// Format version implemented by this build of the core.
pub const FORMAT_VERSION: u8 = format::FORMAT_VERSION;

// =============================================================================
// C ABI (czq_*) — this is what the C++ client links against. See include/czq_core.h
// =============================================================================

use std::os::raw::c_char;
use std::ptr;

/// Opaque handle wrapping a [`Context`].
pub struct CzqContext(Context);

#[inline]
fn slice<'a>(p: *const u8, len: usize) -> &'a [u8] {
    if p.is_null() || len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(p, len) }
    }
}

/// Copy `data` into the caller buffer, writing the needed length to `out_len`.
/// If the buffer is too small (or null), sets `out_len` and returns ShortBuffer.
fn copy_out(data: &[u8], out: *mut u8, out_cap: usize, out_len: *mut usize) -> i32 {
    if !out_len.is_null() {
        unsafe { *out_len = data.len() };
    }
    if out.is_null() || out_cap < data.len() {
        return Error::ShortBuffer.code();
    }
    unsafe {
        ptr::copy_nonoverlapping(data.as_ptr(), out, data.len());
    }
    0
}

/// Format version of this core build.
#[no_mangle]
pub extern "C" fn czq_format_version() -> u32 {
    FORMAT_VERSION as u32
}

/// Boot the context (RFC §14). `pubkey` points to the 32-byte Ed25519 key
/// compiled into the client. On success writes a heap handle to `*out_ctx`
/// (free with [`czq_free`]). Returns 0 or an error code (see error.rs).
///
/// # Safety
/// All pointers must be valid for their stated lengths; `pubkey` must be 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn czq_boot(
    material: *const u8,
    material_len: usize,
    manifest: *const u8,
    manifest_len: usize,
    pubkey: *const u8,
    out_ctx: *mut *mut CzqContext,
) -> i32 {
    if out_ctx.is_null() || pubkey.is_null() {
        return Error::BadFormat.code();
    }
    *out_ctx = ptr::null_mut();
    let pk: [u8; 32] = match slice(pubkey, 32).try_into() {
        Ok(v) => v,
        Err(_) => return Error::BadFormat.code(),
    };
    match Context::boot(slice(material, material_len), slice(manifest, manifest_len), &pk) {
        Ok(ctx) => {
            *out_ctx = Box::into_raw(Box::new(CzqContext(ctx)));
            0
        }
        Err(e) => e.code(),
    }
}

/// Version fields resolved from the signed manifest (RFC §14 step 4).
#[no_mangle]
pub unsafe extern "C" fn czq_versions(
    ctx: *mut CzqContext,
    dat_version: *mut u16,
    spr_version: *mut u16,
    feature_flags: *mut u32,
) -> i32 {
    let c = match ctx.as_ref() {
        Some(c) => &c.0,
        None => return Error::BadFormat.code(),
    };
    if !dat_version.is_null() {
        *dat_version = c.dat_version;
    }
    if !spr_version.is_null() {
        *spr_version = c.spr_version;
    }
    if !feature_flags.is_null() {
        *feature_flags = c.feature_flags;
    }
    0
}

/// Look up an asset id by logical name (from the manifest table).
#[no_mangle]
pub unsafe extern "C" fn czq_asset_id_by_name(
    ctx: *mut CzqContext,
    name: *const c_char,
    out_id: *mut u64,
) -> i32 {
    let c = match ctx.as_ref() {
        Some(c) => &c.0,
        None => return Error::BadFormat.code(),
    };
    if name.is_null() || out_id.is_null() {
        return Error::BadFormat.code();
    }
    let cstr = std::ffi::CStr::from_ptr(name);
    let name = match cstr.to_str() {
        Ok(s) => s,
        Err(_) => return Error::BadFormat.code(),
    };
    match c.asset_id_by_name(name) {
        Some(id) => {
            *out_id = id;
            0
        }
        None => Error::NotFound.code(),
    }
}

/// Look up an asset id by path suffix (handles the client dropping the `data/`
/// mount prefix). NotFound if zero or ambiguous.
#[no_mangle]
pub unsafe extern "C" fn czq_asset_id_by_suffix(
    ctx: *mut CzqContext,
    name: *const c_char,
    out_id: *mut u64,
) -> i32 {
    let c = match ctx.as_ref() {
        Some(c) => &c.0,
        None => return Error::BadFormat.code(),
    };
    if name.is_null() || out_id.is_null() {
        return Error::BadFormat.code();
    }
    let name = match std::ffi::CStr::from_ptr(name).to_str() {
        Ok(s) => s,
        Err(_) => return Error::BadFormat.code(),
    };
    match c.asset_id_by_suffix(name) {
        Some(id) => {
            *out_id = id;
            0
        }
        None => Error::NotFound.code(),
    }
}

/// Does the signed manifest contain any asset whose name ends with `suffix`?
/// Returns 0 (OK) if yes, NotFound if not. Lets the client enforce the manifest as
/// an access allowlist for a kind only when that kind was actually packed (so a
/// partial pack does not lock out unpacked files). `suffix` is a NUL-terminated
/// UTF-8 string.
#[no_mangle]
pub unsafe extern "C" fn czq_has_asset_suffix(ctx: *mut CzqContext, suffix: *const c_char) -> i32 {
    let c = match ctx.as_ref() {
        Some(c) => &c.0,
        None => return Error::BadFormat.code(),
    };
    if suffix.is_null() {
        return Error::BadFormat.code();
    }
    let s = match std::ffi::CStr::from_ptr(suffix).to_str() {
        Ok(s) => s,
        Err(_) => return Error::BadFormat.code(),
    };
    if c.has_asset_ending(s) {
        0
    } else {
        Error::NotFound.code()
    }
}

/// Decrypt a cold/ui/stream envelope (profiles B/C/D).
#[no_mangle]
pub unsafe extern "C" fn czq_decrypt_cold(
    ctx: *mut CzqContext,
    asset_id: u64,
    envelope: *const u8,
    envelope_len: usize,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    let c = match ctx.as_ref() {
        Some(c) => &c.0,
        None => return Error::BadFormat.code(),
    };
    match c.decrypt_cold(asset_id, slice(envelope, envelope_len)) {
        Ok(pt) => copy_out(&pt, out, out_cap, out_len),
        Err(e) => e.code(),
    }
}

/// Load + decrypt the sprite index into the context (kept in RAM).
#[no_mangle]
pub unsafe extern "C" fn czq_load_index(
    ctx: *mut CzqContext,
    asset_id: u64,
    envelope: *const u8,
    envelope_len: usize,
) -> i32 {
    let c = match ctx.as_mut() {
        Some(c) => &mut c.0,
        None => return Error::BadFormat.code(),
    };
    match c.load_index(asset_id, slice(envelope, envelope_len)) {
        Ok(()) => 0,
        Err(e) => e.code(),
    }
}

/// The chunk id holding `sprite_id` (so the client knows which chunk file to read).
#[no_mangle]
pub unsafe extern "C" fn czq_chunk_of(
    ctx: *mut CzqContext,
    sprite_id: u32,
    out_chunk: *mut u32,
) -> i32 {
    let c = match ctx.as_ref() {
        Some(c) => &c.0,
        None => return Error::BadFormat.code(),
    };
    match c.chunk_of(sprite_id) {
        Ok(cid) => {
            if !out_chunk.is_null() {
                *out_chunk = cid;
            }
            0
        }
        Err(e) => e.code(),
    }
}

/// Write the logical name of the sprite index (asset ending in "chunks/index")
/// into `out` (UTF-8, not NUL-terminated). Same buffer protocol as the decrypt
/// calls. NotFound if the manifest has no sprite index.
#[no_mangle]
pub unsafe extern "C" fn czq_sprite_index_name(
    ctx: *mut CzqContext,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    let c = match ctx.as_ref() {
        Some(c) => &c.0,
        None => return Error::BadFormat.code(),
    };
    match c.sprite_index_name() {
        Some(name) => copy_out(name.as_bytes(), out, out_cap, out_len),
        None => Error::NotFound.code(),
    }
}

/// Original `.spr` sprite count (max id) from the loaded index — the client's
/// `m_spritesCount`. 0 if no index loaded.
#[no_mangle]
pub unsafe extern "C" fn czq_sprite_total(ctx: *mut CzqContext, out_total: *mut u32) -> i32 {
    let c = match ctx.as_ref() {
        Some(c) => &c.0,
        None => return Error::BadFormat.code(),
    };
    if !out_total.is_null() {
        *out_total = c.sprite_total();
    }
    0
}

/// Verify a chunk's MAC (RFC §13). Call once per chunk at preload; then decrypt
/// sprites with verify=0. Returns 0 on success.
#[no_mangle]
pub unsafe extern "C" fn czq_verify_chunk(
    ctx: *mut CzqContext,
    chunk_id: u32,
    chunk: *const u8,
    chunk_len: usize,
) -> i32 {
    let c = match ctx.as_ref() {
        Some(c) => &c.0,
        None => return Error::BadFormat.code(),
    };
    match c.verify_chunk(chunk_id, slice(chunk, chunk_len)) {
        Ok(()) => 0,
        Err(e) => e.code(),
    }
}

/// Decrypt one sprite from its chunk bytes (profile A). `verify` != 0 checks the
/// chunk MAC (do it once per chunk, then pass 0 for subsequent sprites).
#[no_mangle]
pub unsafe extern "C" fn czq_decrypt_sprite(
    ctx: *mut CzqContext,
    sprite_id: u32,
    chunk: *const u8,
    chunk_len: usize,
    verify: i32,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    let c = match ctx.as_ref() {
        Some(c) => &c.0,
        None => return Error::BadFormat.code(),
    };
    match c.decrypt_sprite(sprite_id, slice(chunk, chunk_len), verify != 0) {
        Ok(pt) => copy_out(&pt, out, out_cap, out_len),
        Err(e) => e.code(),
    }
}

/// Free a context handle.
#[no_mangle]
pub unsafe extern "C" fn czq_free(ctx: *mut CzqContext) {
    if !ctx.is_null() {
        drop(Box::from_raw(ctx));
    }
}

/// Compiler-resistant memory wipe for buffers the client owns (RFC §7.4).
#[no_mangle]
pub unsafe extern "C" fn czq_secure_zero(ptr: *mut u8, len: usize) {
    if ptr.is_null() || len == 0 {
        return;
    }
    for i in 0..len {
        std::ptr::write_volatile(ptr.add(i), 0u8);
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

// =============================================================================
// Round-trip tests: prove pack (seal) and client (open) agree end to end.
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::{IndexEntry, CAT_RAW};
    use crate::profile::{encrypt_sprite, seal_chunk, seal_cold};
    use crate::read::Writer;
    use ed25519_dalek::{Signer, SigningKey};

    // Build a signed manifest body the way the packer will (mirrors FORMAT.md §5).
    fn make_manifest(
        sk: &SigningKey,
        sprite_cipher: u8,
        chunk_size: u32,
        assets: &[(u64, u8, [u8; 32], &str)],
    ) -> (Vec<u8>, [u8; 32]) {
        let pubkey = sk.verifying_key().to_bytes();
        let mut w = Writer::new();
        w.bytes(b"CZQM");
        w.u8(FORMAT_VERSION);
        w.u16(1057); // dat_version
        w.u16(1057); // spr_version
        w.u32(0xABCD); // feature_flags
        w.u8(sprite_cipher);
        w.u32(chunk_size);
        w.u32(assets.len() as u32);
        for (id, profile, sha, name) in assets {
            w.u64(*id);
            w.u8(*profile);
            w.bytes(sha);
            w.u16(name.len() as u16);
            w.bytes(name.as_bytes());
        }
        w.bytes(&pubkey);
        let body = w.into_vec();
        let sig = sk.sign(&body);
        let mut blob = body;
        blob.extend_from_slice(&sig.to_bytes());
        (blob, pubkey)
    }

    fn build_material(
        build_seed: [u8; 32],
        build_salt: [u8; 16],
        shares: [[u8; 32]; 4],
        sprite_secret: [u8; 32],
    ) -> Vec<u8> {
        let mut w = Writer::new();
        w.u8(1);
        w.bytes(&build_seed);
        w.bytes(&build_salt);
        for s in &shares {
            w.bytes(s);
        }
        w.bytes(&sprite_secret);
        w.into_vec()
    }

    #[test]
    fn full_round_trip() {
        // --- packer-side setup ---
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let master = [0x42u8; 32]; // stand-in for Argon2id output
        let build_seed = [0x11u8; 32];
        let build_salt = [0x22u8; 16];
        let sprite_cipher = cipher::CIPHER_AES_CTR;
        let chunk_size = 256u32;
        // Key Y (sprites) — independent of master (key X).
        let sprite_secret = [0x55u8; 32];

        let (manifest, pubkey) =
            make_manifest(&sk, sprite_cipher, chunk_size, &[(1, 1, [0u8; 32], "index")]);
        let integrity = kdf::sha256(&manifest[..manifest.len() - 64]);
        let shares = shares::solve_shares(&master, &build_seed, &integrity, &[[1u8; 32], [2u8; 32], [3u8; 32]]);

        // sanity: reconstruction reproduces the real master
        assert_eq!(shares::reconstruct_master(&shares, &build_seed, &integrity), master);

        let material = build_material(build_seed, build_salt, shares, sprite_secret);

        // --- boot the client context (manifest is encrypted at rest, item C) ---
        let mut manifest = manifest;
        crate::manifest::xor_manifest(&build_seed, &mut manifest);
        let mut c = CzqContext(Context::boot(&material, &manifest, &pubkey).unwrap());
        let ctx = &mut c.0;
        assert_eq!(ctx.dat_version, 1057);

        // --- profile B: cold round trip ---
        let codec = format::HeaderCodec::new(&build_seed);
        let plaintext = b"local a = 1 -- lua bytecode stand-in".to_vec();
        let cold = seal_cold(
            &codec,
            &master,
            &build_salt,
            42,
            format::ASSET_COLD,
            cipher::CIPHER_AES_GCM,
            0,
            [9u8; 16],
            &plaintext,
        );
        assert_eq!(ctx.decrypt_cold(42, &cold).unwrap(), plaintext);
        // tamper -> auth failure
        let mut bad = cold.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert!(ctx.decrypt_cold(42, &bad).is_err());

        // --- profile A: two sprites in one chunk + index ---
        let s10 = vec![1u8, 2, 3, 4, 5];
        let s11 = vec![9u8; 40];
        // Dense index is RAW-only: derivation context (category/assembled/sub) is
        // reconstructed from the id, so both sprites are packed as RAW.
        let ct10 = encrypt_sprite(&sprite_secret, sprite_cipher, CAT_RAW, 10, &[10], &s10);
        let ct11 = encrypt_sprite(&sprite_secret, sprite_cipher, CAT_RAW, 11, &[11], &s11);
        let mut payload = Vec::new();
        let off10 = payload.len() as u32;
        payload.extend_from_slice(&ct10);
        let off11 = payload.len() as u32;
        payload.extend_from_slice(&ct11);
        let chunk = seal_chunk(&codec, &sprite_secret, &build_salt, 0, sprite_cipher, &payload);

        // sprites 10 and 11 both land in chunk 0 (spc = 256); offsets are rebuilt
        // by the parser from the sizes, matching off10/off11 here.
        let entries = vec![
            IndexEntry { sprite_id: 10, chunk_id: 0, offset: off10, length: ct10.len() as u32, flags: 0, category: CAT_RAW, assembled_id: 10, sub_ids: vec![10] },
            IndexEntry { sprite_id: 11, chunk_id: 0, offset: off11, length: ct11.len() as u32, flags: 0, category: CAT_RAW, assembled_id: 11, sub_ids: vec![11] },
        ];
        let idx_plain = index::build(&entries, 11, 256);
        let idx_env = seal_cold(&codec, &master, &build_salt, 1, format::ASSET_COLD, cipher::CIPHER_AES_GCM, 0, [5u8; 16], &idx_plain);

        ctx.load_index(1, &idx_env).unwrap();
        assert_eq!(ctx.index_len(), 2);
        assert_eq!(ctx.decrypt_sprite(10, &chunk, true).unwrap(), s10);
        assert_eq!(ctx.decrypt_sprite(11, &chunk, false).unwrap(), s11);

        // chunk tamper -> MAC failure
        let mut bad_chunk = chunk.clone();
        bad_chunk[format::HEADER_LEN] ^= 0xFF;
        assert!(ctx.decrypt_sprite(10, &bad_chunk, true).is_err());
    }

    #[test]
    fn lua_permuted_cold_round_trip() {
        use crate::format::{ASSET_COLD, PROFILE_FLAG_LUA};

        let sk = SigningKey::from_bytes(&[9u8; 32]);
        let master = [0x24u8; 32];
        let build_seed = [0x77u8; 32];
        let build_salt = [0x33u8; 16];

        // Real LuaJIT 2.1 bytecode (same fixture the integration test uses).
        let bytecode = include_bytes!("../tests/fixtures/sample_stripped.ljbc").to_vec();

        // Packer side: permute opcodes with this build's forward perm, then seal as
        // a compressed cold asset (exercises the permute-before-compress ordering).
        let perm = luajit::opcode_perm(&build_seed);
        let permuted = luajit::transcode(&bytecode, &perm).unwrap();
        assert_ne!(permuted, bytecode);

        let asset_id = 55u64;
        let (manifest, pubkey) = make_manifest(
            &sk,
            cipher::CIPHER_AES_CTR,
            256,
            &[(asset_id, ASSET_COLD | PROFILE_FLAG_LUA, [0u8; 32], "modules/x.lua")],
        );
        let integrity = kdf::sha256(&manifest[..manifest.len() - 64]);
        let shares =
            shares::solve_shares(&master, &build_seed, &integrity, &[[1u8; 32], [2u8; 32], [3u8; 32]]);
        let material = build_material(build_seed, build_salt, shares, [0u8; 32]);

        let codec = format::HeaderCodec::new(&build_seed);
        let env = seal_cold(
            &codec,
            &master,
            &build_salt,
            asset_id,
            ASSET_COLD,
            cipher::CIPHER_AES_GCM,
            format::FLAG_COMPRESSED,
            [1u8; 16],
            &permuted,
        );

        // Client side: decrypt_cold must transparently un-permute back to the exact
        // stock bytecode, because the manifest entry carries PROFILE_FLAG_LUA.
        let mut manifest = manifest;
        crate::manifest::xor_manifest(&build_seed, &mut manifest);
        let c = CzqContext(Context::boot(&material, &manifest, &pubkey).unwrap());
        assert_eq!(c.0.decrypt_cold(asset_id, &env).unwrap(), bytecode);
    }

    #[test]
    fn wrong_pubkey_rejected() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let (manifest, _pk) = make_manifest(&sk, 0, 256, &[]);
        let material = build_material([0u8; 32], [0u8; 16], [[0u8; 32]; 4], [0u8; 32]);
        // Encrypt with the same build_seed (all-zero here) so boot decrypts cleanly
        // and the rejection is genuinely the wrong pubkey, not decrypt garbage.
        let mut manifest = manifest;
        crate::manifest::xor_manifest(&[0u8; 32], &mut manifest);
        let wrong = [0xAAu8; 32];
        assert!(Context::boot(&material, &manifest, &wrong).is_err());
    }
}

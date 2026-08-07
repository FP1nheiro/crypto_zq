//! Pack pipeline (RFC §15). Orchestrates: root key → version resolve → seal assets
//! → partition sprites + index → manifest+sign → solve shares → codegen.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use rand::RngCore;

use czq_core::cipher::{CIPHER_AES_CTR, CIPHER_AES_GCM, CIPHER_CHACHA20};
use czq_core::format::{HeaderCodec, ASSET_COLD, ASSET_STREAM, ASSET_UI};
use czq_core::index::{self, IndexEntry, CAT_RAW};
use czq_core::profile::{encrypt_sprite, seal_chunk, seal_cold};
use czq_core::kdf::sha256;

use crate::codegen;
use crate::manifest::{build_and_sign, AssetRecord};
use crate::rootkey::{self, ArgonParams};
use crate::spr;
use crate::versions::{self, Resolved};

const INDEX_ASSET_ID: u64 = 1;
const FIRST_COLD_ASSET_ID: u64 = 100;

pub struct PackConfig {
    pub spr_path: PathBuf,
    pub dat_path: Option<PathBuf>,
    pub otb_path: Option<PathBuf>,
    pub cold_paths: Vec<PathBuf>,
    pub out_dir: PathBuf,
    pub passphrase: String,
    pub versions_xml: PathBuf,
    pub force_version: Option<u16>,
    pub chunk_size: u32,
    pub sprite_cipher: u8,
    pub argon: ArgonParams,
}

/// Pick a profile + cipher from a cold file's extension (RFC §8.2).
fn profile_for(path: &Path) -> (u8, u8, &'static str) {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    match ext.as_str() {
        "png" | "otui" | "ttf" | "otfont" | "qml" | "bmp" => (ASSET_UI, CIPHER_AES_GCM, "ui"),
        "ogg" | "wav" | "mp3" | "flac" => (ASSET_STREAM, CIPHER_AES_CTR, "stream"),
        // lua/luac/dat/otb/otbm and everything else → cold
        _ => (ASSET_COLD, CIPHER_AES_GCM, "cold"),
    }
}

fn rand16() -> [u8; 16] {
    let mut n = [0u8; 16];
    OsRng.fill_bytes(&mut n);
    n
}

fn rand32() -> [u8; 32] {
    let mut n = [0u8; 32];
    OsRng.fill_bytes(&mut n);
    n
}

pub fn parse_sprite_cipher(s: &str) -> Result<u8> {
    Ok(match s.to_ascii_lowercase().as_str() {
        "aes" | "aes-ctr" | "aes256ctr" => CIPHER_AES_CTR,
        "chacha" | "chacha20" => CIPHER_CHACHA20,
        other => bail!("unknown sprite cipher '{other}' (use aes-ctr | chacha20)"),
    })
}

pub fn run(cfg: PackConfig) -> Result<()> {
    fs::create_dir_all(&cfg.out_dir)?;
    let spr_bytes = fs::read(&cfg.spr_path)
        .with_context(|| format!("reading {}", cfg.spr_path.display()))?;
    let dat_bytes = match &cfg.dat_path {
        Some(p) => Some(fs::read(p).with_context(|| format!("reading {}", p.display()))?),
        None => None,
    };

    // --- version resolution (RFC §6.1) ---
    let table_xml = fs::read_to_string(&cfg.versions_xml)
        .with_context(|| format!("reading {}", cfg.versions_xml.display()))?;
    let table = versions::load_table(&table_xml)?;
    let resolved: Resolved = versions::resolve(
        dat_bytes.as_deref(),
        &spr_bytes,
        &table,
        cfg.force_version,
    )?;
    eprintln!(
        "[pack] version dat={} spr={} feature_flags=0x{:X} u32_sprite_ids={}",
        resolved.dat_version, resolved.spr_version, resolved.feature_flags, resolved.u32_sprite_ids
    );

    // --- root key (RFC §7.1) ---
    let argon_salt = rand16();
    let master = rootkey::derive_master(cfg.passphrase.as_bytes(), &argon_salt, cfg.argon)?;
    let build_seed = rand32();
    let build_salt = rand16();
    // Key Y root — SPRITE tier (independent of `master`; see context.rs).
    let sprite_secret = rand32();
    let codec = HeaderCodec::new(&build_seed);

    // --- sprites: partition + per-sprite encrypt + index (RFC §9, §10) ---
    let sprites = spr::parse(&spr_bytes, resolved.u32_sprite_ids)?;
    eprintln!("[pack] {} non-empty sprites", sprites.len());

    let mut chunk_payloads: BTreeMap<u32, Vec<u8>> = BTreeMap::new();
    let mut index_entries: Vec<IndexEntry> = Vec::with_capacity(sprites.len());
    for s in &sprites {
        let chunk_id = s.id / cfg.chunk_size;
        // raw per-sprite context (RFC §9); `.dat`-driven enrichment is the
        // documented extension point in dat::thing_context.
        let ct = encrypt_sprite(&sprite_secret, cfg.sprite_cipher, CAT_RAW, s.id, &[s.id], &s.data);
        let payload = chunk_payloads.entry(chunk_id).or_default();
        let offset = payload.len() as u32;
        payload.extend_from_slice(&ct);
        index_entries.push(IndexEntry {
            sprite_id: s.id,
            chunk_id,
            offset,
            length: ct.len() as u32,
            flags: 0,
            category: CAT_RAW,
            assembled_id: s.id,
            sub_ids: vec![s.id],
        });
    }

    // seal + write chunk files
    let mut chunk_count = 0usize;
    for (chunk_id, payload) in &chunk_payloads {
        let sealed = seal_chunk(&codec, &sprite_secret, &build_salt, *chunk_id, cfg.sprite_cipher, payload);
        fs::write(cfg.out_dir.join(format!("spr_chunk_{chunk_id}.czq")), &sealed)?;
        chunk_count += 1;
    }
    eprintln!("[pack] {chunk_count} chunk files");

    // --- cold/ui/stream assets + index → envelopes + manifest records (RFC §8, §12) ---
    let mut assets: Vec<AssetRecord> = Vec::new();
    let mut next_id = FIRST_COLD_ASSET_ID;

    // index envelope (profile B)
    let sprite_total = index_entries.iter().map(|e| e.sprite_id).max().unwrap_or(0);
    let index_plain = index::build(&index_entries, sprite_total, cfg.chunk_size);
    let index_env = seal_cold(&codec, &master, &build_salt, INDEX_ASSET_ID, ASSET_COLD, CIPHER_AES_GCM, 0, rand16(), &index_plain);
    fs::write(cfg.out_dir.join("index.czq"), &index_env)?;
    assets.push(AssetRecord { asset_id: INDEX_ASSET_ID, profile: ASSET_COLD, sha256: sha256(&index_env), name: "index".into() });

    // collect cold inputs: dat, otb, then explicit cold list
    let mut cold_inputs: Vec<PathBuf> = Vec::new();
    if let Some(p) = &cfg.dat_path { cold_inputs.push(p.clone()); }
    if let Some(p) = &cfg.otb_path { cold_inputs.push(p.clone()); }
    cold_inputs.extend(cfg.cold_paths.iter().cloned());

    for path in &cold_inputs {
        let data = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
        let (asset_type, cipher, kind) = profile_for(path);
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("asset").to_string();
        let asset_id = next_id;
        next_id += 1;
        let env = seal_cold(&codec, &master, &build_salt, asset_id, asset_type, cipher, 0, rand16(), &data);
        let out_name = format!("{name}.czq");
        fs::write(cfg.out_dir.join(&out_name), &env)?;
        assets.push(AssetRecord { asset_id, profile: asset_type, sha256: sha256(&env), name: name.clone() });
        eprintln!("[pack] sealed {kind}: {name} -> {out_name} (id {asset_id})");
    }

    // --- manifest + signature (RFC §12) ---
    let mut sk_seed = [0u8; 32];
    OsRng.fill_bytes(&mut sk_seed);
    let sk = SigningKey::from_bytes(&sk_seed);
    let pubkey = sk.verifying_key().to_bytes();

    let built = build_and_sign(
        &sk,
        resolved.dat_version,
        resolved.spr_version,
        resolved.feature_flags,
        cfg.sprite_cipher,
        cfg.chunk_size,
        &assets,
    );
    // Item C: encrypt the manifest at rest (build_seed key; integrity is the plaintext hash).
    let mut manifest_out = built.blob.clone();
    czq_core::manifest::xor_manifest(&build_seed, &mut manifest_out);
    fs::write(cfg.out_dir.join("manifest.czq"), &manifest_out)?;

    // --- solve + emit shares (RFC §7.3, §15 step 6) ---
    let r = [rand32(), rand32(), rand32()];
    let shares = czq_core::shares::solve_shares(&master, &build_seed, &built.integrity_material, &r);
    // sanity: the client's reconstruction must reproduce `master`
    let check = czq_core::shares::reconstruct_master(&shares, &build_seed, &built.integrity_material);
    if check != master {
        bail!("internal error: share reconstruction mismatch");
    }
    codegen::write_all(&cfg.out_dir, &build_seed, &build_salt, &shares, &sprite_secret, &pubkey)?;

    eprintln!(
        "[pack] done -> {}  ({} assets, {} chunks)\n[pack] embed/ has material.bin, pubkey.bin, czq_build_material.h",
        cfg.out_dir.display(),
        assets.len(),
        chunk_count
    );
    Ok(())
}

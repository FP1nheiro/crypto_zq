//! Directory-mirror encryptor: take a whole client folder, encrypt every file, and
//! write the result to an output folder preserving the exact tree (same names and
//! relative paths). The client's loader decrypts each file on read.
//!
//! `.spr` handling (RFC §9/§10): a `.spr` IS partitioned into chunks + an encrypted
//! index. The chunks go into a `chunks/` folder created next to where the `.spr`
//! was (e.g. `data/Tibia.spr` -> `data/chunks/spr_chunk_<id>.czq` + `data/chunks/index.czq`).
//! Every other file is sealed as a single whole-file envelope (RFC §8) at its
//! mirrored path.

use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use rand::RngCore;

use czq_core::cipher::{CIPHER_AES_CTR, CIPHER_AES_GCM, CIPHER_CHACHA20};
use czq_core::flate::maybe_compress;
use czq_core::format::{HeaderCodec, ASSET_COLD, ASSET_STREAM, ASSET_UI, FLAG_COMPRESSED};
use czq_core::index::{self, IndexEntry, CAT_RAW};
use czq_core::kdf::sha256;
use czq_core::profile::{encrypt_sprite, seal_chunk, seal_cold};

use crate::codegen;
use crate::manifest::{build_and_sign, AssetRecord};
use crate::rootkey::{self, ArgonParams};
use crate::spr;
use crate::versions::{self, Resolved};

const FIRST_ASSET_ID: u64 = 100;

pub struct PackDirConfig {
    pub in_dir: PathBuf,
    pub out_dir: PathBuf,
    pub passphrase: String,
    pub versions_xml: PathBuf,
    pub force_version: Option<u16>,
    pub sprite_cipher: u8,
    /// If true, pick the sprite cipher (AES-CTR or ChaCha20) at random per build,
    /// ignoring `sprite_cipher`. Both are equally secure; rotating them makes an
    /// attacker's tooling handle both. The choice is recorded in the signed manifest,
    /// so the client uses whatever this build picked.
    pub sprite_cipher_random: bool,
    pub chunk_size: u32,
    /// If > 0, target this many chunks per `.spr` (overrides `chunk_size`:
    /// sprites-per-chunk = ceil(total_sprites / num_chunks)).
    pub num_chunks: u32,
    pub compress: bool,
    /// Prepended to every asset's logical name AND output path. Use it to encrypt
    /// a subfolder while keeping names aligned to the client's read paths, e.g.
    /// `--in data/things/1098 --prefix data/things/1098`.
    pub name_prefix: String,
    pub argon: ArgonParams,
    /// Compile `.lua` source to LuaJIT bytecode before encrypting, so the opcode
    /// remap covers them. Requires the client's own `luajit` (see `luajit`).
    pub lua_compile: bool,
    /// Path to the client's `luajit.exe` (same LuaJIT the client links). If None
    /// and `lua_compile` is set, we auto-detect from the input's `vcpkg_installed`.
    pub luajit: Option<PathBuf>,
    /// Phase 1: mark permuted dumps so the *patched client LuaJIT* un-permutes them
    /// (stock bytecode never materializes). Emits `embed/lj_czq_perm.h`. Requires a
    /// LuaJIT built with the czq patch — do NOT enable with a stock LuaJIT.
    pub lua_vm_perm: bool,
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

fn ext_of(path: &Path) -> String {
    path.extension().and_then(|e| e.to_str()).unwrap_or("").to_ascii_lowercase()
}

/// Cheap check: does the file already start with the LuaJIT dump magic? Reads only
/// the first 4 bytes so we never pull a big file in just to classify it.
fn head_is_bytecode(path: &Path) -> bool {
    let mut f = match fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return false,
    };
    let mut head = [0u8; 4];
    match f.read(&mut head) {
        Ok(n) => czq_core::luajit::is_bytecode(&head[..n]),
        Err(_) => false,
    }
}

/// (asset_type, cipher_id) by extension for whole-file assets (RFC §8.2).
fn profile_for(ext: &str, sprite_cipher: u8) -> (u8, u8) {
    match ext {
        "ogg" | "wav" | "mp3" | "flac" => (ASSET_STREAM, CIPHER_AES_CTR),
        "png" | "otui" | "ttf" | "otfont" | "qml" | "bmp" | "jpg" | "jpeg" => (ASSET_UI, CIPHER_AES_GCM),
        "spr" => (ASSET_STREAM, sprite_cipher), // (unused: .spr is chunked, not whole-file)
        _ => (ASSET_COLD, CIPHER_AES_GCM),
    }
}

fn collect(dir: &Path, base: &Path, out: &mut Vec<(String, PathBuf)>) -> Result<()> {
    for entry in fs::read_dir(dir).with_context(|| format!("reading dir {}", dir.display()))? {
        let p = entry?.path();
        if p.is_dir() {
            collect(&p, base, out)?;
        } else if p.is_file() {
            let rel = p.strip_prefix(base).unwrap().to_string_lossy().replace('\\', "/");
            out.push((rel, p));
        }
    }
    Ok(())
}

/// Read at most `max` bytes from the start of a file (so version detection never
/// pulls a 2 GB `.spr` into memory — signature + address table live in the head).
fn read_prefix(path: &Path, max: usize) -> Result<Vec<u8>> {
    let mut f = fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut buf = Vec::new();
    f.by_ref().take(max as u64).read_to_end(&mut buf)?;
    Ok(buf)
}

fn detect_version(files: &[(String, PathBuf)], table_xml: &str, force: Option<u16>) -> Result<Option<Resolved>> {
    let spr = files.iter().find(|(r, _)| r.to_ascii_lowercase().ends_with(".spr"));
    let dat = files.iter().find(|(r, _)| r.to_ascii_lowercase().ends_with(".dat"));
    let Some((_, spr_path)) = spr else {
        return Ok(None);
    };
    let table = versions::load_table(table_xml)?;
    // 16 MiB covers header + address table for well over 3M sprites.
    let spr_bytes = read_prefix(spr_path, 16 * 1024 * 1024)?;
    let dat_bytes = match dat {
        Some((_, p)) => Some(read_prefix(p, 4096)?),
        None => None,
    };
    Ok(Some(versions::resolve(dat_bytes.as_deref(), &spr_bytes, &table, force)?))
}

/// Directory of `<rel>`'s parent as a '/'-path prefix ("" at the root).
fn parent_prefix(rel: &str) -> String {
    match Path::new(rel).parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_string_lossy().replace('\\', "/") + "/",
        _ => String::new(),
    }
}

pub fn run(cfg: PackDirConfig) -> Result<()> {
    let in_canon = fs::canonicalize(&cfg.in_dir)
        .with_context(|| format!("input folder not found: {}", cfg.in_dir.display()))?;
    fs::create_dir_all(&cfg.out_dir)?;
    let out_canon = fs::canonicalize(&cfg.out_dir)?;
    if out_canon == in_canon || out_canon.starts_with(&in_canon) {
        bail!("a pasta de saida nao pode ser a de entrada (nem estar dentro dela)");
    }

    let mut files = Vec::new();
    collect(&in_canon, &in_canon, &mut files)?;
    if files.is_empty() {
        bail!("nenhum arquivo encontrado em {}", in_canon.display());
    }
    files.sort_by(|a, b| a.0.cmp(&b.0));
    eprintln!("[packdir] {} arquivos", files.len());

    let table_xml = fs::read_to_string(&cfg.versions_xml)
        .with_context(|| format!("reading {}", cfg.versions_xml.display()))?;
    let resolved = detect_version(&files, &table_xml, cfg.force_version)?;
    let (dat_v, spr_v, feat, u32_ids) = match resolved {
        Some(r) => {
            eprintln!("[packdir] versao dat={} spr={} feat=0x{:X} u32_ids={}", r.dat_version, r.spr_version, r.feature_flags, r.u32_sprite_ids);
            (r.dat_version, r.spr_version, r.feature_flags, r.u32_sprite_ids)
        }
        None => {
            eprintln!("[packdir] nenhum .spr para detectar versao; carimbando 0");
            (0, 0, 0, true)
        }
    };

    let argon_salt = rand16();
    let master = rootkey::derive_master(cfg.passphrase.as_bytes(), &argon_salt, cfg.argon)?;
    let build_seed = rand32();
    let build_salt = rand16();
    // Key Y root — SPRITE tier. Independent random secret, NOT derived from master.
    // Cold assets (files) use `master` (key X); sprites use this (key Y).
    let sprite_secret = rand32();
    let codec = HeaderCodec::new(&build_seed);
    // Per-build LuaJIT opcode permutation (Lua ladder #2). The client derives the
    // inverse from the same build_seed, so both sides agree by construction.
    let lua_perm = czq_core::luajit::opcode_perm(&build_seed);

    // Per-build sprite-cipher rotation (option #2): AES-CTR and ChaCha20 are equally
    // secure; picking one at random each build forces an attacker's tooling to handle
    // both. The pick is stamped into the signed manifest, so the client follows it.
    let sprite_cipher = if cfg.sprite_cipher_random {
        let mut b = [0u8; 1];
        OsRng.fill_bytes(&mut b);
        let pick = if b[0] & 1 == 0 { CIPHER_AES_CTR } else { CIPHER_CHACHA20 };
        eprintln!(
            "[packdir] cipher de sprite (rotacao por build): {}",
            if pick == CIPHER_AES_CTR { "aes-ctr" } else { "chacha20" }
        );
        pick
    } else {
        cfg.sprite_cipher
    };

    // Optional pre-pass: compile .lua *source* to bytecode using the client's own
    // LuaJIT, so the remap above actually covers them. abs_path -> bytecode.
    let compiled: HashMap<PathBuf, Vec<u8>> = if cfg.lua_compile {
        let luajit = cfg
            .luajit
            .clone()
            .or_else(|| crate::luac::detect_luajit(&in_canon));
        match luajit {
            Some(lj) => {
                // source .lua/.luac that are not already bytecode
                let src: Vec<PathBuf> = files
                    .iter()
                    .filter(|(_, abs)| matches!(ext_of(abs).as_str(), "lua" | "luac"))
                    .filter(|(_, abs)| !head_is_bytecode(abs))
                    .map(|(_, abs)| abs.clone())
                    .collect();
                eprintln!("[packdir] compilando {} .lua source com {}", src.len(), lj.display());
                match crate::luac::compile_batch(&lj, &src) {
                    Ok(m) => {
                        eprintln!("[packdir] lua compilados p/ bytecode: {}/{}", m.len(), src.len());
                        m
                    }
                    Err(e) => {
                        eprintln!("[packdir] compilacao lua falhou: {e} (segue cifrando como source)");
                        HashMap::new()
                    }
                }
            }
            None => {
                eprintln!("[packdir] --lua-compile setado mas luajit.exe nao encontrado; segue sem compilar");
                HashMap::new()
            }
        }
    } else {
        HashMap::new()
    };

    let mut assets: Vec<AssetRecord> = Vec::new();
    let mut next_id = FIRST_ASSET_ID;
    let mut spr_count = 0usize;
    let mut file_count = 0usize;
    let mut lua_perm_count = 0usize;
    let mut lua_skip_count = 0usize;

    let prefix = cfg.name_prefix.trim_matches('/').replace('\\', "/");
    for (rel0, abs) in &files {
        // logical name = optional prefix + path relative to --in (aligns to client reads)
        let rel = if prefix.is_empty() {
            rel0.clone()
        } else {
            format!("{prefix}/{rel0}")
        };
        let rel = &rel;
        let ext = ext_of(abs);

        if ext == "spr" {
            // --- stream-partition into a `chunks/` folder next to the .spr (RFC §10) ---
            // Real `.spr` files reach ~2 GB / 1M+ sprites, so we never load the whole
            // file: each chunk is sealed and written the moment it fills, then freed.
            let prefix = parent_prefix(rel); // e.g. "data/things/1098/"
            let chunk_rel_dir = format!("{prefix}chunks");
            let chunk_out = cfg.out_dir.join(&chunk_rel_dir);
            fs::create_dir_all(&chunk_out)?;

            // sprites-per-chunk: either fixed, or derived from a target chunk count
            let chunk_size = if cfg.num_chunks > 0 {
                let total = spr::header_count(abs, u32_ids)?;
                ((total + cfg.num_chunks - 1) / cfg.num_chunks).max(1)
            } else {
                cfg.chunk_size
            };
            eprintln!("[packdir] {} sprites/chunk (alvo de chunks: {})", chunk_size,
                if cfg.num_chunks > 0 { cfg.num_chunks.to_string() } else { "—".into() });

            let mut entries: Vec<IndexEntry> = Vec::new();
            let mut cur_chunk: u32 = u32::MAX;
            let mut cur_payload: Vec<u8> = Vec::new();
            let mut chunks_written: u32 = 0;

            let total = spr::for_each_sprite(abs, u32_ids, |id, blob| {
                let chunk_id = id / chunk_size;
                if chunk_id != cur_chunk {
                    if cur_chunk != u32::MAX && !cur_payload.is_empty() {
                        let sealed = seal_chunk(&codec, &sprite_secret, &build_salt, cur_chunk, sprite_cipher, &cur_payload);
                        fs::write(chunk_out.join(format!("s{cur_chunk}.bin")), &sealed)?;
                        chunks_written += 1;
                    }
                    cur_chunk = chunk_id;
                    cur_payload.clear();
                }
                // compress-then-encrypt per sprite (RFC §10 + FORMAT.md §2)
                let (body, flags) = if cfg.compress {
                    let (c, did) = maybe_compress(blob);
                    (c, if did { FLAG_COMPRESSED } else { 0 })
                } else {
                    (blob.to_vec(), 0)
                };
                let ct = encrypt_sprite(&sprite_secret, sprite_cipher, CAT_RAW, id, &[id], &body);
                let offset = cur_payload.len() as u32;
                cur_payload.extend_from_slice(&ct);
                entries.push(IndexEntry {
                    sprite_id: id,
                    chunk_id,
                    offset,
                    length: ct.len() as u32,
                    flags,
                    category: CAT_RAW,
                    assembled_id: id,
                    sub_ids: vec![id],
                });
                Ok(())
            })?;
            // flush the final chunk
            if !cur_payload.is_empty() {
                let sealed = seal_chunk(&codec, &sprite_secret, &build_salt, cur_chunk, sprite_cipher, &cur_payload);
                fs::write(chunk_out.join(format!("s{cur_chunk}.bin")), &sealed)?;
                chunks_written += 1;
            }

            // encrypted index (profile B) as "<chunkdir>/index.czq"
            let index_name = format!("{chunk_rel_dir}/index");
            let index_id = next_id;
            next_id += 1;
            let index_plain = index::build(&entries, total, chunk_size);
            let cflag = if cfg.compress { FLAG_COMPRESSED } else { 0 };
            let index_env = seal_cold(&codec, &master, &build_salt, index_id, ASSET_COLD, CIPHER_AES_GCM, cflag, rand16(), &index_plain);
            fs::write(chunk_out.join("index.bin"), &index_env)?;
            assets.push(AssetRecord { asset_id: index_id, profile: ASSET_COLD, sha256: sha256(&index_env), name: index_name });
            eprintln!("[packdir] {} -> {}/  ({} sprites, {} chunks)", rel, chunk_rel_dir, total, chunks_written);
            spr_count += 1;
            continue;
        }

        // --- whole-file envelope at the mirrored path ---
        // If we precompiled this source .lua to bytecode, encrypt the bytecode
        // instead (so the opcode remap below applies).
        let mut data = match compiled.get(abs.as_path()) {
            Some(bc) => bc.clone(),
            None => fs::read(abs).with_context(|| format!("reading {}", abs.display()))?,
        };
        let (asset_type, cipher) = profile_for(&ext, sprite_cipher);
        let asset_id = next_id;
        next_id += 1;

        // Opcode-remap LuaJIT bytecode (Lua ladder #2): scramble the opcode byte of
        // every instruction so the decrypted asset won't run on stock LuaJIT nor
        // open in a decompiler without the per-build permutation. Only real dumps
        // are touched; Lua *source* and everything else pass through unchanged. The
        // flag rides in the manifest entry so the client un-permutes after decrypt.
        let mut manifest_profile = asset_type;
        if czq_core::luajit::is_bytecode(&data) {
            match czq_core::luajit::transcode(&data, &lua_perm) {
                Ok(permuted) => {
                    data = permuted;
                    // Phase 1: mark so the patched client VM un-permutes (czq_core
                    // then leaves it permuted). Phase 0: leave unmarked (czq_core
                    // un-permutes to stock for a vanilla LuaJIT).
                    if cfg.lua_vm_perm {
                        czq_core::luajit::mark_vm_version(&mut data);
                    }
                    manifest_profile |= czq_core::format::PROFILE_FLAG_LUA;
                    lua_perm_count += 1;
                }
                Err(_) => lua_skip_count += 1, // looked like a dump but did not parse
            }
        } else if matches!(ext.as_str(), "lua" | "luac") {
            lua_skip_count += 1; // source (or non-LuaJIT) — encrypted but not remapped
        }

        // Skip compression for media that is already compressed (png/ogg/…).
        let cflag = if cfg.compress && matches!(ext.as_str(), "spr" | "" | "dat" | "otb" | "otbm" | "lua" | "luac" | "otui" | "xml" | "json" | "txt" | "ttf") {
            FLAG_COMPRESSED
        } else {
            0
        };
        let env = seal_cold(&codec, &master, &build_salt, asset_id, asset_type, cipher, cflag, rand16(), &data);
        let out_path = cfg.out_dir.join(rel);
        if let Some(parent) = out_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&out_path, &env)?;
        assets.push(AssetRecord { asset_id, profile: manifest_profile, sha256: sha256(&env), name: rel.clone() });
        file_count += 1;
    }

    let mut sk_seed = [0u8; 32];
    OsRng.fill_bytes(&mut sk_seed);
    let sk = SigningKey::from_bytes(&sk_seed);
    let pubkey = sk.verifying_key().to_bytes();
    let built = build_and_sign(&sk, dat_v, spr_v, feat, sprite_cipher, cfg.chunk_size, &assets);
    // Item C: encrypt the manifest at rest (hides the asset index). integrity_material
    // is the hash of the PLAINTEXT body (computed above), so shares are unaffected.
    let mut manifest_out = built.blob.clone();
    czq_core::manifest::xor_manifest(&build_seed, &mut manifest_out);
    fs::write(cfg.out_dir.join("client.dat"), &manifest_out)?;

    let r = [rand32(), rand32(), rand32()];
    let shares = czq_core::shares::solve_shares(&master, &build_seed, &built.integrity_material, &r);
    if czq_core::shares::reconstruct_master(&shares, &build_seed, &built.integrity_material) != master {
        bail!("internal error: share reconstruction mismatch");
    }
    codegen::write_all(&cfg.out_dir, &build_seed, &build_salt, &shares, &sprite_secret, &pubkey)?;
    if cfg.lua_vm_perm {
        codegen::write_lua_perm_header(&cfg.out_dir, &build_seed)?;
        eprintln!("[packdir] Phase 1 (VM-permute): embed/lj_czq_perm.h gerado — patchar o LuaJIT do client");
    }

    eprintln!(
        "[packdir] pronto -> {}\n[packdir] {} arquivos + {} .spr particionadas; manifest.czq + embed/ na raiz da saida",
        cfg.out_dir.display(), file_count, spr_count
    );
    eprintln!(
        "[packdir] lua opcode-remap: {} bytecode remapeados, {} source/nao-LuaJIT (so cifrados)",
        lua_perm_count, lua_skip_count
    );
    Ok(())
}

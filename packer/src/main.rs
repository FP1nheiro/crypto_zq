//! czq-pack — offline packer CLI (RFC §15). Produces the protected asset set and
//! the embedded build material. Run once per build; each run rotates all keys.

mod codegen;
mod dat;
mod luac;
mod manifest;
mod pack;
mod packdir;
mod rootkey;
mod spr;
mod versions;

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};

use rootkey::ArgonParams;

#[derive(Parser)]
#[command(name = "czq-pack", version, about = "CZQ asset packer (RFC v1.0)")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Resolve `.dat`/`.spr` version from signatures (RFC §6.1) and print it.
    Detect(DetectArgs),
    /// Pack an asset set + emit embedded build material.
    Pack(PackArgs),
    /// Encrypt a whole client folder, mirroring the tree to an output folder.
    Packdir(PackdirArgs),
    /// Build a tiny synthetic `.spr` (+ optional `.dat` sig) for testing.
    Synth(SynthArgs),
    /// Boot a packed output dir and check the sprite index / decrypt one sprite.
    Verify(VerifyArgs),
}

#[derive(Args)]
struct VerifyArgs {
    /// The packdir output directory (has embed/, manifest.czq, data/...).
    #[arg(long)]
    out: PathBuf,
    /// Sprite id to test-decrypt.
    #[arg(long, default_value_t = 924)]
    sprite: u32,
}

#[derive(Args)]
struct PackdirArgs {
    /// Client folder to encrypt (recursed).
    #[arg(long = "in")]
    input: PathBuf,
    /// Output folder (mirrors the tree; must be outside the input folder).
    #[arg(long)]
    out: PathBuf,
    #[arg(long)]
    passphrase: Option<String>,
    #[arg(long, default_value = "versions.xml")]
    versions: PathBuf,
    #[arg(long)]
    force_version: Option<u16>,
    #[arg(long, default_value = "aes-ctr")]
    sprite_cipher: String,
    #[arg(long, default_value_t = 256)]
    chunk_size: u32,
    /// Quantidade de chunks desejada por .spr (sobrepõe --chunk-size).
    #[arg(long, default_value_t = 0)]
    num_chunks: u32,
    /// Prefixo aplicado aos nomes/paths (para cifrar uma subpasta alinhada ao
    /// client), ex.: --in data/things/1098 --prefix data/things/1098
    #[arg(long, default_value = "")]
    prefix: String,
    /// Desativa a compressão zlib (por padrão comprime sprites e arquivos textuais).
    #[arg(long)]
    no_compress: bool,
    #[arg(long, default_value_t = 262144)]
    argon_mcost_kib: u32,
    #[arg(long, default_value_t = 4)]
    argon_tcost: u32,
    #[arg(long, default_value_t = 1)]
    argon_pcost: u32,
    /// Compila .lua source para bytecode LuaJIT antes de cifrar (habilita o remap
    /// de opcodes nesses arquivos). Precisa do luajit.exe do client.
    #[arg(long)]
    lua_compile: bool,
    /// Caminho do luajit.exe do client (mesma versao). Auto-detecta no
    /// vcpkg_installed da pasta de entrada se vazio.
    #[arg(long)]
    luajit: Option<PathBuf>,
    /// Fase 1: marca os dumps para o LuaJIT PATCHADO do client des-permutar (o
    /// bytecode stock nunca aparece). Gera embed/lj_czq_perm.h. NAO use com LuaJIT
    /// stock — os .lua nao vao carregar.
    #[arg(long)]
    lua_vm_perm: bool,
}

#[derive(Args)]
struct DetectArgs {
    #[arg(long)]
    spr: PathBuf,
    #[arg(long)]
    dat: Option<PathBuf>,
    #[arg(long, default_value = "versions.xml")]
    versions: PathBuf,
    #[arg(long)]
    force_version: Option<u16>,
}

#[derive(Args)]
struct PackArgs {
    #[arg(long)]
    spr: PathBuf,
    #[arg(long)]
    dat: Option<PathBuf>,
    #[arg(long)]
    otb: Option<PathBuf>,
    /// Extra cold/ui/stream files (repeatable); profile inferred from extension.
    #[arg(long = "cold")]
    cold: Vec<PathBuf>,
    #[arg(long)]
    out: PathBuf,
    /// Build passphrase (Argon2id input). Prefer $CZQ_PASSPHRASE over the flag.
    #[arg(long)]
    passphrase: Option<String>,
    #[arg(long, default_value = "versions.xml")]
    versions: PathBuf,
    #[arg(long)]
    force_version: Option<u16>,
    #[arg(long, default_value_t = 256)]
    chunk_size: u32,
    #[arg(long, default_value = "aes-ctr")]
    sprite_cipher: String,
    #[arg(long, default_value_t = 262144)]
    argon_mcost_kib: u32,
    #[arg(long, default_value_t = 4)]
    argon_tcost: u32,
    #[arg(long, default_value_t = 1)]
    argon_pcost: u32,
}

#[derive(Args)]
struct SynthArgs {
    #[arg(long)]
    out_spr: PathBuf,
    #[arg(long, default_value_t = 16)]
    count: u32,
    /// Signature to stamp (hex, big-endian as in versions.xml). Default = 10.98's spr.
    #[arg(long, default_value = "57BBD603")]
    spr_sig: String,
    /// Emit a u32-id (extended, >= 9.60) `.spr`. Match this to the signature's era.
    #[arg(long)]
    extended: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Detect(a) => detect(a),
        Cmd::Pack(a) => do_pack(a),
        Cmd::Packdir(a) => do_packdir(a),
        Cmd::Synth(a) => synth(a),
        Cmd::Verify(a) => verify(a),
    }
}

fn verify(a: VerifyArgs) -> Result<()> {
    let material = std::fs::read(a.out.join("embed/material.bin")).context("read embed/material.bin")?;
    let pkbuf = std::fs::read(a.out.join("embed/pubkey.bin")).context("read embed/pubkey.bin")?;
    let pubkey: [u8; 32] = pkbuf.as_slice().try_into().context("pubkey must be 32 bytes")?;
    let manifest = std::fs::read(a.out.join("manifest.czq")).context("read manifest.czq")?;

    let mut ctx = czq_core::Context::boot(&material, &manifest, &pubkey)
        .map_err(|e| anyhow::anyhow!("boot failed: {e}"))?;
    println!("booted OK. dat={} spr={}", ctx.dat_version, ctx.spr_version);

    let idx_name = ctx
        .sprite_index_name()
        .ok_or_else(|| anyhow::anyhow!("no sprite index in manifest"))?
        .to_string();
    let idx_id = ctx
        .asset_id_by_name(&idx_name)
        .ok_or_else(|| anyhow::anyhow!("index asset id not found"))?;
    let idx_env = std::fs::read(a.out.join(format!("{idx_name}.czq")))
        .with_context(|| format!("read {idx_name}.czq"))?;
    ctx.load_index(idx_id, &idx_env).map_err(|e| anyhow::anyhow!("load_index failed: {e}"))?;
    println!(
        "index '{}' loaded: entries={} sprite_total={}",
        idx_name,
        ctx.index_len(),
        ctx.sprite_total()
    );

    let chunk_dir = std::path::Path::new(&idx_name)
        .parent()
        .map(|p| p.to_string_lossy().replace('\\', "/"))
        .unwrap_or_default();
    match ctx.chunk_of(a.sprite) {
        Ok(cid) => {
            let chunk_path = a.out.join(format!("{chunk_dir}/spr_chunk_{cid}.czq"));
            let chunk = std::fs::read(&chunk_path).with_context(|| format!("read {}", chunk_path.display()))?;
            match ctx.decrypt_sprite(a.sprite, &chunk, true) {
                Ok(px) => println!(
                    "sprite {} -> chunk {} -> {} bytes, first={:02X?}",
                    a.sprite, cid, px.len(),
                    &px[..px.len().min(6)]
                ),
                Err(e) => println!("sprite {} decrypt FAILED: {e}", a.sprite),
            }
        }
        Err(_) => println!("sprite {} NOT in index (chunk_of NotFound)", a.sprite),
    }
    Ok(())
}

fn do_packdir(a: PackdirArgs) -> Result<()> {
    let passphrase = a
        .passphrase
        .or_else(|| std::env::var("CZQ_PASSPHRASE").ok())
        .context("no passphrase: pass --passphrase or set $CZQ_PASSPHRASE")?;
    // "random" = rotate the sprite cipher per build (option #2).
    let random_cipher = a.sprite_cipher.eq_ignore_ascii_case("random");
    let sprite_cipher = if random_cipher {
        czq_core::cipher::CIPHER_AES_CTR // placeholder; run() picks at random when the flag is set
    } else {
        pack::parse_sprite_cipher(&a.sprite_cipher)?
    };
    let cfg = packdir::PackDirConfig {
        in_dir: a.input,
        out_dir: a.out,
        passphrase,
        versions_xml: a.versions,
        force_version: a.force_version,
        sprite_cipher,
        sprite_cipher_random: random_cipher,
        chunk_size: a.chunk_size,
        num_chunks: a.num_chunks,
        compress: !a.no_compress,
        name_prefix: a.prefix,
        argon: ArgonParams {
            m_cost_kib: a.argon_mcost_kib,
            t_cost: a.argon_tcost,
            p_cost: a.argon_pcost,
        },
        lua_compile: a.lua_compile,
        luajit: a.luajit,
        lua_vm_perm: a.lua_vm_perm,
    };
    packdir::run(cfg)
}

fn detect(a: DetectArgs) -> Result<()> {
    let spr = std::fs::read(&a.spr).with_context(|| format!("reading {}", a.spr.display()))?;
    let dat = match &a.dat {
        Some(p) => Some(std::fs::read(p)?),
        None => None,
    };
    let xml = std::fs::read_to_string(&a.versions)?;
    let table = versions::load_table(&xml)?;
    let r = versions::resolve(dat.as_deref(), &spr, &table, a.force_version)?;
    println!(
        "dat_version={} spr_version={} feature_flags=0x{:X} u32_sprite_ids={}",
        r.dat_version, r.spr_version, r.feature_flags, r.u32_sprite_ids
    );
    Ok(())
}

fn do_pack(a: PackArgs) -> Result<()> {
    let passphrase = a
        .passphrase
        .or_else(|| std::env::var("CZQ_PASSPHRASE").ok())
        .context("no passphrase: pass --passphrase or set $CZQ_PASSPHRASE")?;
    let cfg = pack::PackConfig {
        spr_path: a.spr,
        dat_path: a.dat,
        otb_path: a.otb,
        cold_paths: a.cold,
        out_dir: a.out,
        passphrase,
        versions_xml: a.versions,
        force_version: a.force_version,
        chunk_size: a.chunk_size,
        sprite_cipher: pack::parse_sprite_cipher(&a.sprite_cipher)?,
        argon: ArgonParams {
            m_cost_kib: a.argon_mcost_kib,
            t_cost: a.argon_tcost,
            p_cost: a.argon_pcost,
        },
    };
    pack::run(cfg)
}

fn synth(a: SynthArgs) -> Result<()> {
    let sig = u32::from_str_radix(&a.spr_sig, 16).context("spr_sig must be hex")?;
    let sprites: Vec<Vec<u8>> = (0..a.count)
        .map(|i| {
            // deterministic pseudo pixel-data block body
            let n = 8 + (i as usize % 24);
            (0..n).map(|k| (i as u8).wrapping_add(k as u8)).collect()
        })
        .collect();
    let bytes = spr::synthesize(sig, &sprites, a.extended);
    std::fs::write(&a.out_spr, &bytes)?;
    // silence unused warning for the extension-point module
    let _ = dat::thing_context(&[], a.extended)?;
    println!("wrote {} ({} sprites)", a.out_spr.display(), a.count);
    Ok(())
}

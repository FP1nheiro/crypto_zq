//! Runtime context: the boot-time reconstruction (RFC §14) and the high-level
//! decrypt operations. This is what the client's stable interface wraps.

use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::format::HeaderCodec;
use crate::index::SpriteIndex;
use crate::manifest::{AssetEntry, Manifest};
use crate::profile::{decrypt_sprite_ct, open_chunk, open_cold};
use crate::read::Reader;
use crate::shares::reconstruct_master;

pub const MATERIAL_LEN: usize = 1 + 32 + 16 + 4 * 32 + 32; // = 209 (FORMAT.md §1.1)

/// Parsed embedded build material (FORMAT.md §1.1).
struct BuildMaterial {
    build_seed: [u8; 32],
    build_salt: [u8; 16],
    shares: [[u8; 32]; 4],
    /// SPRITE key root (key Y) — an INDEPENDENT per-build random secret, NOT derived
    /// from `master`. The two key trees are genuinely separate: FILE keys (key X) come
    /// from `master` (shares + build_seed + manifest integrity); SPRITE keys come from
    /// this. So the sprite tier can later be swapped to a server-delivered secret
    /// without touching the file tier. (Both live in the binary today, so a static
    /// dump still yields both — the separation is structural, for that future move.)
    sprite_secret: [u8; 32],
}

impl BuildMaterial {
    fn parse(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        if r.u8()? != 1 {
            return Err(Error::Unsupported);
        }
        let build_seed = r.arr32()?;
        let build_salt: [u8; 16] = r.take(16)?.try_into().unwrap();
        let mut shares = [[0u8; 32]; 4];
        for s in shares.iter_mut() {
            *s = r.arr32()?;
        }
        let sprite_secret = r.arr32()?;
        Ok(BuildMaterial {
            build_seed,
            build_salt,
            shares,
            sprite_secret,
        })
    }
}

pub struct Context {
    /// Key X root — FILE tier (cold/UI/stream envelopes + the sprite index).
    master_files: Zeroizing<[u8; 32]>,
    /// Key Y root — SPRITE tier (chunks + per-sprite keys).
    master_sprites: Zeroizing<[u8; 32]>,
    build_salt: [u8; 16],
    codec: HeaderCodec,
    /// Inverse LuaJIT opcode permutation for this build (un-permutes cold Lua
    /// assets flagged `PROFILE_FLAG_LUA` back to stock bytecode).
    lua_inv: [u8; 256],
    pub sprite_cipher: u8,
    pub chunk_size: u32,
    pub dat_version: u16,
    pub spr_version: u16,
    pub feature_flags: u32,
    assets: Vec<AssetEntry>,
    index: Option<SpriteIndex>,
}

impl Context {
    /// Boot: verify manifest, reconstruct `master'`, configure the parser fields
    /// (RFC §14 steps 3–5). Returns an error on any integrity failure — the caller
    /// (client boot) turns that into a delayed, non-obvious failure (RFC §14).
    pub fn boot(material: &[u8], manifest_blob: &[u8], embedded_pubkey: &[u8; 32]) -> Result<Context> {
        let mat = BuildMaterial::parse(material)?;
        // Item C: the manifest is confidentiality-wrapped with a build_seed key.
        // Reverse it before verifying/parsing (a wrong key -> garbage -> sig fails).
        let mut mbuf = manifest_blob.to_vec();
        crate::manifest::xor_manifest(&mat.build_seed, &mut mbuf);
        let m = Manifest::parse_and_verify(&mbuf, embedded_pubkey)?;
        // Key X (FILE tier): master from the shares, bound to the manifest hash.
        let master_files = reconstruct_master(&mat.shares, &mat.build_seed, &m.integrity_material);
        // Key Y (SPRITE tier): the independent embedded secret. Kept as its own root
        // (not derived from key X) so it can later become server-delivered.
        let master_sprites = mat.sprite_secret;
        let codec = HeaderCodec::new(&mat.build_seed);
        let lua_inv = crate::luajit::invert(&crate::luajit::opcode_perm(&mat.build_seed));
        Ok(Context {
            master_files: Zeroizing::new(master_files),
            master_sprites: Zeroizing::new(master_sprites),
            build_salt: mat.build_salt,
            codec,
            lua_inv,
            sprite_cipher: m.sprite_cipher,
            chunk_size: m.chunk_size,
            dat_version: m.dat_version,
            spr_version: m.spr_version,
            feature_flags: m.feature_flags,
            assets: m.assets,
            index: None,
        })
    }

    pub fn asset_id_by_name(&self, name: &str) -> Option<u64> {
        self.assets.iter().find(|a| a.name == name).map(|a| a.asset_id)
    }

    /// Match an asset by path suffix at a `/` boundary. The client mounts `data/`
    /// at the PhysFS root, so a file packed as `data/locales/de.lua` is requested
    /// as `locales/de.lua` — the `data/` prefix is dropped. This resolves that (and
    /// any search-path collapse) as long as the tail is unambiguous. Returns None
    /// if zero or more than one asset matches (ambiguous → caller leaves it alone).
    pub fn asset_id_by_suffix(&self, suffix: &str) -> Option<u64> {
        let mut found: Option<u64> = None;
        for a in &self.assets {
            let n = &a.name;
            let is_match = n == suffix
                || (n.len() > suffix.len()
                    && n.ends_with(suffix)
                    && n.as_bytes()[n.len() - suffix.len() - 1] == b'/');
            if is_match {
                if found.is_some() {
                    return None; // ambiguous
                }
                found = Some(a.asset_id);
            }
        }
        found
    }

    /// Logical name of the (first) sprite index in the manifest — an asset whose
    /// name ends in "chunks/index". Lets the client auto-load sprites at boot with
    /// no path guessing.
    pub fn sprite_index_name(&self) -> Option<&str> {
        self.assets
            .iter()
            .find(|a| a.name.ends_with("chunks/index") || a.name == "index")
            .map(|a| a.name.as_str())
    }

    /// Decrypt a cold/ui/stream envelope (profiles B/C/D). If the asset was packed
    /// as opcode-permuted LuaJIT bytecode (manifest `PROFILE_FLAG_LUA`), the opcodes
    /// are un-permuted back to stock here, so the caller/`luaL_loadbuffer` never sees
    /// the permuted form and the C++ side needs no changes.
    pub fn decrypt_cold(&self, asset_id: u64, envelope: &[u8]) -> Result<Vec<u8>> {
        let plain = open_cold(&self.codec, &self.master_files, &self.build_salt, asset_id, envelope)?;
        // Un-permute here only in Phase-0 mode. If the dump is VM-marked (Phase 1),
        // the *patched client LuaJIT* un-permutes it while reading, so we must leave
        // it permuted and hand it through untouched.
        if self.is_lua_permuted(asset_id) && !crate::luajit::is_vm_marked(&plain) {
            // Our own packed assets always parse; if a future format quirk made it
            // fail we fall back to the (still-permuted) bytes rather than erroring —
            // Lua would then fail to load non-obviously (RFC §14), never crash here.
            match crate::luajit::transcode(&plain, &self.lua_inv) {
                Ok(stock) => Ok(stock),
                Err(_) => Ok(plain),
            }
        } else {
            Ok(plain)
        }
    }

    /// Whether the signed manifest contains at least one asset whose name ends with
    /// `suffix`. Used by the client to decide if it should enforce the manifest as an
    /// access allowlist for a given kind (e.g. only enforce `.otmod` if modules were
    /// packed at all), so a partial pack does not break unpacked files.
    pub fn has_asset_ending(&self, suffix: &str) -> bool {
        self.assets.iter().any(|a| a.name.ends_with(suffix))
    }

    /// Whether `asset_id`'s manifest entry carries the LuaJIT-permuted flag.
    fn is_lua_permuted(&self, asset_id: u64) -> bool {
        self.assets
            .iter()
            .any(|a| a.asset_id == asset_id && a.profile & crate::format::PROFILE_FLAG_LUA != 0)
    }

    /// Load + decrypt the sprite index (profile B) and keep it in RAM.
    pub fn load_index(&mut self, asset_id: u64, index_envelope: &[u8]) -> Result<()> {
        let plaintext = self.decrypt_cold(asset_id, index_envelope)?;
        self.index = Some(SpriteIndex::parse(&plaintext)?);
        Ok(())
    }

    pub fn index_len(&self) -> usize {
        self.index.as_ref().map(|i| i.len()).unwrap_or(0)
    }

    /// Original `.spr` header sprite count (max id), for the client's m_spritesCount.
    pub fn sprite_total(&self) -> u32 {
        self.index.as_ref().map(|i| i.total()).unwrap_or(0)
    }

    /// Decrypt one sprite, given the bytes of its chunk file. `verify` toggles the
    /// per-chunk MAC (verify once per chunk on the client, then cache).
    pub fn decrypt_sprite(&self, sprite_id: u32, chunk_bytes: &[u8], verify: bool) -> Result<Vec<u8>> {
        let index = self.index.as_ref().ok_or(Error::NotFound)?;
        let e = index.get(sprite_id)?;
        let (_h, payload) = open_chunk(
            &self.codec,
            &self.master_sprites,
            &self.build_salt,
            e.chunk_id,
            chunk_bytes,
            verify,
        )?;
        let start = e.offset as usize;
        let end = start + e.length as usize;
        if end > payload.len() {
            return Err(Error::Truncated);
        }
        let plain = decrypt_sprite_ct(
            &self.master_sprites,
            self.sprite_cipher,
            e.category,
            e.assembled_id,
            &e.sub_ids,
            &payload[start..end],
        )?;
        if e.flags & crate::format::FLAG_COMPRESSED != 0 {
            crate::flate::decompress(&plain)
        } else {
            Ok(plain)
        }
    }

    /// The chunk id that holds a given sprite (so the client knows which file to read).
    pub fn chunk_of(&self, sprite_id: u32) -> Result<u32> {
        let index = self.index.as_ref().ok_or(Error::NotFound)?;
        Ok(index.get(sprite_id)?.chunk_id)
    }

    /// Verify a chunk's MAC (RFC §13). Used once per chunk at preload so the hot
    /// path can skip the per-sprite MAC while keeping integrity.
    pub fn verify_chunk(&self, chunk_id: u32, chunk_bytes: &[u8]) -> Result<()> {
        open_chunk(&self.codec, &self.master_sprites, &self.build_salt, chunk_id, chunk_bytes, true).map(|_| ())
    }
}

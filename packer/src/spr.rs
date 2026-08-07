//! Classic `.spr` parsing (RFC §6, §10). Version-parametrized by sprite-id width
//! (u16 < 9.60, u32 >= 9.60). We keep each sprite's on-disk block verbatim as the
//! unit of encryption — lossless: the client decrypts back the exact bytes the
//! stock sprite decoder expects, so we never need to understand the RLE pixels.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use anyhow::{bail, Context, Result};

/// One non-empty sprite: its 1-based id and its raw on-disk block
/// (`[3B color key][u16 pixel-data size][pixel data]`).
pub struct RawSprite {
    pub id: u32,
    pub data: Vec<u8>,
}

fn read_count(spr: &[u8], u32_ids: bool) -> Result<(u32, usize)> {
    if u32_ids {
        if spr.len() < 8 {
            bail!("`.spr` truncated (u32 count)");
        }
        Ok((u32::from_le_bytes(spr[4..8].try_into().unwrap()), 8))
    } else {
        if spr.len() < 6 {
            bail!("`.spr` truncated (u16 count)");
        }
        Ok((u16::from_le_bytes(spr[4..6].try_into().unwrap()) as u32, 6))
    }
}

/// Parse all non-empty sprites. Returns them in ascending id order.
pub fn parse(spr: &[u8], u32_ids: bool) -> Result<Vec<RawSprite>> {
    let (count, table_start) = read_count(spr, u32_ids)?;
    let table_end = table_start + (count as usize) * 4;
    if table_end > spr.len() {
        bail!("`.spr` address table overruns file ({count} sprites)");
    }
    let mut out = Vec::new();
    for i in 0..count as usize {
        let off_pos = table_start + i * 4;
        let off = u32::from_le_bytes(spr[off_pos..off_pos + 4].try_into().unwrap()) as usize;
        if off == 0 {
            continue; // empty sprite id
        }
        // block = 3 color-key bytes + u16 size + `size` bytes of pixel data
        if off + 5 > spr.len() {
            bail!("sprite {} offset {off} overruns file", i + 1);
        }
        let size = u16::from_le_bytes(spr[off + 3..off + 5].try_into().unwrap()) as usize;
        let end = off + 5 + size;
        if end > spr.len() {
            bail!("sprite {} data ({size} B) overruns file", i + 1);
        }
        out.push(RawSprite {
            id: (i as u32) + 1,
            data: spr[off..end].to_vec(),
        });
    }
    Ok(out)
}

/// Structural check: does reading with `u32_ids` yield a sane address table?
/// Samples up to 64 non-empty sprites over the WHOLE file (offsets in range,
/// sprite headers readable). Catches the common "old signature but extended
/// (u32) body" case that a prefix-only version check can't see.
fn width_ok(f: &mut File, file_len: u64, u32_ids: bool) -> Result<bool> {
    let head_len: u64 = if u32_ids { 8 } else { 6 };
    if file_len < head_len {
        return Ok(false);
    }
    f.seek(SeekFrom::Start(0))?;
    let mut head = [0u8; 8];
    f.read_exact(&mut head[..head_len as usize])?;
    let count = if u32_ids {
        u32::from_le_bytes(head[4..8].try_into().unwrap())
    } else {
        u16::from_le_bytes(head[4..6].try_into().unwrap()) as u32
    };
    if count == 0 || count as u64 > 20_000_000 {
        return Ok(false);
    }
    let table_end = head_len + count as u64 * 4;
    if table_end > file_len {
        return Ok(false);
    }
    let mut table = vec![0u8; count as usize * 4];
    f.seek(SeekFrom::Start(head_len))?;
    f.read_exact(&mut table)?;

    let mut checked = 0u32;
    for i in 0..count as usize {
        if checked >= 64 {
            break;
        }
        let off = u32::from_le_bytes(table[i * 4..i * 4 + 4].try_into().unwrap()) as u64;
        if off == 0 {
            continue; // empty sprite id
        }
        if off < table_end || off + 5 > file_len {
            return Ok(false);
        }
        f.seek(SeekFrom::Start(off + 3))?;
        let mut sz = [0u8; 2];
        f.read_exact(&mut sz)?;
        let size = u16::from_le_bytes(sz) as u64;
        if off + 5 + size > file_len {
            return Ok(false);
        }
        checked += 1;
    }
    Ok(checked > 0)
}

/// Determine the real sprite-id width by structural validation. Tries `hint_u32`
/// first (from the resolved version), then the other width. This auto-corrects a
/// `.spr` whose signature maps to an old (u16) version but whose body is actually
/// extended (u32), and vice-versa.
pub fn detect_id_width(path: &Path, hint_u32: bool) -> Result<bool> {
    let mut f = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let file_len = f.metadata()?.len();
    for &w in &[hint_u32, !hint_u32] {
        if width_ok(&mut f, file_len, w)? {
            if w != hint_u32 {
                eprintln!(
                    "[spr] sprite-id width auto-corrected to {} (signature suggested {})",
                    if w { "u32" } else { "u16" },
                    if hint_u32 { "u32" } else { "u16" }
                );
            }
            return Ok(w);
        }
    }
    bail!("could not determine `.spr` sprite-id width (u16/u32) — file corrupt or unsupported");
}

/// Read the sprite count from the `.spr` header (auto-detecting the id width).
pub fn header_count(path: &Path, u32_ids_hint: bool) -> Result<u32> {
    let u32_ids = detect_id_width(path, u32_ids_hint)?;
    let mut f = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let n = if u32_ids { 8 } else { 6 };
    let mut head = [0u8; 8];
    f.read_exact(&mut head[..n]).context("`.spr` too small for header")?;
    Ok(if u32_ids {
        u32::from_le_bytes(head[4..8].try_into().unwrap())
    } else {
        u16::from_le_bytes(head[4..6].try_into().unwrap()) as u32
    })
}

/// Streaming parse for very large `.spr` files (real assets reach ~2 GB / 1M+
/// sprites). Reads the header + address table, then reads one sprite blob at a
/// time and hands it to `cb` — memory stays bounded (address table + one blob),
/// never the whole file. `cb` receives the 1-based sprite id and its raw block.
pub fn for_each_sprite<F>(path: &Path, u32_ids_hint: bool, mut cb: F) -> Result<u32>
where
    F: FnMut(u32, &[u8]) -> Result<()>,
{
    let u32_ids = detect_id_width(path, u32_ids_hint)?;
    let mut f = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let head_len = if u32_ids { 8 } else { 6 };
    let mut head = [0u8; 8];
    f.read_exact(&mut head[..head_len])
        .context("`.spr` too small for signature + count")?;
    let count = if u32_ids {
        u32::from_le_bytes(head[4..8].try_into().unwrap())
    } else {
        u16::from_le_bytes(head[4..6].try_into().unwrap()) as u32
    };
    if count == 0 || count > 20_000_000 {
        bail!("`.spr` sprite count {count} out of sane range");
    }

    // address table: count × u32, immediately after the header
    let mut table = vec![0u8; count as usize * 4];
    f.seek(SeekFrom::Start(head_len as u64))?;
    f.read_exact(&mut table).context("`.spr` address table overruns file")?;

    let mut blob: Vec<u8> = Vec::with_capacity(4096);
    for i in 0..count as usize {
        let off = u32::from_le_bytes(table[i * 4..i * 4 + 4].try_into().unwrap());
        if off == 0 {
            continue; // empty sprite id
        }
        f.seek(SeekFrom::Start(off as u64))?;
        let mut hdr = [0u8; 5]; // 3-byte color key + u16 pixel-data size
        f.read_exact(&mut hdr)
            .with_context(|| format!("sprite {} header at offset {off}", i + 1))?;
        let size = u16::from_le_bytes([hdr[3], hdr[4]]) as usize;
        blob.clear();
        blob.extend_from_slice(&hdr);
        blob.resize(5 + size, 0);
        f.read_exact(&mut blob[5..])
            .with_context(|| format!("sprite {} data ({size} B) at offset {off}", i + 1))?;
        cb((i as u32) + 1, &blob)?;
    }
    Ok(count)
}

/// Build a minimal but structurally valid `.spr` in memory (for tests / demo when
/// no real asset is available). `sprites[i]` is the pixel-data block body (without
/// the 3-byte key / size prefix); ids are 1-based and contiguous.
pub fn synthesize(signature: u32, sprites: &[Vec<u8>], u32_ids: bool) -> Vec<u8> {
    let count = sprites.len() as u32;
    let mut out = Vec::new();
    out.extend_from_slice(&signature.to_le_bytes());
    if u32_ids {
        out.extend_from_slice(&count.to_le_bytes());
    } else {
        out.extend_from_slice(&(count as u16).to_le_bytes());
    }
    let table_start = out.len();
    let table_end = table_start + (count as usize) * 4;
    out.resize(table_end, 0); // reserve address table
    for (i, body) in sprites.iter().enumerate() {
        let off = out.len() as u32;
        let pos = table_start + i * 4;
        out[pos..pos + 4].copy_from_slice(&off.to_le_bytes());
        out.extend_from_slice(&[0xFF, 0x00, 0xFF]); // magenta color key
        out.extend_from_slice(&(body.len() as u16).to_le_bytes());
        out.extend_from_slice(body);
    }
    out
}

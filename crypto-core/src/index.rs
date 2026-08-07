//! Encrypted sprite index (FORMAT.md §4, RFC §10). Maps `sprite_id` to its
//! location inside a chunk and to the derivation context used for its key.
//!
//! The index is the *courier* of the per-sprite derivation info: whatever the
//! packer chose (raw sprite id, or a ThingType context parsed from `.dat`), the
//! client reads it back verbatim and reproduces the exact key — it never has to
//! re-derive which thing owns a sprite (resolves the §9 ambiguity).

use std::collections::HashMap;

use crate::error::{Error, Result};
use crate::read::{Reader, Writer};

pub const INDEX_MAGIC: &[u8; 4] = b"CZQI";

// Sprite categories (FORMAT.md §4). `RAW` = one sprite is its own thing.
pub const CAT_ITEM: u8 = 0;
pub const CAT_OUTFIT: u8 = 1;
pub const CAT_EFFECT: u8 = 2;
pub const CAT_MISSILE: u8 = 3;
pub const CAT_RAW: u8 = 255;

#[derive(Clone, Debug)]
pub struct IndexEntry {
    pub sprite_id: u32,
    pub chunk_id: u32,
    pub offset: u32,
    pub length: u32,
    /// Per-sprite flags. bit0 = payload was zlib-compressed before encryption
    /// (FORMAT.md §2 `FLAG_COMPRESSED`).
    pub flags: u8,
    pub category: u8,
    pub assembled_id: u32,
    pub sub_ids: Vec<u32>,
}

pub struct SpriteIndex {
    map: HashMap<u32, IndexEntry>,
    /// Original `.spr` header sprite count (max id, incl. empty ids). Mirrors what
    /// the stock loader stores as `m_spritesCount`.
    total: u32,
}

impl SpriteIndex {
    pub fn get(&self, sprite_id: u32) -> Result<&IndexEntry> {
        self.map.get(&sprite_id).ok_or(Error::NotFound)
    }
    pub fn len(&self) -> usize {
        self.map.len()
    }
    pub fn total(&self) -> u32 {
        self.total
    }
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Parse the decrypted **dense** index (FORMAT.md §4, revised). Only one varint
    /// per sprite id (1..=total) is stored: `size<<1 | compressed`, 0 = empty id.
    /// Everything else — `sprite_id` (= position), `chunk_id` (= id / spc), `offset`
    /// (running sum within the chunk), and the RAW derivation context (category,
    /// assembled_id, sub_ids) — is reconstructed, so the plaintext carries **no
    /// redundant field** an attacker could use to confirm a correct decrypt. The
    /// index envelope is AES-GCM-authenticated, so correctness needs no magic.
    pub fn parse(plaintext: &[u8]) -> Result<SpriteIndex> {
        let mut r = Reader::new(plaintext);
        let total = r.uleb()?;
        let spc = r.uleb()?.max(1);
        let mut map = HashMap::new();
        let mut cum: u32 = 0; // running offset within the current chunk
        let mut cur_chunk = u32::MAX;
        for id in 1..=total {
            let v = r.uleb()?;
            let size = v >> 1;
            let compressed = v & 1 != 0;
            let chunk_id = id / spc;
            if chunk_id != cur_chunk {
                cur_chunk = chunk_id;
                cum = 0; // each chunk file's payload starts at offset 0
            }
            if size > 0 {
                map.insert(
                    id,
                    IndexEntry {
                        sprite_id: id,
                        chunk_id,
                        offset: cum,
                        length: size,
                        flags: if compressed { crate::format::FLAG_COMPRESSED } else { 0 },
                        category: CAT_RAW,
                        assembled_id: id,
                        sub_ids: vec![id],
                    },
                );
            }
            cum = cum.checked_add(size).ok_or(Error::BadFormat)?;
        }
        Ok(SpriteIndex { map, total })
    }
}

/// Serialize the dense index (packer side; also used by tests). RAW sprites only
/// (category/assembled_id/sub_ids derived from the id) — the mode the packer emits.
/// `total` = original `.spr` header sprite count (max id incl. empties);
/// `sprites_per_chunk` matches the packer's `id / spc` chunk assignment.
pub fn build(entries: &[IndexEntry], total: u32, sprites_per_chunk: u32) -> Vec<u8> {
    // Gather size + compressed bit per id (1-based); absent ids stay 0 (empty).
    let mut size = vec![0u32; total as usize + 1];
    let mut comp = vec![false; total as usize + 1];
    for e in entries {
        if e.sprite_id >= 1 && e.sprite_id <= total {
            size[e.sprite_id as usize] = e.length;
            comp[e.sprite_id as usize] = e.flags & crate::format::FLAG_COMPRESSED != 0;
        }
    }
    let mut w = Writer::new();
    w.uleb(total);
    w.uleb(sprites_per_chunk.max(1));
    for id in 1..=total as usize {
        w.uleb((size[id] << 1) | if comp[id] { 1 } else { 0 });
    }
    w.into_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::FLAG_COMPRESSED;

    fn e(id: u32, len: u32, flags: u8) -> IndexEntry {
        IndexEntry {
            sprite_id: id,
            chunk_id: 0,
            offset: 0,
            length: len,
            flags,
            category: CAT_RAW,
            assembled_id: id,
            sub_ids: vec![id],
        }
    }

    #[test]
    fn dense_rebuilds_offsets_chunks_and_gaps() {
        // spc = 4  ->  ids 1..3 in chunk 0, 4..7 in chunk 1, 8 in chunk 2.
        // present: 1 (len 10), 3 (len 5, compressed), 5 (len 7). id 2,4,6,7,8 empty.
        let entries = vec![e(1, 10, 0), e(3, 5, FLAG_COMPRESSED), e(5, 7, 0)];
        let blob = build(&entries, 8, 4);
        let idx = SpriteIndex::parse(&blob).unwrap();

        assert_eq!(idx.total(), 8);
        assert_eq!(idx.len(), 3);

        let a = idx.get(1).unwrap();
        assert_eq!((a.chunk_id, a.offset, a.length), (0, 0, 10));
        // id 3: same chunk, offset = size(1)+size(2 empty) = 10
        let b = idx.get(3).unwrap();
        assert_eq!((b.chunk_id, b.offset, b.length), (0, 10, 5));
        assert!(b.flags & FLAG_COMPRESSED != 0);
        // RAW context reconstructed from position
        assert_eq!((b.category, b.assembled_id, b.sub_ids.clone()), (CAT_RAW, 3, vec![3]));
        // id 5: new chunk -> offset resets to 0
        let c = idx.get(5).unwrap();
        assert_eq!((c.chunk_id, c.offset, c.length), (1, 0, 7));

        assert!(idx.get(2).is_err()); // empty id absent

        // Density: 8 sprites -> a handful of varint bytes, not 8*27.
        assert!(blob.len() < 16, "index not dense: {} bytes", blob.len());
    }
}

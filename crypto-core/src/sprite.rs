//! Per-sprite key + IV derivation (FORMAT.md §1.3, §3.1, RFC §9). Hot path.

use crate::kdf::blake3_keyed;
use crate::read::Writer;

/// `per_sprite_key = blake3_keyed(master', category ‖ assembled_id ‖ sorted(sub_ids))`.
/// `sub_ids` are canonicalized (sorted ascending) so the key is independent of the
/// order the sprites were read in (RFC §9 — otherwise: intermittent render bug).
pub fn per_sprite_key(
    master: &[u8; 32],
    category: u8,
    assembled_id: u32,
    sub_ids: &[u32],
) -> [u8; 32] {
    let mut w = Writer::new();
    w.u8(category);
    w.u32(assembled_id);
    let mut sorted: Vec<u32> = sub_ids.to_vec();
    sorted.sort_unstable();
    for id in sorted {
        w.u32(id);
    }
    blake3_keyed(master, &w.buf)
}

/// Deterministic per-sprite 16-byte IV (FORMAT.md §3.1). Key uniqueness already
/// prevents keystream reuse; this is defense in depth.
pub fn sprite_iv(per_sprite_key: &[u8; 32], assembled_id: u32) -> [u8; 16] {
    let mut d = Vec::with_capacity(6);
    d.extend_from_slice(b"iv");
    d.extend_from_slice(&assembled_id.to_le_bytes());
    let h = blake3_keyed(per_sprite_key, &d);
    let mut iv = [0u8; 16];
    iv.copy_from_slice(&h[0..16]);
    iv
}

//! Classic `.dat` handling. For this subsystem the `.dat` matters in two ways:
//!   1. its 4-byte (≤10.70) / 2-byte (≥10.71) signature feeds version resolution
//!      (handled in `versions::resolve`);
//!   2. it is packed as a cold asset (profile B) so it is protected at rest.
//!
//! Full ThingType parsing (enumerating each thing's sub-sprites to enrich the
//! per-sprite derivation context, RFC §9) is the documented extension point below.
//! The default raw pipeline already produces a correct, unique key per sprite; a
//! ThingType-driven context only raises the reversing cost, it is not required for
//! correctness.

use anyhow::Result;

/// Read the `.dat` signature as both widths; `versions::resolve` decides which to
/// use per candidate row. (Convenience for tooling / the `detect` path.)
#[allow(dead_code)]
pub fn signature(dat: &[u8]) -> Option<(u32, u16)> {
    if dat.len() < 4 {
        return None;
    }
    let u32v = u32::from_le_bytes(dat[0..4].try_into().unwrap());
    let u16v = u16::from_le_bytes(dat[0..2].try_into().unwrap());
    Some((u32v, u16v))
}

/// EXTENSION POINT (RFC §9 enrichment). Given a parsed `.dat` and version/feature
/// flags, produce, per sprite id, its `(category, assembled_id, sub_ids)`. The
/// packer would feed these into the index instead of the raw mapping. Not required
/// for correctness; left unimplemented so the raw pipeline stays the default.
///
/// Returning `None` means "use the raw per-sprite context".
pub fn thing_context(_dat: &[u8], _u32_sprite_ids: bool) -> Result<Option<()>> {
    Ok(None)
}

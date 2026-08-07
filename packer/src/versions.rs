//! Automatic version resolution (RFC §6.1) driven by `versions.xml`.
//!
//! Corrections over the RFC prose, forced by the real data (see spec/FORMAT.md §6):
//!   1. `dat` signature width is NOT a constant 4 bytes — it is 2 bytes for
//!      >= 10.71. We match against whichever width the table row declares.
//!   2. Signatures are not unique (7.60/7.70, 10.60/10.61, many partials), so a
//!      signature hit yields a *candidate set* and structural corroboration is
//!      mandatory, not optional.

use anyhow::{anyhow, bail, Result};

#[derive(Clone, Debug)]
pub struct VersionRow {
    pub value: u16,
    pub label: String,
    /// dat signature value (u16 or u32 wide, see `dat_is_u16`).
    pub dat: u32,
    pub dat_is_u16: bool,
    pub spr: u32,
}

#[derive(Clone, Copy, Debug)]
pub struct Resolved {
    pub dat_version: u16,
    pub spr_version: u16,
    pub feature_flags: u32,
    /// True when sprite ids/count are u32 (extended, >= 9.60) — drives the parser.
    pub u32_sprite_ids: bool,
}

// feature_flags bit layout (stamped into the signed manifest).
pub const FEAT_EXTENDED_SPRITES: u32 = 1 << 0; // u32 sprite ids/count (>= 9.60)
pub const FEAT_FRAME_DURATIONS: u32 = 1 << 1; // animation frame durations (>= 10.50)
pub const FEAT_IDLE_ANIMATIONS: u32 = 1 << 2; // (>= 10.57)

fn features_for(value: u16) -> (u32, bool) {
    let mut f = 0u32;
    let ext = value >= 960;
    if ext {
        f |= FEAT_EXTENDED_SPRITES;
    }
    if value >= 1050 {
        f |= FEAT_FRAME_DURATIONS;
    }
    if value >= 1057 {
        f |= FEAT_IDLE_ANIMATIONS;
    }
    (f, ext)
}

/// Extract the value of `attr="..."` from an XML element line. Tiny and tolerant;
/// enough for the flat `<version .../>` rows in versions.xml.
fn attr<'a>(line: &'a str, name: &str) -> Option<&'a str> {
    let key = format!("{name}=\"");
    let start = line.find(&key)? + key.len();
    let rest = &line[start..];
    let end = rest.find('"')?;
    Some(&rest[..end])
}

/// Parse `versions.xml` into rows. `dat`/`spr` are big-endian hex strings; a 4-hex
/// `dat` means a 2-byte signature (>= 10.71).
pub fn load_table(xml: &str) -> Result<Vec<VersionRow>> {
    let mut rows = Vec::new();
    for line in xml.lines() {
        let line = line.trim();
        // require the trailing space so the `<versions>` wrapper is not matched
        if !line.starts_with("<version ") {
            continue;
        }
        let value: u16 = attr(line, "value")
            .ok_or_else(|| anyhow!("row missing value: {line}"))?
            .parse()?;
        let label = attr(line, "string").unwrap_or("").to_string();
        let dat_hex = attr(line, "dat").ok_or_else(|| anyhow!("row missing dat"))?;
        let spr_hex = attr(line, "spr").ok_or_else(|| anyhow!("row missing spr"))?;
        let dat_is_u16 = dat_hex.len() <= 4;
        let dat = u32::from_str_radix(dat_hex, 16)?;
        let spr = u32::from_str_radix(spr_hex, 16)?;
        rows.push(VersionRow {
            value,
            label,
            dat,
            dat_is_u16,
            spr,
        });
    }
    if rows.is_empty() {
        bail!("versions.xml contained no <version> rows");
    }
    Ok(rows)
}

fn resolved_from_row(row: &VersionRow) -> Resolved {
    let (feature_flags, u32_sprite_ids) = features_for(row.value);
    Resolved {
        dat_version: row.value,
        spr_version: row.value,
        feature_flags,
        u32_sprite_ids,
    }
}

/// Read the sprite count from a `.spr` given the id width, and sanity-check that
/// the first/last offsets fall inside the file. Returns Ok(count) when the parse
/// is structurally plausible (RFC §6.1 step 2).
fn spr_structural_ok(spr: &[u8], u32_ids: bool) -> Option<u32> {
    if spr.len() < 8 {
        return None;
    }
    let (count, table_start) = if u32_ids {
        (u32::from_le_bytes(spr[4..8].try_into().unwrap()), 8usize)
    } else {
        (u16::from_le_bytes(spr[4..6].try_into().unwrap()) as u32, 6usize)
    };
    if count == 0 || count > 5_000_000 {
        return None;
    }
    let table_end = table_start + (count as usize) * 4;
    if table_end > spr.len() {
        return None;
    }
    // Every non-zero offset must point inside the file, past the address table.
    for i in 0..count as usize {
        let off = u32::from_le_bytes(spr[table_start + i * 4..table_start + i * 4 + 4].try_into().unwrap());
        if off != 0 && (off as usize) < table_end {
            return None;
        }
        if off as usize > spr.len() {
            return None;
        }
    }
    Some(count)
}

/// Resolve the asset version (RFC §6.1). Order: forced override → signature
/// candidates → structural corroboration → probing.
pub fn resolve(
    dat: Option<&[u8]>,
    spr: &[u8],
    table: &[VersionRow],
    force_value: Option<u16>,
) -> Result<Resolved> {
    // (4) explicit override — the single manual escape hatch (RFC §6.1 step 4).
    if let Some(v) = force_value {
        let row = table
            .iter()
            .find(|r| r.value == v)
            .ok_or_else(|| anyhow!("--force-version {v} not present in versions.xml"))?;
        return Ok(resolved_from_row(row));
    }

    if spr.len() < 8 {
        bail!("`.spr` too small to contain a signature + count");
    }
    let spr_sig = u32::from_le_bytes(spr[0..4].try_into().unwrap());

    // (1) signature lookup -> candidate set.
    let mut candidates: Vec<&VersionRow> = table.iter().filter(|r| r.spr == spr_sig).collect();

    if let Some(dat) = dat {
        if dat.len() >= 4 {
            let dat_u32 = u32::from_le_bytes(dat[0..4].try_into().unwrap());
            let dat_u16 = u16::from_le_bytes(dat[0..2].try_into().unwrap()) as u32;
            // The `.dat` signature only NARROWS the set. If it matches nothing, the
            // `.dat` is spoofed/custom (common in OT, RFC §6.1) — keep the `.spr`
            // candidates and corroborate structurally instead of discarding them.
            let narrowed: Vec<&VersionRow> = candidates
                .iter()
                .copied()
                .filter(|r| if r.dat_is_u16 { r.dat == dat_u16 } else { r.dat == dat_u32 })
                .collect();
            if !narrowed.is_empty() {
                candidates = narrowed;
            } else if !candidates.is_empty() {
                eprintln!("[versions] assinatura do .dat nao bate (spoofada/custom); corroborando pelo .spr");
            }
        }
    }

    // (2)/(3) corroborate structurally and choose.
    if candidates.is_empty() {
        // (3) probing: signature unknown/spoofed — try both id widths structurally.
        for u32_ids in [true, false] {
            if spr_structural_ok(spr, u32_ids).is_some() {
                // Pick the newest table row matching that structure as a best guess.
                if let Some(row) = table.iter().rev().find(|r| {
                    let (_f, ext) = features_for(r.value);
                    ext == u32_ids
                }) {
                    eprintln!(
                        "[versions] unknown signature (spr={spr_sig:08X}); probed structure -> guessing {} ({}). Use --force-version to pin.",
                        row.value, row.label
                    );
                    return Ok(resolved_from_row(row));
                }
            }
        }
        bail!("could not resolve version: signature unknown and structural probing failed. Pass --force-version.");
    }

    // Keep only candidates whose structure actually parses.
    let mut viable: Vec<&VersionRow> = candidates
        .iter()
        .copied()
        .filter(|r| {
            let (_f, ext) = features_for(r.value);
            spr_structural_ok(spr, ext).is_some()
        })
        .collect();
    if viable.is_empty() {
        viable = candidates; // structure ambiguous; fall back to signature hits
    }

    // Full-signature collisions that also parse identically (7.60/7.70, 10.60/10.61):
    // any of them yields identical crypto, so pick the lowest value deterministically.
    viable.sort_by_key(|r| r.value);
    let chosen = viable[0];
    if viable.len() > 1 {
        let others: Vec<String> = viable.iter().map(|r| r.label.clone()).collect();
        eprintln!(
            "[versions] signature ambiguous among [{}]; structures agree -> using {} ({}).",
            others.join(", "),
            chosen.value,
            chosen.label
        );
    } else {
        eprintln!("[versions] resolved -> {} ({})", chosen.value, chosen.label);
    }
    Ok(resolved_from_row(chosen))
}

#[cfg(test)]
mod tests {
    use super::*;

    const XML: &str = include_str!("../../versions.xml");

    fn mini_spr(sig: u32, u32_ids: bool) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&sig.to_le_bytes());
        if u32_ids {
            v.extend_from_slice(&1u32.to_le_bytes());
        } else {
            v.extend_from_slice(&1u16.to_le_bytes());
        }
        let off = (v.len() + 4) as u32; // one offset, points just past the table
        v.extend_from_slice(&off.to_le_bytes());
        v.extend_from_slice(&[0xFF, 0x00, 0xFF]); // color key
        v.extend_from_slice(&0u16.to_le_bytes()); // empty pixel data
        v
    }

    #[test]
    fn dat_signature_is_two_bytes_for_10_71_plus() {
        let table = load_table(XML).unwrap();
        // 10.98 dat="42A3" is a 2-byte signature; spr stays 4 bytes.
        let r = table.iter().find(|r| r.value == 1098).unwrap();
        assert!(r.dat_is_u16, "10.98 dat must be parsed as 2 bytes");
        assert_eq!(r.dat, 0x42A3);
        // 10.70 dat is still 4 bytes.
        let old = table.iter().find(|r| r.value == 1070).unwrap();
        assert!(!old.dat_is_u16);
        assert_eq!(old.dat, 0x5481BB97);
    }

    #[test]
    fn full_signature_collision_resolves_deterministically() {
        // 7.60 and 7.70 share dat=439D5A33 / spr=439852BE. Signature can't tell them
        // apart; the resolver must pick deterministically (lowest value).
        let table = load_table(XML).unwrap();
        let spr = mini_spr(0x439852BE, false);
        let r = resolve(None, &spr, &table, None).unwrap();
        assert_eq!(r.dat_version, 760);
        assert!(!r.u32_sprite_ids);
    }

    #[test]
    fn extended_flag_tracks_960_boundary() {
        let table = load_table(XML).unwrap();
        let spr = mini_spr(0x57BBD603, true); // 10.98
        let r = resolve(None, &spr, &table, None).unwrap();
        assert_eq!(r.dat_version, 1098);
        assert!(r.u32_sprite_ids);
        assert_eq!(r.feature_flags & FEAT_EXTENDED_SPRITES, FEAT_EXTENDED_SPRITES);
    }

    #[test]
    fn spoofed_dat_falls_back_to_spr() {
        // A custom/edited .dat signature must not discard the correct .spr match.
        let table = load_table(XML).unwrap();
        let spr = mini_spr(0x57BBD603, true); // 10.98
        let bogus_dat = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let r = resolve(Some(&bogus_dat), &spr, &table, None).unwrap();
        assert_eq!(r.dat_version, 1098);
    }

    #[test]
    fn force_version_overrides() {
        let table = load_table(XML).unwrap();
        let spr = mini_spr(0xDEADBEEF, false); // unknown signature
        let r = resolve(None, &spr, &table, Some(854)).unwrap();
        assert_eq!(r.dat_version, 854);
    }
}

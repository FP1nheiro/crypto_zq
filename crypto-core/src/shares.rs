//! Master reconstruction from the 4 masked shares (FORMAT.md §1.2, RFC §7.1/§7.3).
//!
//! The whole XOR combine is what lives inside the VMProtect/OLLVM-virtualized
//! routine on the client. `master'` never exists as a contiguous 32-byte blob in
//! the binary (RFC §7.1): it is recomputed here from dispersed shares + masks +
//! the seed term + `integrity_material`.

use crate::kdf::{blake3_keyed, K_SEED_TERM, K_SHARE_MASK};

#[inline]
fn xor_into(acc: &mut [u8; 32], v: &[u8; 32]) {
    for i in 0..32 {
        acc[i] ^= v[i];
    }
}

fn mask_i(build_seed: &[u8; 32], i: u8) -> [u8; 32] {
    let mut material = Vec::with_capacity(33);
    material.extend_from_slice(build_seed);
    material.push(i);
    blake3_keyed(&K_SHARE_MASK, &material)
}

/// Reconstruct `master'` (FORMAT.md §1.2). Runs on the client at boot.
pub fn reconstruct_master(
    shares: &[[u8; 32]; 4],
    build_seed: &[u8; 32],
    integrity_material: &[u8; 32],
) -> [u8; 32] {
    let mut acc = [0u8; 32];
    for s in shares {
        xor_into(&mut acc, s);
    }
    for i in 0..4u8 {
        xor_into(&mut acc, &mask_i(build_seed, i));
    }
    xor_into(&mut acc, &blake3_keyed(&K_SEED_TERM, build_seed));
    xor_into(&mut acc, integrity_material);
    acc
}

/// Packer side: given the real `master`, choose stored shares so that
/// [`reconstruct_master`] reproduces it. `r` are 3 random shares; the 4th is
/// solved. (FORMAT.md §1.2)
pub fn solve_shares(
    master: &[u8; 32],
    build_seed: &[u8; 32],
    integrity_material: &[u8; 32],
    r: &[[u8; 32]; 3],
) -> [[u8; 32]; 4] {
    // target = XOR of all stored shares required
    let mut target = *master;
    target
        .iter_mut()
        .zip(blake3_keyed(&K_SEED_TERM, build_seed))
        .for_each(|(t, s)| *t ^= s);
    target
        .iter_mut()
        .zip(integrity_material.iter())
        .for_each(|(t, s)| *t ^= *s);
    for i in 0..4u8 {
        let m = mask_i(build_seed, i);
        for k in 0..32 {
            target[k] ^= m[k];
        }
    }
    // shares[3] = target ^ r0 ^ r1 ^ r2
    let mut s3 = target;
    for rr in r {
        for k in 0..32 {
            s3[k] ^= rr[k];
        }
    }
    [r[0], r[1], r[2], s3]
}

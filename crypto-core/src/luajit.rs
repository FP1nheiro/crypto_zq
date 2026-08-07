//! LuaJIT bytecode opcode remapping (RFC §11 "camada de conteúdo", Lua ladder #2).
//!
//! The transform permutes only the **opcode byte** of every bytecode instruction
//! inside a LuaJIT dump — offset 0 of each 4-byte `BCIns` (offset 3 on a
//! big-endian dump). Field order, sizes, constants, upvalues and debug info are
//! left byte-identical, so the transform is a pure bijection over the opcode
//! alphabet: `transcode(transcode(x, perm), inverse(perm)) == x`.
//!
//! Why this raises the bar: an attacker who defeats the *cipher* and extracts the
//! (still-permuted) bytecode gets a dump whose opcodes are scrambled. Stock LuaJIT
//! won't run it and no standard decompiler will read it — they must first recover
//! the per-build permutation from the client binary. The packer permutes on the
//! way in; the client un-permutes inside `decrypt_cold` right after the cipher,
//! before the bytes ever reach `luaL_loadbuffer`. The VM itself is never touched.
//!
//! The permutation is derived from `build_seed`, so it rotates with every build
//! exactly like the rest of the format (RFC §16). Both sides derive it from the
//! same core routine, so they agree by construction.
//!
//! Format reference: LuaJIT 2.1 `lj_bcwrite.c` / `lj_bcread.c`. A dump is
//!   `ESC 'L' 'J' <ver:u8> <flags:uleb> [<namelen:uleb> <name>]?`
//!   then repeated `<protolen:uleb> <proto>` records, terminated by a 0-length.
//! A proto body is
//!   `flags:u8 numparams:u8 framesize:u8 sizeuv:u8 <sizekgc:uleb> <sizekn:uleb>
//!    <sizebc:uleb> [<sizedbg:uleb> [<firstline:uleb> <numline:uleb>]]?`
//!   followed by `sizebc*4` instruction bytes, then upvalues/constants/debug.
//! (`sizebc` here is the serialized count — the reconstructed FUNCF/FUNCV header
//! instruction is *not* in the dump, so it is never permuted.)

use crate::error::{Error, Result};
use crate::kdf::{blake3_xof, K_LUA_OP};

const HEAD1: u8 = 0x1B; // ESC
const HEAD2: u8 = 0x4C; // 'L'
const HEAD3: u8 = 0x4A; // 'J'

const F_BE: u32 = 0x01; // big-endian dump
const F_STRIP: u32 = 0x02; // no debug info / no chunk name
const F_KNOWN: u32 = 0x0F; // BE | STRIP | FFI | FR2 — reject anything else

/// True if `data` looks like a LuaJIT bytecode dump (magic `ESC 'L' 'J'`).
pub fn is_bytecode(data: &[u8]) -> bool {
    data.len() >= 4 && data[0] == HEAD1 && data[1] == HEAD2 && data[2] == HEAD3
}

/// High bit of the dump's version byte (offset 3), set by the packer in
/// "VM-permute" mode (Lua ladder Phase 1). A patched client LuaJIT recognizes it,
/// un-permutes opcodes itself while reading, and normalizes the version. Stock
/// LuaJIT sees an unknown version and rejects the dump (fail-safe); `czq_core`
/// sees the mark and skips its own un-permute (the VM owns it).
pub const VM_VERSION_FLAG: u8 = 0x80;

/// Mark a (already opcode-permuted) dump so the *patched client VM* un-permutes it,
/// instead of `czq_core`. No-op if `data` is not a dump.
pub fn mark_vm_version(data: &mut [u8]) {
    if is_bytecode(data) {
        data[3] |= VM_VERSION_FLAG;
    }
}

/// Whether a dump carries the VM-permute mark (see [`mark_vm_version`]).
pub fn is_vm_marked(data: &[u8]) -> bool {
    is_bytecode(data) && data[3] & VM_VERSION_FLAG != 0
}

/// Forward opcode permutation for a build: `perm[internal_op] = disk_op`.
/// Fisher–Yates over the full byte alphabet keyed by `build_seed`. Opcodes only
/// ever occupy a small prefix of `0..256`, but a full-alphabet bijection keeps us
/// independent of the exact `BC__MAX` of the target LuaJIT.
pub fn opcode_perm(build_seed: &[u8; 32]) -> [u8; 256] {
    let mut xof = blake3_xof(build_seed, &K_LUA_OP);
    let mut p = [0u8; 256];
    for (i, e) in p.iter_mut().enumerate() {
        *e = i as u8;
    }
    for i in (1..256).rev() {
        let j = (xof.next_u32() as usize) % (i + 1);
        p.swap(i, j);
    }
    p
}

/// Inverse of [`opcode_perm`]: `inv[disk_op] = internal_op`. Used by the client.
pub fn invert(perm: &[u8; 256]) -> [u8; 256] {
    let mut inv = [0u8; 256];
    for (i, &v) in perm.iter().enumerate() {
        inv[v as usize] = i as u8;
    }
    inv
}

struct Cur<'a> {
    d: &'a [u8],
    p: usize,
}

impl<'a> Cur<'a> {
    fn u8(&mut self) -> Result<u8> {
        let b = *self.d.get(self.p).ok_or(Error::Truncated)?;
        self.p += 1;
        Ok(b)
    }
    /// LuaJIT unsigned LEB128 (`lj_buf_ruleb128`): 7 bits/byte, LSB first, up to 5
    /// bytes for a 32-bit value.
    fn uleb(&mut self) -> Result<u32> {
        let mut val: u32 = 0;
        for i in 0..5 {
            let b = self.u8()?;
            val |= ((b & 0x7f) as u32) << (7 * i);
            if b & 0x80 == 0 {
                return Ok(val);
            }
        }
        Err(Error::BadFormat)
    }
    fn skip(&mut self, n: usize) -> Result<()> {
        self.p = self.p.checked_add(n).ok_or(Error::BadFormat)?;
        if self.p > self.d.len() {
            return Err(Error::Truncated);
        }
        Ok(())
    }
}

/// Apply the opcode map `map` (forward on the packer, inverse on the client) to
/// every instruction opcode byte in a LuaJIT dump. Sizes are preserved, so this
/// only rewrites individual bytes of a clone. Returns [`Error::BadFormat`] /
/// [`Error::Truncated`] if the input is not a dump we can parse — the caller then
/// leaves the asset untransformed (safe: it is still encrypted).
pub fn transcode(dump: &[u8], map: &[u8; 256]) -> Result<Vec<u8>> {
    let mut out = dump.to_vec();
    let mut c = Cur { d: dump, p: 0 };

    if c.u8()? != HEAD1 || c.u8()? != HEAD2 || c.u8()? != HEAD3 {
        return Err(Error::BadFormat);
    }
    let _ver = c.u8()?;
    let flags = c.uleb()?;
    if flags & !F_KNOWN != 0 {
        return Err(Error::BadFormat); // unknown flag bit — refuse to guess
    }
    let strip = flags & F_STRIP != 0;
    let op_off = if flags & F_BE != 0 { 3 } else { 0 };
    if !strip {
        let namelen = c.uleb()? as usize;
        c.skip(namelen)?;
    }

    loop {
        let plen = c.uleb()? as usize;
        if plen == 0 {
            break; // end-of-protos terminator
        }
        let proto_start = c.p;
        let proto_end = proto_start.checked_add(plen).ok_or(Error::BadFormat)?;
        if proto_end > dump.len() {
            return Err(Error::Truncated);
        }

        // proto header
        let _pflags = c.u8()?;
        let _numparams = c.u8()?;
        let _framesize = c.u8()?;
        let _sizeuv = c.u8()?;
        let _sizekgc = c.uleb()?;
        let _sizekn = c.uleb()?;
        let bccount = c.uleb()? as usize;
        if !strip {
            let sizedbg = c.uleb()?;
            if sizedbg != 0 {
                let _firstline = c.uleb()?;
                let _numline = c.uleb()?;
            }
        }

        // instruction block: bccount * 4 bytes, opcode at `op_off` of each word
        let bc_start = c.p;
        let bc_bytes = bccount.checked_mul(4).ok_or(Error::BadFormat)?;
        let bc_end = bc_start.checked_add(bc_bytes).ok_or(Error::BadFormat)?;
        if bc_end > proto_end {
            return Err(Error::BadFormat);
        }
        for k in 0..bccount {
            let off = bc_start + k * 4 + op_off;
            out[off] = map[out[off] as usize];
        }

        // the remainder (upvalues/constants/debug) is untouched
        c.p = proto_end;
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn perm_is_a_bijection() {
        let perm = opcode_perm(&[0x11; 32]);
        let inv = invert(&perm);
        for i in 0..256usize {
            assert_eq!(inv[perm[i] as usize] as usize, i);
        }
        // different seeds -> different permutations
        assert_ne!(opcode_perm(&[0x22; 32]), perm);
    }

    // A minimal but structurally real stripped dump: header + one proto with 2
    // instructions (opcodes 0x10, 0x20), then a fake constant byte and terminator.
    fn synthetic() -> Vec<u8> {
        let mut d = vec![HEAD1, HEAD2, HEAD3, 0x02];
        d.push(F_STRIP as u8); // flags: stripped
                               // proto body we will length-prefix:
        let mut body = vec![
            0x00, // pflags
            0x01, // numparams
            0x05, // framesize
            0x00, // sizeuv
            0x01, // sizekgc (uleb)
            0x00, // sizekn (uleb)
            0x02, // sizebc (uleb) = 2 instructions
        ];
        body.extend_from_slice(&[0x10, 0xAA, 0xBB, 0xCC]); // instr 0
        body.extend_from_slice(&[0x20, 0xDD, 0xEE, 0xFF]); // instr 1
        body.push(0x77); // one kgc byte (untouched region)
        d.push(body.len() as u8); // proto len (fits in one uleb byte)
        d.extend_from_slice(&body);
        d.push(0x00); // end of protos
        d
    }

    #[test]
    fn transcode_round_trips_and_moves_opcodes() {
        let perm = opcode_perm(&[0x33; 32]);
        let inv = invert(&perm);
        let orig = synthetic();

        let permuted = transcode(&orig, &perm).unwrap();
        // proto body starts at idx 6; the two opcode bytes land at idx 13 and 17
        // (after the 7-byte proto header). Only those two bytes may differ.
        assert_eq!(permuted.len(), orig.len());
        assert_eq!(permuted[13], perm[0x10]);
        assert_eq!(permuted[17], perm[0x20]);
        // operands and the trailing constant byte are untouched
        assert_eq!(&permuted[14..17], &[0xAA, 0xBB, 0xCC]);
        assert_eq!(&permuted[18..21], &[0xDD, 0xEE, 0xFF]);
        assert_eq!(*permuted.last().unwrap(), 0x00);

        // full inverse recovers the original exactly
        assert_eq!(transcode(&permuted, &inv).unwrap(), orig);
    }

    #[test]
    fn rejects_non_bytecode() {
        assert!(!is_bytecode(b"not lua"));
        assert!(transcode(b"MZ\x00\x00garbage", &opcode_perm(&[0; 32])).is_err());
    }
}

//! Validate the opcode transform against *real* LuaJIT 2.1 bytecode (GC64/FR2),
//! produced by the client's own vcpkg LuaJIT via `string.dump` (see fixtures/).
//! Covers both a stripped dump and a dump that keeps debug info + chunk name.

use czq_core::luajit::{
    invert, is_bytecode, is_vm_marked, mark_vm_version, opcode_perm, transcode, VM_VERSION_FLAG,
};

const STRIPPED: &[u8] = include_bytes!("fixtures/sample_stripped.ljbc");
const DEBUG: &[u8] = include_bytes!("fixtures/sample_debug.ljbc");

fn check(dump: &[u8]) {
    assert!(is_bytecode(dump), "fixture is not recognized as bytecode");

    let perm = opcode_perm(&[0x5A; 32]);
    let inv = invert(&perm);

    // The parser must consume the whole real dump (nested protos, constants,
    // upvalues, optional debug) without error.
    let permuted = transcode(dump, &perm).expect("transcode real bytecode");

    // Same size, and the permutation actually moved bytes (opcodes are not fixed
    // points under this seed for a non-trivial program).
    assert_eq!(permuted.len(), dump.len());
    assert_ne!(permuted, dump, "permutation left the dump unchanged");

    // Round-trips back to the exact original bytes.
    assert_eq!(transcode(&permuted, &inv).expect("inverse"), dump);
}

/// Simulate exactly what the patched client LuaJIT does (Lua ladder Phase 1):
/// the packer permutes opcodes + marks the version byte; the VM sees the mark,
/// clears it, and maps each opcode through the inverse table while reading —
/// reconstructing the original stock dump byte-for-byte.
fn check_vm_phase1(dump: &[u8]) {
    let perm = opcode_perm(&[0xC3; 32]);
    let inv = invert(&perm);

    // packer side: permute, then mark for the VM
    let mut wire = transcode(dump, &perm).expect("permute");
    mark_vm_version(&mut wire);
    assert!(is_vm_marked(&wire), "dump should carry the VM mark");
    assert_eq!(wire[3] & VM_VERSION_FLAG, VM_VERSION_FLAG);

    // patched VM side: clear the version flag, then un-permute via the inverse table
    wire[3] &= !VM_VERSION_FLAG;
    let stock = transcode(&wire, &inv).expect("vm un-permute");
    assert_eq!(stock, dump, "VM must reconstruct the exact original stock dump");
    assert!(!is_vm_marked(&stock));
}

#[test]
fn real_stripped_bytecode_round_trips() {
    check(STRIPPED);
}

#[test]
fn phase1_vm_reconstruction() {
    check_vm_phase1(STRIPPED);
    check_vm_phase1(DEBUG);
}

#[test]
fn real_debug_bytecode_round_trips() {
    check(DEBUG);
}

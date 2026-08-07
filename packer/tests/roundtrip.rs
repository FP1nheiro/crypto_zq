//! End-to-end: drive the real `czq-pack` binary to produce an asset set, then use
//! `crypto-core` (the same code the client links) to boot and decrypt it. This is
//! the packer↔client agreement proof at the file level.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use czq_core::Context;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_czq-pack")
}

fn versions_xml() -> PathBuf {
    // packer/ -> repo root -> versions.xml
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..").join("versions.xml")
}

fn run(args: &[&str]) {
    let status = Command::new(bin()).args(args).status().expect("spawn czq-pack");
    assert!(status.success(), "czq-pack {:?} failed", args);
}

#[test]
fn pack_then_boot_and_decrypt() {
    let tmp = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("czq_e2e");
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(&tmp).unwrap();

    let spr = tmp.join("Tibia.spr");
    let out = tmp.join("out");
    let lua = tmp.join("hello.lua");
    fs::write(&lua, b"function greet() print('protected') end\n").unwrap();

    // 1) synthesize a small .spr, 2) pack it (tiny Argon2 params so the test is fast)
    // default synth signature = 10.98 (extended / u32 sprite ids), so emit extended
    run(&["synth", "--out-spr", spr.to_str().unwrap(), "--count", "40", "--extended"]);
    run(&[
        "pack",
        "--spr", spr.to_str().unwrap(),
        "--cold", lua.to_str().unwrap(),
        "--out", out.to_str().unwrap(),
        "--passphrase", "correct horse battery staple",
        "--versions", versions_xml().to_str().unwrap(),
        "--chunk-size", "16",
        "--argon-mcost-kib", "8",
        "--argon-tcost", "1",
    ]);

    // --- boot as the client would ---
    let material = fs::read(out.join("embed/material.bin")).unwrap();
    let pubkey: [u8; 32] = fs::read(out.join("embed/pubkey.bin")).unwrap().try_into().unwrap();
    let manifest = fs::read(out.join("manifest.czq")).unwrap();

    let mut ctx = Context::boot(&material, &manifest, &pubkey).expect("boot");

    // cold asset round-trips to the original bytes
    let lua_id = ctx.asset_id_by_name("hello.lua").expect("asset id");
    let lua_env = fs::read(out.join("hello.lua.czq")).unwrap();
    let dec = ctx.decrypt_cold(lua_id, &lua_env).expect("decrypt cold");
    assert_eq!(dec, fs::read(&lua).unwrap());

    // sprite path: load the index, then decrypt sprite id 1 from its chunk
    let index_env = fs::read(out.join("index.czq")).unwrap();
    ctx.load_index(1, &index_env).expect("load index");
    assert_eq!(ctx.index_len(), 40);

    let chunk_id = ctx.chunk_of(1).expect("chunk of sprite 1");
    let chunk = fs::read(out.join(format!("spr_chunk_{chunk_id}.czq"))).unwrap();
    let pixels = ctx.decrypt_sprite(1, &chunk, true).expect("decrypt sprite");
    assert!(!pixels.is_empty());

    // tamper the manifest -> boot must fail (bad signature AND wrong master')
    let mut bad = manifest.clone();
    bad[5] ^= 0xFF;
    assert!(Context::boot(&material, &bad, &pubkey).is_err());
}

#[test]
fn packdir_mirrors_tree_and_compresses() {
    let tmp = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("czq_packdir");
    let _ = fs::remove_dir_all(&tmp);
    let input = tmp.join("client");
    let out = tmp.join("client_enc");
    fs::create_dir_all(input.join("data")).unwrap();
    fs::create_dir_all(input.join("modules")).unwrap();

    // a .spr in a subfolder -> should become data/chunks/
    let spr = input.join("data/Tibia.spr");
    run(&["synth", "--out-spr", spr.to_str().unwrap(), "--count", "40", "--extended"]);
    // a highly compressible cold file
    let lua = input.join("modules/game.lua");
    let lua_body = "-- protected module\nlocal x = 1\n".repeat(300);
    fs::write(&lua, lua_body.as_bytes()).unwrap();

    run(&[
        "packdir",
        "--in", input.to_str().unwrap(),
        "--out", out.to_str().unwrap(),
        "--passphrase", "chave de teste",
        "--versions", versions_xml().to_str().unwrap(),
        "--argon-mcost-kib", "8",
        "--argon-tcost", "1",
    ]);

    // tree mirrored: chunks live next to where the .spr was
    assert!(out.join("data/chunks/index.czq").exists());
    assert!(out.join("data/chunks/spr_chunk_0.czq").exists());
    assert!(out.join("modules/game.lua").exists()); // same name, encrypted

    // compression actually shrank the cold file below the plaintext size
    let enc_len = fs::metadata(out.join("modules/game.lua")).unwrap().len();
    assert!(enc_len < lua_body.len() as u64, "expected compression to shrink the cold file");

    // boot + decrypt
    let material = fs::read(out.join("embed/material.bin")).unwrap();
    let pubkey: [u8; 32] = fs::read(out.join("embed/pubkey.bin")).unwrap().try_into().unwrap();
    let manifest = fs::read(out.join("manifest.czq")).unwrap();
    let mut ctx = Context::boot(&material, &manifest, &pubkey).expect("boot");

    // cold round-trips through decompression
    let lua_id = ctx.asset_id_by_name("modules/game.lua").expect("id");
    let lua_env = fs::read(out.join("modules/game.lua")).unwrap();
    assert_eq!(ctx.decrypt_cold(lua_id, &lua_env).unwrap(), lua_body.as_bytes());

    // sprite round-trips through the index in data/chunks/
    let idx_id = ctx.asset_id_by_name("data/chunks/index").expect("index id");
    let idx_env = fs::read(out.join("data/chunks/index.czq")).unwrap();
    ctx.load_index(idx_id, &idx_env).unwrap();
    let cid = ctx.chunk_of(1).unwrap();
    let chunk = fs::read(out.join(format!("data/chunks/spr_chunk_{cid}.czq"))).unwrap();
    let pixels = ctx.decrypt_sprite(1, &chunk, true).unwrap();
    assert_eq!(&pixels[0..3], &[0xFF, 0x00, 0xFF]); // sprite color key survived
}

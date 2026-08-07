# CZQ Format Specification v1 — byte-exact contract

This document is the single source of truth shared by the **packer** (offline, Rust)
and the **crypto-core** (runtime, Rust → C ABI, linked into the client).
Both consume the same `crypto-core` code, so agreement is by construction; this
document exists so the format is auditable and reproducible.

All integers are **little-endian** unless stated. All hashes are SHA-256 or BLAKE3
as noted. "‖" denotes byte concatenation.

Maps to RFC v1.0 sections: envelope §8, key hierarchy §7, sprite derivation §9,
`.spr` partition §10, manifest/signature §12, version resolution §6.

---

## 0. Domain-separation strings

Every KDF call is domain-separated with an ASCII context string:

| Constant | Value |
|---|---|
| `CTX_SEED_TERM`  | `"czq.v1.seed_term"` |
| `CTX_SHARE_MASK` | `"czq.v1.share_mask"` |
| `CTX_COLD`       | `"czq.v1.asset.cold"` |
| `CTX_CHUNK_MAC`  | `"czq.v1.chunk.mac"` |
| `CTX_SPRITE`     | `"czq.v1.sprite"` |
| `CTX_HEADER`     | `"czq.v1.header"` |

`blake3_derive_key(context: &str, material: &[u8]) -> [u8;32]` is the BLAKE3
`derive_key` mode (context is the literal string; material is keyed).

---

## 1. Root key hierarchy (RFC §7)

```
master_key = Argon2id(passphrase, build_salt_argon, m,t,p)   # PACKER ONLY, offline
```

`master_key` is 32 bytes and is the derivation root. It is **never** stored.

### 1.1 Embedded build material (compiled into the client binary)

Emitted by the packer (`codegen`), embedded **before** hardening (RFC §17 step 4).

```
BuildMaterial {
    format_version : u8         # = 1
    build_seed     : [u8;32]    # drives masks, seed_term, header permutation, magic
    build_salt     : [u8;16]    # HKDF/BLAKE3 salt for per-asset derivation
    shares         : [[u8;32];4]# XOR-masked shares (RFC §7.3)
}
```

The four shares are emitted as separate `.rodata` constants in distinct
translation units (RFC §7.3: "espalhadas em seções distintas"). The struct above
is the *logical* view reassembled at boot inside the virtualized routine.

### 1.2 Reconstruction of `master'` (runtime, virtualized — RFC §7.1)

```
seed_term = blake3_derive_key(CTX_SEED_TERM, build_seed)                 # 32B
mask_i    = blake3_derive_key(CTX_SHARE_MASK, build_seed ‖ [i as u8])    # 32B, i=0..3
master'   = shares[0] ^ shares[1] ^ shares[2] ^ shares[3]
          ^ mask_0 ^ mask_1 ^ mask_2 ^ mask_3
          ^ seed_term
          ^ integrity_material
```

`integrity_material` = `SHA-256(manifest_body)` (see §5). The packer, knowing
`master_key`, `integrity_material` and `build_seed`, solves for the stored shares:

```
target = master_key ^ seed_term ^ integrity_material ^ (mask_0^mask_1^mask_2^mask_3)
shares[0..3] = random; shares[3] = target ^ shares[0] ^ shares[1] ^ shares[2]
```

Correct assets + correct code ⇒ `master' == master_key`. Any tamper of the signed
manifest changes `integrity_material` ⇒ `master'` is wrong ⇒ decryption fails on its
own, with no "nop-able" branch (RFC §7.2).

### 1.3 Per-asset key derivation

**Cold / UI / Stream (profiles B, C, D)** — HKDF-SHA256 (RFC §8):
```
info = CTX_COLD ‖ [profile:u8] ‖ [asset_id: u64 LE]
key  = HKDF-SHA256(ikm=master', salt=build_salt, info)[0:32]
```

**Chunk MAC key (profiles A, C)** — HKDF-SHA256:
```
info = CTX_CHUNK_MAC ‖ [chunk_id: u32 LE]
mac_key = HKDF-SHA256(ikm=master', salt=build_salt, info)[0:32]
```

**Hot sprite (profile A)** — BLAKE3 keyed (RFC §9):
```
data = [category:u8] ‖ [assembled_id: u32 LE] ‖ (for s in sort(sub_ids): [s:u32 LE])
per_sprite_key = blake3_keyed(key=master', data)[0:32]
sprite_nonce   = blake3_keyed(key=build_salt‖... )  # see §3.1
```
`sub_ids` are sorted ascending (canonicalization, RFC §9) so key is independent of
read order.

---

## 2. Envelope (RFC §8)

An envelope wraps one encrypted unit: a cold file, a UI file, a stream, or one
sprite **chunk**. Logical fields:

| Field | Size | Notes |
|---|---|---|
| `magic`       | 4  | = `blake3_derive_key(CTX_HEADER, build_seed)[0:4]` |
| `version`     | 1  | format version = 1 |
| `asset_type`  | 1  | 0=A hot-chunk, 1=B cold, 2=C stream, 3=D ui |
| `cipher_id`   | 1  | 0=AES-256-CTR, 1=AES-256-GCM, 2=ChaCha20 |
| `flags`       | 1  | bit0 = payload zlib-compressed (before encryption) |
| `nonce`       | 16 | per-envelope random (see §3) |
| `payload_len` | 4  | length of `payload` in bytes (u32 LE) |

Physical layout = **header** (the 7 fields above, total 28 bytes) followed by
`payload` (`payload_len` bytes) then `auth_tag` (16 bytes).

### 2.1 Header permutation + mask (RFC §8.3)

The 7 header fields are emitted in a **permuted order** determined by `build_seed`,
and the resulting 28-byte header is XORed with a keystream. Both are reversible by
any client built from the same `build_seed`. This is obfuscation, never a security
pillar.

```
perm      = fisher_yates(n=7, rng=Blake3Xof(key=build_seed, ctx="czq.v1.perm"))
hdr_mask  = Blake3Xof(key=build_seed, ctx=CTX_HEADER).fill(28 bytes)
```

Encode: write fields in order `perm`, giving 28 raw bytes; `out = raw ^ hdr_mask`.
Decode: `raw = bytes ^ hdr_mask`; read fields in order `perm`; reassemble; verify
`magic`. `Blake3Xof` = BLAKE3 keyed-hash XOF over an empty message, one keyed
hasher per `(key, ctx)`; `ctx` is fed as the first update block.

The `perm` and `hdr_mask` are computed **once at boot** and cached.

### 2.2 auth_tag

- Profiles **B, D** (AES-256-GCM): `auth_tag` = 16-byte GCM tag over `payload`
  (AAD = the 28-byte permuted+masked header).
- Profiles **A, C** (CTR/ChaCha): `auth_tag` = `blake3_keyed(mac_key, header ‖ payload)[0:16]`
  (MAC per chunk / per block).

---

## 3. Ciphers (RFC §8.2, D10–D13)

| cipher_id | Algorithm | Key | Nonce/IV use |
|---|---|---|---|
| 0 | AES-256-CTR | 32B | 16B counter block = `nonce` |
| 1 | AES-256-GCM | 32B | 12B nonce = `nonce[0:12]` |
| 2 | ChaCha20 (IETF) | 32B | 12B nonce = `nonce[0:12]` |

### 3.1 Sprite nonce derivation (profile A)

Each sprite is encrypted with its own `per_sprite_key`; the per-sprite IV is
derived deterministically so it need not be stored per sprite:

```
sprite_iv = blake3_keyed(key=per_sprite_key, data="iv" ‖ [assembled_id:u32 LE])[0:16]
```
Key uniqueness already prevents keystream reuse; the derived IV is defense in depth.

---

## 4. `.spr` partition + encrypted index (RFC §10)

The `.spr` is sliced into fixed-size **chunks** of `chunk_size` sprites (default
256). Chunk `c` contains sprites `[c*chunk_size, (c+1)*chunk_size)`.

**Chunk file** = envelope (asset_type=A). Its plaintext payload is the plain
**concatenation** of per-sprite ciphertexts (ascending sprite id), with no length
prefixes — the encrypted index (below) carries each sprite's `(offset, length)`:
```
payload = per_sprite_ct(s_k0) ‖ per_sprite_ct(s_k1) ‖ ...
```
The whole payload is authenticated by one chunk MAC (§2.2). The chunk envelope
carries `flags bit1 = FLAG_CHUNK_PASSTHROUGH`: the chunk cipher does not re-encrypt
the payload (each sprite is already ciphertext via its own key/IV, §1.3/§3.1); the
chunk-level `nonce` is unused (zero) and `cipher_id` is informational only.

**Encrypted index** = envelope (asset_type=B, profile cold). Plaintext:
```
IDX magic "CZQI" 4B
count : u32 LE
repeat count:
    sprite_id    : u32 LE
    chunk_id     : u32 LE
    offset       : u32 LE   # byte offset of this sprite inside the chunk payload
    length       : u32 LE   # per-sprite ciphertext length
    category     : u8       # 0 item /1 outfit /2 effect /3 missile /255 raw
    assembled_id : u32 LE
    sub_count    : u8
    sub_ids      : u32 LE × sub_count
```
Loaded and decrypted at boot; kept in RAM. Never is the whole `.spr` on disk in
clear (RFC §10).

---

## 5. Manifest (RFC §12) — signed binary body

`manifest.czq` = `body ‖ signature(64B Ed25519 over body)`.

```
body:
  magic          : "CZQM" 4B
  format_version : u8   = 1
  dat_version    : u16 LE
  spr_version    : u16 LE
  feature_flags  : u32 LE
  sprite_cipher  : u8         # cipher_id used for profile A in this build
  chunk_size     : u32 LE
  asset_count    : u32 LE
  repeat asset_count:
      asset_id : u64 LE
      profile  : u8
      sha256   : 32B          # SHA-256 of the on-disk envelope file
      name_len : u16 LE
      name     : name_len bytes UTF-8
  ed25519_pubkey : 32B        # the public key the client must have embedded
```

- `integrity_material = SHA-256(body)`.
- The client verifies `signature` over `body` with its **embedded** public key,
  and independently checks `ed25519_pubkey == embedded_pubkey` (a swapped-key
  manifest is rejected). Version fields drive the parser before any asset load
  (RFC §14 step 4).

---

## 6. Version resolution (RFC §6.1) — table `versions.xml`

`(dat_sig, spr_sig) -> {value, feature_flags}`. Corrections over RFC §6.1 driven
by the actual data in `versions.xml`:

1. **`dat` signature width is not constant.** ≤ 10.70 it is a 4-byte timestamp;
   **≥ 10.71 it is 2 bytes**. The reader is version-range aware; a fixed 4-byte
   read corrupts detection for 10.71+.
2. **Signature is not unique.** Full `(dat,spr)` collisions exist (7.60 vs 7.70,
   10.60 vs 10.61) and many partial collisions. Signature lookup yields a
   *candidate set*; **structural corroboration is mandatory**, not optional:
   a `.dat`/`.spr` parse that terminates cleanly (no overrun, sprite count matches)
   selects among candidates.
3. Classic `.dat/.spr` range is ≤ 10.99. 13.10 is protobuf/appearances → out of
   scope for this format (RFC §6 excludes it).

Resolved `(dat_version, spr_version, feature_flags)` is stamped into the signed
manifest (§5) and is the source of truth at boot.

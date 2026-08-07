//! Optional payload compression (zlib/deflate), applied BEFORE encryption
//! (FORMAT.md §2 `FLAG_COMPRESSED`). Compress-then-encrypt: ciphertext does not
//! compress, so this only ever runs on plaintext. Pure Rust (miniz_oxide), so it
//! links cleanly into the staticlib. LZMA could be added as a second algorithm id
//! if a size/ratio trade-off ever justifies its cost.

use crate::error::{Error, Result};

pub fn compress(data: &[u8]) -> Vec<u8> {
    miniz_oxide::deflate::compress_to_vec_zlib(data, 6)
}

pub fn decompress(data: &[u8]) -> Result<Vec<u8>> {
    miniz_oxide::inflate::decompress_to_vec_zlib(data).map_err(|_| Error::BadFormat)
}

/// Compress `data` only if it actually shrinks. Returns `(bytes, compressed?)`.
pub fn maybe_compress(data: &[u8]) -> (Vec<u8>, bool) {
    let c = compress(data);
    if c.len() < data.len() {
        (c, true)
    } else {
        (data.to_vec(), false)
    }
}

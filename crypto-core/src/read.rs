//! Minimal bounds-checked little-endian cursor for parsing manifest/index blobs.
//! No serde: the on-wire bytes are the signed contract, so parsing is explicit.

use crate::error::{Error, Result};

pub struct Reader<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(b: &'a [u8]) -> Self {
        Reader { b, pos: 0 }
    }
    pub fn remaining(&self) -> usize {
        self.b.len() - self.pos
    }
    pub fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.remaining() < n {
            return Err(Error::Truncated);
        }
        let s = &self.b[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    pub fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }
    pub fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    pub fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    pub fn arr32(&mut self) -> Result<[u8; 32]> {
        Ok(self.take(32)?.try_into().unwrap())
    }
    /// Unsigned LEB128 (varint), up to 5 bytes for a u32.
    pub fn uleb(&mut self) -> Result<u32> {
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
    pub fn expect_magic(&mut self, m: &[u8; 4]) -> Result<()> {
        if self.take(4)? == m {
            Ok(())
        } else {
            Err(Error::BadFormat)
        }
    }
}

/// Little-endian byte sink used by the packer side (and tests) to build blobs.
#[derive(Default)]
pub struct Writer {
    pub buf: Vec<u8>,
}

impl Writer {
    pub fn new() -> Self {
        Writer { buf: Vec::new() }
    }
    pub fn bytes(&mut self, b: &[u8]) {
        self.buf.extend_from_slice(b);
    }
    pub fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }
    pub fn u16(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    pub fn u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    pub fn u64(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    /// Unsigned LEB128 (varint).
    pub fn uleb(&mut self, mut v: u32) {
        loop {
            let b = (v & 0x7f) as u8;
            v >>= 7;
            if v != 0 {
                self.buf.push(b | 0x80);
            } else {
                self.buf.push(b);
                break;
            }
        }
    }
    pub fn into_vec(self) -> Vec<u8> {
        self.buf
    }
}

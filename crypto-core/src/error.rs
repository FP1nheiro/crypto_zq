//! Error type shared across the core. Kept deliberately coarse: at the boundary
//! with the client (RFC §14) we never reveal *where* integrity failed — callers
//! map everything to an opaque, delayed failure.

use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Buffer too short / field overrun while parsing.
    Truncated,
    /// A magic / version / structural sentinel did not match.
    BadFormat,
    /// Authentication tag or MAC did not verify (tamper or wrong key).
    AuthFailed,
    /// Ed25519 signature invalid, or embedded pubkey mismatch.
    BadSignature,
    /// Requested id not present in the loaded index.
    NotFound,
    /// Output buffer supplied by the caller is too small.
    ShortBuffer,
    /// Unsupported cipher id / profile / format version.
    Unsupported,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Error::Truncated => "truncated",
            Error::BadFormat => "bad format",
            Error::AuthFailed => "auth failed",
            Error::BadSignature => "bad signature",
            Error::NotFound => "not found",
            Error::ShortBuffer => "short buffer",
            Error::Unsupported => "unsupported",
        })
    }
}

impl std::error::Error for Error {}

pub type Result<T> = core::result::Result<T, Error>;

/// Stable numeric codes for the C ABI. `0` is success.
impl Error {
    pub fn code(self) -> i32 {
        match self {
            Error::Truncated => 1,
            Error::BadFormat => 2,
            Error::AuthFailed => 3,
            Error::BadSignature => 4,
            Error::NotFound => 5,
            Error::ShortBuffer => 6,
            Error::Unsupported => 7,
        }
    }
}

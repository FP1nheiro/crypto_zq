//! Root key derivation (RFC §7.1, §15 step 1): `passphrase -> Argon2id -> master`.
//! Runs once, offline, in the packer. The client never sees this.

use anyhow::{Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};

/// Argon2id parameters. Defaults are memory-hard enough to make passphrase
/// brute-force costly while running in ~1s once (RFC D6).
#[derive(Clone, Copy)]
pub struct ArgonParams {
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl Default for ArgonParams {
    fn default() -> Self {
        ArgonParams {
            m_cost_kib: 256 * 1024, // 256 MiB
            t_cost: 4,
            p_cost: 1,
        }
    }
}

/// Derive the 32-byte master key. `salt` is per-build; it is ephemeral (the client
/// never re-derives — the master is baked into the shares), so a fresh random salt
/// each run yields fresh keys = rotation (RFC §15, §16).
pub fn derive_master(passphrase: &[u8], salt: &[u8], p: ArgonParams) -> Result<[u8; 32]> {
    let params = Params::new(p.m_cost_kib, p.t_cost, p.p_cost, Some(32))
        .map_err(|e| anyhow::anyhow!("argon2 params: {e}"))?;
    let a = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; 32];
    a.hash_password_into(passphrase, salt, &mut out)
        .map_err(|e| anyhow::anyhow!("argon2: {e}"))
        .context("deriving master key")?;
    Ok(out)
}

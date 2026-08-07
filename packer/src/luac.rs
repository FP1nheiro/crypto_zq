//! Compile Lua *source* to LuaJIT bytecode before packing, so the opcode-remap
//! layer (Lua ladder #2) has something to permute. Bytecode is specific to the
//! LuaJIT build, so this MUST use the *client's own* LuaJIT — we shell out to its
//! `luajit.exe` (the one in the client's `vcpkg_installed`, same version). One
//! process compiles the whole batch via a jobs file; files that are already
//! bytecode, or that fail to compile, are simply left as source (absent from the
//! returned map) and the caller encrypts them unchanged.
//!
//! We use `string.dump(chunk, true)` (strip debug) — no `jit.bcsave` module needed,
//! only the base library, so it works with a bare `luajit.exe`.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};
use czq_core::luajit::is_bytecode;

/// The client's `luajit.exe`, embedded into this binary at build time so the packer
/// is a single self-contained exe — no vcpkg, no separate file. It must match the
/// LuaJIT the client links (bytecode is version-specific); if the client's LuaJIT
/// ever changes, replace `packer/vendor/luajit.exe` and rebuild. Overridable at
/// runtime by a real `luajit.exe` next to the exe, in the input's vcpkg tree, or
/// via `--luajit` — the embedded copy is only the last-resort fallback.
#[cfg(windows)]
const EMBEDDED_LUAJIT: &[u8] = include_bytes!("../vendor/luajit.exe");
#[cfg(not(windows))]
const EMBEDDED_LUAJIT: &[u8] = &[];

/// Extract the embedded `luajit.exe` to a stable temp path (size-stamped so a new
/// build refreshes it) and return it. None if there is no embedded copy.
fn embedded_luajit() -> Option<PathBuf> {
    if EMBEDDED_LUAJIT.is_empty() {
        return None;
    }
    let dir = std::env::temp_dir().join("czq_luac_bin");
    fs::create_dir_all(&dir).ok()?;
    let name = if cfg!(windows) { "exe" } else { "bin" };
    let p = dir.join(format!("luajit_{}.{}", EMBEDDED_LUAJIT.len(), name));
    let fresh = fs::metadata(&p).map(|m| m.len() as usize == EMBEDDED_LUAJIT.len()).unwrap_or(false);
    if !fresh {
        // write to a pid-unique temp then rename, so concurrent runs don't tear it
        let tmp = dir.join(format!("luajit_{}.tmp", std::process::id()));
        fs::write(&tmp, EMBEDDED_LUAJIT).ok()?;
        let _ = fs::rename(&tmp, &p);
    }
    p.is_file().then_some(p)
}

/// The dumper runs *inside* the client's LuaJIT. It reads a jobs file (one
/// `input<TAB>output` per line), compiles each input and writes stripped bytecode.
const DUMPER: &str = r#"
local jobs = assert(arg[1], "jobs file")
for line in io.lines(jobs) do
  local i, o = line:match("^(.-)\t(.+)$")
  if i and o then
    local f = io.open(i, "rb")
    if f then
      local src = f:read("*a"); f:close()
      local chunk = loadstring(src, "@s")
      if chunk then
        local ok, bc = pcall(string.dump, chunk, true)  -- strip debug
        if ok and bc then
          local of = io.open(o, "wb")
          if of then of:write(bc); of:close() end
        end
      end
    end
  end
end
"#;

/// Locate a usable `luajit`. Order: (1) a real `luajit.exe` next to *this*
/// executable (lets you override the embedded copy); (2) the client's
/// `vcpkg_installed/.../tools/luajit/luajit.exe`, walking up from `start` (the
/// input folder); (3) the `luajit.exe` embedded in this binary, extracted to temp —
/// the always-available fallback that needs no vcpkg and no separate file.
pub fn detect_luajit(start: &Path) -> Option<PathBuf> {
    let exe = if cfg!(windows) { "luajit.exe" } else { "luajit" };

    // (1) a real luajit next to the packer / GUI executable (override)
    if let Ok(cur) = std::env::current_exe() {
        if let Some(dir) = cur.parent() {
            let cand = dir.join(exe);
            if cand.is_file() {
                return Some(cand);
            }
        }
    }

    // (2) the client's vcpkg tree, if present near the input
    let mut dir = Some(start);
    while let Some(d) = dir {
        let vroot = d.join("vcpkg_installed");
        if vroot.is_dir() {
            // vcpkg_installed/<triplet>[/<triplet>]/tools/luajit/luajit.exe
            if let Ok(rd) = fs::read_dir(&vroot) {
                for tri in rd.flatten().map(|e| e.path()).filter(|p| p.is_dir()) {
                    for mid in [tri.clone(), tri.join(tri.file_name().unwrap_or_default())] {
                        let cand = mid.join("tools").join("luajit").join(exe);
                        if cand.is_file() {
                            return Some(cand);
                        }
                    }
                }
            }
        }
        dir = d.parent();
    }

    // (3) the embedded copy, extracted to temp — always works, no vcpkg needed
    embedded_luajit()
}

/// Compile the given source files to bytecode. Returns `abs_path -> bytecode` for
/// each file that compiled to a valid LuaJIT dump. Never errors on a per-file
/// failure — only on setup/spawn problems.
pub fn compile_batch(luajit: &Path, inputs: &[PathBuf]) -> Result<HashMap<PathBuf, Vec<u8>>> {
    let mut out = HashMap::new();
    if inputs.is_empty() {
        return Ok(out);
    }
    if !luajit.is_file() {
        bail!("luajit nao encontrado: {}", luajit.display());
    }

    let tmp = std::env::temp_dir().join("czq_luac");
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(&tmp).with_context(|| format!("criando {}", tmp.display()))?;
    let dumper = tmp.join("dump.lua");
    fs::write(&dumper, DUMPER)?;

    let mut jobs = String::new();
    let mut pairs: Vec<(PathBuf, PathBuf)> = Vec::with_capacity(inputs.len());
    for (i, inp) in inputs.iter().enumerate() {
        let o = tmp.join(format!("{i}.ljbc"));
        jobs.push_str(&inp.to_string_lossy());
        jobs.push('\t');
        jobs.push_str(&o.to_string_lossy());
        jobs.push('\n');
        pairs.push((inp.clone(), o));
    }
    let jobs_path = tmp.join("jobs.txt");
    fs::write(&jobs_path, jobs)?;

    let status = Command::new(luajit)
        .arg(&dumper)
        .arg(&jobs_path)
        .status()
        .with_context(|| format!("executando {}", luajit.display()))?;
    if !status.success() {
        bail!("luajit saiu com erro (code {:?})", status.code());
    }

    for (inp, o) in pairs {
        if let Ok(bc) = fs::read(&o) {
            if is_bytecode(&bc) {
                out.insert(inp, bc);
            }
        }
    }
    let _ = fs::remove_dir_all(&tmp);
    Ok(out)
}

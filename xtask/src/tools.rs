//! Process and path helpers shared by tasks.
use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use std::{
    env,
    ffi::OsStr,
    fs,
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus},
    thread,
    time::{Duration, Instant},
};
use stela_runtime::sha256;

pub fn root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask lives in the repository root")
}

/// The cargo that launched this task, so nested builds share its toolchain.
pub fn cargo() -> Command {
    let mut command = Command::new(env::var_os("CARGO").unwrap_or_else(|| "cargo".into()));
    command.current_dir(root());
    command
}

pub fn exec(command: &mut Command) -> Result<()> {
    let status = command
        .status()
        .with_context(|| format!("cannot start {:?}", command.get_program()))?;
    if !status.success() {
        bail!("{command:?} failed with {status}");
    }
    Ok(())
}

pub fn which(name: impl AsRef<OsStr>) -> Option<PathBuf> {
    let name = name.as_ref();
    env::split_paths(&env::var_os("PATH")?)
        .map(|directory| directory.join(name))
        .find(|path| path.is_file())
}

/// `llvm-objdump` from the Rust toolchain's `llvm-tools`.
pub fn toolchain_objdump() -> Option<PathBuf> {
    let output = Command::new(env::var_os("RUSTC").unwrap_or_else(|| "rustc".into()))
        .args(["--print", "sysroot"])
        .output()
        .ok()?;
    let sysroot = PathBuf::from(String::from_utf8(output.stdout).ok()?.trim());
    fs::read_dir(sysroot.join("lib/rustlib"))
        .ok()?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path().join("bin/llvm-objdump"))
        .find(|path| path.is_file())
}

pub fn qemu() -> Result<PathBuf> {
    let local = root().join(".tools/qemu/bin/qemu-system-x86_64");
    if local.exists() {
        return Ok(local);
    }
    which("qemu-system-x86_64").context("install QEMU 11 or newer")
}

/// Path, size and digest of one input or output file.
pub fn binding(path: &Path) -> Result<Value> {
    let data = fs::read(path).with_context(|| format!("cannot read {}", path.display()))?;
    Ok(json!({ "path": path, "bytes": data.len(), "sha256": sha256(&data) }))
}

/// Wait for `child` until `timeout`, then terminate it. Returns `None` on timeout.
pub fn wait(child: &mut Child, timeout: Duration) -> Result<Option<ExitStatus>> {
    let Some(deadline) = Instant::now().checked_add(timeout) else {
        return Ok(Some(child.wait()?));
    };
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait()? {
            return Ok(Some(status));
        }
        thread::sleep(Duration::from_millis(20));
    }
    stop(child);
    Ok(None)
}

pub fn stop(child: &mut Child) {
    if matches!(child.try_wait(), Ok(None)) {
        let _ = child.kill();
    }
    let _ = child.wait();
}

//! Build evidence shared by the native GPU tasks.
use anyhow::{Context, Result, ensure};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

pub fn capture(command: &mut Command) -> Result<String> {
    let output = command
        .output()
        .with_context(|| format!("cannot execute {command:?}"))?;
    ensure!(
        output.status.success(),
        "{command:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).context("tool output is not UTF-8")
}

/// A tool from Stela's local GPU tool environment, or else from PATH.
pub fn tool(name: &str, local: &str) -> Result<PathBuf> {
    let path = crate::tools::root()
        .join(".tools/gpu")
        .join(local)
        .join(name);
    path.is_file()
        .then_some(path)
        .or_else(|| crate::tools::which(name))
        .with_context(|| format!("install {name} and put it in PATH"))
}

pub fn evidence_directory() -> Result<PathBuf> {
    let run = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let parent = crate::tools::root().join(".stela/gpu/evidence");
    fs::create_dir_all(&parent)?;
    let path = parent.join(run.to_string());
    fs::create_dir(&path)?;
    Ok(path)
}

/// Bind the actual fork through its links, including patches, local edits
/// and downloaded build dependencies.
/// Ignored caches and generated Python bytecode are not source inputs.
pub fn source_binding(root: &Path) -> Result<String> {
    fn collect(root: &Path, paths: &mut Vec<PathBuf>) -> Result<()> {
        for entry in fs::read_dir(root)? {
            let entry = entry?;
            let name = entry.file_name();
            if [".git", "__pycache__", "packagecache", ".wraplock"]
                .iter()
                .any(|n| name == *n)
            {
                continue;
            }
            // Upstream files are links into their pinned checkouts.
            let metadata = fs::metadata(entry.path())?;
            if metadata.is_dir() {
                collect(&entry.path(), paths)?;
            } else if metadata.is_file() {
                paths.push(entry.path());
            }
        }
        Ok(())
    }
    let mut paths = Vec::new();
    collect(root, &mut paths)?;
    paths.sort();
    let mut digest = Sha256::new();
    for path in paths {
        let name = path.strip_prefix(root)?.to_string_lossy();
        digest.update((name.len() as u64).to_le_bytes());
        digest.update(name.as_bytes());
        let mut input = File::open(path)?;
        let mut file_hash = Sha256::new();
        let mut buffer = [0; 64 * 1024];
        loop {
            let n = input.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            file_hash.update(&buffer[..n]);
        }
        digest.update(file_hash.finalize());
    }
    Ok(format!("{:x}", digest.finalize()))
}

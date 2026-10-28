//! Source fingerprints for build scripts.
//!
//! A fingerprint is the SHA-256 of every file under a crate's inputs, keyed
//! by its `/`-separated path relative to the crate root and hashed with
//! CRLF line endings folded to LF. Checkouts of one commit on Windows
//! (`core.autocrlf`), Linux and macOS therefore produce the same digest, so
//! translation caches keyed by it move between hosts. Hidden entries (names
//! starting with `.`, such as `.DS_Store` or editor swap files) are skipped.
use sha2::{Digest, Sha256};
use std::{fs, path::Path};

/// Prints `cargo:rerun-if-changed` for each input of the crate whose build
/// script is running and sets the environment variable `variable` to the
/// inputs' fingerprint for the crate's compilation.
pub fn emit(variable: &str, inputs: &[&str]) {
    for input in inputs {
        println!("cargo:rerun-if-changed={input}");
    }
    let root = std::env::var_os("CARGO_MANIFEST_DIR").expect("build script environment");
    println!(
        "cargo:rustc-env={variable}={}",
        source_sha256(Path::new(&root), inputs)
    );
}

/// The lowercase hex SHA-256 of the files under `inputs`, each a file or
/// directory relative to `root`.
pub fn source_sha256(root: &Path, inputs: &[&str]) -> String {
    let mut files = Vec::new();
    for input in inputs {
        collect(
            root,
            &mut input.split('/').map(str::to_owned).collect(),
            &mut files,
        );
    }
    files.sort();
    files.dedup();
    let mut hasher = Sha256::new();
    for file in files {
        let content = normalize(&fs::read(root.join(&file)).expect("readable source file"));
        hasher.update(file.as_bytes());
        hasher.update([0]);
        hasher.update((content.len() as u64).to_le_bytes());
        hasher.update(&content);
    }
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Adds the `/`-joined relative paths of the files at `components` to `files`.
fn collect(root: &Path, components: &mut Vec<String>, files: &mut Vec<String>) {
    let path = components
        .iter()
        .fold(root.to_owned(), |path, part| path.join(part));
    if path.is_dir() {
        for entry in fs::read_dir(&path).expect("readable source directory") {
            let name = entry.expect("source entry").file_name();
            let name = name.into_string().expect("UTF-8 source file name");
            if name.starts_with('.') {
                continue;
            }
            components.push(name);
            collect(root, components, files);
            components.pop();
        }
    } else {
        files.push(components.join("/"));
    }
}

/// `bytes` with each CRLF pair replaced by LF.
fn normalize(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    for (index, &byte) in bytes.iter().enumerate() {
        if byte == b'\r' && bytes.get(index + 1) == Some(&b'\n') {
            continue;
        }
        out.push(byte);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree(name: &str, files: &[(&str, &[u8])]) -> std::path::PathBuf {
        let root =
            std::env::temp_dir().join(format!("stela-fingerprint-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        for (path, content) in files {
            let path = root.join(path);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, content).unwrap();
        }
        root
    }

    #[test]
    fn crlf_and_lf_checkouts_match() {
        let lf = tree(
            "lf",
            &[("src/a.rs", b"fn a() {}\n"), ("src/b/c.rs", b"x\n")],
        );
        let crlf = tree(
            "crlf",
            &[("src/a.rs", b"fn a() {}\r\n"), ("src/b/c.rs", b"x\r\n")],
        );
        assert_eq!(source_sha256(&lf, &["src"]), source_sha256(&crlf, &["src"]));
        fs::remove_dir_all(lf).unwrap();
        fs::remove_dir_all(crlf).unwrap();
    }

    #[test]
    fn hidden_entries_are_skipped() {
        let plain = tree("plain", &[("src/a.rs", b"a")]);
        let hidden = tree("hidden", &[("src/a.rs", b"a"), ("src/.DS_Store", b"\0")]);
        assert_eq!(
            source_sha256(&plain, &["src"]),
            source_sha256(&hidden, &["src"])
        );
        fs::remove_dir_all(plain).unwrap();
        fs::remove_dir_all(hidden).unwrap();
    }

    #[test]
    fn content_and_path_changes_change_the_digest() {
        let base = tree("base", &[("src/a.rs", b"a")]);
        let edited = tree("edited", &[("src/a.rs", b"b")]);
        let moved = tree("moved", &[("src/b.rs", b"a")]);
        let digest = source_sha256(&base, &["src"]);
        assert_ne!(digest, source_sha256(&edited, &["src"]));
        assert_ne!(digest, source_sha256(&moved, &["src"]));
        for root in [base, edited, moved] {
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn sibling_semantic_crates_invalidate_for_nested_source_and_manifest_changes() {
        let workspace = tree(
            "semantic-dependencies",
            &[
                ("engine/src/lib.rs", b"engine"),
                ("contracts/Cargo.toml", b"contracts"),
                ("contracts/src/generated/features.rs", b"feature-a\n"),
                ("formats/Cargo.toml", b"formats"),
                ("formats/src/payload/manifest.rs", b"format-a"),
            ],
        );
        let root = workspace.join("engine");
        let inputs = [
            "src",
            "../contracts/Cargo.toml",
            "../contracts/src",
            "../formats/Cargo.toml",
            "../formats/src",
        ];
        let mut digest = source_sha256(&root, &inputs);
        fs::write(
            workspace.join("contracts/src/generated/features.rs"),
            b"feature-a\r\n",
        )
        .unwrap();
        assert_eq!(digest, source_sha256(&root, &inputs));
        for (path, content) in [
            (
                "contracts/src/generated/features.rs",
                b"feature-b".as_slice(),
            ),
            ("formats/src/payload/manifest.rs", b"format-b".as_slice()),
            ("formats/Cargo.toml", b"new dependency".as_slice()),
            ("contracts/src/new_effect.rs", b"new module".as_slice()),
        ] {
            fs::write(workspace.join(path), content).unwrap();
            let changed = source_sha256(&root, &inputs);
            assert_ne!(digest, changed, "semantic input {path}");
            digest = changed;
        }
        fs::remove_dir_all(workspace).unwrap();
    }

    #[test]
    fn lone_carriage_returns_are_kept() {
        assert_eq!(normalize(b"a\r\nb\rc\r"), b"a\nb\rc\r");
    }
}

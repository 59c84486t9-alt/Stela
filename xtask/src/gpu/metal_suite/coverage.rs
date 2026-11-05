//! What macOS's own shaders use that the suite's libraries do not: the
//! measure of what the suite leaves untested.
//!
//! `coverage` copies every system metallib from the Mac into the ignored
//! DIR/system (once; `--refresh` copies again) and splits each into its
//! function modules (each wrapped by 0x0B17C0DE: bitcode at the offset in
//! bytes 8..12, of the size in bytes 12..16). It takes two inventories of
//! each module with the host's LLVM tools, which read AIR, and of the
//! suite's AIR in DIR/plan/lib:
//!
//! - the AIR intrinsics it calls (`llvm-nm -u`), compared by family, their
//!   type suffixes removed;
//! - the AIR metadata keys it carries (`llvm-dis`), which name what no call
//!   shows: entry point arguments and their qualifiers (render target
//!   inputs, imageblocks, raster order groups...), function kinds and
//!   compile options.
//!
//! What the suite lacks of each is ranked by how many system libraries use
//! it.
use anyhow::{Context, Result, bail};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    process::Command,
};

const ROOTS: &str = "/System/Library /System/iOSSupport /usr/lib";

/// Which files use each name.
type Uses = BTreeMap<String, BTreeSet<PathBuf>>;

/// An intrinsic's family: its name without type tokens (f32, v4f16, i64,
/// p1i8...) or signedness (s, u, f) segments.
pub fn family(name: &str) -> String {
    let typed = |p: &str| {
        let p = p.strip_prefix('v').map_or(p, |rest| {
            rest.trim_start_matches(|c: char| c.is_ascii_digit())
        });
        (p.len() > 1
            && matches!(p.as_bytes()[0], b'f' | b'i' | b'u' | b'p')
            && p[1..].chars().next().is_some_and(|c| c.is_ascii_digit()))
            || matches!(p, "s" | "u" | "f")
    };
    name.split('.')
        .filter(|p| !typed(p))
        .collect::<Vec<_>>()
        .join(".")
}

/// The function modules of a metallib, or the file itself for AIR.
fn modules(data: &[u8]) -> Vec<&[u8]> {
    if data.starts_with(b"BC\xC0\xDE") || data.starts_with(b"\xDE\xC0\x17\x0B") {
        return vec![data];
    }
    let mut out = vec![];
    let mut at = 0;
    while let Some(found) = data[at..].windows(4).position(|w| w == b"\xDE\xC0\x17\x0B") {
        let start = at + found;
        if start + 16 <= data.len() {
            let word = |o: usize| {
                u32::from_le_bytes(data[start + o..start + o + 4].try_into().unwrap()) as usize
            };
            let end = start + word(8) + word(12);
            if end <= data.len() {
                out.push(&data[start..end]);
            }
        }
        at = start + 4;
    }
    out
}

/// The `air.` metadata keys of disassembled IR: each `!"air.name"`.
fn metadata_keys(ir: &str) -> BTreeSet<String> {
    let mut keys = BTreeSet::new();
    for piece in ir.split("!\"air.").skip(1) {
        let name: String = piece
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.'))
            .collect();
        if piece[name.len()..].starts_with('"') {
            keys.insert(format!("air.{name}"));
        }
    }
    keys
}

/// Every file's undefined `air.` symbols and `air.` metadata keys.
fn inventory(files: &[PathBuf], scratch: &Path) -> Result<(Uses, Uses)> {
    fs::create_dir_all(scratch)?;
    let (mut calls, mut keys) = (Uses::new(), Uses::new());
    for file in files {
        let data = fs::read(file)?;
        let mut paths = vec![];
        for (k, module) in modules(&data).iter().enumerate() {
            let path = scratch.join(format!("{k}.bc"));
            fs::write(&path, module)?;
            paths.push(path);
        }
        for batch in paths.chunks(256) {
            let out = Command::new("llvm-nm")
                .arg("-u")
                .args(batch)
                .output()
                .context("llvm-nm")?;
            for line in String::from_utf8_lossy(&out.stdout).lines() {
                if let Some(name) = line.trim().strip_prefix("U ")
                    && name.starts_with("air.")
                {
                    calls
                        .entry(name.to_string())
                        .or_default()
                        .insert(file.clone());
                }
            }
            // Writes each module's IR beside it, as k.ll.
            Command::new("llvm-dis")
                .args(batch)
                .status()
                .context("llvm-dis")?;
        }
        for path in paths {
            let ir = path.with_extension("ll");
            if let Ok(text) = fs::read_to_string(&ir) {
                for key in metadata_keys(&text) {
                    keys.entry(key).or_default().insert(file.clone());
                }
                fs::remove_file(ir)?;
            }
            fs::remove_file(path)?;
        }
    }
    Ok((calls, keys))
}

fn files_under(dir: &Path, extension: &str) -> Result<Vec<PathBuf>> {
    let mut out = vec![];
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for entry in fs::read_dir(&d)? {
            let path = entry?.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == extension) {
                out.push(path);
            }
        }
    }
    out.sort();
    Ok(out)
}

/// Copies the Mac's system metallibs into DIR/system, keeping their paths.
fn fetch(out: &Path, host: &str) -> Result<()> {
    let system = out.join("system");
    if system.exists() {
        fs::remove_dir_all(&system)?;
    }
    fs::create_dir_all(&system)?;
    let mut list = Command::new("ssh");
    list.arg(host).arg(format!(
        "find {ROOTS} -name '*.metallib' -type f 2>/dev/null | tar -cf - -T - 2>/dev/null"
    ));
    let mut extract = Command::new("tar");
    extract
        .arg("--warning=no-unknown-keyword")
        .arg("-C")
        .arg(&system)
        .arg("-xf")
        .arg("-");
    super::remote::pipe(list, extract)
}

/// The system's uses of `names` missing from `covered`, ranked.
fn section(title: &str, names: &Uses, covered: &BTreeSet<String>, system: &Path) -> String {
    let mut missing: Vec<(usize, &String, &BTreeSet<PathBuf>)> = names
        .iter()
        .filter(|(n, _)| !covered.contains(*n))
        .map(|(n, u)| (u.len(), n, u))
        .collect();
    missing.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(b.1)));
    let mut text = format!(
        "{title}: the system uses {}, the suite {}, leaving {}\n",
        names.len(),
        names.len() - missing.len(),
        missing.len()
    );
    for (count, name, users) in &missing {
        let example = users
            .iter()
            .next()
            .map(|p| p.strip_prefix(system).unwrap_or(p).display().to_string());
        text += &format!("{count:4} {name}  ({})\n", example.unwrap_or_default());
    }
    text
}

pub fn run(out: &Path, host: &str, refresh: bool, report: Option<&Path>) -> Result<()> {
    let system = out.join("system");
    if refresh || !system.exists() {
        fetch(out, host)?;
    }
    let libraries = files_under(&system, "metallib")?;
    let suite = files_under(&out.join("plan/lib"), "air")?;
    if suite.is_empty() {
        bail!(
            "no suite AIR in {}: run `mac` first",
            out.join("plan/lib").display()
        );
    }
    let scratch = out.join("coverage-scratch");
    let (system_calls, system_keys) = inventory(&libraries, &scratch)?;
    let (suite_calls, suite_keys) = inventory(&suite, &scratch)?;
    fs::remove_dir_all(&scratch)?;
    let mut families = Uses::new();
    for (name, users) in &system_calls {
        families
            .entry(family(name))
            .or_default()
            .extend(users.iter().cloned());
    }
    let covered: BTreeSet<String> = suite_calls.keys().map(|n| family(n)).collect();
    let keys: BTreeSet<String> = suite_keys.into_keys().collect();
    let text = format!(
        "{} system libraries\n{}\n{}",
        libraries.len(),
        section("intrinsic families", &families, &covered, &system),
        section("metadata keys", &system_keys, &keys, &system)
    );
    print!("{text}");
    if let Some(path) = report {
        fs::write(path, text)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn families_drop_type_and_sign_tokens() {
        assert_eq!(
            family("air.sample_texture_2d.v4f32"),
            "air.sample_texture_2d"
        );
        assert_eq!(family("air.convert.f.v4f16.f.v4f32"), "air.convert");
        assert_eq!(
            family("air.atomic.global.xor.u.i32"),
            "air.atomic.global.xor"
        );
        assert_eq!(family("air.fma.f16"), "air.fma");
        assert_eq!(
            family("air.quad_shuffle_down.u.i32"),
            "air.quad_shuffle_down"
        );
        assert_eq!(family("air.convert.f.v4bf16.f.v4f32"), "air.convert.v4bf16");
    }

    #[test]
    fn metallib_modules_split_by_wrapper() {
        let mut lib = b"MTLB....".to_vec();
        let mut module = vec![0xDE, 0xC0, 0x17, 0x0B, 0, 0, 0, 0];
        module.extend(20u32.to_le_bytes());
        module.extend(4u32.to_le_bytes());
        module.extend([0; 4]);
        module.extend(b"BC\xC0\xDE");
        lib.extend(&module);
        lib.extend(b"tail");
        assert_eq!(modules(&lib), vec![&module[..]]);
    }

    #[test]
    fn metadata_keys_are_quoted_air_names() {
        let ir = r#"!1 = !{i32 0, !"air.render_target", i32 0, !"air.arg_name", !"air.x"}
                    @s = constant [9 x i8] c"!\22air.no\00""#;
        let keys: Vec<String> = metadata_keys(ir).into_iter().collect();
        assert_eq!(keys, ["air.arg_name", "air.render_target", "air.x"]);
    }
}

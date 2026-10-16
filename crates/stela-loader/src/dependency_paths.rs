//! Expansion of `@loader_path`, `@executable_path` and `@rpath` into guest paths,
//! following dyld's `Loader.cpp`. Purely lexical: no filesystem access.
use anyhow::{Context, Result, bail, ensure};
use serde::Serialize;
use std::collections::BTreeSet;

const MAX_GUEST_PATH_BYTES: usize = 4096;
const MAX_RPATHS: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RPath {
    /// Absolute guest filename of the image that declares this LC_RPATH.
    pub owner: String,
    pub value: String,
}

#[derive(Debug)]
pub struct PathContext<'a> {
    /// Absolute guest filename of the main executable.
    pub executable: &'a str,
    /// Absolute guest filename of the requesting image.
    pub loader: &'a str,
    /// Requester's LC_RPATHs in load-command order, then nearest ancestor's,
    /// continuing through the main executable. Owners retain their own anchors.
    pub rpaths: &'a [RPath],
}

fn checked_path(path: &str) -> Result<()> {
    ensure!(!path.as_bytes().contains(&0), "guest path contains NUL");
    ensure!(
        path.len() <= MAX_GUEST_PATH_BYTES,
        "guest path exceeds length limit"
    );
    Ok(())
}

/// Normalize an absolute lexical guest path without clamping escaped `..`.
/// This does not inspect or resolve filesystem symlinks.
pub fn normalize_guest_path(path: &str) -> Result<String> {
    checked_path(path)?;
    ensure!(path.starts_with('/'), "guest path must be absolute");
    let mut components = Vec::new();
    for component in path.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                ensure!(
                    components.pop().is_some(),
                    "guest path escapes virtual root"
                );
            }
            component => components.push(component),
        }
    }
    Ok(format!("/{}", components.join("/")))
}

fn directory(filename: &str) -> Result<String> {
    let normalized = normalize_guest_path(filename)?;
    let (directory, _) = normalized
        .rsplit_once('/')
        .context("guest image path has no directory")?;
    Ok(if directory.is_empty() {
        "/".into()
    } else {
        directory.into()
    })
}

fn token_suffix<'a>(path: &'a str, token: &str) -> Option<&'a str> {
    path.strip_prefix(token)
        .filter(|suffix| suffix.is_empty() || suffix.starts_with('/'))
}

fn append(base: &str, suffix: &str) -> Result<String> {
    let length = base
        .len()
        .checked_add(suffix.len())
        .context("expanded guest path length overflow")?;
    ensure!(
        length <= MAX_GUEST_PATH_BYTES,
        "expanded guest path exceeds length limit"
    );
    normalize_guest_path(&format!("{base}{suffix}"))
}

fn expand_without_rpath(path: &str, executable_dir: &str, loader_dir: &str) -> Result<String> {
    checked_path(path)?;
    if path.starts_with('/') {
        return normalize_guest_path(path);
    }
    if let Some(suffix) = token_suffix(path, "@loader_path") {
        return append(loader_dir, suffix);
    }
    if let Some(suffix) = token_suffix(path, "@executable_path") {
        return append(executable_dir, suffix);
    }
    if path.starts_with('@') {
        bail!("unsupported guest path token in {path:?}");
    }
    bail!("bare relative guest dependency path is unsupported: {path:?}")
}

/// Expand an install name into ordered, deduplicated absolute guest paths.
///
/// `ctx.rpaths` holds the requesting image's load chain, nearest first. Each
/// LC_RPATH's `@loader_path` refers to the image that declares it;
/// `@executable_path` always refers to the main executable. Recursive `@rpath`
/// entries and bare relative paths are unsupported. An empty result means an
/// `@rpath` request had no search directories.
pub fn candidates(name: &str, ctx: &PathContext<'_>) -> Result<Vec<String>> {
    checked_path(name)?;
    ensure!(
        ctx.rpaths.len() <= MAX_RPATHS,
        "guest rpath count exceeds limit"
    );
    let executable_dir = directory(ctx.executable)?;
    let loader_dir = directory(ctx.loader)?;
    let Some(suffix) = token_suffix(name, "@rpath") else {
        return Ok(vec![expand_without_rpath(
            name,
            &executable_dir,
            &loader_dir,
        )?]);
    };
    ensure!(
        suffix.starts_with('/') && suffix.len() > 1,
        "@rpath dependency requires a nonempty suffix"
    );
    let mut result = Vec::new();
    let mut seen = BTreeSet::new();
    for rpath in ctx.rpaths {
        checked_path(&rpath.value)?;
        ensure!(
            token_suffix(&rpath.value, "@rpath").is_none(),
            "recursive @rpath LC_RPATH is unsupported"
        );
        let owner_dir = directory(&rpath.owner)?;
        let expanded = expand_without_rpath(&rpath.value, &executable_dir, &owner_dir)?;
        let candidate = append(&expanded, suffix)?;
        if seen.insert(candidate.clone()) {
            result.push(candidate);
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context(rpaths: &[RPath]) -> PathContext<'_> {
        PathContext {
            executable: "/Applications/Demo.app/Contents/MacOS/Demo",
            loader: "/Applications/Demo.app/Contents/Frameworks/A.framework/Versions/A/A",
            rpaths,
        }
    }
    fn rpath(owner: &str, value: &str) -> RPath {
        RPath {
            owner: owner.into(),
            value: value.into(),
        }
    }

    #[test]
    fn direct_tokens_anchor_to_requester_or_global_executable() {
        let ctx = context(&[]);
        assert_eq!(
            candidates("@loader_path/Helpers/libB.dylib", &ctx).unwrap(),
            [
                "/Applications/Demo.app/Contents/Frameworks/A.framework/Versions/A/Helpers/libB.dylib"
            ]
        );
        assert_eq!(
            candidates("@executable_path/../Frameworks/libB.dylib", &ctx).unwrap(),
            ["/Applications/Demo.app/Contents/Frameworks/libB.dylib"]
        );
        assert_eq!(
            candidates("@loader_path", &ctx).unwrap(),
            ["/Applications/Demo.app/Contents/Frameworks/A.framework/Versions/A"]
        );
        assert_eq!(
            candidates("@executable_path", &ctx).unwrap(),
            ["/Applications/Demo.app/Contents/MacOS"]
        );
    }

    #[test]
    fn nearest_ancestor_order_and_defining_owner_are_preserved() {
        let rpaths = [
            rpath("/Bundle/Libraries/Leaf.dylib", "@loader_path/leaf-first"),
            rpath(
                "/Bundle/Libraries/Leaf.dylib",
                "@executable_path/leaf-second",
            ),
            rpath("/Bundle/Plugins/Parent.dylib", "@loader_path/parent-first"),
            rpath("/Bundle/Plugins/Parent.dylib", "/shared/parent-second"),
            rpath(
                "/Applications/Demo.app/Contents/MacOS/Demo",
                "@loader_path/main-last",
            ),
        ];
        assert_eq!(
            candidates("@rpath/libTarget.dylib", &context(&rpaths)).unwrap(),
            [
                "/Bundle/Libraries/leaf-first/libTarget.dylib",
                "/Applications/Demo.app/Contents/MacOS/leaf-second/libTarget.dylib",
                "/Bundle/Plugins/parent-first/libTarget.dylib",
                "/shared/parent-second/libTarget.dylib",
                "/Applications/Demo.app/Contents/MacOS/main-last/libTarget.dylib",
            ]
        );
    }

    #[test]
    fn lexical_normalization_deduplicates_without_reordering() {
        let rpaths = [
            rpath("/a/loader", "/z//./lib"),
            rpath("/a/loader", "/a/lib"),
            rpath("/a/loader", "/z/tmp/../lib/"),
        ];
        assert_eq!(
            candidates("@rpath//Sub/../libA.dylib", &context(&rpaths)).unwrap(),
            ["/z/lib/libA.dylib", "/a/lib/libA.dylib"]
        );
        assert_eq!(
            candidates("//System/Library/./Frameworks/Unused/../A", &context(&[])).unwrap(),
            ["/System/Library/Frameworks/A"]
        );
        assert_eq!(
            candidates("/usr/lib/../lib/libé.dylib", &context(&[])).unwrap(),
            ["/usr/lib/libé.dylib"]
        );
    }

    #[test]
    fn root_escape_is_refused_for_inputs_and_every_expansion() {
        for name in [
            "/../libA",
            "/a/../../libA",
            "@executable_path/../../../../../../libA",
            "@loader_path/../../../../../../../../../../libA",
        ] {
            assert!(
                candidates(name, &context(&[]))
                    .unwrap_err()
                    .to_string()
                    .contains("escapes virtual root")
            );
        }
        let rpaths = [rpath("/a/owner", "@loader_path/../../lib")];
        assert!(candidates("@rpath/libA", &context(&rpaths)).is_err());
        let rpaths = [rpath("/a/owner", "/safe")];
        assert!(candidates("@rpath/../../outside", &context(&rpaths)).is_err());
        // A suffix may leave its search directory while remaining in guest root.
        assert_eq!(
            candidates("@rpath/../sibling/libA", &context(&rpaths)).unwrap(),
            ["/sibling/libA"]
        );
    }

    #[test]
    fn unsupported_tokens_relative_paths_and_recursive_rpaths_fail() {
        for name in [
            "",
            "libA.dylib",
            "./libA",
            "../libA",
            "@rpath",
            "@rpath/",
            "@unknown/libA",
            "@loader_pathology/libA",
            "@executable_pathology/libA",
            "@rpathname/libA",
        ] {
            assert!(
                candidates(name, &context(&[])).is_err(),
                "accepted {name:?}"
            );
        }
        for value in ["@rpath/nested", "@rpath", "@unknown/path", "relative/path"] {
            let rpaths = [rpath("/a/loader", value)];
            assert!(
                candidates("@rpath/libA", &context(&rpaths)).is_err(),
                "accepted LC_RPATH {value:?}"
            );
        }
        assert!(candidates("@rpath/libA", &context(&[])).unwrap().is_empty());
    }

    #[test]
    fn null_and_excessive_paths_are_rejected_without_truncation() {
        assert!(candidates("/lib\0A", &context(&[])).is_err());
        let invalid_context = PathContext {
            executable: "/a\0main",
            loader: "/a/loader",
            rpaths: &[],
        };
        assert!(candidates("/libA", &invalid_context).is_err());
        let rpaths = [rpath("/a\0owner", "/lib")];
        assert!(candidates("@rpath/libA", &context(&rpaths)).is_err());
        let rpaths = [rpath("/a/owner", "/lib\0")];
        assert!(candidates("@rpath/libA", &context(&rpaths)).is_err());
        let long = format!("/{}", "a".repeat(MAX_GUEST_PATH_BYTES));
        assert!(candidates(&long, &context(&[])).is_err());
        let rpaths = [rpath(
            "/a/owner",
            &format!("/{}", "a".repeat(MAX_GUEST_PATH_BYTES - 2)),
        )];
        assert!(candidates("@rpath/libA", &context(&rpaths)).is_err());
        let rpaths = vec![rpath("/a/owner", "/lib"); MAX_RPATHS + 1];
        assert!(candidates("@rpath/libA", &context(&rpaths)).is_err());
    }

    #[test]
    fn root_level_owners_and_dot_components_stay_posix_paths() {
        let rpaths = [rpath("/library", "@loader_path/./lib")];
        let ctx = PathContext {
            executable: "/main",
            loader: "/requester",
            rpaths: &rpaths,
        };
        assert_eq!(candidates("@loader_path/./libA", &ctx).unwrap(), ["/libA"]);
        assert_eq!(
            candidates("@executable_path/libA", &ctx).unwrap(),
            ["/libA"]
        );
        assert_eq!(candidates("@rpath/libA", &ctx).unwrap(), ["/lib/libA"]);
        assert_eq!(
            candidates("/literal/@unknown/libA", &ctx).unwrap(),
            ["/literal/@unknown/libA"]
        );
        assert_eq!(candidates("/a/..", &ctx).unwrap(), ["/"]);
    }
}

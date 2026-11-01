//! Linux header layout, generated asm wrappers and Kbuild compilation settings.
use std::{
    fs,
    path::{Path, PathBuf},
};

/// Source and output trees owned by the invoking build.
pub struct Roots {
    pub linux: PathBuf,
    pub compat: PathBuf,
    pub output: PathBuf,
}

/// A Linux module's names from Kbuild.
pub struct Module<'a> {
    pub name: &'a str,
    pub file: &'a str,
}

pub struct Environment {
    linux: PathBuf,
    compat: PathBuf,
    wrappers: PathBuf,
}
impl Environment {
    pub fn new(roots: Roots) -> Self {
        additions(&roots.compat, &roots.compat, &roots.linux.join("include"));
        let wrappers = roots.output.join("linux-asm");
        let include = roots.linux.join("include");
        let x86_uapi = roots.linux.join("arch/x86/include/uapi");
        for (list, arch, directory) in [
            ("asm-generic/Kbuild", roots.compat.join("asm"), "asm"),
            ("uapi/asm-generic/Kbuild", x86_uapi.join("asm"), "uapi/asm"),
        ] {
            let output = wrappers.join(directory);
            fs::create_dir_all(&output).expect("create the asm wrapper directory");
            let contents = fs::read_to_string(include.join(list))
                .unwrap_or_else(|error| panic!("{list}: {error}"));
            for header in contents
                .lines()
                .filter_map(|line| line.strip_prefix("mandatory-y += "))
                .filter(|header| !arch.join(header).exists())
            {
                fs::write(
                    output.join(header),
                    format!("#include <asm-generic/{header}>\n"),
                )
                .expect("write an asm wrapper");
            }
        }
        Self {
            linux: roots.linux,
            compat: roots.compat,
            wrappers,
        }
    }

    /// Apply the shared Linux ABI and header search order. The caller supplies
    /// its class-specific include directories and optional generated headers.
    pub fn apply(
        &self,
        build: &mut cc::Build,
        generated: Option<&Path>,
        directories: &[PathBuf],
        module: Option<&Module<'_>>,
    ) {
        build
            .flag("-nostdinc")
            .define("__KERNEL__", None)
            .define("__DISABLE_EXPORTS", None);
        for flag in [
            "-fms-extensions",
            "-fshort-wchar",
            "-fno-strict-aliasing",
            "-fno-common",
            "-fno-strict-overflow",
            "-fno-delete-null-pointer-checks",
            "-funsigned-char",
        ] {
            build.flag(flag);
        }
        let include = self.linux.join("include");
        let x86_uapi = self.linux.join("arch/x86/include/uapi");
        let mm = self.linux.join("mm");
        for header in [
            include.join("linux/kconfig.h"),
            include.join("linux/compiler_types.h"),
            self.compat.join("stela/compiler.h"),
        ] {
            build.flag("-include").flag(header);
        }
        if let Some(module) = module {
            build
                .define("KBUILD_MODNAME", format!("\"{}\"", module.name).as_str())
                .define("KBUILD_MODFILE", format!("\"{}\"", module.file).as_str());
        }
        for directory in directories.iter().map(PathBuf::as_path).chain([
            self.compat.as_path(),
            include.as_path(),
            x86_uapi.as_path(),
            mm.as_path(),
        ]) {
            println!("cargo:rerun-if-changed={}", directory.display());
        }
        for directory in generated
            .map(Path::to_path_buf)
            .into_iter()
            .chain(directories.iter().cloned())
            .chain([
                self.compat.clone(),
                self.wrappers.clone(),
                include.clone(),
                x86_uapi,
                self.wrappers.join("uapi"),
                include.join("uapi"),
                mm,
            ])
        {
            build.flag("-isystem").flag(directory);
        }
    }
}

/// Stela may add headers and provide its architecture, while common Linux
/// headers continue to come from the selected upstream tree.
fn additions(directory: &Path, compat: &Path, include: &Path) {
    for entry in fs::read_dir(directory).expect("read the kernel-API directory") {
        let path = entry.expect("readable directory entry").path();
        let header = path.strip_prefix(compat).expect("a kernel-API path");
        if path.is_dir() {
            if header != Path::new("asm") {
                additions(&path, compat, include);
            }
            continue;
        }
        for tree in [include.to_path_buf(), include.join("uapi")] {
            assert!(
                !tree.join(header).exists(),
                "{}/{} would replace Linux's in {}",
                compat.display(),
                header.display(),
                tree.display()
            );
        }
    }
}

#[cfg(test)]
mod tests {
    //! Header ownership and architecture-wrapper controls in independent trees.
    use super::*;
    use tempfile::TempDir;

    fn roots() -> (TempDir, Roots) {
        let temporary = tempfile::tempdir().unwrap();
        let linux = temporary.path().join("linux");
        let compat = temporary.path().join("compat");
        for directory in [
            linux.join("include/asm-generic"),
            linux.join("include/uapi/asm-generic"),
            compat.join("asm"),
        ] {
            fs::create_dir_all(directory).unwrap();
        }
        for path in [
            "include/asm-generic/Kbuild",
            "include/uapi/asm-generic/Kbuild",
        ] {
            fs::write(linux.join(path), "mandatory-y += types.h\n").unwrap();
        }
        let output = temporary.path().join("output");
        (
            temporary,
            Roots {
                linux,
                compat,
                output,
            },
        )
    }

    #[test]
    fn mandatory_headers_get_original_generic_wrappers() {
        let (_temporary, roots) = roots();
        let output = roots.output.clone();
        let _environment = Environment::new(roots);
        for path in ["linux-asm/asm/types.h", "linux-asm/uapi/asm/types.h"] {
            assert_eq!(
                fs::read_to_string(output.join(path)).unwrap(),
                "#include <asm-generic/types.h>\n"
            );
        }
    }

    #[test]
    fn common_headers_cannot_override_linux_or_uapi() {
        for tree in ["include", "include/uapi"] {
            let (_temporary, roots) = roots();
            fs::create_dir_all(roots.compat.join("linux")).unwrap();
            fs::create_dir_all(roots.linux.join(tree).join("linux")).unwrap();
            fs::write(roots.compat.join("linux/example.h"), "compat").unwrap();
            fs::write(roots.linux.join(tree).join("linux/example.h"), "upstream").unwrap();
            assert!(std::panic::catch_unwind(|| Environment::new(roots)).is_err());
        }
    }

    #[test]
    fn architecture_headers_keep_their_selected_implementation() {
        let (_temporary, roots) = roots();
        fs::write(roots.compat.join("asm/types.h"), "Stela architecture").unwrap();
        let arch = roots.linux.join("arch/x86/include/uapi/asm");
        fs::create_dir_all(&arch).unwrap();
        fs::write(arch.join("types.h"), "Linux architecture UAPI").unwrap();
        let output = roots.output.clone();
        let _environment = Environment::new(roots);
        assert!(!output.join("linux-asm/asm/types.h").exists());
        assert!(!output.join("linux-asm/uapi/asm/types.h").exists());
        assert_eq!(
            fs::read_to_string(arch.join("types.h")).unwrap(),
            "Linux architecture UAPI"
        );
    }
}

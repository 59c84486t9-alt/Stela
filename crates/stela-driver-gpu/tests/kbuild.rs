//! The bounded Kbuild reader the native ports select Linux objects with.
#[path = "../build/kbuild.rs"]
mod kbuild;

use kbuild::{Config, Kbuild};
use std::{fs, path::PathBuf};

/// A fresh driver tree holding `files`, each a (path, contents) pair.
fn tree(name: &str, files: &[(&str, &str)]) -> PathBuf {
    let root = std::env::temp_dir().join(format!("stela-kbuild-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    for (path, text) in files {
        let path = root.join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, text).unwrap();
    }
    root
}

fn config(header: &str) -> Config {
    Config::parse(header).unwrap()
}

#[test]
fn composes_includes_conditions_and_simple_references() {
    let root = tree(
        "composes",
        &[
            (
                "Kbuild",
                "# SPDX-License-Identifier: MIT\n\
                 ccflags-y += -I $(src)/include\n\
                 ccflags-y += -I $(src)\n\
                 include $(src)/core/Kbuild\n\
                 drv-y := $(core-y)\n\
                 ifdef CONFIG_X86\n\
                 drv-y += x86.o\n\
                 endif\n\
                 drv-$(CONFIG_ACPI) += acpi.o\n\
                 drv-$(CONFIG_DEBUG_FS) += debugfs.o\n\
                 drv-y += main.o\n\
                 obj-$(CONFIG_DRV) += drv.o\n",
            ),
            ("core/Kbuild", "core-y := core/a.o\ncore-y += core/b.o\n"),
        ],
    );
    let kbuild = Kbuild::read(
        &root,
        &config("#define CONFIG_X86 1\n#define CONFIG_ACPI 1\n#define CONFIG_DRV 1\n"),
    )
    .unwrap();
    assert_eq!(
        kbuild.objects("drv").unwrap(),
        ["core/a.o", "core/b.o", "x86.o", "acpi.o", "main.o"]
    );
    assert_eq!(kbuild.objects("obj").unwrap(), ["drv.o"]);
    assert_eq!(kbuild.includes, [root.join("include"), root.join(".")]);
    assert_eq!(
        kbuild.files,
        [root.join("Kbuild"), root.join("core/Kbuild")]
    );
    let without = Kbuild::read(&root, &config("")).unwrap();
    assert_eq!(
        without.objects("drv").unwrap(),
        ["core/a.o", "core/b.o", "main.o"]
    );
    assert!(without.objects("obj").is_err());
}

#[test]
fn refuses_what_it_cannot_evaluate_even_when_inactive() {
    for (name, text, header) in [
        ("unknown", "ifdef CONFIG_OFF\nifeq ($(A),b)\nendif\n", ""),
        ("shell", "drv-y += $(shell ls)\n", ""),
        ("pattern", "drv-y += $(patsubst %.c,%.o,a.c)\n", ""),
        ("escape", "include $(src)/../Kbuild\n", ""),
        ("source", "drv-y += core/a.c\n", ""),
        ("recursive", "a-y += a.o\ndrv-y += $(a-y)\n", ""),
        ("undefined", "drv-y := $(missing-y)\n", ""),
        (
            "module",
            "drv-$(CONFIG_M) += m.o\n",
            "#define CONFIG_M_MODULE 1\n",
        ),
        (
            "string",
            "drv-$(CONFIG_S) += s.o\n",
            "#define CONFIG_S \"s\"\n",
        ),
        ("unbalanced", "ifdef CONFIG_X86\ndrv-y += a.o\n", ""),
        ("stray", "endif\n", ""),
        ("flag", "ccflags-y += -DDEBUG\n", ""),
        ("loop", "include $(src)/Kbuild\n", ""),
    ] {
        let root = tree(name, &[("Kbuild", text)]);
        assert!(
            Kbuild::read(&root, &config(header)).is_err(),
            "{name} was accepted"
        );
    }
    assert!(Config::parse("#define CONFIG_A 1\n#define CONFIG_A 1\n").is_err());
}

#!/usr/bin/env python3
"""Bounded original-source Linux Wi-Fi object census; executes no kernel code.

Run under the shared heavy-job lock. Inputs use the production Linux gitlink and
canonical patches. This exploratory configuration is not a complete Kconfig or
production build. Compilation grants no hardware or platform capability.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[4]
PIN = "cc9de5d4b5ab6459f5774946aa3195ad51236fa8"
IWL = "drivers/net/wireless/intel/iwlwifi"
SOURCE_TREES = [IWL, "net/mac80211", "net/wireless", "net/rfkill", "net/core", "crypto"]
CONFIG = [
    "NET", "INET", "IPV6", "WLAN", "WIRELESS", "CFG80211", "MAC80211", "IWLWIFI",
    "IWLMVM", "IWLMLD", "PM", "PM_SLEEP", "ACPI", "EFI", "RFKILL", "CRYPTO",
    "CFG80211_REQUIRE_SIGNED_REGDB", "CFG80211_USE_KERNEL_REGDB_KEYS",
    "PTP_1588_CLOCK", "MAC80211_MESH", "MAC80211_RC_MINSTREL", "KEYS",
    "ASSOCIATIVE_ARRAY", "ASYMMETRIC_KEY_TYPE", "X509_CERTIFICATE_PARSER",
    "PKCS7_MESSAGE_PARSER", "SYSTEM_DATA_VERIFICATION",
]
SUBSET = [
    f"{IWL}/iwl-drv.c", f"{IWL}/pcie/drv.c", f"{IWL}/pcie/gen1_2/tx-gen2.c",
    f"{IWL}/pcie/gen1_2/rx.c", f"{IWL}/mvm/mac80211.c", f"{IWL}/mld/mac80211.c",
    f"{IWL}/mld/tx.c", "net/mac80211/main.c", "net/mac80211/tx.c", "net/mac80211/rx.c",
    "net/wireless/core.c", "net/wireless/reg.c", "net/wireless/nl80211.c",
    "net/core/skbuff.c", "net/core/dev.c", "net/rfkill/core.c",
]


def command(args, cwd=None):
    return subprocess.check_output(args, cwd=cwd, text=True)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def symbols(path, undefined=False):
    flag = "-u" if undefined else "--defined-only"
    lines = command(["nm", "-g", flag, str(path)]).splitlines()
    return {line.split()[-1] for line in lines if len(line.split()) >= 2}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--network", required=True, type=Path, help="git-archive source root")
    parser.add_argument("--output", required=True, type=Path, help="new output directory")
    parser.add_argument("--common-archive", type=Path)
    args = parser.parse_args()
    linux = ROOT / "third_party/linux"
    compat = ROOT / "crates/stela-linux/src/compat"
    head = command(["git", "rev-parse", "HEAD"], linux).strip()
    subprocess.run(["git", "merge-base", "--is-ancestor", PIN, head], cwd=linux, check=True)
    subprocess.run(["git", "diff", "--quiet", "HEAD"], cwd=linux, check=True)
    source = args.network.resolve()
    object_format = command(["git", "rev-parse", "--show-object-format"], linux).strip()
    entries = subprocess.check_output(["git", "ls-tree", "-rz", head, "--", *SOURCE_TREES], cwd=linux)
    source_files = 0
    for entry in entries.split(b"\0"):
        if not entry:
            continue
        metadata, name = entry.split(b"\t", 1)
        mode, kind, expected = metadata.split()
        path = source / name.decode()
        if kind != b"blob" or mode == b"120000" or not path.is_file():
            raise ValueError(f"expected regular source blob: {path}")
        data = path.read_bytes()
        actual = hashlib.new(object_format, b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
        if actual != expected.decode():
            raise ValueError(f"source differs from patched Linux tree: {path}")
        source_files += 1
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    (out / "generated").mkdir()
    config = (compat / "generated/autoconf.h").read_text() + "\n"
    config += "".join(f"#define CONFIG_{name} 1\n" for name in CONFIG)
    (out / "generated/autoconf.h").write_text(config)
    wrappers = out / "asm-wrappers"
    for listing, arch, target in [
        ("asm-generic/Kbuild", compat / "asm", wrappers / "asm"),
        ("uapi/asm-generic/Kbuild", linux / "arch/x86/include/uapi/asm", wrappers / "uapi/asm"),
    ]:
        target.mkdir(parents=True)
        for line in (linux / "include" / listing).read_text().splitlines():
            if line.startswith("mandatory-y += "):
                header = line.removeprefix("mandatory-y += ")
                if not (arch / header).exists():
                    (target / header).write_text(f"#include <asm-generic/{header}>\n")
    flags = [
        "clang", "-std=gnu11", "-ffreestanding", "-fno-stack-protector", "-mno-red-zone",
        "-mgeneral-regs-only", "-nostdinc", "-D__KERNEL__", "-D__DISABLE_EXPORTS",
        '-DKBUILD_MODNAME="stela_iwlwifi_probe"', f'-DKBUILD_MODFILE="{IWL}"',
        "-fms-extensions", "-fno-strict-aliasing", "-fno-common", "-fno-strict-overflow",
        "-fno-delete-null-pointer-checks", "-funsigned-char", "-fshort-wchar", "-Wno-everything",
        "-Werror=implicit-function-declaration", "-Werror=implicit-int",
        "-Werror=incompatible-pointer-types", "-Werror=return-type",
        "-ferror-limit=8", "-O2", "-c",
    ]
    for header in [linux / "include/linux/kconfig.h", linux / "include/linux/compiler_types.h",
                   compat / "stela/compiler.h"]:
        flags += ["-include", str(header)]
    # Upstream x86 fallback headers expose missing architecture dependencies;
    # they do not implement Stela's production architecture boundary. Stela's
    # include_next architecture headers must still reach UAPI before x86 kernel headers.
    for directory in [out, compat, wrappers, linux / "include", linux / "arch/x86/include/uapi",
                      wrappers / "uapi", linux / "include/uapi", linux / "mm",
                      linux / "arch/x86/include", source / IWL, source / "net/mac80211",
                      source / "net/wireless"]:
        flags += ["-isystem", str(directory)]
    save(out / "configuration.json", {
        "linux_gitlink": PIN, "patched_head": head, "source_files_verified": source_files,
        "configuration": CONFIG, "flags": flags,
        "autoconf_sha256": sha(out / "generated/autoconf.h"),
        "compiler": command(["clang", "--version"]).splitlines()[0],
    })

    def compile_one(name):
        obj = out / (name.replace("/", "_") + ".o")
        invocation = flags + [str(source / name), "-o", str(obj)]
        result = subprocess.run(invocation, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        obj.with_suffix(".log").write_text(result.stdout)
        return {
            "source": name, "sha256": sha(source / name), "command": invocation,
            "exit": result.returncode, "log": obj.with_suffix(".log").name,
            "undefined": sorted(symbols(obj, True)) if result.returncode == 0 else [],
            "defined": sorted(symbols(obj)) if result.returncode == 0 else [],
            "first_error": next((s for s in result.stdout.splitlines() if "error:" in s), ""),
        }

    with ThreadPoolExecutor(max_workers=6) as pool:
        rows = list(pool.map(compile_one, SUBSET))
    save(out / "objects.json", rows)
    undefined = {name for row in rows for name in row["undefined"]}
    defined = {name for row in rows for name in row["defined"]}
    common = symbols(args.common_archive) if args.common_archive else set()
    traps = set()
    for path in (compat / "kernel").glob("*.c"):
        traps.update(re.findall(r"\bSTELA_UNSUPPORTED\s*\(\s*[^,]+,\s*(\w+)\s*,", path.read_text()))
    save(out / "imports.json", {
        "compiled": sum(row["exit"] == 0 for row in rows), "attempted": len(rows),
        "unique_undefined": len(undefined), "defined_in_subset": sorted(undefined & defined),
        "present_in_common_including_traps": sorted((undefined - defined) & common),
        "known_traps_referenced": sorted(undefined & traps),
        "remaining_including_other_upstream_objects": sorted(undefined - defined - common),
        "common_archive_sha256": sha(args.common_archive) if args.common_archive else None,
        "scope": "Undefined names include other uncompiled upstream units, not only implementation gaps; archive presence does not prove an implemented service.",
    })
    for row in rows:
        print(f"{row['source']}: {'PASS' if row['exit'] == 0 else row['first_error']}")


if __name__ == "__main__":
    main()
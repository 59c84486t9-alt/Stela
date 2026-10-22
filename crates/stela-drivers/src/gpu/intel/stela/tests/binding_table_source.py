#!/usr/bin/env python3
"""Prove the hosted BTI move against complete original donor files.

This reads source bytes only. It neither builds a driver nor claims that the
full Gallium translation units compile. Donors are required external evidence,
not a second production implementation or a generated OS compatibility layer.
"""
import argparse
import hashlib
import json
from pathlib import Path


def digest(data):
    return hashlib.sha256(data.encode()).hexdigest()


def check(root, donors, name, emit):
    current = root / "crates/stela-drivers/src/gpu/common/mesa/src/gallium/drivers" / name
    donor = donors / name
    program = (donor / f"{name}_program.c").read_text()
    context = (donor / f"{name}_context.h").read_text()
    meson = (donor / "meson.build").read_text()
    moved = (current / f"{name}_binding_table.c").read_text()
    header = (current / f"{name}_binding_table.h").read_text()
    a = program.index("static const char *surface_group_names[] = {")
    end = "static void iris_shader_perf_log" if name == "iris" else "static void\ncrocus_debug_recompile"
    b = program.index(end, a)
    body = program[a:b]
    static = f"static void\n{name}_setup_binding_table"
    exported = f"void\n{name}_setup_binding_table"
    assert body.count(static) == 1
    actual_body = moved[moved.index("static const char *surface_group_names[] = {"):]
    assert actual_body == body.replace(static, exported, 1)
    assert actual_body.replace(exported, static, 1) == body

    new_program = (current / f"{name}_program.c").read_text()
    assert new_program == program[:a] + program[b:]
    assert program[:program.index("*/") + 2] in moved
    da = context.index(f"enum {name}_surface_group {{")
    stop = "#define IRIS_SYSVAL_CLIP_PLANE" if name == "iris" else "/**\n * A compiled shader variant"
    db = context.index(stop, da)
    declarations = context[da:db]
    assert header.count(declarations) == 1
    assert context[:context.index("*/") + 2] in header
    rewritten = context[:da] + f'#include "{name}_binding_table.h"\n\n' + context[db:]
    if name == "crocus":
        ia = rewritten.index("/**\n * Map a <group, index> pair to a binding table index.")
        ib = rewritten.index("/* crocus_disk_cache.c */", ia)
        inline = rewritten[ia:ib]
        assert header.count(inline) == 1
        rewritten = rewritten[:ia] + rewritten[ib:]
    assert rewritten == (current / f"{name}_context.h").read_text()
    entry = f"  '{name}_binding_table.c',\n"
    new_meson = (current / "meson.build").read_text()
    assert new_meson.count(entry) == 1 and new_meson.replace(entry, "", 1) == meson
    assert f"void {name}_setup_binding_table(" in header
    for forbidden in [f'{name}_context.h', 'p_context.h', 'p_screen.h', 'bufmgr', 'winsys']:
        assert forbidden not in moved and forbidden not in header
    if emit:
        emit.mkdir(parents=True, exist_ok=True)
        # Test-only symbol bindings isolate the complete original donor from
        # the moved production module. No function body or OS service changes.
        prefix = program[:program.index("*/") + 2] + "\n"
        prefix += f"#define {name}_setup_binding_table stela_unused_{name}_declaration\n"
        if name == "iris":
            for function in ["iris_group_index_to_bti", "iris_bti_to_group_index"]:
                prefix += f"#define {function} stela_donor_{function}\n"
        prefix += f'#include "gallium/drivers/{name}/{name}_binding_table.h"\n'
        prefix += f"#undef {name}_setup_binding_table\n"
        prefix += '#include "compiler/nir/nir_builder.h"\n#include "intel/dev/intel_device_info.h"\n'
        prefix += '#include "intel/dev/intel_debug.h"\n#include "util/u_debug.h"\n#include "util/u_math.h"\n'
        prefix += '#include <stdio.h>\n#include <string.h>\n'
        if name == "crocus":
            prefix += '#include "intel/compiler/elk/elk_compiler.h"\n'
        args = (f"const struct intel_device_info *d, struct nir_shader *n, struct {name}_binding_table *b, "
                "unsigned targets, unsigned values, unsigned cbufs, " +
                ("bool null_rt" if name == "iris" else "const struct elk_sampler_prog_key_data *key"))
        wrapper = f"\nvoid stela_donor_{name}_setup({args});\nvoid stela_donor_{name}_setup({args})\n{{\n"
        wrapper += f"   {name}_setup_binding_table(d,n,b,targets,values,cbufs," + ("null_rt" if name == "iris" else "key") + ");\n}\n"
        (emit / f"{name}_donor.c").write_text(prefix + body + wrapper)
    return {"driver": name, "whole_body_bytes": len(body.encode()),
            "whole_body_sha256": digest(body), "declarations_sha256": digest(declarations),
            "unchanged_unrelated_program": True, "unchanged_unrelated_context": True,
            "one_original_meson_source_addition": True, "only_setup_linkage_changed": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--donor-root", type=Path, required=True,
                        help="Directory containing original iris/ and crocus/ program/context/Meson files")
    parser.add_argument("--emit-donor-dir", type=Path,
                        help="Emit complete source-bound donor TUs for focused hosted comparison; does not compile them")
    args = parser.parse_args()
    print(json.dumps({"schema": 1, "scope": "source-only; no compilation or runtime qualification",
                      "results": [check(args.root, args.donor_root, name, args.emit_donor_dir) for name in ["iris", "crocus"]]},
                     indent=2))


if __name__ == "__main__":
    main()

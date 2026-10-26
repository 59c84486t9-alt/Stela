#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Reproduce Intel GPIO community tables from the exact pinned original donors.

Only numeric community/group data and ACPI joins are translated. No pinctrl
implementation is extracted, executed or credited by this table generator.
"""
import argparse
import hashlib
import json
import pathlib
import re

PIN = "cc9de5d4b5ab6459f5774946aa3195ad51236fa8"
FAMILIES = "sunrisepoint cannonlake icelake tigerlake alderlake meteorlake broxton geminilake jasperlake elkhartlake".split()
HASHES = dict(zip(FAMILIES, [
    "cfb37b60fb8ad30ce8f9995b55febda4f649ea118a7a95f0b81eee3a1f216d59",
    "567120f40c817ab662faf50c64b9b29e5c022b8121b0df6a759deddbd17d4965",
    "9205b56f08a73c466a1d152d47fedfad399e46c2712421735aae2fa8674d8904",
    "aa8ca30b64f9f538918a83979634f0fcb5519c9f94ec34c00b51bda4b1016792",
    "78dfea6bcc992aeb2bb78a224f578ae96ee9b9a8965ed41b8e5f5128ff2e6f8f",
    "bfe4955b8d1bf12acb969217aba8027e03a0c52ea9bf6db60c4e630c40d96174",
    "e60362f831daa51a36dab771dc408f0018609695ec6c1ed7b55f47d642c66cac",
    "fcb5d931f70b865d2bb11ece1fb54b28ef2348f584782b2ce6b5198d4b5e13b8",
    "74fe754a79f3a2ddf7c249702627ef263fa8a244f156492cbeca6c3fe3997655",
    "2053a20812463151a89fee162fab7f46ac530e8bde57efc575b4acb3dc1ee8c7",
]))


def arrays(text, typename):
    pattern = r"static const " + re.escape(typename) + r"\s*(\w+)\[\]\s*=\s*\{(.*?)\n\};"
    return dict(re.findall(pattern, text, re.S))


def structs(text, typename):
    pattern = r"static const " + re.escape(typename) + r"\s+(\w+)\s*=\s*\{(.*?)\n\};"
    return dict(re.findall(pattern, text, re.S))


def number(token, definitions):
    token = token.strip()
    if token in definitions:
        return number(definitions[token], definitions)
    return int(token, 0)


def generate(reference):
    output = ["// SPDX-License-Identifier: GPL-2.0", "// Copyright (C) 2015-2022 Intel Corporation", "// Generated numeric tables: tests/reference/intel_gpio_tables.py.", f"// Linux {PIN}; original family-specific notices in ../THIRD_PARTY.md.", "use super::{Community, Group, Profile};", ""]
    joins = []
    manifest = []
    for family in FAMILIES:
        path = reference / f"pinctrl-{family}.c"
        data = path.read_bytes()
        if hashlib.sha256(data).hexdigest() != HASHES[family]:
            raise ValueError("pinned donor identity mismatch: " + str(path))
        source = re.sub(r"/\*.*?\*/", "", data.decode(), flags=re.S)
        source = source.replace("\\\n", "")
        definitions = dict(re.findall(r"^#define\s+(\w+)\s+(0x[0-9a-fA-F]+|[0-9]+)\s*$", source, re.M))
        definitions.update(INTEL_GPIO_BASE_MATCH="0", INTEL_GPIO_BASE_ZERO="-2", INTEL_GPIO_BASE_NOMAP="-1")
        macros = dict(re.findall(r"^#define\s+(\w+_COMMUNITY)\([^\n]*?\)\s+(INTEL_COMMUNITY_[^\n]+)", source, re.M))
        groups = {}
        for name, body in arrays(source, "struct intel_padgroup").items():
            rows = []
            for args in re.findall(r"INTEL_GPP\(([^)]+)\)", body):
                reg, first, last, gpio = [number(x, definitions) for x in args.split(",")]
                assert 0 <= first <= last and last - first < 32
                rows.append((reg, first, last - first + 1, first if gpio == 0 else 0 if gpio == -2 else gpio))
            assert rows, (family, name)
            groups[name] = rows
        communities = {}
        for name, body in arrays(source, "struct intel_community").items():
            rows = []
            for macro, args in re.findall(r"(\w+_COMMUNITY)\(([^)]+)\)", body):
                args = [x.strip() for x in args.split(",")]
                bar, first, last = [number(x, definitions) for x in args[:3]]
                expansion = macros[macro]
                if expansion.startswith("INTEL_COMMUNITY_GPPS"):
                    group_rows = groups[args[3]]
                    prefix = expansion.rsplit(",", 1)[1].strip(" )\t")
                    padown = 0
                    resolved = []
                    for reg, base, count, gpio in group_rows:
                        resolved.append((reg, base, count, gpio, padown))
                        padown += (count + 7) // 8
                else:
                    assert expansion.startswith("INTEL_COMMUNITY_SIZE"), expansion
                    tokens = expansion[expansion.index("(") + 1:expansion.rindex(")")].split(",")
                    size, increment = [number(x, definitions) for x in tokens[3:5]]
                    prefix = tokens[5].strip()
                    resolved = []
                    for index, base in enumerate(range(first, last + 1, size)):
                        resolved.append((index, base, min(size, last - base + 1), base, index * increment))
                assert resolved and set(range(first, last + 1)) == {pin for _, base, count, _, _ in resolved for pin in range(base, base + count)}
                offsets = [number(definitions[prefix + "_" + field], definitions) for field in ("PAD_OWN", "PADCFGLOCK", "HOSTSW_OWN", "GPI_IS", "GPI_IE")]
                rows.append((bar, first, last - first + 1, offsets, resolved))
            assert rows, (family, name, body)
            communities[name] = rows
        socs = structs(source, "struct intel_pinctrl_soc_data")
        tables = arrays(source, "struct intel_pinctrl_soc_data *")
        for name, body in socs.items():
            uid = re.search(r'\.uid\s*=\s*"([^"]+)"', body)
            comm = re.search(r"\.communities\s*=\s*(\w+)", body).group(1)
            rows = communities[comm]
            const_name = name.upper()
            output.append(f"pub(super) static {const_name}: Profile = Profile {{ name: \"{name}\", uid: " + (f'Some("{uid.group(1)}")' if uid else "None") + ", communities: &[")
            for bar, first, count, offsets, group_rows in rows:
                output.append(f"    Community {{ bar: {bar}, first: {first}, count: {count}, pad_own: {offsets[0]:#x}, lock: {offsets[1]:#x}, host_own: {offsets[2]:#x}, status: {offsets[3]:#x}, enable: {offsets[4]:#x}, groups: &[")
                for reg, base, size, gpio, padown in group_rows:
                    output.append(f"        Group {{ register: {reg}, first: {base}, count: {size}, gpio: {gpio}, pad_own: {padown} }},")
                output.append("    ] },")
            output.append("] };\n")
        for body in arrays(source, "struct acpi_device_id").values():
            for hid, target in re.findall(r'\{\s*"([^"]+)"\s*,\s*\(kernel_ulong_t\)&?(\w+)\s*\}', body):
                targets = [target] if target in socs else re.findall(r"&(\w+)", tables[target])
                joins.extend((hid, x.upper()) for x in targets)
        manifest.append({"path": str(path), "sha256": hashlib.sha256(data).hexdigest(), "profiles": len(socs), "communities": sum(len(x) for x in communities.values())})
    output.append("pub(super) static MATCHES: &[(&str, &Profile)] = &[")
    output.extend(f'    ("{hid}", &{target}),' for hid, target in joins)
    output.append("];\n")
    return "\n".join(output), manifest


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("reference", type=pathlib.Path)
    parser.add_argument("output", type=pathlib.Path)
    parser.add_argument("--manifest", type=pathlib.Path)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    result, inputs = generate(args.reference)
    if args.check:
        def tokens(value):
            # rustfmt may insert optional trailing commas in struct/array
            # literals; those and whitespace do not alter numeric table data.
            value = re.sub(r"\s+", "", value)
            return re.sub(r",([}\]])", r"\1", value)
        assert tokens(args.output.read_text()) == tokens(result), "generated Intel community tables differ"
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(result, newline="\n")
    if args.manifest:
        args.manifest.parent.mkdir(parents=True, exist_ok=True)
        args.manifest.write_text(json.dumps({"pin": PIN, "inputs": inputs, "output_sha256": hashlib.sha256(result.encode()).hexdigest()}, indent=2) + "\n")

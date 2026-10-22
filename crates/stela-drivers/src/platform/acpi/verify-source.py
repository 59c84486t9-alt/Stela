#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Verify the pinned, unchanged ACPICA inventory and authored fixture inputs."""
import hashlib
import json
from pathlib import Path

base = Path(__file__).resolve().parent
manifest = json.loads((base / "sources.json").read_text())
assert manifest["linux_commit"] == "a804c5742bff224d4cb4d25dd383554d598be32b"
assert manifest["acpica_version"] == "20260408"
allowed_adaptations = {
    "vendor/include/acpi/platform/acenv.h",
    "vendor/include/acpi/platform/acenvex.h",
}
seen = set()
for entry in manifest["files"]:
    relative = entry["vendor"]
    assert relative not in seen, relative
    seen.add(relative)
    path = (base / relative).resolve()
    assert path.is_relative_to(base), relative
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    assert digest == entry["adapted_sha256"], f"changed source: {relative}"
    if entry["sha256"] != entry["adapted_sha256"]:
        assert relative in allowed_adaptations, f"unexpected core adaptation: {relative}"
for entry in manifest["fixtures"]:
    assert hashlib.sha256((base / entry["path"]).read_bytes()).hexdigest() == entry["sha256"], entry["path"]
compiled = [p for p in (base / "vendor/core").glob("*.c") if not p.name.startswith("db") and p.name != "rsdump.c"]
assert len(compiled) == 162, len(compiled)
assert all(str(p.relative_to(base)) in seen for p in compiled)
print(f"Verified {len(seen)} pinned sources/licenses, {len(compiled)} interpreter units and {len(manifest['fixtures'])} authored fixture inputs")

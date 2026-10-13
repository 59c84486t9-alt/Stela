"""Preserve report snapshots by content hash before updating a convenient view."""
import hashlib
import json
import os
from pathlib import Path
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def retain_native_evidence(family, source, native, manifest, accounting, harness_source, *, root=ROOT):
    """Retain the exact inputs, emitted bytes, manifest and measured accounting."""
    if not isinstance(family, str) or not family or family in (".", "..") or any(
        character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-"
        for character in family
    ):
        raise ValueError("Evidence family must be one plain path component")
    files = {
        "source.arm64": source,
        "native.bin": native,
        "manifest.json": (json.dumps(manifest, sort_keys=True, indent=2) + "\n").encode(),
        "accounting.json": (json.dumps(accounting, sort_keys=True, indent=2) + "\n").encode(),
    }
    digest = hashlib.sha256(len(harness_source).to_bytes(8, "little"))
    digest.update(harness_source)
    for name, data in files.items():
        digest.update(name.encode())
        digest.update(len(data).to_bytes(8, "little"))
        digest.update(data)
    root = Path(root)
    directory = root / ".stela/native-evidence" / family / digest.hexdigest()
    directory.mkdir(parents=True, exist_ok=True)
    receipts = {}
    for name, data in files.items():
        path = directory / name
        try:
            with path.open("xb") as file:
                file.write(data)
        except FileExistsError:
            if path.read_bytes() != data:
                raise AssertionError(f"Immutable native evidence changed: {path}")
        receipts[name] = {"path": str(path.relative_to(root)), "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}
    return receipts


def write_evidence(destination, report):
    destination = Path(destination)
    destination.parent.mkdir(parents=True,exist_ok=True)
    history = ROOT / ".stela/evidence" / destination.stem
    history.mkdir(parents=True,exist_ok=True)
    data = (json.dumps(report,indent=2)+"\n").encode()
    snapshots = [data]
    if destination.exists():
        snapshots.append(destination.read_bytes())
    for snapshot in snapshots:
        archive = history / (hashlib.sha256(snapshot).hexdigest()+".json")
        try:
            with archive.open("xb") as file:
                file.write(snapshot)
        except FileExistsError:
            if archive.read_bytes() != snapshot:
                raise RuntimeError("Evidence archive content mismatch")
    with tempfile.NamedTemporaryFile(dir=destination.parent,delete=False) as temporary:
        temporary.write(data)
        temporary.flush()
        os.fsync(temporary.fileno())
        pending = temporary.name
    try:
        os.replace(pending,destination)
    finally:
        if os.path.exists(pending):
            os.unlink(pending)
    return history / (hashlib.sha256(data).hexdigest()+".json")

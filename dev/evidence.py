"""Preserve report snapshots by content hash before updating a convenient view."""
import hashlib
import json
import os
from pathlib import Path
import tempfile

ROOT = Path(__file__).resolve().parents[1]


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

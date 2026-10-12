#!/usr/bin/env python3
"""Install pinned Homebrew QEMU bottles locally, without root or Homebrew.

Uses Homebrew's public OCI registry and dependency metadata. Keeps upstream
licenses in the extracted bottles. Intended for this development sandbox;
normal Homebrew/package-manager installation is preferable when available.
"""
import hashlib
import json
import os
from pathlib import Path
import platform
import tarfile
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
PREFIX = ROOT / ".tools" / "qemu"
REGISTRY = "https://ghcr.io"
VERSION = "10.0.2"


def fetch(url, headers=None):
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers or {}), timeout=120) as response:
        return response.read()


def index(name, tag):
    repository = "homebrew/core/" + name.replace("@", "/")
    query = urllib.parse.urlencode({"service": "ghcr.io", "scope": f"repository:{repository}:pull"})
    token = json.loads(fetch(REGISTRY + "/token?" + query))["token"]
    headers = {"Authorization": "Bearer " + token, "Accept": "application/vnd.oci.image.manifest.v1+json, application/vnd.oci.image.index.v1+json"}
    data = json.loads(fetch(f"{REGISTRY}/v2/{repository}/manifests/{tag}", headers))
    arch = "arm64" if platform.machine() == "arm64" else "amd64"
    matches = [m for m in data["manifests"] if m["platform"]["os"] == "darwin" and m["platform"]["architecture"] == arch]
    # Sonoma bottles work on newer macOS, and are available for both CPU types.
    match = next((m for m in matches if m.get("annotations", {}).get("org.opencontainers.image.ref.name", "").endswith(".sonoma" if arch == "amd64" else ".arm64_sonoma")), None)
    if not match:
        match = next((m for m in data["manifests"] if m.get("annotations", {}).get("org.opencontainers.image.ref.name", "").endswith(".all")), None)
    if not match:
        raise RuntimeError(f"No macOS {arch} Sonoma bottle for {name} {tag}")
    manifest = json.loads(fetch(f"{REGISTRY}/v2/{repository}/manifests/{match['digest']}", headers))
    return repository, headers, match, manifest


def install(name, tag):
    repository, headers, match, manifest = index(name, tag)
    stamp = PREFIX / "receipts" / (name.replace("@", "-") + ".json")
    if stamp.exists() and json.loads(stamp.read_text())["manifest"] == match["digest"]:
        return match
    print(f"Installing {name} {tag}", flush=True)
    for layer in manifest["layers"]:
        digest = layer["digest"].removeprefix("sha256:")
        cache = PREFIX / "downloads" / (digest + ".tar.gz")
        cache.parent.mkdir(parents=True, exist_ok=True)
        if not cache.exists():
            data = fetch(f"{REGISTRY}/v2/{repository}/blobs/{layer['digest']}", headers)
            if hashlib.sha256(data).hexdigest() != digest:
                raise RuntimeError("Bottle checksum mismatch")
            cache.write_bytes(data)
        if hashlib.sha256(cache.read_bytes()).hexdigest() != digest:
            raise RuntimeError("Cached bottle checksum mismatch")
        with tarfile.open(cache) as archive:
            # data filter rejects traversal and unsafe links on Python 3.12+.
            archive.extractall(PREFIX / "Cellar", filter="data")
    stamp.parent.mkdir(parents=True, exist_ok=True)
    stamp.write_text(json.dumps({"manifest": match["digest"], "name": name, "tag": tag}, indent=2))
    return match


def main():
    if platform.system() != "Darwin":
        raise SystemExit("On Linux, install qemu-system-x86 with your package manager.")
    match = install("qemu", VERSION)
    dependencies = json.loads(match["annotations"]["sh.brew.tab"])["runtime_dependencies"]
    for dependency in dependencies:
        # Registry version tags already incorporate the formula revision.
        install(dependency["full_name"], dependency["pkg_version"])
    libraries = [str(p) for p in (PREFIX / "Cellar").glob("*/*/lib")]
    # DYLD_LIBRARY_PATH resolves original Homebrew install names by basename.
    # No global files or system dynamic-library paths are changed.
    bindir = PREFIX / "bin"
    bindir.mkdir(parents=True, exist_ok=True)
    import shlex
    qemu = PREFIX / "Cellar" / "qemu" / VERSION
    for executable in ("qemu-system-x86_64", "qemu-system-aarch64", "qemu-img"):
        script = bindir / executable
        extra = ["-L", str(qemu / "share/qemu")] if executable != "qemu-img" else []
        script.write_text("#!/bin/sh\nexport DYLD_LIBRARY_PATH=" + shlex.quote(":".join(libraries)) + "\nexec " + shlex.join([str(qemu / "bin" / executable), *extra]) + ' "$@"\n')
        script.chmod(0o755)
    print(f"Installed QEMU {VERSION} in {bindir}")


if __name__ == "__main__":
    main()

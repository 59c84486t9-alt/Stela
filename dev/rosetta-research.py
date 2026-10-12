#!/usr/bin/env python3
"""Acquire an exact-build Rosetta package from Apple and inspect it without installation."""
import argparse
import hashlib
import json
import plistlib
from pathlib import Path
import re
import struct
import subprocess
import tempfile
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
import zlib

from evidence import ROOT, write_evidence

CATALOG = "https://swscan.apple.com/content/catalogs/others/index-rosettaupdateauto-1.sucatalog"
HOSTS = {"swscan.apple.com", "swcdn.apple.com", "swdist.apple.com"}
LIMIT = 32 * 1024 * 1024


def apple_url(url):
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or parsed.hostname not in HOSTS or parsed.port not in (None, 443) or parsed.username is not None:
        raise ValueError("Expected an HTTPS Apple software-update URL")
    return url


def download(url, limit):
    with urllib.request.urlopen(apple_url(url), timeout=30) as response:
        apple_url(response.url)
        data = response.read(limit + 1)
    if len(data) > limit:
        raise ValueError("Apple response exceeds configured byte limit")
    return data


def verify_xar(data, catalog_digest):
    if not 28 <= len(data) <= LIMIT:
        raise ValueError("Invalid XAR size")
    magic, header, version, compressed, uncompressed, algorithm = struct.unpack_from(">4sHHQQI", data)
    if magic != b"xar!" or header != 28 or version != 1 or algorithm != 1 or uncompressed > LIMIT or compressed > len(data) - header:
        raise ValueError("Unsupported/truncated XAR header")
    toc_bytes = data[header:header + compressed]
    toc_sha1 = hashlib.sha1(toc_bytes).hexdigest()
    # Software Update's Digest binds the compressed XAR TOC, not the whole PKG.
    if toc_sha1 != catalog_digest:
        raise ValueError("Catalog XAR TOC digest mismatch")
    decoder = zlib.decompressobj()
    xml = decoder.decompress(toc_bytes, uncompressed + 1)
    if len(xml) != uncompressed or not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
        raise ValueError("XAR TOC decompression/length mismatch")
    toc = ET.fromstring(xml)
    heap = data[header + compressed:]
    def span(offset, size):
        if offset < 0 or size < 0 or offset + size > len(heap):
            raise ValueError("XAR heap range exceeds package")
        return heap[offset:offset + size]
    checksum = toc.find("./toc/checksum")
    if checksum is None or checksum.get("style") != "sha1":
        raise ValueError("Unsupported XAR TOC checksum")
    stored = span(int(checksum.findtext("offset")), int(checksum.findtext("size")))
    if stored.hex() != toc_sha1:
        raise ValueError("Stored XAR TOC checksum mismatch")
    checked = 0
    for item in toc.findall(".//file/data"):
        checksum = item.find("archived-checksum")
        if checksum is None or checksum.get("style") not in ("sha1", "sha256"):
            raise ValueError("Missing/unsupported XAR archived checksum")
        payload = span(int(item.findtext("offset")), int(item.findtext("length")))
        if hashlib.new(checksum.get("style"), payload).hexdigest() != checksum.text:
            raise ValueError("XAR archived payload checksum mismatch")
        checked += 1
    if not checked:
        raise ValueError("XAR contains no checked payloads")
    return {"catalog_digest_kind": "SHA-1 of compressed XAR TOC", "catalog_digest_verified": True, "checked_archive_members": checked}


def fetch(args):
    if not re.fullmatch(r"[A-Za-z0-9._-]+", args.build):
        raise ValueError("Invalid build identifier")
    catalog_bytes = args.catalog.read_bytes() if args.catalog else download(CATALOG, 16 * 1024 * 1024)
    if len(catalog_bytes) > 16 * 1024 * 1024:
        raise ValueError("Catalog exceeds limit")
    catalog = plistlib.loads(catalog_bytes)
    matches = [(key, row) for key, row in catalog["Products"].items() if row.get("ExtendedMetaInfo", {}).get("BuildVersion") == args.build]
    if len(matches) != 1 or len(matches[0][1]["Packages"]) != 1:
        raise ValueError("Expected exactly one package for the requested build")
    product, row = matches[0]
    package = row["Packages"][0]
    size = package["Size"]
    if not 0 < size <= LIMIT:
        raise ValueError("Package exceeds research download limit")
    directory = args.output_root / args.build
    path = directory / "RosettaUpdateAuto.pkg"
    data = path.read_bytes() if path.exists() else download(package["URL"], size)
    if len(data) != size:
        raise ValueError("Package size differs from catalog")
    validation = verify_xar(data, package["Digest"])
    directory.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        with path.open("xb") as output:
            output.write(data)
    signature = subprocess.check_output(["pkgutil", "--check-signature", str(path)], text=True, timeout=30)
    if "Status: signed Apple Software" not in signature:
        raise ValueError("Package does not report a trusted Apple Software signature")
    receipt = {"kind": "apple_rosetta_package", "build": args.build, "product": product, "catalog_url": CATALOG,
               "catalog_sha256": hashlib.sha256(catalog_bytes).hexdigest(), "catalog_index_date_utc": str(catalog.get("IndexDate")),
               "url": apple_url(package["URL"]), "bytes": len(data), "whole_file_sha256": hashlib.sha256(data).hexdigest(),
               "whole_file_sha1": hashlib.sha1(data).hexdigest(), "catalog_digest": package["Digest"], **validation,
               "package_signature_verified": True, "signature_observation": signature, "installed": False}
    write_evidence(directory / "package-receipt.json", receipt)
    if args.expand:
        destination = directory / "expanded-verified"
        if destination.exists():
            raise ValueError("Expanded destination exists; preserve it and use a fresh output root")
        with tempfile.TemporaryDirectory(prefix=".expand-", dir=directory) as temporary:
            staged = Path(temporary) / "expanded"
            subprocess.run(["pkgutil", "--expand-full", str(path), str(staged)], check=True, timeout=60)
            staged.rename(destination)
        print(json.dumps({"package": str(path), "expanded": str(destination), **validation, "signature_verified": True, "installed": False}, indent=2))
    else:
        print(json.dumps(receipt, indent=2))


def function_starts(data):
    if data[:4] != b"\xcf\xfa\xed\xfe" or len(data) < 32:
        raise ValueError("Expected thin little-endian Mach-O 64")
    count, command_bytes = struct.unpack_from("<II", data, 16)
    at, text_base, stream = 32, None, None
    end = at + command_bytes
    if end > len(data):
        raise ValueError("Mach-O load commands exceed input")
    for _ in range(count):
        if at + 8 > end:
            raise ValueError("Truncated load command")
        command, size = struct.unpack_from("<II", data, at)
        if size < 8 or at + size > end:
            raise ValueError("Invalid load-command extent")
        if command == 0x19 and size >= 72 and data[at + 8:at + 24].rstrip(b"\0") == b"__TEXT":
            text_base = struct.unpack_from("<Q", data, at + 24)[0]
        if command == 0x26 and size >= 16:
            offset, length = struct.unpack_from("<II", data, at + 8)
            if offset + length > len(data):
                raise ValueError("Function-start stream exceeds input")
            stream = data[offset:offset + length]
        at += size
    if at != end or text_base is None:
        raise ValueError("Inconsistent Mach-O load-command metadata")
    if stream is None:
        return None
    from importlib.util import spec_from_file_location, module_from_spec
    spec = spec_from_file_location("rosetta_leaf_metadata", ROOT / "dev/kernel-leaves.py")
    helper = module_from_spec(spec)
    spec.loader.exec_module(helper)
    return helper.starts(stream, text_base)


def inspect(args):
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
    subprocess.run([str(ROOT / "dev/cargo"), "build", "--locked", "-p", "stela-cli"], check=True)
    cli = ROOT / "target/debug/stela"
    rows, links = [], []
    decoder = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    for path in sorted(args.expanded.rglob("*")):
        if path.is_symlink():
            links.append({"path": str(path.relative_to(args.expanded)), "target": str(path.readlink()), "followed": False})
            continue
        if not path.is_file() or path.stat().st_size > LIMIT:
            continue
        data = path.read_bytes()
        if data[:4] != b"\xcf\xfa\xed\xfe":
            continue
        exported = json.loads(subprocess.check_output([str(cli), "binary-text", str(path)]))[0]["slice"]
        starts = function_starts(data)
        sections = [(s["guest_address"], bytes.fromhex(s["data_hex"])) for s in exported["sections"]]
        exports = []
        for name, address in exported["defined_text_symbols"].items():
            if "rosetta14librosetta_aot" not in name:
                continue
            section = next(((base, code) for base, code in sections if base <= address < base + len(code)), None)
            if section is None or starts is None or address not in starts:
                raise ValueError("Export not at a validated text function start")
            base, text = section
            end = min(next((value for value in starts if value > address), base + len(text)), base + len(text))
            code = text[address - base:end - base]
            decoded = list(decoder.disasm_lite(code, address))
            if sum(i[1] for i in decoded) != len(code):
                raise ValueError("Incomplete ARM function disassembly")
            exports.append({"name": name, "guest_address": address, "bytes": len(code), "source_sha256": hashlib.sha256(code).hexdigest(),
                            "instructions": len(decoded), "direct_call_targets": [op for _, _, mnemonic, op in decoded if mnemonic == "bl"],
                            "assembly_sample": [[pc, mnemonic, operands] for pc, _, mnemonic, operands in decoded[:40]]})
        strings = [value.decode("ascii") for value in re.findall(rb"[ -~]{5,}", data)]
        diagnostics = [s for s in strings if re.search(r"compute_flag_liveness|flags liveout|translate_block|translate_instruction|JIT compilation|fixups|single_step|ROSETTA_", s)]
        rows.append({"path": str(path.relative_to(args.expanded)), "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(),
                     "architecture": exported["artifact"]["architecture"], "function_starts": len(starts) if starts is not None else None,
                     "exported_aot_functions": sorted(exports, key=lambda item: item["guest_address"]), "diagnostic_strings": diagnostics[:80]})
    report = {"kind": "static_rosetta_binary_inspection", "static_only": True, "binaries": rows, "symlinks": links,
              "inspector_source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "limits": "Symbols, decoded instructions and diagnostic strings establish observed interfaces, not complete algorithms or runtime behavior. Absolute payload symlinks are recorded without following them into the host OS. No installer scripts or Rosetta executables are run."}
    write_evidence(args.output, report)
    print(json.dumps({"report": str(args.output), "regular_binaries": len(rows), "symlinks_not_followed": len(links),
                      "aot_exports": sum(len(row["exported_aot_functions"]) for row in rows)}, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    acquire = sub.add_parser("fetch")
    acquire.add_argument("--build", required=True)
    acquire.add_argument("--catalog", type=Path)
    acquire.add_argument("--output-root", type=Path, default=ROOT / ".stela/rosetta")
    acquire.add_argument("--expand", action="store_true")
    analyze = sub.add_parser("inspect")
    analyze.add_argument("expanded", type=Path)
    analyze.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    fetch(args) if args.command == "fetch" else inspect(args)


if __name__ == "__main__":
    main()

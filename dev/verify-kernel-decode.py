#!/usr/bin/env python3
"""Compare Rust-decoded kernel bytes with Apple's native LZFSE implementation.

macOS-only development oracle. The production decoder is portable Rust.
"""
import argparse
import ctypes
import hashlib
import json
from pathlib import Path
import platform

from evidence import write_evidence


def element(data, offset):
    if offset+2 > len(data):
        raise ValueError("Truncated ASN.1")
    tag, length = data[offset:offset+2]
    start = offset+2
    if length & 128:
        width = length & 127
        if not 0 < width <= 8 or start+width > len(data):
            raise ValueError("Invalid ASN.1 length")
        length = int.from_bytes(data[start:start+width],"big")
        start += width
    end = start+length
    if end > len(data):
        raise ValueError("ASN.1 range exceeds input")
    return tag,start,end


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("container",type=Path)
    parser.add_argument("decoded",type=Path)
    parser.add_argument("--output",type=Path,required=True)
    args = parser.parse_args()
    if platform.system() != "Darwin":
        raise SystemExit("Apple Compression oracle requires macOS.")
    source = args.container.read_bytes()
    tag,start,end = element(source,0)
    if tag != 0x30 or end != len(source):
        raise ValueError("Expected one IM4P sequence")
    fields = []
    while start < end:
        tag,value,next_offset = element(source,start)
        fields.append((tag,source[value:next_offset]))
        start = next_offset
    if [tag for tag,_ in fields[:4]] != [0x16,0x16,0x16,0x04] or fields[0][1] != b"IM4P":
        raise ValueError("Unexpected IM4P schema")
    payload = fields[3][1]
    receipt = json.loads(Path(str(args.decoded)+".json").read_text())
    expected_size = receipt["declared_uncompressed_bytes"]
    if not isinstance(expected_size,int) or not 0 < expected_size <= 1024*1024*1024:
        raise ValueError("Expected a bounded declared uncompressed size")
    library = ctypes.CDLL("/usr/lib/libcompression.dylib")
    decode = library.compression_decode_buffer
    decode.argtypes = [ctypes.c_void_p,ctypes.c_size_t,ctypes.c_void_p,ctypes.c_size_t,ctypes.c_void_p,ctypes.c_int]
    decode.restype = ctypes.c_size_t
    output = ctypes.create_string_buffer(expected_size)
    input_buffer = ctypes.create_string_buffer(payload)
    size = decode(output,expected_size,input_buffer,len(payload),None,0x801)
    if size != expected_size:
        raise AssertionError(f"Apple decoder produced {size}, expected {expected_size}")
    apple_hash = hashlib.sha256(output.raw[:size]).hexdigest()
    decoded_hash = hashlib.sha256(args.decoded.read_bytes()).hexdigest()
    if apple_hash != decoded_hash or decoded_hash != receipt["decoded_sha256"]:
        raise AssertionError("Independent decompression result mismatch")
    report = {"kind":"kernel_decompression_comparison","passed":True,
              "oracle":"Apple libcompression COMPRESSION_LZFSE",
              "container_sha256":hashlib.sha256(source).hexdigest(),
              "decoded_bytes":size,"decoded_sha256":decoded_hash,
              "limits":"Byte-for-byte decompression identity only; no signature, translation, or boot verification."}
    write_evidence(args.output,report)
    print(json.dumps(report,indent=2))


if __name__ == "__main__":
    main()

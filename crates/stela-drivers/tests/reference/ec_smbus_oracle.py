#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2007 Alexey Starikovskiy
"""Compile exact pinned sbshc helpers against an independent EC peripheral.

Kernel scheduling/EC byte I/O are the only substituted services. Source function
bodies stay unchanged. The trace records source limitations rather than treating
zero-byte block32, PEC reads or missing Process Call responses as correct.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

PIN = "a804c5742bff224d4cb4d25dd383554d598be32b"
HASHES = {
    "drivers/acpi/sbshc.c": "f8ca1fee508e3eb560a7c7c0e83d384ae0ea058a33ea6e582a36bd861f057d5b",
    "drivers/acpi/sbshc.h": "9ea00ff497586a62ae3f61c8f821cce9e140971b3550235d3404e93ed775f086",
}


def declaration(source, marker, semicolon=False):
    start = source.index(marker)
    opened = source.index("{", start)
    depth = 1
    end = opened + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end] + (";" if semicolon else "")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--linux", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--cc", default="clang")
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    sources = {}
    for name, digest in HASHES.items():
        raw = subprocess.check_output(["git", "-C", str(args.linux.resolve()), "show", f"{PIN}:{name}"])
        if hashlib.sha256(raw).hexdigest() != digest:
            raise SystemExit(f"source integrity mismatch: {name}")
        (args.out / Path(name).name).write_bytes(raw)
        sources[name] = raw.decode()
    source = sources["drivers/acpi/sbshc.c"]
    bodies = [declaration(source, marker, marker.startswith(("struct ", "enum "))) for marker in [
        "struct acpi_smb_hc {", "enum acpi_smb_offset {",
        "static inline int smb_hc_read(", "static inline int smb_hc_write(",
        "static int wait_transaction_complete(", "static int acpi_smbus_transaction(",
    ]]
    prefix = r'''
// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2007 Alexey Starikovskiy
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
typedef uint8_t u8;
struct acpi_ec { unsigned unused; };
struct mutex { unsigned unused; };
typedef struct { unsigned unused; } wait_queue_head_t;
typedef void (*smbus_alarm_callback)(void *);
static u8 registers[256], published[256];
static unsigned waits;
static u8 read_count;
static int ec_read(u8 address, u8 *data) { *data=registers[address]; return 0; }
static int ec_write(u8 address, u8 data) {
    registers[address]=data;
    if(address==64) memcpy(published,registers,sizeof registers);
    return 0;
}
static int peripheral_complete(void) {
    ++waits;
    registers[65]=128;
    registers[64]=0;
    registers[100]=read_count;
    for(unsigned n=0;n<32;++n) registers[68+n]=(u8)(0xa0+n);
    return 1;
}
#define mutex_lock(x) ((void)(x))
#define mutex_unlock(x) ((void)(x))
#define pr_err(...) ((void)0)
#define wait_event_timeout(wait,condition,timeout) peripheral_complete()
'''
    protocol_enum = declaration(sources["drivers/acpi/sbshc.h"], "enum acpi_smb_protocol {", True)
    suffix = r'''
int main(void) {
    const u8 protocols[]={4,5,6,7,8,9,10,11,12,0x85,0x87,0x89,0x8b};
    for(unsigned p=0;p<sizeof protocols;++p) for(unsigned count=1;count<=33;++count) {
        u8 protocol=protocols[p];
        if(protocol==10 && count>32) continue;
        memset(registers,0,sizeof registers); memset(published,0,sizeof published);
        struct acpi_smb_hc host={.offset=64};
        u8 data[32]; memset(data,0xcc,sizeof data);
        const u8 length=protocol==10?count:protocol==6?1:(protocol==8||protocol==12)?2:0;
        for(unsigned n=0;n<length;++n) data[n]=(u8)(0x31+n);
        read_count=count; waits=0;
        int result=acpi_smbus_transaction(&host,protocol,11,0x37,data,length);
        if(result || waits!=1 || published[64]!=protocol || published[66]!=22) return 1;
        printf("%u,%u,%u,%u,",protocol,count,published[66],published[67]);
        for(unsigned n=0;n<32;++n) printf("%02x",data[n]);
        putchar(',');
        for(unsigned n=0;n<32;++n) printf("%02x",published[68+n]);
        putchar('\n');
    }
    return 0;
}
'''
    harness = prefix + protocol_enum + "\n" + "\n".join(bodies) + suffix
    (args.out / "oracle.c").write_text(harness)
    command = [args.cc, "-std=gnu11", "-O1", "-g", "-fsanitize=address,undefined", "-fno-sanitize-recover=all", str(args.out / "oracle.c"), "-o", str(args.out / "oracle")]
    (args.out / "compiler-command.json").write_text(json.dumps(command) + "\n")
    compiled = subprocess.run(command, capture_output=True)
    (args.out / "compiler-stdout.txt").write_bytes(compiled.stdout)
    (args.out / "compiler-stderr.txt").write_bytes(compiled.stderr)
    compiled.check_returncode()
    run = subprocess.run([str((args.out / "oracle").resolve())], capture_output=True)
    (args.out / "trace.csv").write_bytes(run.stdout)
    (args.out / "stderr.txt").write_bytes(run.stderr)
    run.check_returncode()
    receipt = {"pin": PIN, "sources": HASHES, "extracted_functions": {
        marker: hashlib.sha256(body.encode()).hexdigest()
        for marker, body in zip(["struct", "offset", "read", "write", "wait", "transaction"], bodies)
    }, "cases": len(run.stdout.splitlines()), "trace_sha256": hashlib.sha256(run.stdout).hexdigest(), "compiler_command": command,
        "oracle_limits": ["Linux masks read block count with 0x1f, including raw32 -> zero bytes", "Linux does not decode PEC-tagged read lengths", "Linux Process Call path does not copy returned word", "Kernel scheduler/EC byte services replaced; success-path protocol oracle, not physical qualification"]}
    (args.out / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps(receipt, indent=2))


if __name__ == "__main__":
    main()

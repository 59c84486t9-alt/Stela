#!/usr/bin/env python3
"""Profile instruction sections in an identified, collection-relative fileset.

This measures source instructions and platform dependencies, not compilation.
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from evidence import write_evidence

PLATFORM = {"mrs","msr","sys","sysl","dc","ic","tlbi","dsb","dmb","isb","eret","eretaa","eretab","wfi","wfe","sev","sevl","svc","hvc","smc","brk"}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("collection",type=Path)
    parser.add_argument("manifest",type=Path)
    parser.add_argument("--output",type=Path,required=True)
    args=parser.parse_args()
    data=args.collection.read_bytes()
    manifest=json.loads(args.manifest.read_text())
    source_hash=hashlib.sha256(data).hexdigest()
    if source_hash != manifest["container_sha256"] or len(data) != manifest["container_bytes"]:
        raise ValueError("Collection differs from fileset manifest")
    combined=Counter()
    rows=[]
    total_invalid=0
    decoder=Cs(CS_ARCH_ARM64,CS_MODE_ARM)
    decoder.skipdata=True
    for image in manifest["images"]:
        if image["cpu_type"] != 0x0100000c:
            raise ValueError("Kernel corpus currently requires ARM64 images")
        counts=Counter()
        invalid=0
        for section in image["sections"]:
            if not section["instructions"] or section["zero_fill"]:
                continue
            offset,size=section["file_offset"],section["bytes"]
            if offset < 0 or size < 0 or offset+size > len(data):
                raise ValueError("Section exceeds collection")
            code=data[offset:offset+size]
            if hashlib.sha256(code).hexdigest() != section["sha256"]:
                raise ValueError("Section identity mismatch")
            for _,length,mnemonic,_ in decoder.disasm_lite(code,section["vm_address"]):
                if mnemonic.startswith("."):
                    invalid+=length
                else:
                    counts[mnemonic]+=1
        combined.update(counts)
        total_invalid+=invalid
        rows.append({"id":image["id"],"linear_instructions":sum(counts.values()),"invalid_or_data_bytes":invalid,
                     "platform_sensitive":{name:count for name,count in counts.items() if name in PLATFORM},
                     "pointer_authentication":{name:count for name,count in counts.items() if name.startswith(("pac","aut","braa","brab","blraa","blrab","retaa","retab"))},
                     "top_mnemonics":dict(counts.most_common(24)),"symbol_count":image["symbol_count"]})
    report={"schema_version":1,"kind":"arm64_kernel_collection_corpus","container_sha256":source_hash,
            "fileset_manifest_sha256":hashlib.sha256(args.manifest.read_bytes()).hexdigest(),
            "image_count":len(rows),"linear_instructions":sum(combined.values()),"invalid_or_data_bytes":total_invalid,
            "unique_executable_file_bytes":manifest["unique_executable_file_bytes"],"images":rows,
            "mnemonics":dict(combined.most_common()),
            "limits":"Linear disassembly can include unreachable code/data. Counts are not semantic translation coverage. Some platform-sensitive instructions are also legal in userspace; this grouping marks adaptation requirements, not privilege level."}
    write_evidence(args.output,report)
    print(json.dumps({"report":str(args.output),"images":len(rows),"linear_instructions":report["linear_instructions"],
                      "invalid_or_data_bytes":total_invalid,"top_mnemonics":combined.most_common(16),
                      "platform_sensitive":{name:count for name,count in combined.items() if name in PLATFORM}},indent=2))


if __name__ == "__main__":
    main()

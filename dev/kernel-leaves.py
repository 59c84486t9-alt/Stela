#!/usr/bin/env python3
"""Compile and compare bounded integer-only leaves from the real ARM kernel.

Function starts and symbols come from the validated fileset manifest. The
current subset cannot access guest memory or system registers. Unsupported
functions are retained as declines, never patched into successful stubs.
"""
import argparse
from collections import Counter,defaultdict
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import tempfile

from capstone import Cs,CS_ARCH_ARM64,CS_MODE_ARM
from differential import ROOT,State,reference,states,bounded_native
from evidence import write_evidence

ALLOWED={"mov","movz","movn","movk","add","adds","sub","subs","cmp","cmn","and","ands","bic","bics","orr","orn","eor","eon","tst","nop","ret","b","cbz","cbnz","tbz","tbnz",
         "csel","csinc","csinv","csneg","cinc","cinv","cneg","cset","csetm",
         "madd","msub","mul","mneg","smaddl","smsubl","smull","smnegl",
         "umaddl","umsubl","umull","umnegl","smulh","umulh"}


def equal_register_pair(value):
    """Parse two distinct real X registers; SP and XZR are not state slots."""
    names=value.split(",")
    if len(names)!=2 or any(re.fullmatch(r"x(?:[0-9]|[12][0-9]|30)",name,re.IGNORECASE) is None for name in names):
        raise argparse.ArgumentTypeError("Expected two registers X0..X30 separated by one comma, e.g. X0,X1")
    pair=tuple(int(name[1:]) for name in names)
    if pair[0]==pair[1]:
        raise argparse.ArgumentTypeError("Equality inputs need two distinct registers")
    return pair


def input_states(equal_registers=None):
    initial=states(all_flags=True)
    if equal_registers is not None:
        left,right=equal_registers
        matched=[]
        for original in initial:
            state=State.from_buffer_copy(original)
            state.x[right]=state.x[left]
            matched.append(state)
        initial+=matched
    return initial


def starts(data,base):
    result=[]
    at=0
    address=base
    while at<len(data):
        value=0
        shift=0
        while True:
            if at>=len(data) or shift>=64:
                raise ValueError("Malformed function-start ULEB128")
            byte=data[at];at+=1
            value|=(byte&127)<<shift
            if not byte&128:
                break
            shift+=7
        if value==0:
            if any(data[at:]):
                raise ValueError("Nonzero function-start padding")
            return result
        address+=value
        if address>(1<<64)-1:
            raise ValueError("Function address overflow")
        result.append(address)
    raise ValueError("Missing function-start terminator")


def candidates(data,image,allowed=ALLOWED):
    symbol_names=defaultdict(list)
    string_offset=image["string_table_file_offset"]
    string_size=image["string_table_bytes"]
    strings=data[string_offset:string_offset+string_size]
    for index in range(image["symbol_count"]):
        name,kind,_,_,address=struct.unpack_from("<IBBHQ",data,image["symbol_table_file_offset"]+index*16)
        if kind&0xe0 or kind&0xe!=0xe:
            continue
        end=strings.find(b"\0",name)
        if name>=len(strings) or end<0:
            raise ValueError("Symbol name exceeds string table")
        if end>name:
            symbol_names[address].append(strings[name:end].decode())
    text=next(s for s in image["segments"] if s["name"]=="__TEXT")
    offset=image["function_starts_file_offset"]
    length=image["function_starts_bytes"]
    addresses=starts(data[offset:offset+length],text["vm_address"])
    decoder=Cs(CS_ARCH_ARM64,CS_MODE_ARM)
    rows=[]
    for index,address in enumerate(addresses):
        if address not in symbol_names:
            continue
        section=next((s for s in image["sections"] if s["instructions"] and not s["zero_fill"] and s["vm_address"]<=address<s["vm_address"]+s["bytes"]),None)
        if section is None:
            continue
        end=section["vm_address"]+section["bytes"]
        if index+1<len(addresses):
            end=min(end,addresses[index+1])
        size=end-address
        if not 0<size<=256 or size%4:
            continue
        file_offset=section["file_offset"]+address-section["vm_address"]
        code=data[file_offset:file_offset+size]
        words=struct.unpack("<"+"I"*(len(code)//4),code)
        returns=[i for i,w in enumerate(words) if w==0xd65f03c0]
        if not returns:
            continue
        # All control flow must remain inside this prefix or the compiler will
        # reject it. No caller-dependent indirect returns/calls are accepted.
        code=code[:(returns[-1]+1)*4]
        decoded=list(decoder.disasm_lite(code,address))
        if sum(i[1] for i in decoded)!=len(code):
            continue
        if any(i[2] not in allowed and not i[2].startswith("b.") for i in decoded):
            continue
        rows.append({"names":symbol_names[address],"address":address,"file_offset":file_offset,"function_extent_bytes":size,"source_bytes":len(code),"code":code})
    return addresses,rows


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("collection",type=Path)
    parser.add_argument("manifest",type=Path)
    parser.add_argument("--output",type=Path,required=True)
    parser.add_argument("--max-functions",type=int,default=64)
    parser.add_argument("--symbol",action="append",default=[],help="Select an exact symbol name; repeat for multiple symbols")
    parser.add_argument("--equal-registers",type=equal_register_pair,help="Add copies of every input state with the second register equal to the first, e.g. X0,X1")
    args=parser.parse_args()
    if args.max_functions<=0:
        raise ValueError("--max-functions must be positive")
    data=args.collection.read_bytes()
    manifest=json.loads(args.manifest.read_text())
    if hashlib.sha256(data).hexdigest()!=manifest["container_sha256"]:
        raise ValueError("Collection identity mismatch")
    image=next(i for i in manifest["images"] if i["id"]=="com.apple.kernel")
    addresses,eligible=candidates(data,image)
    if args.symbol:
        requested=set(args.symbol)
        available={name for entry in eligible for name in entry["names"]}
        missing=requested-available
        if missing:
            parser.error("No eligible bounded integer leaf for exact symbol(s): "+", ".join(sorted(missing)))
        eligible=[entry for entry in eligible if requested.intersection(entry["names"])]
    subprocess.run([str(ROOT/"dev/cargo"),"build","--locked","-p","stela-cli"],check=True)
    cli=ROOT/"target/debug/stela"
    verified=[];declined=[]
    initial_states=input_states(args.equal_registers)
    with tempfile.TemporaryDirectory(prefix="stela-kernel-leaves-") as temporary:
        source=Path(temporary)/"leaf.arm64"
        for entry in eligible[:args.max_functions]:
            code=entry.pop("code")
            entry["source_sha256"]=hashlib.sha256(code).hexdigest()
            source.write_bytes(code)
            process=subprocess.run([str(cli),"prepare-leaf",str(source),"--guest-base",hex(entry["address"])],capture_output=True,text=True)
            if process.returncode:
                declined.append({**entry,"reason":process.stderr.strip()});continue
            prepared=json.loads(process.stdout)
            try:
                expected=[reference(code,state) for state in initial_states]
            except Exception as error:
                declined.append({**entry,"reason":"ARM reference did not complete: "+str(error)});continue
            native_path=Path(prepared["directory"])/"native.bin"
            actual=bounded_native(native_path.read_bytes(),initial_states)
            if expected!=actual:
                raise AssertionError(f"Native/ARM mismatch for {entry['names']}")
            verified.append({**entry,"cache_key":prepared["key"],"native_artifact":str(native_path),
                             "native_sha256":prepared["manifest"]["native_sha256"],"compiler_source_sha256":prepared["manifest"]["identity"]["compiler_source_sha256"],
                             "state_comparisons":len(initial_states),"passed":True})
    report={"kind":"real_kernel_integer_leafs","container_sha256":manifest["container_sha256"],
            "kernel_function_starts":len(addresses),"filtered_candidates":len(eligible),"attempted":min(len(eligible),args.max_functions),
            "verified":verified,"declined":declined,"deferred_candidates":max(0,len(eligible)-args.max_functions),
            "state_comparisons":sum(v["state_comparisons"] for v in verified),
            "limits":"Only bounded integer-only named leaf prefixes with internal direct branches are considered. Guest memory, PAC, system registers, kernel ABI, faults, and full kernel boot are not tested."}
    if args.symbol:
        report["selected_exact_symbols"]=sorted(set(args.symbol))
    if args.equal_registers is not None:
        report["additional_equal_register_inputs"]={"copied_from":f"X{args.equal_registers[0]}","copied_to":f"X{args.equal_registers[1]}","extra_states":len(initial_states)//2}
    write_evidence(args.output,report)
    print(json.dumps({"report":str(args.output),"function_starts":len(addresses),"filtered_candidates":len(eligible),
                      "verified":len(verified),"declined":len(declined),"state_comparisons":report["state_comparisons"],
                      "verified_sizes":dict(Counter(r["source_bytes"] for r in verified)),
                      "verified_name_sample":[r["names"] for r in verified[:12]]},indent=2))


if __name__=="__main__":
    main()

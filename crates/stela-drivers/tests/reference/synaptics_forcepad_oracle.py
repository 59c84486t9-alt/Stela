#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Unchanged ForcePad temporal parse branch with an explicit microsecond clock.

This models jiffies in microseconds to compare the source's strict50ms rule;
it does not qualify any Linux HZ setting, physical firmware or native PnP owner.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

helper = Path(__file__).with_name("synaptics_absolute_oracle.py")
spec = importlib.util.spec_from_file_location("absolute", helper)
absolute = importlib.util.module_from_spec(spec)
spec.loader.exec_module(absolute)

MAIN = r'''
int main(void) {
    for(unsigned group=0;group<256;++group) {
        struct synaptics_data data={0};
        data.is_forcepad=true;data.info.model_id=0x80;
        data.info.capabilities=BIT(23)|BIT(18)|3;
        data.info.ext_cap_0c=(group&1)?BIT(20):0;
        jiffies=(group&2)?~0UL-100000:1000000;
        static const unsigned delta[]={0,50000,1,1000,1000,1000,1000,1000,49999,1,1};
        for(unsigned n=0;n<32;++n) {
            unsigned z=50,w=5,above=1;
            if(n<11) {
                jiffies+=delta[n];
                if(n==3)w=0;
                if(n==4)z=0;
                if(n==6)w=1;
            } else {
                static const unsigned delays[]={0,49999,50000,50001};
                jiffies+=delays[(group+n)&3];
                w=(group+n)&15;z=((group+n)%7)?(group+n)&255:0;above=(group+n)&1;
            }
            u8 right=(group>>2)&1;
            u8 packet[]={0x80|((w&12)<<2)|((w&2)<<1)|(right<<1),0x97,z,
                0xc0|((w&1)<<2)|above,0xd0,0xc4};
            struct synaptics_hw_state hw;
            assert(synaptics_parse_hw_state(packet,&data,&hw)==0);
            assert(hw.middle==0&&hw.scroll==0);
            printf("%u %u %lu ",group,group&1,jiffies);
            for(unsigned i=0;i<6;++i)printf("%02x",packet[i]);
            printf(" %u\n",hw.left|(hw.right<<1));
        }
    }
    return 0;
}
'''


def main():
    root, output = map(Path, sys.argv[1:])
    output.mkdir(parents=True, exist_ok=False)
    mouse = root / "drivers/input/mouse"
    for name, expected in absolute.HASHES.items():
        assert hashlib.sha256((mouse/name).read_bytes()).hexdigest() == expected
    source = (mouse/"synaptics.c").read_text()
    bodies = {name: absolute.function(source, name) for name in absolute.NAMES}
    prefix = absolute.PREFIX.replace("SYNAPTICS_HEADER", str((mouse/"synaptics.h").resolve()))
    prefix = prefix.replace("#define msecs_to_jiffies(n) (n)", "#define msecs_to_jiffies(n) ((n)*1000UL)")
    c = output/"oracle.c"
    c.write_text(prefix+"\n".join(bodies.values())+MAIN)
    binary = output/"oracle"
    subprocess.run(["clang", "-std=gnu11", "-O1", "-g", "-fsanitize=address,undefined",
                    "-fno-sanitize-recover=all", str(c), "-o", str(binary)], check=True, timeout=60)
    result = subprocess.run([str(binary.resolve())], capture_output=True, text=True, check=True, timeout=60)
    (output/"records.txt").write_text(result.stdout)
    (output/"manifest.json").write_text(json.dumps({
        "pin": absolute.PIN, "sources": absolute.HASHES,
        "helper_sha256": hashlib.sha256(helper.read_bytes()).hexdigest(),
        "unchanged_functions": {name: hashlib.sha256(body.encode()).hexdigest() for name, body in bodies.items()},
        "records": len(result.stdout.splitlines()), "oracle_limit": [
            "Original parser's ForcePad branch executes sequentially,256 independent devices32packets each, including strict threshold and unsigned clock wrap.",
            "Modeled jiffies use microseconds; no Linux HZ/scheduler equivalence or physical timing is claimed.",
            "Native actual i8042 tests separately cover PnP profile admission, configuration, interleaved records, explicit release and restart.",
        ]}, indent=2)+"\n")
    print(len(result.stdout.splitlines()), "original ForcePad temporal records")


if __name__ == "__main__":
    main()

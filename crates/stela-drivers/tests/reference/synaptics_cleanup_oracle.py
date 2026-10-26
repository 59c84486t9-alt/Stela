#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Unchanged Synaptics firmware-relative cleanup command; native stop separate."""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

helper=Path(__file__).with_name("synaptics_passthrough_oracle.py")
spec=importlib.util.spec_from_file_location("passthrough",helper)
pt=importlib.util.module_from_spec(spec)
spec.loader.exec_module(pt)
MAIN=r'''
int main(void){
    static const u8 modes[]={0x84,0xc4,0x85,0xc5,0x87,0xc7};
    for(unsigned i=0;i<sizeof(modes);++i){
        struct synaptics_data data={0};data.mode=modes[i];
        struct psmouse mouse={0};mouse.private=&data;txlen=0;
        synaptics_reset(&mouse);assert(!locked);
        printf("%u ",modes[i]);for(unsigned n=0;n<txlen;++n)printf("%02x",tx[n]);printf("\n");
    }
    return 0;
}
'''


def main():
    root,output=map(Path,sys.argv[1:]);output.mkdir(parents=True,exist_ok=False)
    mouse=root/"drivers/input/mouse"
    for name,expected in pt.absolute.HASHES.items():assert hashlib.sha256((mouse/name).read_bytes()).hexdigest()==expected
    lib=(root/"drivers/input/serio/libps2.c").read_bytes();assert hashlib.sha256(lib).hexdigest()==pt.LIB_SHA
    source=(mouse/"synaptics.c").read_text()
    bodies={"ps2_sliced_command":pt.exported(lib.decode(),"int ps2_sliced_command("),
            "synaptics_mode_cmd":pt.absolute.function(source,"synaptics_mode_cmd"),
            "synaptics_reset":pt.exported(source,"void synaptics_reset(")}
    c=output/"oracle.c";c.write_text(pt.PREFIX.replace("SYNAPTICS_HEADER",str((mouse/"synaptics.h").resolve()))+"\n".join(bodies.values())+MAIN)
    binary=output/"oracle"
    subprocess.run(["clang","-std=gnu11","-O1","-g","-fsanitize=address,undefined","-fno-sanitize-recover=all",str(c),"-o",str(binary)],check=True,timeout=60)
    result=subprocess.run([str(binary.resolve())],capture_output=True,text=True,check=True,timeout=60)
    (output/"records.txt").write_text(result.stdout)
    (output/"manifest.json").write_text(json.dumps({
        "pin":pt.absolute.PIN,"sources":pt.absolute.HASHES,"libps2_sha256":pt.LIB_SHA,
        "helper_sha256":hashlib.sha256(helper.read_bytes()).hexdigest(),
        "unchanged_functions":{name:hashlib.sha256(body.encode()).hexdigest()for name,body in bodies.items()},
        "records":len(result.stdout.splitlines()),"oracle_limit":[
            "Complete original reset/mode/sliced helpers execute against recorded modeled PS2 services; source reset returns void and ignores mode errors.",
            "Native actual keyboard/parent/child disable, ACK publication, port inhibition, retained effects/no replay and explicit held-state release are tested separately.",
            "No native resource ownership handoff, firmware takeover, physical operation or full driver-core qualification.",
        ]},indent=2)+"\n")
    print(len(result.stdout.splitlines()),"original cleanup mode records")


if __name__=="__main__":main()

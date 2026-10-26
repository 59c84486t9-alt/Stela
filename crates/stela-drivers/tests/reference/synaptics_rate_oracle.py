#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Original Synaptics rate quantization/mode command with recorded PS/2 IO."""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

helper = Path(__file__).with_name("synaptics_passthrough_oracle.py")
spec = importlib.util.spec_from_file_location("passthrough", helper)
pt = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pt)

MAIN = r'''
int main(void) {
    static const u8 modes[]={0x85,0x87,0xc5,0xc7};
    for(unsigned i=0;i<4;++i)for(unsigned n=0;n<257;++n) {
        unsigned requested=n==256?~0U:n;
        struct synaptics_data data={0};data.mode=modes[i];
        struct psmouse mouse={0};mouse.private=&data;txlen=0;
        /* Protected source attribute dispatch deactivates/reactivates around
           the unchanged rate callback. Native tests require each actual ACK. */
        ps2_command(&mouse.ps2dev,NULL,PSMOUSE_CMD_DISABLE);
        synaptics_set_rate(&mouse,requested);
        ps2_command(&mouse.ps2dev,NULL,PSMOUSE_CMD_ENABLE);
        printf("%u %u %u %u ",modes[i],requested,mouse.rate,data.mode);
        for(unsigned j=0;j<txlen;++j)printf("%02x",tx[j]);printf("\n");
    }
    return 0;
}
'''


def main():
    root, output = map(Path, sys.argv[1:])
    output.mkdir(parents=True, exist_ok=False)
    mouse = root/"drivers/input/mouse"
    for name, expected in pt.absolute.HASHES.items():
        assert hashlib.sha256((mouse/name).read_bytes()).hexdigest() == expected
    lib = (root/"drivers/input/serio/libps2.c").read_bytes()
    assert hashlib.sha256(lib).hexdigest() == pt.LIB_SHA
    source = (mouse/"synaptics.c").read_text()
    bodies = {"ps2_sliced_command": pt.exported(lib.decode(), "int ps2_sliced_command(")}
    for name in ["synaptics_mode_cmd", "synaptics_set_rate"]:
        bodies[name] = pt.absolute.function(source, name)
    prefix = pt.PREFIX.replace("SYNAPTICS_HEADER", str((mouse/"synaptics.h").resolve()))
    prefix = prefix.replace("unsigned state,pktsize;", "unsigned state,pktsize,rate;")
    c = output/"oracle.c"
    c.write_text(prefix+"\n".join(bodies.values())+MAIN)
    binary = output/"oracle"
    subprocess.run(["clang", "-std=gnu11", "-O1", "-g", "-fsanitize=address,undefined",
                    "-fno-sanitize-recover=all", str(c), "-o", str(binary)], check=True, timeout=60)
    result = subprocess.run([str(binary.resolve())], capture_output=True, text=True, check=True, timeout=60)
    (output/"records.txt").write_text(result.stdout)
    (output/"manifest.json").write_text(json.dumps({
        "pin": pt.absolute.PIN, "sources": pt.absolute.HASHES, "libps2_sha256": pt.LIB_SHA,
        "helper_sha256": hashlib.sha256(helper.read_bytes()).hexdigest(),
        "unchanged_functions": {name: hashlib.sha256(body.encode()).hexdigest() for name, body in bodies.items()},
        "records": len(result.stdout.splitlines()), "oracle_limit": [
            "Original rate/mode/sliced helpers run against modeled Linux PS2 command services; protected-attribute disable/enable wrapper is fixture context.",
            "Source rate callback ignores command errors; native separately tests actual ACK publication, uncertain effects and no replay.",
            "No physical rate measurement, Linux controller, scheduler or child binding qualification.",
        ]}, indent=2)+"\n")
    print(len(result.stdout.splitlines()), "original rate command records")


if __name__ == "__main__":
    main()

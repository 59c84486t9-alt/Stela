#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Original Synaptics parse/report policy; kernel event delivery is modeled."""
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

SERVICES = r'''
// Numeric names from pinned input-event-codes.h, serio.h and psmouse.h.
#define BTN_0 0x100
#define BTN_1 0x101
#define PSMOUSE_OOB_EXTRA_BTNS 1
#define SERIO_OOB_DATA 8
static unsigned seen, logical_buttons, pt_step, pt_buttons;
static void input_report_key(struct input_dev *dev,unsigned code,int value) {
    assert(code>=BTN_0 && code<BTN_0+8);
    unsigned bit=code-BTN_0;
    // The real input core ignores keys not declared by set_input_params.
    if(bit>=dev->count) return;
    seen=1;
    if(value) logical_buttons|=1U<<bit;
    else logical_buttons&=~(1U<<bit);
}
static void serio_interrupt(struct serio *s,u8 data,unsigned flags) {
    (void)s; assert(flags==SERIO_OOB_DATA);
    if(pt_step++==0) assert(data==PSMOUSE_OOB_EXTRA_BTNS);
    else { assert(pt_step==2); seen=1; pt_buttons=data; }
}
'''
MAIN = r'''
int main(void) {
    const unsigned versions[]={0x705,0x801,0x802,0x803};
    for(unsigned n=0;n<8192;++n) {
        unsigned count=(n&7)+1,stick=(n>>3)&1,version=versions[(n>>4)&3];
        unsigned four=(n>>6)&1,switches=(n>>7)&3,bitmap=(n>>2)&255;
        unsigned bits=(count+1)/2,mask=(1U<<bits)-1;
        struct synaptics_data data={0};
        data.info.identity=((version&255)<<16)|0x4700|(version>>8);
        data.info.model_id=0x80;
        data.info.capabilities=BIT(23)|BIT(18)|3|(four?8:0);
        data.info.ext_cap=count<<12; data.info.ext_cap_10=stick?BIT(16):0;
        struct serio port={0}; data.pt_port=&port;
        struct input_dev dev={count};
        struct psmouse mouse={0};mouse.private=&data;mouse.dev=&dev;
        u8 *p=mouse.packet;
        p[0]=0x90|((n>>10)&3);p[1]=0x99;p[2]=50;
        p[3]=(0xc0|(p[0]&3))^switches;
        p[4]=(0x88&~mask)|(bitmap&mask);
        p[5]=(0x99&~mask)|((bitmap>>bits)&mask);
        struct synaptics_hw_state hw;
        assert(synaptics_parse_hw_state(p,&data,&hw)==0);
        seen=logical_buttons=pt_step=pt_buttons=0;
        synaptics_report_ext_buttons(&mouse,&hw);
        unsigned buttons=hw.left|(hw.right<<1)|(hw.middle<<2)|(hw.down<<3)|(hw.up<<4);
        printf("%u %u %u %u ",count,stick,version,four);
        for(unsigned i=0;i<6;++i)printf("%02x",p[i]);
        printf(" %u %u %c %u\n",hw.ext_buttons,buttons,!seen?'N':stick?'S':'T',stick?pt_buttons:logical_buttons);
    }
    return 0;
}
'''


def main():
    root, output = map(Path, sys.argv[1:])
    output.mkdir(parents=True, exist_ok=False)
    source = root / "drivers/input/mouse"
    for name, expected in absolute.HASHES.items():
        assert hashlib.sha256((source/name).read_bytes()).hexdigest() == expected
    text = (source/"synaptics.c").read_text()
    names = absolute.NAMES + ["synaptics_report_ext_buttons"]
    bodies = {name: absolute.function(text, name) for name in names}
    prefix = absolute.PREFIX.replace("SYNAPTICS_HEADER", str((source/"synaptics.h").resolve()))
    prefix = prefix.replace("struct psmouse { u8 packet[6]; void *private; };",
        "struct input_dev { unsigned count; }; struct serio { int unused; };\nstruct psmouse { u8 packet[6]; void *private; struct input_dev *dev; };")
    c = output/"oracle.c"
    c.write_text(prefix + SERVICES + "\n".join(bodies.values()) + MAIN)
    binary = output/"oracle"
    subprocess.run(["clang", "-std=gnu11", "-O1", "-g", "-fsanitize=address,undefined", "-fno-sanitize-recover=all", str(c), "-o", str(binary)], check=True, timeout=60)
    result = subprocess.run([str(binary.resolve())], capture_output=True, text=True, check=True, timeout=60)
    (output/"records.txt").write_text(result.stdout)
    (output/"manifest.json").write_text(json.dumps({"pin": absolute.PIN,
        "sources": absolute.HASHES, "helper_sha256": hashlib.sha256(helper.read_bytes()).hexdigest(),
        "unchanged_functions": {name: hashlib.sha256(body.encode()).hexdigest() for name, body in bodies.items()},
        "records": len(result.stdout.splitlines()), "oracle_limit": [
            "Original raw button parsing and complete report_ext_buttons execute unchanged.",
            "Input key capability filtering and serio OOB delivery are modeled services, not Linux input-core or actual child qualification.",
            "No physical, MT frontend or child association/lifecycle claim.",
        ]}, indent=2)+"\n")
    print(f"{len(result.stdout.splitlines())} original button records")


if __name__ == "__main__":
    main()

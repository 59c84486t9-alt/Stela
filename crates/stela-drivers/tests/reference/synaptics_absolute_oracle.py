#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Unchanged pinned Synaptics packet decode/validation; native IO tests separate."""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

PIN = "cc9de5d4b5ab6459f5774946aa3195ad51236fa8"
HASHES = {"synaptics.c": "f5537de875d9b8cd9618ea74dd08d936c2a3150bd7a38b36e73d4445ffa3648f",
          "synaptics.h": "962ff0efe585c2cd477f0dc254fd677c0cad496ca48d7dfdd1cec4dcf440d87b"}
NAMES = ["synaptics_has_agm", "synaptics_has_multifinger", "synaptics_parse_agm", "synaptics_parse_ext_buttons", "synaptics_parse_hw_state", "synaptics_validate_byte", "synaptics_image_sensor_process"]


def function(source, name):
    match = re.search(r"^static [^;{}]*\b" + name + r"\([^;{}]*\)\n\{", source, re.M)
    assert match, name
    at, depth = match.end(), 1
    while depth:
        depth += (source[at] == "{") - (source[at] == "}")
        at += 1
    return source[match.start():at]


PREFIX = r'''
// SPDX-License-Identifier: GPL-2.0-only
// Synaptics source notices remain in the original included header/source manifest.
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef uint8_t u8; typedef int8_t s8; typedef uint32_t u32;
#define BIT(n) (1UL << (n))
#define GENMASK(h,l) ((~0UL << (l)) & (~0UL >> (sizeof(unsigned long)*8-1-(h))))
struct psmouse; struct serio;
#include "SYNAPTICS_HEADER"
struct psmouse { u8 packet[6]; void *private; };
#define psmouse_err(p, ...) ((void)(p))
#define X_MAX_POSITIVE 8176
#define Y_MAX_POSITIVE 8176
#define ABS_POS_BITS 13
#define XMAX 6143
#define YMAX 6143
static unsigned long jiffies;
#define time_after(a,b) ((long)((b)-(a)) < 0)
#define msecs_to_jiffies(n) (n)
static unsigned reported_fingers;
static void synaptics_report_mt_data(struct psmouse *p,const struct synaptics_hw_state *h,int n) {
    (void)p; (void)h; reported_fingers=n;
}
'''
SUFFIX = r'''
int main(void) {
    static const unsigned xy[][2] = {{0,1},{1,2},{1000,800},{2000,2500},{6000,5000},{8176,8177},{8191,8191},{4095,4096},{6143,6143}};
    for (unsigned n=0; n<8192; ++n) {
        bool newer = n & 1;
        bool clickpad = newer && (n & 128);
        unsigned x=xy[(n/17)%9][0], y=xy[(n/17)%9][1];
        u8 w=(n>>1)&15, z=(n>>5)&255, buttons=(n/3)&(newer?7:3);
        struct psmouse mouse = {0};
        u8 *p=mouse.packet;
        if (newer) {
            p[0]=0x80|((w&12)<<2)|((w&2)<<1)|(buttons&3);
            p[1]=((x>>8)&15)|((y>>4)&0xf0); p[2]=z;
            p[3]=0xc0|((x>>8)&0x10)|((y>>7)&0x20)|((w&1)<<2)|((buttons&1)^((buttons>>2)&1));
            p[4]=x; p[5]=y;
        } else {
            p[0]=0xc0|((z&0xc0)>>2)|((w&2)<<1)|(buttons&3);
            p[1]=((x>>8)&31)|((w&8)<<4); p[2]=x;
            p[3]=0x80|(z&0x3f); p[4]=(y>>8)&31; p[5]=y;
        }
        struct synaptics_data data = {0};
        data.info.model_id = newer ? 0x80 : 0;
        data.info.capabilities = newer ? BIT(23)|BIT(18)|3 : 0;
        data.info.ext_cap_0c = clickpad ? BIT(20) : 0;
        struct synaptics_hw_state hw;
        assert(synaptics_parse_hw_state(p,&data,&hw)==0);
        for (int i=0;i<5;++i) assert(synaptics_validate_byte(&mouse,i,newer?SYN_NEWABS_STRICT:SYN_OLDABS));
        printf("%u %u ",newer,clickpad);
        for(unsigned i=0;i<6;++i) printf("%02x",p[i]);
        printf(" %d %d %d %d %u %d\n",hw.x,hw.y,hw.z,hw.w,hw.left|(hw.right<<1)|(hw.middle<<2),hw.scroll);
    }
    return 0;
}
'''
AGM_SUFFIX = r'''
int main(void) {
    for(unsigned n=0;n<8192;++n) {
        u8 p[6] = {0x84,(n>>1)&255,(n>>4)&255,0xc0|((n>>2)&0x30),(n>>3)&255,((n&3)<<4)|((n>>6)&15)};
        struct synaptics_data data = {0};
        data.info.model_id=0x80;
        data.info.capabilities=BIT(23)|BIT(18)|1;
        data.info.ext_cap_0c=BIT(19);
        assert(synaptics_has_multifinger(&data));
        struct synaptics_hw_state hw;
        assert(synaptics_parse_hw_state(p,&data,&hw)==1);
        for(unsigned i=0;i<6;++i) printf("%02x",p[i]);
        printf(" %u %d %d %d %u\n",n&3,data.agm.x,data.agm.y,data.agm.z,data.agm_count);
    }
    return 0;
}
'''
IMAGE_SUFFIX = r'''
int main(void) {
    for(unsigned n=0;n<8192;++n) {
        unsigned w=n&15,z=(n>>4)&255,count=(n>>5)&255;
        unsigned x=n%7?2000+(n&2047):0,y=2500+(n&1023);
        u8 p[6]={0x80|((w&12)<<2)|((w&2)<<1),((x>>8)&15)|((y>>4)&0xf0),z,
                 0xc0|((x>>8)&0x10)|((y>>7)&0x20)|((w&1)<<2),x,y};
        struct synaptics_data data={0};
        data.info.model_id=0x80; data.info.capabilities=BIT(23)|1;
        data.info.ext_cap_0c=BIT(11);
        struct psmouse mouse={0}; mouse.private=&data;
        struct synaptics_hw_state hw;
        u8 prior[6]={0x84,count,0,0xc0,0,0x20};
        assert(synaptics_parse_hw_state(prior,&data,&hw)==1);
        assert(data.agm_count==count);
        int advanced=synaptics_parse_hw_state(p,&data,&hw);
        if(!advanced) synaptics_image_sensor_process(&mouse,&hw);
        printf("%c ",advanced?'A':'F');
        for(unsigned i=0;i<6;++i) printf("%02x",p[i]);
        printf(" %u %u\n",count,advanced?0:reported_fingers);
    }
    return 0;
}
'''


def main():
    root, output = map(Path, sys.argv[1:3])
    agm = sys.argv[3:] == ["--agm"]
    image = sys.argv[3:] == ["--image"]
    output.mkdir(parents=True, exist_ok=False)
    source = root / "drivers/input/mouse"
    for name, expected in HASHES.items():
        assert hashlib.sha256((source/name).read_bytes()).hexdigest() == expected
    text = (source/"synaptics.c").read_text()
    bodies = {name: function(text, name) for name in NAMES}
    generated = output/"oracle.c"
    generated.write_text(PREFIX.replace("SYNAPTICS_HEADER", str((source/"synaptics.h").resolve())) + "\n".join(bodies.values()) + (IMAGE_SUFFIX if image else AGM_SUFFIX if agm else SUFFIX))
    binary = output/"oracle"
    subprocess.run(["clang", "-std=gnu11", "-O1", "-g", "-fsanitize=address,undefined", "-fno-sanitize-recover=all", str(generated), "-o", str(binary)], check=True, timeout=60)
    result = subprocess.run([str(binary.resolve())], capture_output=True, text=True, check=True, timeout=60)
    (output/"records.txt").write_text(result.stdout)
    (output/"manifest.json").write_text(json.dumps({"pin": PIN, "sources": HASHES,
        "unchanged_functions": {name: hashlib.sha256(body.encode()).hexdigest() for name, body in bodies.items()},
        "records": len(result.stdout.splitlines()), "profile": "image sensor" if image else "advanced gesture" if agm else "ordinary absolute", "oracle_limit": [
            "Packet helpers execute unchanged; this is not a Linux i8042/full driver qualification.",
            "ForcePad/PT/extra button paths compile but are not selected; AGM/image paths only in their stated profiles.",
            "Image count processing executes unchanged; Linux MT frontend service only retains its actual num_fingers argument. No software slot/tracking or physical claim.",
            "Native models separately exercise actual Stela query/configuration, lane routing and lifecycle.",
        ]}, indent=2)+"\n")
    print(f"{len(result.stdout.splitlines())} unchanged-source packet records")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Unchanged psmouse packet/OOB reporting for the actually bound PT mouse.

Input callbacks model logical keys/motion within a source sync frame. Numeric
Linux input ABI codes, child discovery and the Linux driver core are not modeled.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys

helper = Path(__file__).with_name("synaptics_passthrough_oracle.py")
spec = importlib.util.spec_from_file_location("passthrough", helper)
pt = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pt)
BASE_SHA = "9b88120f4b32e43180ae23d65566241048380f8c487c459585744c2270ab436d"
HEADER_SHA = "9ee4f530d7c954d80828bd51cd6194494581e05764c1604d5c0bbb5b704aa5a1"

PREFIX = r'''
// SPDX-License-Identifier: GPL-2.0-only
// Original psmouse copyright Vojtech Pavlik1999-2002/Dmitry Torokhov2003-2004.
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint8_t u8;typedef int8_t s8;
#define BIT(n) (1U<<(n))
/* Callback-only logical indices, not the numeric Linux input ABI. */
#define BTN_LEFT 0
#define BTN_RIGHT 1
#define BTN_MIDDLE 2
#define BTN_SIDE 3
#define BTN_EXTRA 4
#define REL_X 0
#define REL_Y 1
#define REL_WHEEL 2
#define REL_HWHEEL 3
#define PSMOUSE_OOB_NONE 0
#define PSMOUSE_OOB_EXTRA_BTNS 1
#define psmouse_warn(...) ((void)0)
typedef enum {PSMOUSE_BAD_DATA,PSMOUSE_GOOD_DATA,PSMOUSE_FULL_PACKET} psmouse_ret_t;
struct input_dev {u8 buttons;int dx,dy,wheel;};
struct psmouse_protocol {int type;};
struct psmouse {struct input_dev*dev;const struct psmouse_protocol*protocol;u8 packet[8],pktcnt,pktsize,extra_buttons,oob_data_type;};
static bool psmouse_a4tech_2wheels;
static int sign_extend32(unsigned value,unsigned index){value&=(1U<<(index+1))-1;return (int)((value^(1U<<index))-(1U<<index));}
static void input_report_key(struct input_dev*d,unsigned key,int value){assert(key<5);if(value)d->buttons|=1U<<key;else d->buttons&=~(1U<<key);}
static void input_report_rel(struct input_dev*d,unsigned axis,int value){switch(axis){case REL_X:d->dx+=value;break;case REL_Y:d->dy+=value;break;case REL_WHEEL:d->wheel+=value;break;default:assert(!value);}}
static void input_sync(struct input_dev*d){(void)d;}
'''
MAIN = r'''
int main(void){
    for(unsigned group=0;group<256;++group){
        unsigned id=group%3==0?0:group%3==1?3:4;
        struct psmouse_protocol protocol={id==0?PSMOUSE_PS2:id==3?PSMOUSE_IMPS:PSMOUSE_IMEX};
        struct input_dev dev={0};struct psmouse mouse={0};
        mouse.dev=&dev;mouse.protocol=&protocol;mouse.pktsize=id?4:3;mouse.pktcnt=mouse.pktsize;
        for(unsigned n=0;n<32;++n){
            int oob=n%3?((group+n)&7):-1;
            if(oob>=0){psmouse_handle_oob_data(&mouse,PSMOUSE_OOB_EXTRA_BTNS);psmouse_handle_oob_data(&mouse,oob);}
            unsigned before=dev.buttons;
            u8 extra=(group*17+n*13)&255;
            if(id==4)extra=(extra&0x3f)|((n&1)?0xc0:0);
            u8 packet[]={8|((group+n)&0xf7),(group*7+n*19)&255,(group*11+n*23)&255,extra};
            memcpy(mouse.packet,packet,4);dev.dx=dev.dy=dev.wheel=0;
            assert(psmouse_process_byte(&mouse)==PSMOUSE_FULL_PACKET);
            printf("%u %u ",group,id);for(unsigned i=0;i<4;++i)printf("%02x",packet[i]);
            printf(" %d %u %u %d %d %d\n",oob,before,dev.buttons,dev.dx,dev.dy,dev.wheel);
        }
    }
    return 0;
}
'''


def main():
    root, output = map(Path, sys.argv[1:3])
    assert sys.argv[3:] in [[],["--enhanced"]]
    enhanced=sys.argv[3:]==["--enhanced"]
    output.mkdir(parents=True, exist_ok=False)
    mouse = root/"drivers/input/mouse"
    source = (mouse/"psmouse-base.c").read_bytes()
    header = (mouse/"psmouse.h").read_bytes()
    assert hashlib.sha256(source).hexdigest() == BASE_SHA
    assert hashlib.sha256(header).hexdigest() == HEADER_SHA
    enum = re.search(r"enum psmouse_type \{.*?\n\};", header.decode(), re.S).group()
    text = source.decode()
    bodies = {}
    for name in ["psmouse_report_standard_buttons", "psmouse_report_standard_motion", "psmouse_report_standard_packet"]:
        bodies[name] = pt.exported(text, "void "+name+"(")
    bodies["psmouse_process_byte"] = pt.exported(text,"psmouse_ret_t psmouse_process_byte(")
    bodies["psmouse_handle_oob_data"] = pt.absolute.function(text,"psmouse_handle_oob_data")
    c = output/"oracle.c"
    prefix,main=PREFIX,MAIN
    if enhanced:
        prefix=prefix.replace("int dx,dy,wheel;","int dx,dy,wheel,horizontal;")
        prefix=prefix.replace("case REL_WHEEL:d->wheel+=value;break;default:assert(!value);","case REL_WHEEL:d->wheel+=value;break;case REL_HWHEEL:d->horizontal+=value;break;default:assert(0);")
        main=main.replace("if(id==4)extra=(extra&0x3f)|((n&1)?0xc0:0);","")
        main=main.replace("dev.dx=dev.dy=dev.wheel=0;","dev.dx=dev.dy=dev.wheel=dev.horizontal=0;")
        main=main.replace(r"%d %d %d\n",r"%d %d %d %d\n").replace("dev.dx,dev.dy,dev.wheel);","dev.dx,dev.dy,dev.wheel,dev.horizontal);")
    c.write_text(prefix+enum+"\n"+"\n".join(bodies.values())+main)
    binary = output/"oracle"
    subprocess.run(["clang", "-std=gnu11", "-O1", "-g", "-fsanitize=address,undefined",
                    "-fno-sanitize-recover=all", str(c), "-o", str(binary)], check=True, timeout=60)
    result = subprocess.run([str(binary.resolve())], capture_output=True, text=True, check=True, timeout=60)
    (output/"records.txt").write_text(result.stdout)
    (output/"manifest.json").write_text(json.dumps({
        "pin": pt.absolute.PIN, "sources": {"psmouse-base.c":BASE_SHA,"psmouse.h":HEADER_SHA},
        "helper_sha256": hashlib.sha256(helper.read_bytes()).hexdigest(),
        "unchanged_functions": {name: hashlib.sha256(body.encode()).hexdigest() for name, body in bodies.items()},
        "records": len(result.stdout.splitlines()), "enhanced_scroll":enhanced,"oracle_limit": [
            "Complete original five packet/report/OOB bodies execute for standard,IntelliMouse and "+("fullExplorer4 scroll modes." if enhanced else "ordinaryExplorer modes only."),
            "Callback keys are logical indices,not numericLinuxABI; effects within each source sync frame are compared independently of callback ordering.",
            "Explorer4.0 full mode bytes execute in enhanced profile only; A4Tech/vendor paths compile but are unselected. Native identity/activationACK/failure/stop ownership separately exercised actuali8042tests.",
        ]}, indent=2)+"\n")
    print(len(result.stdout.splitlines()), "original child packet/OOB records")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Original Synaptics passthrough write/format/byte-routing reference.

Modeled Linux command and serio services retain actual bytes. A source callback
view is not proof of native child discovery, activation or held-state teardown.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

helper=Path(__file__).with_name("synaptics_absolute_oracle.py")
spec=importlib.util.spec_from_file_location("absolute",helper)
absolute=importlib.util.module_from_spec(spec)
spec.loader.exec_module(absolute)
LIB_SHA="3280d7c5a6eb120aabcb85b6177ceeb14df2f2fc2dcdf1283862f14667848a38"

PREFIX=r'''
// SPDX-License-Identifier: GPL-2.0-only
// Original libps2 copyright Vojtech Pavlik1999-2002/Dmitry Torokhov2004;
// Synaptics notices retained by the pinned source/header manifest.
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef uint8_t u8;typedef int8_t s8;typedef uint32_t u32;
#define BIT(n) (1UL<<(n))
#define GENMASK(h,l) ((~0UL<<(l))&(~0UL>>(sizeof(unsigned long)*8-1-(h))))
struct psmouse;struct serio;
#include "SYNAPTICS_HEADER"
struct serio {struct serio *parent;struct psmouse *mouse;};
struct ps2dev {struct serio *serio;};
struct psmouse {struct ps2dev ps2dev;void *private;unsigned state,pktsize;};
#define PS2_CMD_SETSCALE11 0x00e6
#define PS2_CMD_SETRES 0x10e8
#define PSMOUSE_CMD_SETRATE 0x10f3
#define PSMOUSE_CMD_DISABLE 0x00f5
#define PSMOUSE_CMD_ENABLE 0x00f4
#define PSMOUSE_ACTIVATED 4
#define dev_dbg(...) ((void)0)
#define psmouse_warn(...) ((void)0)
static u8 tx[32],rx[8];static unsigned txlen,rxlen,locked;
static struct psmouse *psmouse_from_serio(struct serio *s){return s?s->mouse:NULL;}
static void ps2_begin_command(struct ps2dev*d){(void)d;assert(!locked);locked=1;}
static void ps2_end_command(struct ps2dev*d){(void)d;assert(locked);locked=0;}
static int __ps2_command(struct ps2dev*d,u8*param,unsigned command){
    (void)d;assert(txlen+2<=sizeof(tx));tx[txlen++]=command&255;
    if(command>>12){assert((command>>12)==1);tx[txlen++]=param[0];}return 0;
}
static int ps2_command(struct ps2dev*d,u8*p,unsigned c){return __ps2_command(d,p,c);}
static void serio_interrupt(struct serio*s,u8 value,unsigned flags){
    (void)s;assert(flags==0);assert(rxlen<sizeof(rx));rx[rxlen++]=value;
}
'''
MAIN=r'''
static void hex(const u8*p,unsigned n){for(unsigned i=0;i<n;++i)printf("%02x",p[i]);}
int main(void){
    struct synaptics_data data={0};data.mode=0xc5;
    struct psmouse parent={0},child={0};parent.private=&data;
    struct serio parent_port={NULL,&parent},child_port={&parent_port,&child};
    parent.ps2dev.serio=&parent_port;data.pt_port=&child_port;
    for(unsigned value=0;value<256;++value){
        txlen=0;assert(synaptics_pt_write(&child_port,value)==0);assert(!locked);
        printf("W %u ",value);hex(tx,txlen);printf("\n");
    }
    for(unsigned format=3;format<=4;++format){
        child.pktsize=format;data.mode=0xc5;txlen=0;
        ps2_command(&parent.ps2dev,NULL,PSMOUSE_CMD_DISABLE);
        synaptics_pt_activate(&parent);
        ps2_command(&parent.ps2dev,NULL,PSMOUSE_CMD_ENABLE);
        printf("M %u %u ",format,data.mode);hex(tx,txlen);printf("\n");
        for(unsigned profile=0;profile<3;++profile){
            data.pt_port_open=profile!=0;
            child.state=profile!=1?PSMOUSE_ACTIVATED:0;
            for(unsigned n=0;n<256;++n){
                u8 packet[]={0x84|(n&3),n,n*11,0xc4|(n&0x30),n+13,n+27};
                assert(synaptics_is_pt_packet(packet));rxlen=0;
                synaptics_pass_pt_packet(&data,packet);
                assert(rxlen==(profile==2?format:1));
                printf("R %u %u ",format,profile);hex(packet,6);
                printf(" %u ",rxlen);hex(rx,rxlen);printf("\n");
            }
        }
    }
    return 0;
}
'''


def exported(source,marker):
    start=source.index(marker);at=source.index("{",start)+1;depth=1
    while depth:
        depth+=(source[at]=="{")-(source[at]=="}");at+=1
    return source[start:at]


def main():
    root,output=map(Path,sys.argv[1:]);output.mkdir(parents=True,exist_ok=False)
    mouse=root/"drivers/input/mouse"
    for name,expected in absolute.HASHES.items():assert hashlib.sha256((mouse/name).read_bytes()).hexdigest()==expected
    lib=(root/"drivers/input/serio/libps2.c").read_bytes();assert hashlib.sha256(lib).hexdigest()==LIB_SHA
    bodies={"ps2_sliced_command":exported(lib.decode(),"int ps2_sliced_command(")}
    source=(mouse/"synaptics.c").read_text()
    for name in ["synaptics_mode_cmd","synaptics_pt_write","synaptics_is_pt_packet","synaptics_pass_pt_packet","synaptics_pt_activate"]:
        bodies[name]=absolute.function(source,name)
    c=output/"oracle.c";c.write_text(PREFIX.replace("SYNAPTICS_HEADER",str((mouse/"synaptics.h").resolve()))+"\n".join(bodies.values())+MAIN)
    binary=output/"oracle"
    subprocess.run(["clang","-std=gnu11","-O1","-g","-fsanitize=address,undefined","-fno-sanitize-recover=all",str(c),"-o",str(binary)],check=True,timeout=60)
    result=subprocess.run([str(binary.resolve())],capture_output=True,text=True,check=True,timeout=60)
    (output/"records.txt").write_text(result.stdout)
    (output/"manifest.json").write_text(json.dumps({"pin":absolute.PIN,"sources":absolute.HASHES,"libps2_sha256":LIB_SHA,
        "helper_sha256":hashlib.sha256(helper.read_bytes()).hexdigest(),
        "unchanged_functions":{name:hashlib.sha256(body.encode()).hexdigest()for name,body in bodies.items()},
        "records":len(result.stdout.splitlines()),"oracle_limit":[
            "Original complete write/sliced/mode/format and receive routing helpers execute against modeled Linux command/serio services.",
            "Callback active/format views are fixture context, not native child identity/activation/association authority.",
            "Receive profiles0/1/2 select closed-active/open-command/open-active respectively; actual callback count is asserted1/1/format.",
            "Native tests separately exercise real i8042 ownership, actual outer ACKs, failed effects and raw retention; physical/child lifecycle remains separate.",
        ]},indent=2)+"\n")
    print(len(result.stdout.splitlines()),"original passthrough records")


if __name__=="__main__":main()

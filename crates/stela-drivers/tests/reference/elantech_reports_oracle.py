#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Complete pinned Elantech v1/v2 report/validation bodies, logical input services."""
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
HASHES={"elantech.c":"d419d9d67f95f6b370ecfb45f7aa781f6d38794d20233596597f894d3a503446",
        "elantech.h":"02e644ecac5282cbe042bcb0b4853718dbd0494125ba950faf46e9076a21bb21",
        "psmouse-base.c":"9b88120f4b32e43180ae23d65566241048380f8c487c459585744c2270ab436d"}
PREFIX=r'''
// SPDX-License-Identifier: GPL-2.0-only
// Elantech Copyright2007-2009 Arjan Opmeer; original psmouse notices retained.
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
typedef uint8_t u8;typedef int8_t s8;
#define BIT(n) (1U<<(n))
struct psmouse;struct input_dev;
#include "ELANTECH_HEADER"
/* Logical callback indices, not Linux input ABI numeric codes. */
#define BTN_LEFT 0
#define BTN_RIGHT 1
#define BTN_MIDDLE 2
#define BTN_BACK 3
#define BTN_FORWARD 4
#define BTN_TOUCH 8
#define BTN_TOOL_FINGER 9
#define BTN_TOOL_DOUBLETAP 10
#define BTN_TOOL_TRIPLETAP 11
#define BTN_TOOL_QUADTAP 12
#define ABS_X 0
#define ABS_Y 1
#define ABS_PRESSURE 2
#define ABS_TOOL_WIDTH 3
#define ABS_MT_POSITION_X 4
#define ABS_MT_POSITION_Y 5
#define MT_TOOL_FINGER 0
#define fallthrough __attribute__((fallthrough))
#define elantech_debug(...) ((void)0)
struct input_dev {unsigned allowed,buttons,touch,tools,slots,current,sync;int x,y,sx[2],sy[2],pressure,width;};
struct psmouse {struct input_dev*dev;void*private;u8 packet[8];};
static int synaptics_send_cmd(struct psmouse*p,unsigned char c,unsigned char*v){(void)p;(void)c;(void)v;assert(0);return -1;}
static int elantech_send_cmd(struct psmouse*p,unsigned char c,unsigned char*v){return synaptics_send_cmd(p,c,v);}
static const int elantech_dmi_force_crc_enabled[1],no_hw_res_dmi_table[1];
static int dmi_check_system(const void*p){(void)p;return 0;}
static void input_report_key(struct input_dev*d,unsigned key,int value){
    if(key<5){if(!(d->allowed&(1U<<key)))return;if(value)d->buttons|=1U<<key;else d->buttons&=~(1U<<key);}
    else if(key==BTN_TOUCH)d->touch=!!value;
    else {assert(key>=BTN_TOOL_FINGER&&key<=BTN_TOOL_QUADTAP);if(value)d->tools|=1U<<(key-BTN_TOOL_FINGER);else d->tools&=~(1U<<(key-BTN_TOOL_FINGER));}
}
static void input_report_abs(struct input_dev*d,unsigned axis,int value){switch(axis){
    case ABS_X:d->x=value;break;case ABS_Y:d->y=value;break;
    case ABS_PRESSURE:d->pressure=value;break;case ABS_TOOL_WIDTH:d->width=value;break;
    case ABS_MT_POSITION_X:d->sx[d->current]=value;break;case ABS_MT_POSITION_Y:d->sy[d->current]=value;break;default:assert(0);}}
static void input_sync(struct input_dev*d){++d->sync;}
static void input_mt_slot(struct input_dev*d,unsigned slot){assert(slot<2);d->current=slot;}
static void input_mt_report_slot_state(struct input_dev*d,unsigned tool,bool active){assert(tool==MT_TOOL_FINGER);if(active)d->slots|=1U<<d->current;else d->slots&=~(1U<<d->current);}
'''
MAIN=r'''
static u8 parity(u8 value){unsigned count=0;for(;value;value&=value-1)++count;return !(count&1);}
int main(void){
    static const unsigned versions[]={0x010000,0x020022,0x020600,0x020030,0x020800,0x020b00,0x020801,0x040216,0x040219,0x140900};
    static const unsigned counts[]={1,1,1,2,1,1,1,0,3,4};
    for(unsigned group=0;group<256;++group){
        unsigned firmware=versions[group%10];bool fixed=firmware==0x140900&&(group&128);
        struct elantech_data data={0};data.info.fw_version=firmware;assert(elantech_set_properties(&data.info)==0);assert(data.info.hw_version<=2);
        bool old=firmware<0x020000,rocker=old&&(group&32);data.info.capabilities[0]=rocker?4:0;
        data.y_max=data.info.hw_version==1?352:firmware==0x020801?704:firmware==0x040216?405:firmware==0x040219?500:firmware==0x140900?(fixed?100:640):768;
        data.parity[0]=1;for(unsigned i=1;i<256;++i)data.parity[i]=data.parity[i&(i-1)]^1;
        struct input_dev dev={0};dev.allowed=3|(rocker?24:0);dev.pressure=dev.width=-1;
        struct psmouse mouse={&dev,&data,{0}};
        for(unsigned n=0;n<32;++n){
            u8*p=mouse.packet;memset(p,0,8);unsigned fingers=counts[n%10];unsigned buttons=(group+n)&3;
            unsigned x=(group*31+n*67)&4095,y=(group*47+n*89)&4095;
            if(data.info.hw_version==1){
                x&=1023;y&=1023;p[0]=8|buttons;p[1]=((x>>6)&12)|((y>>8)&3);p[2]=x;p[3]=y;
                if(old){p[0]|=((n&1)<<6)|((n&2)<<6);p[1]|=fingers==4?0xb0:fingers<<4;}
                else {if(fingers>3)fingers=3;p[0]|=fingers<<6;}
                p[0]|=parity(p[1])<<(old?5:4);p[0]|=parity(p[2])<<(old?4:5);p[0]|=parity(p[3])<<2;
                /* Driver-core BAT prefix handling is qualified separately. */
                if(p[0]==0xaa&&p[1]==0)p[0]^=1;
                assert(elantech_packet_check_v1(&mouse));
            }else if(fingers==2){
                unsigned x1=x&2044,y1=y&2044,x2=(x+400)&2044,y2=(y+600)&2044;
                p[0]=0x80|(data.info.reports_pressure?4:12)|((x1>>6)&16)|((y1>>5)&32)|buttons;p[1]=x1>>2;p[2]=y1>>2;
                p[3]=(data.info.reports_pressure?2:8)|((x2>>6)&16)|((y2>>5)&32);p[4]=x2>>2;p[5]=y2>>2;
            }else{
                unsigned z=(group*13+n*29)&255,w=(group+n)&15;
                p[0]=((fingers>3?3:fingers)<<6)|buttons;p[1]=(x>>8)&15;p[2]=x;p[4]=(y>>8)&15;p[5]=y;
                if(data.info.reports_pressure){p[0]|=4|((w&12)<<2);p[3]=2|((w&3)<<4);p[1]|=z&0xf0;p[4]|=(z&15)<<4;}
                else{p[0]|=0x3c;p[3]=0x38;}if(fingers==4)p[3]|=0x80;
            }
            char kind='F';unsigned before=dev.sync;
            if(data.info.hw_version==2&&n==23){const u8 debounce[]={0x84,0xff,0xff,2,0xff,0xff};memcpy(p,debounce,6);}
            if(data.info.hw_version==1)elantech_report_absolute_v1(&mouse);
            else if(elantech_debounce_check_v2(&mouse))kind='B';
            else{assert(elantech_packet_check_v2(&mouse));elantech_report_absolute_v2(&mouse);}
            if(kind=='F'&&before==dev.sync)kind='S';
            printf("%u %u %u %u ",group,firmware,fixed,rocker);for(unsigned i=0;i<(data.info.hw_version==1?4:6);++i)printf("%02x",p[i]);
            printf(" %c %u %u %u %d %d %u %d %d %d %d %d %d\n",kind,dev.touch,dev.tools,dev.buttons,dev.x,dev.y,dev.slots,dev.sx[0],dev.sy[0],dev.sx[1],dev.sy[1],dev.pressure,dev.width);
        }
    }
    return 0;
}
'''


def main():
    root,output=map(Path,sys.argv[1:]);output.mkdir(parents=True,exist_ok=False)
    mouse=root/"drivers/input/mouse"
    for name,expected in HASHES.items():assert hashlib.sha256((mouse/name).read_bytes()).hexdigest()==expected
    source=(mouse/"elantech.c").read_text()
    names=["elantech_set_properties","elantech_report_absolute_v1","elantech_set_slot","elantech_report_semi_mt_data","elantech_report_absolute_v2","elantech_packet_check_v1","elantech_debounce_check_v2","elantech_packet_check_v2"]
    bodies={"psmouse_report_standard_buttons":pt.exported((mouse/"psmouse-base.c").read_text(),"void psmouse_report_standard_buttons(")}
    bodies.update({name:pt.absolute.function(source,name)for name in names})
    c=output/"oracle.c";c.write_text(PREFIX.replace("ELANTECH_HEADER",str((mouse/"elantech.h").resolve()))+"\n".join(bodies.values())+MAIN)
    binary=output/"oracle"
    subprocess.run(["clang","-std=gnu11","-O1","-g","-fsanitize=address,undefined","-fno-sanitize-recover=all",str(c),"-o",str(binary)],check=True,timeout=60)
    result=subprocess.run([str(binary.resolve())],capture_output=True,text=True,check=True,timeout=60)
    (output/"records.txt").write_text(result.stdout)
    (output/"manifest.json").write_text(json.dumps({
        "pin":pt.absolute.PIN,"sources":HASHES,"helper_sha256":hashlib.sha256(helper.read_bytes()).hexdigest(),
        "unchanged_functions":{name:hashlib.sha256(body.encode()).hexdigest()for name,body in bodies.items()},
        "records":len(result.stdout.splitlines()),"oracle_limit":[
            "Nine complete original property/report/validation/button bodies execute with modeled logical input services; numeric Linux input ABI/DMI/physical authority is not modeled.",
            "Range context is supplied by declared query fixtures and separately qualified by actual native configuration tests; no software MT slot/guest frontend implementation is inferred.",
            "Source semi-MT default secondary zero and pressure defaults are service effects, never fabricated hardware positions/measurements in native records.",
            "Driver-core BAT prefix is excluded here and retained as separate native failure/lifecycle behavior. Only v1/v2 ordinary no-middle-button profiles execute.",
        ]},indent=2)+"\n")
    print(len(result.stdout.splitlines()),"original Elantech report records")


if __name__=="__main__":main()

#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Unchanged v4 reports and kernel MT slot/pointer policy, modeled input services."""
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys

helper = Path(__file__).with_name('elantech_reports_oracle.py')
spec = importlib.util.spec_from_file_location('reports',helper)
reports = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reports)
pt = reports.pt
MT_SHA = '8037cc3f03bfb2a55452b0d549ea75b80ac7cbe95d75bd3c48a562b33624fc3a'
MT_HEADER_SHA = '956bc9f627ba07083d440d7eb57250f47e0d3a454c2f819fe08432619742fdea'
PREFIX = r'''
// SPDX-License-Identifier: GPL-2.0-only
// Elantech Copyright2007-2009 Arjan Opmeer; input MT Copyright2008-2010 Henrik Rydberg.
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
typedef uint8_t u8;typedef int8_t s8;typedef uint16_t __be16;
#define BIT(n) (1U<<(n))
#define EV_KEY 1
#define EV_ABS 2
#define EV_REL 3
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
#define BTN_TOOL_QUINTTAP 13
#define ABS_X 0
#define ABS_Y 1
#define ABS_PRESSURE 2
#define ABS_TOOL_WIDTH 3
#define ABS_DISTANCE 4
#define ABS_MT_SLOT 15
#define ABS_MT_FIRST 16
#define ABS_MT_POSITION_X 16
#define ABS_MT_POSITION_Y 17
#define ABS_MT_PRESSURE 18
#define ABS_MT_TOUCH_MAJOR 19
#define ABS_MT_TRACKING_ID 20
#define ABS_MT_TOOL_TYPE 21
#define ABS_MT_DISTANCE 22
#define ABS_MT_LAST 22
#define MT_TOOL_FINGER 0
#define INPUT_PROP_POINTER 0
#define INPUT_PROP_DIRECT 1
#define INPUT_PROP_SEMI_MT 2
#define INPUT_PROP_BUTTONPAD 3
#define fallthrough __attribute__((fallthrough))
#define __counted_by(x)
#define __free(x)
#define no_free_ptr(p) (p)
#define kzalloc_flex(obj,member,n) calloc(1,sizeof(obj)+sizeof((obj).member[0])*(n))
#define kzalloc_objs(obj,n) calloc((n),sizeof(obj))
#define kfree(p) free(p)
#define psmouse_err(...) ((void)0)
#define psmouse_warn(...) ((void)0)
#define psmouse_dbg(...) ((void)0)
#define psmouse_info(...) ((void)0)
#define elantech_debug(...) ((void)0)
struct psmouse;struct input_dev;
#include "ELANTECH_HEADER"
MT_DECLARATIONS
struct axis {int value,minimum,maximum,fuzz,resolution;};
struct input_dev {unsigned buttons,touch,tools,sync;unsigned long absbit[1],keybit[1],evbit[1],propbit[1];struct axis*absinfo;struct input_mt*mt;};
struct psmouse {struct input_dev*dev;void*private;u8 packet[8];};
static void __set_bit(unsigned n,unsigned long*b){b[0]|=1UL<<n;}
static void __clear_bit(unsigned n,unsigned long*b){b[0]&=~(1UL<<n);}
static bool test_bit(unsigned n,const unsigned long*b){return !!(b[0]&(1UL<<n));}
static unsigned firmware;static u8 capabilities[3],samples[3];
static unsigned be16_to_cpup(const __be16*p){const u8*b=(const u8*)p;return ((unsigned)b[0]<<8)|b[1];}
static int synaptics_send_cmd(struct psmouse*p,u8 id,u8*out){(void)p;switch(id){
case 0:out[0]=0x35;out[1]=0x78;out[2]=0x84;break;
case 1:out[0]=firmware>>16;out[1]=firmware>>8;out[2]=firmware;break;
case 2:memcpy(out,capabilities,3);break;case 3:memcpy(out,samples,3);break;
case 4:out[0]=0;out[1]=0xab;out[2]=0;break;case 5:out[0]=0;out[1]=0x11;out[2]=0;break;
default:assert(0);}return 0;}
static int elantech_send_cmd(struct psmouse*p,u8 id,u8*out){return synaptics_send_cmd(p,id,out);}
static int elantech_change_report_id(struct psmouse*p){(void)p;assert(0);return -EIO;}
static const int elantech_dmi_force_crc_enabled[1],no_hw_res_dmi_table[1],elantech_dmi_has_middle_button[1];
static int dmi_check_system(const void*p){(void)p;return 0;}
static void input_event(struct input_dev*d,unsigned type,unsigned code,int value){
    if(type==EV_KEY){if(!test_bit(code,d->keybit))return;
        if(code<5){if(value)d->buttons|=1U<<code;else d->buttons&=~(1U<<code);}
        else if(code==BTN_TOUCH)d->touch=!!value;
        else{assert(code>=BTN_TOOL_FINGER&&code<=BTN_TOOL_QUINTTAP);if(value)d->tools|=1U<<(code-BTN_TOOL_FINGER);else d->tools&=~(1U<<(code-BTN_TOOL_FINGER));}}
    else {assert(type==EV_ABS);if(!test_bit(code,d->absbit))return;
        if(code==ABS_MT_SLOT){assert(value>=0&&value<d->mt->num_slots);d->mt->slot=value;}
        else if(code>=ABS_MT_FIRST&&code<=ABS_MT_LAST)d->mt->slots[d->mt->slot].abs[code-ABS_MT_FIRST]=value;
        else d->absinfo[code].value=value;}
}
static void input_report_key(struct input_dev*d,unsigned c,int v){input_event(d,EV_KEY,c,!!v);}
static void input_report_abs(struct input_dev*d,unsigned c,int v){input_event(d,EV_ABS,c,v);}
static void input_set_abs_params(struct input_dev*d,unsigned c,int low,int high,int fuzz,int flat){(void)flat;__set_bit(c,d->absbit);d->absinfo[c].minimum=low;d->absinfo[c].maximum=high;d->absinfo[c].fuzz=fuzz;}
static void input_abs_set_res(struct input_dev*d,unsigned c,int resolution){d->absinfo[c].resolution=resolution;}
static int input_abs_get_val(struct input_dev*d,unsigned c){return d->absinfo[c].value;}
static void input_sync(struct input_dev*d){++d->sync;}
MT_INLINE
'''
MAIN = r'''
int main(void){
    static const unsigned versions[]={0x060001,0x064001,0x070001,0x0a1001,0x0f2002,0x0f6002};
    for(unsigned group=0;group<256;++group){
        firmware=versions[group%6];capabilities[0]=0;capabilities[1]=16+(group&15);capabilities[2]=12;
        samples[0]=0;samples[1]=(firmware==0x070001)?0x2a:10;samples[2]=20;
        struct elantech_data data={0};struct axis axes[64]={0};struct input_dev dev={0};dev.absinfo=axes;
        struct psmouse mouse={&dev,&data,{0}};
        assert(elantech_query_info(&mouse,&data.info)==0);assert(data.info.hw_version==4);
        assert(elantech_set_input_params(&mouse)==0);assert(dev.mt&&dev.mt->num_slots==5);
        for(unsigned n=0;n<32;++n){
            u8*p=mouse.packet;memset(p,0,8);unsigned step=n%16,type,id=0,sid=0;
            unsigned buttons=(group+n)&7,x=(group*31+n*67)&4095,y=(group*47+n*89)&4095;
            unsigned pressure=(group*13+n*29)&255,traces=(group+n)&15;
            bool extra=(data.info.crc_enabled||(firmware==0x070001))&&(n&1);
            if(step==1||step==9||step==14){
                type=0;p[0]=((group&15)<<4)|buttons;p[1]=step==1?31:step==9?5:0;p[2]=0xdd;p[4]=0xee;p[5]=0xff;
            }else if(step==0||step==7||step==8||step==11||step==13){
                type=2;id=step==0?2:step==8?5:step==13?6:1;sid=step==7?2:step==8?5:step==11?0:3;
                p[0]=(id<<5)|((group&1)?16:0)|buttons;
                p[1]=(group*17+n*31)&255;p[2]=(group*23+n*47)&255;p[3]=sid<<5;
                p[4]=(group*29+n*13)&255;p[5]=(group*37+n*19)&255;
            }else{
                type=1;id=step==12?0:step==15?3:step==10?2:step-1;
                p[0]=(traces<<4)|buttons;p[1]=(pressure&0xf0)|((x>>8)&15);p[2]=x;p[3]=id<<5;p[4]=((pressure&15)<<4)|((y>>8)&15);p[5]=y;
            }
            if(extra)p[0]|=8;
            p[3]|=(data.info.crc_enabled?0:0x10)|type;
            /* Generic driver-core BAT handling is a separate native control. */
            if(p[0]==0xaa&&p[1]==0)p[0]^=1;
            int packet_type=elantech_packet_check_v4(&mouse);assert(packet_type!=PACKET_UNKNOWN&&packet_type!=PACKET_TRACKPOINT);
            unsigned before=dev.sync;elantech_report_absolute_v4(&mouse,packet_type);
            printf("%u %u ",group,firmware);for(unsigned i=0;i<6;++i)printf("%02x",p[i]);
            printf(" %u %u %u %u %d %d %d %d %d",dev.sync-before,dev.buttons,dev.touch,dev.tools,axes[ABS_X].value,axes[ABS_Y].value,axes[ABS_PRESSURE].value,axes[ABS_TOOL_WIDTH].value,dev.mt->trkid);
            for(unsigned slot=0;slot<5;++slot){struct input_mt_slot*s=&dev.mt->slots[slot];printf(" %d %d %d %d %d",input_mt_get_value(s,ABS_MT_TRACKING_ID),input_mt_get_value(s,ABS_MT_POSITION_X),input_mt_get_value(s,ABS_MT_POSITION_Y),input_mt_get_value(s,ABS_MT_PRESSURE),input_mt_get_value(s,ABS_MT_TOUCH_MAJOR));}
            printf("\n");
        }
        input_mt_destroy_slots(&dev);
    }
    return 0;
}
'''


def main():
    root,output = map(Path,sys.argv[1:])
    output.mkdir(parents=True,exist_ok=False)
    mouse = root/'drivers/input/mouse'
    for name,expected in reports.HASHES.items():
        assert hashlib.sha256((mouse/name).read_bytes()).hexdigest()==expected
    mt = (root/'drivers/input/input-mt.c').read_text()
    header = (root/'include/linux/input/mt.h').read_text()
    assert hashlib.sha256(mt.encode()).hexdigest()==MT_SHA
    assert hashlib.sha256(header.encode()).hexdigest()==MT_HEADER_SHA
    source = (mouse/'elantech.c').read_text()
    structs = '\n'.join(re.search(r'struct '+name+r' \{.*?\n\};',header,re.S).group() for name in ['input_mt_slot','input_mt'])
    definitions = '\n'.join(line for line in header.splitlines() if line.startswith(('#define TRKID_MAX','#define INPUT_MT_')))
    inline_names = ['input_mt_set_value','input_mt_get_value','input_mt_new_trkid','input_mt_slot']
    inline = {name:pt.absolute.function(header,name) for name in inline_names}
    bodies = {'psmouse_report_standard_buttons':pt.exported((mouse/'psmouse-base.c').read_text(),'void psmouse_report_standard_buttons(')}
    for name in ['copy_abs','input_mt_init_slots','input_mt_destroy_slots','input_mt_report_slot_state','input_mt_report_finger_count','input_mt_report_pointer_emulation']:
        signature = {'copy_abs':None,'input_mt_init_slots':'int input_mt_init_slots(', 'input_mt_destroy_slots':'void input_mt_destroy_slots(', 'input_mt_report_slot_state':'bool input_mt_report_slot_state(', 'input_mt_report_finger_count':'void input_mt_report_finger_count(', 'input_mt_report_pointer_emulation':'void input_mt_report_pointer_emulation('}[name]
        bodies[name] = pt.exported(mt,signature) if signature else pt.absolute.function(mt,name)
    for name in ['elantech_is_buttonpad','elantech_convert_res','elantech_get_resolution_v4','elantech_set_properties','elantech_query_info','elantech_set_buttonpad_prop','elantech_set_input_params',
                 'elantech_input_sync_v4','process_packet_status_v4','process_packet_head_v4','process_packet_motion_v4','elantech_report_absolute_v4','elantech_packet_check_v4']:
        bodies[name] = pt.absolute.function(source,name)
    prefix = PREFIX.replace('ELANTECH_HEADER',str((mouse/'elantech.h').resolve()))
    prefix = prefix.replace('MT_DECLARATIONS',definitions+'\n#define TRKID_SGN ((TRKID_MAX+1)>>1)\n'+structs)
    prefix = prefix.replace('MT_INLINE','\n'.join(inline.values()))
    c = output/'oracle.c'
    c.write_text(prefix+'\n'.join(bodies.values())+MAIN)
    binary = output/'oracle'
    subprocess.run(['clang','-std=gnu11','-O1','-g','-fsanitize=address,undefined','-fno-sanitize-recover=all',str(c),'-o',str(binary)],check=True,timeout=60)
    result = subprocess.run([str(binary.resolve())],capture_output=True,text=True,check=True,timeout=60)
    (output/'records.txt').write_text(result.stdout)
    (output/'manifest.json').write_text(json.dumps({
        'pin':pt.absolute.PIN,'sources':reports.HASHES,'input_mt_sha256':MT_SHA,'input_mt_header_sha256':MT_HEADER_SHA,
        'unchanged_functions':{name:hashlib.sha256(body.encode()).hexdigest() for name,body in {**inline,**bodies}.items()},
        'helper_sha256':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in [Path(__file__),helper,Path(pt.__file__),Path(pt.absolute.__file__)]},
        'records':len(result.stdout.splitlines()),
        'oracle_limit':['Complete original v4 reports/checks/query/input-parameter and MT init/slot/tracking/pointer bodies execute with logical input callback services; numeric Linux ABI and kernel event buffering are not modeled.',
                       'Ordinary no-DMI/no-trackpoint profiles select MT flags0 exactly as source. Unsupported keys/axes are filtered by actual source-advertised capabilities; five contacts do not fabricate an unadvertised quinttap key.',
                       'Raw hardware reports, source unsigned coordinate cache, software tracking identities/defaults, inactive-slot motion, dual alias motion, status releases and pointer emulation remain distinct.',
                       'Native v4 implementation, source failure policies, full kernel input frontend/guest association and physical qualification are not established by these source records.']},indent=2)+'\n')
    print(len(result.stdout.splitlines()),'original v4 report and MT policy records')


if __name__=='__main__':
    main()

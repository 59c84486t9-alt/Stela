#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Complete pinned Elantech detection/query/register/init functions and PS2 wire."""
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys

helper=Path(__file__).with_name("elantech_reports_oracle.py")
spec=importlib.util.spec_from_file_location("reports",helper)
reports=importlib.util.module_from_spec(spec)
spec.loader.exec_module(reports)
pt=reports.pt
PREFIX=r'''
// SPDX-License-Identifier: GPL-2.0-only
// Original Elantech/libps2/psmouse notices are retained by source manifests.
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
typedef uint8_t u8;typedef uint16_t __be16;
struct psmouse;struct input_dev;
#include "ELANTECH_HEADER"
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#define psmouse_err(...) ((void)0)
#define psmouse_warn(...) ((void)0)
#define psmouse_dbg(...) ((void)0)
#define psmouse_info(...) ((void)0)
#define elantech_debug(...) ((void)0)
#define dev_dbg(...) ((void)0)
struct ps2dev {void*serio;};
struct psmouse {struct ps2dev ps2dev;void*private;const char*vendor,*name;unsigned rate,resolution;void(*set_rate)(struct psmouse*,unsigned);void(*set_resolution)(struct psmouse*,unsigned);void(*set_scale)(struct psmouse*,enum psmouse_scale);};
static enum psmouse_type psmouse_max_proto=PSMOUSE_AUTO;
static const int elantech_dmi_force_crc_enabled[1],no_hw_res_dmi_table[1],elantech_dmi_has_middle_button[1];
static int dmi_check_system(const void*p){(void)p;return 0;}
static unsigned source_sleep_ms;
static unsigned rejected_services,service_calls;
static void msleep(unsigned value){source_sleep_ms+=value;}
static unsigned be16_to_cpup(const __be16*p){const u8*b=(const u8*)p;return ((unsigned)b[0]<<8)|b[1];}
static int elantech_change_report_id(struct psmouse*p){(void)p;assert(0);return -EIO;}
static int elantech_get_resolution_v4(struct psmouse*p,unsigned*x,unsigned*y,unsigned*b){(void)p;(void)x;(void)y;(void)b;assert(0);return -EIO;}
static unsigned firmware,knock_tail,readback_value,firmware_queries,sample_queries,scale_count,sliced,quarters;
static u8 capabilities[3],samples[3],firmware_id[3],regs[256],slice_values[4],custom_values[4],wire[1024];
static unsigned slice_count,custom_count,wire_count;static bool resolution_arg,custom_literal,locked;
static void device_byte(u8 byte){
    assert(wire_count<sizeof(wire));wire[wire_count++]=byte;
    if(custom_literal){custom_literal=false;assert(custom_count<4);custom_values[custom_count++]=byte;return;}
    if(resolution_arg){resolution_arg=false;assert(byte<4);sliced=((sliced<<2)|byte)&255;if(++quarters==4){assert(slice_count<4);slice_values[slice_count++]=sliced;quarters=0;}return;}
    switch(byte){
    case 0xf6:memset(regs,0,sizeof(regs));scale_count=quarters=slice_count=custom_count=0;break;
    case 0xf5:case 0xf4:scale_count=quarters=slice_count=custom_count=0;break;
    case 0xe6:
        if(slice_count==3){assert(slice_values[0]==0x11);regs[slice_values[1]]=slice_values[2];slice_count=0;}
        if(custom_count==3){assert(custom_values[0]==0x11);regs[custom_values[1]]=custom_values[2];custom_count=0;}
        ++scale_count;sliced=quarters=0;break;
    case 0xe8:resolution_arg=true;scale_count=0;break;
    case 0xf8:custom_literal=true;scale_count=0;break;
    default:break;
    }
}
static void reply(u8*param){
    if(slice_count==2&&slice_values[0]==0x10){param[0]=readback_value;param[1]=0xfa;param[2]=0xfe;}
    else if(custom_count==2&&custom_values[0]==0x10){param[0]=readback_value;param[1]=0xfa;param[2]=0xfe;}
    else if(slice_count==1){switch(slice_values[0]){
        case 0:memcpy(param,firmware_id,3);break;
        case 1:++firmware_queries;param[0]=firmware>>16;param[1]=firmware>>8;param[2]=firmware;break;
        case 2:memcpy(param,capabilities,3);break;
        case 3:++sample_queries;memcpy(param,samples,3);break;
        default:assert(0);}}
    else {assert(scale_count>=3);param[0]=0x3c;param[1]=3;param[2]=knock_tail;}
    scale_count=slice_count=custom_count=0;
}
static void ps2_begin_command(struct ps2dev*p){(void)p;assert(!locked);locked=true;}
static void ps2_end_command(struct ps2dev*p){(void)p;assert(locked);locked=false;}
static int __ps2_command(struct ps2dev*p,u8*param,unsigned command){
    (void)p;++service_calls;if((command&255)==0xf8&&rejected_services){--rejected_services;return -EAGAIN;}device_byte(command&255);
    if(command>>12){assert(command>>12==1);device_byte(param[0]);}
    if((command&255)==0xe9){assert(((command>>8)&15)==3);reply(param);}
    return 0;
}
static int ps2_command(struct ps2dev*p,u8*param,unsigned command){return __ps2_command(p,param,command);}
'''
REJECTED_MAIN=r'''
int main(void){
    for(unsigned failures=0;failures<5;++failures){
        struct elantech_data data={0};struct psmouse mouse={0};mouse.private=&data;
        rejected_services=failures;service_calls=source_sleep_ms=wire_count=0;
        int result=elantech_ps2_command(&mouse,NULL,ETP_PS2_CUSTOM_COMMAND);
        printf("%u %u %u %d\n",failures,service_calls,source_sleep_ms,result);
    }
    return 0;
}
'''
MAIN=r'''
int main(void){
    static const unsigned versions[]={0x010000,0x020022,0x020600,0x020030,0x020800,0x020b00,0x020801,0x0208ff,0x020900,0x040215,0x040216,0x040219,0x140900,0x140900};
    for(unsigned index=0;index<ARRAY_SIZE(versions);++index)for(unsigned n=0;n<32;++n){
        firmware=versions[index];knock_tail=(n&1)?0:0xc8;readback_value=(n*17)&255;
        capabilities[0]=n&1?0:4;capabilities[1]=16+(n&15);capabilities[2]=10+(n&7);
        samples[0]=0;samples[1]=10+(n&7);samples[2]=20+((n>>1)&7);
        firmware_id[0]=0;firmware_id[1]=index==13?0x10:0;firmware_id[2]=0;
        firmware_queries=sample_queries=scale_count=sliced=quarters=slice_count=custom_count=wire_count=source_sleep_ms=0;
        resolution_arg=custom_literal=locked=false;memset(regs,0,sizeof(regs));
        struct elantech_data data={0};struct psmouse mouse={0};mouse.private=&data;mouse.rate=100;mouse.resolution=200;
        mouse.set_rate=psmouse_set_rate;mouse.set_resolution=psmouse_set_resolution;mouse.set_scale=psmouse_set_scale;
        assert(elantech_detect(&mouse,false)==0);
        struct elantech_device_info info;assert(elantech_query_info(&mouse,&info)==0);assert(info.hw_version<=2);data.info=info;
        int result=elantech_set_absolute_mode(&mouse);int runtime=-1;
        if(result==0){psmouse_initialize(&mouse);ps2_command(&mouse.ps2dev,NULL,PSMOUSE_CMD_ENABLE);
            ps2_command(&mouse.ps2dev,NULL,PSMOUSE_CMD_DISABLE);u8 actual=0;assert(elantech_read_reg(&mouse,7,&actual)==0);runtime=actual;ps2_command(&mouse.ps2dev,NULL,PSMOUSE_CMD_ENABLE);}
        assert(!locked);assert(source_sleep_ms==0);
        printf("%u ",firmware);for(unsigned i=0;i<3;++i)printf("%02x",capabilities[i]);printf(" ");for(unsigned i=0;i<3;++i)printf("%02x",samples[i]);
        printf(" ");for(unsigned i=0;i<3;++i)printf("%02x",firmware_id[i]);
        printf(" %u %u %d %u %u %u %u %u %u %u %d ",knock_tail,readback_value,result,info.hw_version,info.x_min,info.y_min,info.x_max,info.y_max,info.reports_pressure,info.jumpy_cursor,runtime);
        for(unsigned i=0;i<wire_count;++i)printf("%02x",wire[i]);printf("\n");
    }
    return 0;
}
'''


def main():
    root,output=map(Path,sys.argv[1:3]);output.mkdir(parents=True,exist_ok=False)
    assert sys.argv[3:] in [[],["--rejected"]]
    rejected=sys.argv[3:]==["--rejected"]
    mouse=root/"drivers/input/mouse"
    for name,expected in reports.HASHES.items():assert hashlib.sha256((mouse/name).read_bytes()).hexdigest()==expected
    lib=(root/"drivers/input/serio/libps2.c").read_bytes();assert hashlib.sha256(lib).hexdigest()==pt.LIB_SHA
    header=(mouse/"psmouse.h").read_text();assert hashlib.sha256(header.encode()).hexdigest()=="9ee4f530d7c954d80828bd51cd6194494581e05764c1604d5c0bbb5b704aa5a1"
    constants="\n".join(line for line in header.splitlines()if line.startswith("#define PSMOUSE_CMD_"))+"\n"
    constants+="\n".join(line for line in lib.decode().splitlines()if line.startswith("#define PS2_CMD_"))+"\n"
    enums="\n".join(re.search(r"enum "+name+r" \{.*?\n\};",header,re.S).group()for name in ["psmouse_scale","psmouse_type"])
    constants+=enums+"\n"
    source=(mouse/"elantech.c").read_text();base=(mouse/"psmouse-base.c").read_text()
    bodies={"ps2_sliced_command":pt.exported(lib.decode(),"int ps2_sliced_command(")}
    for name in ["synaptics_send_cmd","elantech_send_cmd","elantech_ps2_command","elantech_read_reg","elantech_write_reg","elantech_is_buttonpad","elantech_is_signature_valid","elantech_set_properties","elantech_query_info","elantech_set_absolute_mode"]:
        bodies[name]=pt.absolute.function(source,name)
    bodies["elantech_detect"]=pt.exported(source,"int elantech_detect(")
    bodies["psmouse_set_resolution"]=pt.exported(base,"void psmouse_set_resolution(")
    for name in ["psmouse_set_rate","psmouse_set_scale","psmouse_initialize"]:bodies[name]=pt.absolute.function(base,name)
    c=output/"oracle.c";c.write_text(constants+PREFIX.replace("ELANTECH_HEADER",str((mouse/"elantech.h").resolve()))+"\n".join(bodies.values())+(REJECTED_MAIN if rejected else MAIN))
    binary=output/"oracle"
    subprocess.run(["clang","-std=gnu11","-O1","-g","-fsanitize=address,undefined","-fno-sanitize-recover=all",str(c),"-o",str(binary)],check=True,timeout=60)
    result=subprocess.run([str(binary.resolve())],capture_output=True,text=True,check=True,timeout=60)
    (output/"records.txt").write_text(result.stdout)
    (output/"manifest.json").write_text(json.dumps({
        "pin":pt.absolute.PIN,"sources":reports.HASHES,"libps2_sha256":pt.LIB_SHA,"psmouse_header_sha256":hashlib.sha256(header.encode()).hexdigest(),"unchanged_parameter_enums_sha256":hashlib.sha256(enums.encode()).hexdigest(),
        "helper_sha256":hashlib.sha256(helper.read_bytes()).hexdigest(),"unchanged_functions":{name:hashlib.sha256(body.encode()).hexdigest()for name,body in bodies.items()},
        "records":len(result.stdout.splitlines()),"rejected_service_profile":rejected,"oracle_limit":[
            "Sixteen complete original detection/property/query/register/absolute-mode/default-initialization/sliced functions execute against modeled PS2 command services.",
            "Command services record exact wire and return successful transactions; v1 readback-bit rejection and v2 successful-read admission execute, including non-echo readbacks.",
            "Rejected profile executes original EAGAIN service retry count/delay; normal profile has successful command services. Native maps only actual exhausted RESEND rejection to this safe retry subset.",
            "Source retries for uncertain effects/full failed-read replay remain unselected; native quarantine is separately tested and remains an error-parity obligation.",
            "DMI callbacks select the ordinary profile; unselected v3/v4/trackpoint services assert if called. No native firmware authority/guest/frontend/physical qualification.",
        ]},indent=2)+"\n")
    print(len(result.stdout.splitlines()),"original Elantech initialization/control records")


if __name__=="__main__":main()

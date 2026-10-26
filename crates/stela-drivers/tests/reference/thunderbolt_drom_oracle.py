#!/usr/bin/env python3
"""Unchanged Linux USB4 DROM acquisition, original CRC tables and parsed metadata.

Usage: thunderbolt_drom_oracle.py PINNED_THUNDERBOLT_DIRECTORY FRESH_OUTPUT
Register/clock boundaries only; no firmware proxy, physical device or GPU credit.
Source register, allocation and clock boundaries are captured; no native platform rights or physical qualification.
"""
import hashlib
import json
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path
import re
import subprocess
import sys

source, out = map(Path, sys.argv[1:])
hashes = {'drivers/thunderbolt/usb4.c': 'bd8b943a5ab4eeb59ad0f8151fd45a748657cd461d945509cef1a029320597e5', 'drivers/thunderbolt/switch.c': '981a0e577906feba9a00d4df0546cfeea4de06a8a15e439a686e4c1dc77b6f71', 'drivers/thunderbolt/tb_regs.h': '44fa3c1df358a675f23c3fd86af7467fd0541aa8f4822c116d2eb81b0f566300', 'drivers/thunderbolt/nvm.c': 'dc213632f1112fa8f7e609693e345912a3cc4a6a40c5a11d1f66ef56729ce82f', 'drivers/thunderbolt/eeprom.c': '92828ad41977fb67eae44b0907b79a83960f63e42fecef6abfb0a56940e3271b', 'lib/crc/crc32-main.c': '83cf1aab62cf8a05e352fb4acc1fa8cda514ebd4f5601c95e42fa9126a7fb2cb', 'lib/crc/gen_crc32table.c': 'b2d4fe27ca5ae1cdd14bc3fc2919b62568817dd9dccd9da8a35b41a24f3df3fe', 'include/linux/crc32poly.h': 'c977dc568f0d746b6184dd1230cc922fd1a300c6813892f40b3a2efffd76c92f'}
texts = {}
for name, expected in hashes.items():
    raw = (source / name).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == expected, name
    texts[name] = raw.decode()
trace = out / "trace.txt"
assert not trace.exists(), "preserve historical trace; choose fresh output"
out.mkdir(parents=True, exist_ok=False)

def function(filename, name):
    text = texts[filename]
    match = re.search(r"^(?:static )?(?:inline )?(?:int|void|bool|u32|u8|unsigned int|ktime_t)(?: __maybe_unused)?\s+" + name + r"\([^;{}]*?\)\n\{", text, re.M)
    assert match, name
    at, depth = match.end(), 1
    while depth:
        depth += (text[at] == "{") - (text[at] == "}")
        at += 1
    return text[match.start():at]

def declaration(filename, name, packed=False):
    return re.search(re.escape(name) + r" \{.*?\n\}" + (r" __packed;" if packed else ";"), texts[filename], re.S).group()

prelude = r'''// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2014 Andreas Noever <andreas.noever@gmail.com>
// Copyright (C) 2019 Intel Corporation
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <inttypes.h>
typedef uint8_t u8;typedef uint16_t u16;typedef uint32_t u32;typedef uint64_t u64;typedef uint64_t ktime_t;
#define __packed __attribute__((packed))
#define __maybe_unused __attribute__((unused))
#define BIT(n) (1U<<(n))
#define GENMASK(h,l) ((~0U>>(31-(h)))&(~0U<<(l)))
#define TB_CFG_SWITCH 2
#define TB_CFG_PORT 1
#define GFP_KERNEL 0
#define kzalloc(size,flags) calloc(1,(size))
#define kfree free
#define min_t(type,a,b) ((type)(a)<(type)(b)?(type)(a):(type)(b))
#define ALIGN(n,a) (((n)+(a)-1)&~((a)-1))
#define fallthrough __attribute__((fallthrough))
#define tb_sw_warn(...) ((void)0)
#define tb_sw_dbg(...) ((void)0)
#define dev_info_once(...) ((void)0)
static char *allocs[32];static unsigned na;
static char*kstrndup(const char*s,size_t n,int flags){(void)flags;if(na>=32)abort();n=strnlen(s,n);char*r=malloc(n+1);if(!r)abort();memcpy(r,s,n);r[n]=0;allocs[na++]=r;return r;}
static uint32_t crc32ctable_le[256];
#define crc32c_arch crc32c_base
struct tb_switch;
struct tb_cm_ops{int(*usb4_switch_op)(struct tb_switch*,u16,u32*,u8*,const void*,size_t,void*,size_t);};
struct tb{const struct tb_cm_ops*cm_ops;};
struct tb_port{struct tb_switch*sw;unsigned port,type;bool disabled;unsigned link_nr;struct tb_port*dual_link_port;};
struct tb_switch{struct tb*tb;u8*drom;u64 uid,actual_uid;unsigned vendor,device;char*vendor_name,*device_name;struct{unsigned max_port_number;}config;struct tb_port ports[64];u32 metadata,command;unsigned reads;};
typedef int(*read_block_fn)(void*,unsigned int,void*,size_t);
static ktime_t now;static unsigned nw,ncommands,nports,romlen;static u8 romdata[32768];static unsigned retry_mode;
static struct{unsigned offset;u32 word;}writes[512];static unsigned port_reads[4096];
static ktime_t ktime_get(void){return now;}
static ktime_t ktime_add_ms(ktime_t t,int ms){return t+ms;}
static bool ktime_before(ktime_t a,ktime_t b){return a<b;}
static void usleep_range(unsigned a,unsigned b){(void)a;(void)b;now++;}
static unsigned command_status(unsigned index){static const unsigned safe[]={1,0,1,0,1,1,0},exhaust[]={0,1,0,1,1,1};if(retry_mode==1)return index<7?safe[index]:0;if(retry_mode==2)return index<6?exhaust[index]:0;return 0;}
static int tb_sw_write(struct tb_switch*sw,const void*data,int space,unsigned offset,unsigned count){
 if(space!=TB_CFG_SWITCH||count!=1||nw>=512)abort();writes[nw].offset=offset;memcpy(&writes[nw++].word,data,4);
 if(offset==25)memcpy(&sw->metadata,data,4);else if(offset==26){memcpy(&sw->command,data,4);sw->reads=0;ncommands++;}else abort();return 0;
}
static int tb_sw_read(struct tb_switch*sw,void*data,int space,unsigned offset,unsigned count){
 if(space!=TB_CFG_SWITCH||count<1||count>16)abort();
 if(offset==26){if(count!=1)abort();if(sw->command&(1U<<31)){if(++sw->reads>=2){sw->command&=~(1U<<31);sw->command|=command_status(ncommands-1)<<24;}}memcpy(data,&sw->command,4);}
 else if(offset==25){if(count!=1)abort();memcpy(data,&sw->metadata,4);}
 else if(offset==7){if(count!=2)abort();memcpy(data,&sw->actual_uid,8);}
 else if(offset==9){unsigned address=sw->metadata&0x7ffc;if(address+count*4>sizeof(romdata))abort();memcpy(data,romdata+address,count*4);}else abort();return 0;
}
static int tb_port_read(struct tb_port*p,void*data,int space,unsigned offset,unsigned count){if(space!=TB_CFG_PORT||offset!=2||count!=1||nports>=4096)abort();port_reads[nports++]=p->port;memcpy(data,&p->type,4);return 0;}
'''
T="drivers/thunderbolt/"
macros="\n".join(line for line in texts[T+"tb_regs.h"].splitlines()if line.startswith("#define ROUTER_CS_"))
macros+="\n"+declaration(T+"tb_regs.h","enum usb4_switch_op")+"\n"+declaration(T+"tb_regs.h","enum tb_port_type")
for filename,prefixes in [(T+"usb4.c",("#define USB4_DROM_","#define USB4_DATA_")),(T+"nvm.c",("#define NVM_DATA_DWORDS",)),(T+"eeprom.c",("#define TB_DROM_","#define USB4_DROM_")),("include/linux/crc32poly.h",("#define CRC32",))]:
    macros+="\n"+"\n".join(line for line in texts[filename].splitlines()if line.startswith(prefixes))
declarations="\n".join([declaration(T+"eeprom.c","struct tb_drom_header",True),declaration(T+"eeprom.c","enum tb_drom_entry_type"),declaration(T+"eeprom.c","struct tb_drom_entry_header",True),declaration(T+"eeprom.c","struct tb_drom_entry_generic",True),declaration(T+"eeprom.c","struct tb_drom_entry_port",True),declaration(T+"eeprom.c","struct tb_drom_entry_desc")])
functions=[("lib/crc/gen_crc32table.c","crc32init_le_generic"),("lib/crc/gen_crc32table.c","crc32cinit_le"),("lib/crc/crc32-main.c","crc32c_base"),("lib/crc/crc32-main.c","crc32c"),*[(T+"eeprom.c",name)for name in ["tb_crc8","tb_crc32"]],(T+"switch.c","tb_switch_wait_for_bit"),*[(T+"usb4.c",name)for name in ["usb4_native_switch_op","__usb4_switch_op","usb4_switch_op_data","usb4_switch_drom_read_block"]],(T+"nvm.c","tb_nvm_read_data"),*[(T+"usb4.c",name)for name in ["usb4_switch_drom_read","usb4_switch_read_uid"]],*[(T+"eeprom.c",name)for name in ["tb_switch_drom_alloc","tb_switch_drom_free","usb4_copy_drom","tb_drom_parse_entry_generic","tb_drom_parse_entry_port","tb_drom_parse_entries","tb_drom_parse_v1","usb4_drom_parse","tb_drom_parse"]]]
main=r'''
static void put16(unsigned at,u16 n){romdata[at]=n;romdata[at+1]=n>>8;}
static void append(u8 n){if(romlen>=sizeof(romdata))abort();romdata[romlen++]=n;}
static void entry(const u8*p,unsigned n){for(unsigned i=0;i<n;i++)append(p[i]);}
static void make_rom(unsigned revision,unsigned seed,unsigned integrity){
 memset(romdata,0,sizeof(romdata));romlen=revision==1?22:16;u64 uid=0x1122334455667788ULL^((u64)seed*0x1040010100104001ULL);memcpy(romdata+1,&uid,8);romdata[13]=revision;
 if(revision==1){put16(16,seed%4?0x9a00|seed:0);put16(18,seed%4?0xde00|(seed*2):0);}
 unsigned name=68+seed%5;append(name);append(1);entry((const u8*)"STELA",5);append(0);while(romlen<(revision==1?22:16)+name)append('V');
 const u8 dev[]={5,2,'D','P',0};entry(dev,sizeof(dev));const u8 product[]={8,9,0,4,seed,0x12,(u8)(seed*3),0x56};entry(product,sizeof(product));
 const u8 lane[]={8,0x81,(u8)(((seed&1)<<4)|((seed&2)?128:0)),2,0,0,0,0};entry(lane,sizeof(lane));
 const u8 ports[]={2,0xc2,2,0x87,2,0x86};entry(ports,sizeof(ports));
 append(18);append(5);u32 random=0xa5c34112U^(seed*0x104001U);for(unsigned i=0;i<16;i++){random^=random<<13;random^=random>>17;random^=random<<5;append(random);}
 if(seed==15){const u8 late[]={6,1,'L','A','T','E',8,0x81,0,0,0,0,0,0};entry(late,sizeof(late));}
 put16(14,romlen-13);romdata[0]=tb_crc8(romdata+1,8);u32 crc=tb_crc32(romdata+13,romlen-13);memcpy(romdata+9,&crc,4);if(integrity==1)romdata[9]^=1;if(integrity==2)romdata[0]^=1;
}
static void hex(const u8*p,unsigned n){for(unsigned i=0;i<n;i++)printf("%02x",p[i]);}
static void namehex(const char*p){if(!p){printf("-");return;}if(!*p){printf("_");return;}hex((const u8*)p,strlen(p));}
int main(void){
 crc32cinit_le();const struct tb_cm_ops ops={0};struct tb tb={.cm_ops=&ops};
 for(unsigned rev=1;rev<=3;rev+=2)for(unsigned uidzero=0;uidzero<2;uidzero++)for(unsigned integrity=0;integrity<3;integrity++)for(retry_mode=0;retry_mode<3;retry_mode++)for(unsigned seed=0;seed<16;seed++){
  make_rom(rev,seed,integrity);struct tb_switch sw={.tb=&tb,.actual_uid=uidzero?0:(0x0123456789abc000ULL|seed),.config={.max_port_number=6}};
  for(unsigned i=0;i<64;i++){sw.ports[i].sw=&sw;sw.ports[i].port=i;sw.ports[i].type=i<=2?TB_TYPE_PORT:i==6?0x0e0101:0;}
  nw=0;ncommands=0;nports=0;na=0;now=0;u16 size;int ret=usb4_switch_read_uid(&sw,&sw.uid);if(ret)abort();ret=usb4_copy_drom(&sw,&size);if(!ret){if(size!=romlen||memcmp(sw.drom,romdata,romlen))abort();ret=tb_drom_parse(&sw,size);}
  printf("D %u %u %u %u %u %"PRIu64" ",rev,uidzero,integrity,retry_mode,seed,sw.actual_uid);hex(romdata,romlen);printf(" %d %u",ret,nw);
  for(unsigned w=0;w<nw;w++)printf(" %u %u",writes[w].offset,writes[w].word);
  printf(" %u",nports);for(unsigned i=0;i<nports;i++)printf(" %u",port_reads[i]);u32 expected;memcpy(&expected,romdata+9,4);
  printf(" %"PRIu64" %u %u %u %u",sw.uid,sw.vendor,sw.device,expected,tb_crc32(romdata+13,romlen-13));
  for(unsigned i=1;i<=6;i++)printf(" %u %u %u",sw.ports[i].disabled,sw.ports[i].link_nr,sw.ports[i].dual_link_port?sw.ports[i].dual_link_port->port:64);
  printf(" ");namehex(sw.vendor_name);printf(" ");namehex(sw.device_name);puts("");if(sw.drom)tb_switch_drom_free(&sw);for(unsigned i=0;i<na;i++)free(allocs[i]);
 }
}
'''

unit = out / "linux-drom.c"
helper_bodies = [(file, name, function(file, name)) for file, name in functions]
unit.write_text("\n".join([prelude, macros, declarations, *[body for _, _, body in helper_bodies], main]))
sha = lambda path: hashlib.sha256(Path(path).read_bytes()).hexdigest()
wrapper = Path(__file__).resolve()
compiler = Path(shutil.which("cc") or sys.exit("C compiler unavailable")).resolve()
version = subprocess.run([str(compiler), "--version"], capture_output=True, text=True, check=True, timeout=10)
exe = out / "linux-drom"
command = [str(compiler), "-std=gnu11", "-O1", "-g", "-fsanitize=address,undefined",
           "-fno-sanitize-recover=all", str(unit.resolve()), "-o", str(exe.resolve())]
environment = dict(os.environ, ASAN_OPTIONS="detect_leaks=1:halt_on_error=1",
                   UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1")
admission = {
    "started_utc": datetime.now(timezone.utc).isoformat(),
    "cwd": str(Path.cwd().resolve()),
    "linux_pin": "cc9de5d4b5ab6459f5774946aa3195ad51236fa8",
    "donors": {str((source/name).resolve()): digest for name, digest in hashes.items()},
    "helpers": [{"file": file, "name": name, "sha256": hashlib.sha256(body.encode()).hexdigest()}
                for file, name, body in helper_bodies],
    "wrapper": {"path": str(wrapper), "sha256": sha(wrapper)},
    "capture": {"path": str(unit.resolve()), "sha256": sha(unit)},
    "python": {"path": str(Path(sys.executable).resolve()), "version": sys.version},
    "compiler": {"path": str(compiler), "sha256": sha(compiler),
                 "version_stdout": version.stdout, "version_stderr": version.stderr},
    "compile_command": command,
    "execution_command": [str(exe.resolve())],
    "sanitizer_environment": {key: environment[key] for key in ["ASAN_OPTIONS", "UBSAN_OPTIONS"]},
    "timeout_seconds": 60,
}
(out / "admission.json").write_text(json.dumps(admission, indent=2)+"\n")
status = {"compile": "not started", "execution": "not started"}
try:
    with (out / "compile.stdout").open("xb") as stdout, (out / "compile.stderr").open("xb") as stderr:
        result = subprocess.run(command, stdout=stdout, stderr=stderr, timeout=60)
        status["compile"] = result.returncode
        result.check_returncode()
    status["binary_before_execution"] = {"path": str(exe.resolve()), "sha256": sha(exe)}
    (out / "execution-admission.json").write_text(json.dumps(status["binary_before_execution"], indent=2)+"\n")
    with trace.open("xb") as stdout, (out / "execution.stderr").open("xb") as stderr:
        result = subprocess.run([str(exe.resolve())], stdout=stdout, stderr=stderr, env=environment, timeout=60)
        status["execution"] = result.returncode
        result.check_returncode()
    status["binary_after_execution_sha256"] = sha(exe)
    status["source_stable"] = all(sha(source/name) == digest for name, digest in hashes.items())
    status["wrapper_stable"] = sha(wrapper) == admission["wrapper"]["sha256"]
    status["capture_stable"] = sha(unit) == admission["capture"]["sha256"]
    status["compiler_stable"] = sha(compiler) == admission["compiler"]["sha256"]
    assert status["source_stable"] and status["wrapper_stable"] and status["capture_stable"] and status["compiler_stable"]
    assert status["binary_after_execution_sha256"] == status["binary_before_execution"]["sha256"]
    assert len(trace.read_text().splitlines()) == 576
    status["trace_sha256"] = sha(trace)
    status["result"] = "PASS"
except BaseException as error:
    status["result"] = "FAIL"
    status["error"] = repr(error)
    raise
finally:
    status["finished_utc"] = datetime.now(timezone.utc).isoformat()
    status["artifacts"] = {p.name: sha(p) for p in out.iterdir() if p.is_file()}
    (out / "status.json").write_text(json.dumps(status, indent=2)+"\n")
print(f"{len(functions)} unchanged functions; {trace}: {status['trace_sha256']}")

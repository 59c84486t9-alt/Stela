#!/usr/bin/env python3
"""Unchanged Linux native USB4 DP resource and DROM block router operations.

Usage: thunderbolt_operations_oracle.py PINNED_THUNDERBOLT_DIRECTORY FRESH_OUTPUT
Register/clock boundaries only; no firmware proxy, physical device or GPU credit.
Source ONS fallback is recorded explicitly, never used to synthesize native grants.
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
hashes = {
    "usb4.c": "bd8b943a5ab4eeb59ad0f8151fd45a748657cd461d945509cef1a029320597e5",
    "switch.c": "981a0e577906feba9a00d4df0546cfeea4de06a8a15e439a686e4c1dc77b6f71",
    "tb_regs.h": "44fa3c1df358a675f23c3fd86af7467fd0541aa8f4822c116d2eb81b0f566300",
}
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
    match = re.search(r"^(?:static )?(?:inline )?(?:int|void|bool|u32|unsigned int|ktime_t)\s+" + name + r"\([^;{}]*?\)\n\{", text, re.M)
    assert match, name
    at, depth = match.end(), 1
    while depth:
        depth += (text[at] == "{") - (text[at] == "}")
        at += 1
    return text[match.start():at]

def declaration(filename, name, packed=False):
    return re.search(re.escape(name) + r" \{.*?\n\}" + (r" __packed;" if packed else ";"), texts[filename], re.S).group()

prelude = r'''// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2019 Intel Corporation
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
typedef uint8_t u8;typedef uint16_t u16;typedef uint32_t u32;typedef uint64_t ktime_t;
#define BIT(n) (1U<<(n))
#define GENMASK(h,l) ((~0U>>(31-(h)))&(~0U<<(l)))
#define TB_CFG_SWITCH 2
struct tb_switch;
struct tb_cm_ops{int(*usb4_switch_op)(struct tb_switch*,u16,u32*,u8*,const void*,size_t,void*,size_t);};
struct tb{const struct tb_cm_ops*cm_ops;};
struct tb_switch{struct tb*tb;u32 metadata,command,data[16];unsigned reads;bool unsupported;u8 status;};
struct tb_port{unsigned port;};
static ktime_t now;
static ktime_t ktime_get(void){return now;}
static ktime_t ktime_add_ms(ktime_t t,int ms){return t+ms;}
static bool ktime_before(ktime_t a,ktime_t b){return a<b;}
static void usleep_range(unsigned a,unsigned b){(void)a;(void)b;now++;}
static unsigned nw;
static struct{unsigned offset,count;u32 data[16];}writes[4];
static int tb_sw_write(struct tb_switch*sw,const void*data,int space,unsigned offset,unsigned count){
 if(space!=TB_CFG_SWITCH||count!=1||nw>=4)abort();writes[nw].offset=offset;writes[nw].count=count;memcpy(writes[nw++].data,data,count*4);
 if(offset==25)memcpy(&sw->metadata,data,4);else if(offset==26){memcpy(&sw->command,data,4);sw->reads=0;}else abort();return 0;
}
static int tb_sw_read(struct tb_switch*sw,void*data,int space,unsigned offset,unsigned count){
 if(space!=TB_CFG_SWITCH||count<1||count>16)abort();
 if(offset==26){if(count!=1)abort();if(sw->command&(1U<<31)){if(++sw->reads>=2){sw->command&=~(1U<<31);if(sw->unsupported)sw->command|=1U<<30;else{sw->command|=(u32)sw->status<<24;sw->metadata^=0xa5000000U;}}}memcpy(data,&sw->command,4);}
 else if(offset==25){if(count!=1)abort();memcpy(data,&sw->metadata,4);}else if(offset==9)memcpy(data,sw->data,count*4);else abort();return 0;
}
'''
macros = "\n".join(line for line in texts["tb_regs.h"].splitlines() if line.startswith("#define ROUTER_CS_"))
macros += "\n" + declaration("tb_regs.h", "enum usb4_switch_op")
macros += "\n" + "\n".join(line for line in texts["usb4.c"].splitlines() if line.startswith(("#define USB4_DROM_", "#define USB4_DATA_DWORDS")))
functions = [("switch.c", "tb_switch_wait_for_bit"), *[("usb4.c", name) for name in [
    "usb4_native_switch_op", "__usb4_switch_op", "usb4_switch_op", "usb4_switch_op_data",
    "usb4_switch_drom_read_block", "usb4_switch_query_dp_resource", "usb4_switch_alloc_dp_resource", "usb4_switch_dealloc_dp_resource"]]]
main = r'''
int main(void){
 const unsigned statuses[]={0,1,31,63};
 const struct tb_cm_ops ops={0};struct tb tb={.cm_ops=&ops};struct tb_port in={.port=6};
 for(unsigned op=0;op<4;op++)for(unsigned unsupported=0;unsupported<2;unsupported++)for(unsigned si=0;si<4;si++)for(unsigned seed=0;seed<16;seed++){
  unsigned status=statuses[si];
  struct tb_switch sw={.tb=&tb,.unsupported=unsupported,.status=status};u32 data[16]={0};unsigned address=(seed*509)%8177,words=1+seed%16;
  for(unsigned n=0;n<16;n++)sw.data[n]=0xab000000U^(seed*0x01010001U)^(n*0x104001U);
  nw=0;now=0;int ret;
  switch(op){case 0:ret=usb4_switch_query_dp_resource(&sw,&in);break;case 1:ret=usb4_switch_alloc_dp_resource(&sw,&in);break;case 2:ret=usb4_switch_dealloc_dp_resource(&sw,&in);break;case 3:ret=usb4_switch_drom_read_block(&sw,address,data,words);break;default:abort();}
  printf("O %u %u %u %u %u %u %d %u",op,unsupported,status,seed,address,words,ret,nw);
  for(unsigned w=0;w<nw;w++){printf(" %u %u",writes[w].offset,writes[w].count);for(unsigned n=0;n<writes[w].count;n++)printf(" %u",writes[w].data[n]);}
  printf(" %u %u",sw.metadata,sw.command);if(op==3)for(unsigned n=0;n<words;n++)printf(" %u",data[n]);puts("");
 }
}
'''

unit = out / "linux-router-operations.c"
helper_bodies = [(file, name, function(file, name)) for file, name in functions]
unit.write_text("\n".join([prelude, macros, *[body for _, _, body in helper_bodies], main]))
sha = lambda path: hashlib.sha256(Path(path).read_bytes()).hexdigest()
wrapper = Path(__file__).resolve()
compiler = Path(shutil.which("cc") or sys.exit("C compiler unavailable")).resolve()
version = subprocess.run([str(compiler), "--version"], capture_output=True, text=True, check=True, timeout=10)
exe = out / "linux-router-operations"
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
    assert len(trace.read_text().splitlines()) == 512
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

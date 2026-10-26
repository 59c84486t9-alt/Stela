#!/usr/bin/env python3
"""Unchanged Linux ordinary USB4v1 DP register transcript, activation to stop.

Usage: thunderbolt_dp_oracle.py PINNED_THUNDERBOLT_DIRECTORY FRESH_OUTPUT
OS scheduling/refcount delivery is captured by a synchronous call to the actual
source DPRX wait helper; no Linux worker or physical/GPU qualification is claimed.
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
    "path.c": "06454cb34668f0d0de261de82e9ecd0e91fa04ce8ad24e7e4e0a99fbbf230aa0",
    "tunnel.c": "386d7e4a12a71e7da48d064cb9f4d14c235e7e1ebb10b01a1e0f11ab76e565e6",
    "switch.c": "981a0e577906feba9a00d4df0546cfeea4de06a8a15e439a686e4c1dc77b6f71",
    "tb_regs.h": "44fa3c1df358a675f23c3fd86af7467fd0541aa8f4822c116d2eb81b0f566300",
    "tb.h": "00cde540109b1d8ad0c0664745f5faa5e87f9e40a2c7ece93e373cc323fc6a94",
    "nhi.h": "f0026407a0005510e34cb331dba9b4a360bb93bdb5c63cd0cec0f2273fdc1e5c",
    "tunnel.h": "3819b77c0a477815c2075c2658027f880bdc6139e85ea1c35cde5d1672a41f69",
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
// Copyright (c) 2014 Andreas Noever <andreas.noever@gmail.com>
// Copyright (C) 2019 Intel Corporation
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
typedef uint8_t u8;typedef uint32_t u32;typedef uint64_t ktime_t;
#define __packed __attribute__((packed))
#define __counted_by(x)
#define BIT(n) (1U<<(n))
#define GENMASK(h,l) ((~0U>>(31-(h)))&(~0U<<(l)))
#define FIELD_GET(mask,val) (((val)&(mask))>>__builtin_ctz(mask))
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#define fallthrough __attribute__((fallthrough))
#define WARN(c,...) ((c)?(abort(),1):0)
#define min(a,b) ((a)<(b)?(a):(b))
#define min_not_zero(a,b) (!(a)?(b):!(b)?(a):min(a,b))
#define max_t(t,a,b) ((t)(a)>(t)(b)?(t)(a):(t)(b))
#define PCI_VENDOR_ID_INTEL 0x8086
#define TB_CFG_HOPS 0
#define TB_CFG_PORT 1
#define ADP_CS_4 4
#define ADP_CS_4_NFC_BUFFERS_MASK 1023U
#define KTIME_MAX UINT64_MAX
#define tb_port_dbg(...) ((void)0)
#define tb_port_warn(...) ((void)0)
#define tb_WARN(...) ((void)0)
#define tb_dbg(...) ((void)0)
#define tb_warn(...) ((void)0)
#define tb_tunnel_dbg(...) ((void)0)
#define tb_tunnel_warn(...) ((void)0)
#define tb_tunnel_info(...) ((void)0)
#define tb_path_for_each_hop(path,hop) for((hop)=(path)->hops;(hop)<&(path)->hops[(path)->path_length];(hop)++)
#define TB_TUNNEL_ACTIVATING 1
#define TB_TUNNEL_ACTIVE 2
#define TB_TUNNEL_INACTIVE 0
#define TB_TUNNEL_ACTIVATED 1
#define TB_TUNNEL_DEACTIVATED 0
struct tb;struct tb_port;
'''
macros = "\n".join(line for line in texts["tb_regs.h"].splitlines()
                   if line.startswith(("#define ADP_DP_", "#define DP_", "#define USB4_VERSION_MAJOR_MASK")))
macros += "\n" + "\n".join(line for line in texts["tunnel.c"].splitlines()
                            if line.startswith(("#define TB_DP_", "#define TB_MIN_DMA_CREDITS", "#define TB_DPRX_")))
macros += "\n" + "\n".join(line for line in texts["nhi.h"].splitlines()
                            if line.startswith("#define PCI_DEVICE_ID_INTEL_TITAN_RIDGE_"))
stubs = r'''
struct tb {int index;};
struct tb_switch {struct tb *tb;unsigned route,generation;bool credit_allocation,is_unplugged;unsigned max_pcie_credits,max_usb3_credits,max_dma_credits,min_dp_aux_credits,min_dp_main_credits;struct{u32 thunderbolt_version,vendor_id,device_id,depth;}config;};
struct tb_port {struct tb_switch *sw;unsigned port,cap_adap,total_credits,ctl_credits;bool lane,bonded,disabled;unsigned reads;struct{u32 nfc_credits;}config;struct tb_regs_hop hop[2];u32 csr[8];unsigned cm_reads,dprx_reads;};
struct tb_tunnel {struct tb*tb;unsigned type;int state,npaths,max_up,max_down;struct tb_port *src_port,*dst_port;struct tb_path *paths[3];int(*pre_activate)(struct tb_tunnel*);int(*activate)(struct tb_tunnel*,bool);void(*post_deactivate)(struct tb_tunnel*);};
static unsigned dma_credits=14;
static bool tb_acpi_may_tunnel_usb3(void){return false;}
static bool tb_acpi_may_tunnel_pcie(void){return false;}
static bool tb_acpi_is_xdomain_allowed(void){return false;}
static bool tb_acpi_may_tunnel_dp(void){return true;}
static bool tb_port_is_null(const struct tb_port*p){return p->lane;}
static bool tb_port_is_dpin(const struct tb_port*p){return !p->lane&&!p->sw->route;}
static bool tb_port_is_dpout(const struct tb_port*p){return !p->lane&&p->sw->route;}
static unsigned tb_route(const struct tb_switch*sw){return sw->route;}
static ktime_t now;static unsigned nw,events;
static struct{unsigned route,port,space,offset,count;u32 words[2];}writes[48];
static ktime_t ktime_get(void){return now;}
static ktime_t ktime_add_ms(ktime_t n,unsigned ms){return n+ms;}
static bool ktime_before(ktime_t a,ktime_t b){return a<b;}
static void usleep_range(unsigned a,unsigned b){(void)a;(void)b;now++;}
static int tb_port_clear_counter(struct tb_port*p,int n){(void)p;(void)n;abort();}
static int usb4_dp_port_set_cm_id(struct tb_port*p,int id){(void)p;(void)id;abort();}
static int tb_dp_bandwidth_alloc_mode_enable(struct tb_tunnel*t){(void)t;abort();}
static bool usb4_dp_port_bandwidth_mode_enabled(struct tb_port*p){(void)p;abort();}
static int usb4_dp_port_set_cm_bandwidth_mode_supported(struct tb_port*p,bool yes){(void)p;(void)yes;abort();}
static void tb_tunnel_event(struct tb*t,unsigned event,unsigned type,struct tb_port*s,struct tb_port*d){(void)t;(void)type;(void)s;(void)d;if(event!=(events==0?TB_TUNNEL_ACTIVATED:TB_TUNNEL_DEACTIVATED))abort();events++;}
static unsigned hop_slot(struct tb_port*p,int offset){if(p->lane)return p->sw->route?(offset==60?0:offset==62?1:(abort(),0)):(offset==64?0:(abort(),0));return offset==16?0:offset==18?1:(abort(),0);}
static int tb_port_read(struct tb_port*p,void*out,int space,int offset,int count){
 if(space==TB_CFG_HOPS){if(count!=2)abort();struct tb_regs_hop*h=&p->hop[hop_slot(p,offset)];if(!h->enable&&++p->reads>=2)h->pending=0;memcpy(out,h,8);return 0;}
 if(space!=TB_CFG_PORT)abort();if(offset==4){if(count!=1)abort();memcpy(out,&p->config.nfc_credits,4);return 0;}
 if(offset<0x50||offset+count>0x58)abort();unsigned at=offset-p->cap_adap;
 if(at==6&&p->csr[6]&DP_STATUS_CTRL_CMHS&&++p->cm_reads>=2)p->csr[6]&=~DP_STATUS_CTRL_CMHS;
 if(at==7&&++p->dprx_reads>=2)p->csr[7]|=DP_COMMON_CAP_DPRX_DONE;
 memcpy(out,p->csr+at,count*4);return 0;
}
static int tb_port_write(struct tb_port*p,const void*in,int space,int offset,int count){
 if(nw>=48||count<1||count>2)abort();writes[nw].route=p->sw->route;writes[nw].port=p->port;writes[nw].space=space;writes[nw].offset=offset;writes[nw].count=count;memcpy(writes[nw++].words,in,count*4);
 if(space==TB_CFG_HOPS){if(count!=2)abort();struct tb_regs_hop*h=&p->hop[hop_slot(p,offset)];memcpy(h,in,8);if(!h->enable)p->reads=0;return 0;}
 if(space!=TB_CFG_PORT)abort();if(offset==4){if(count!=1)abort();memcpy(&p->config.nfc_credits,in,4);return 0;}
 if(offset<0x50||offset+count>0x58)abort();unsigned at=offset-p->cap_adap;memcpy(p->csr+at,in,count*4);if(at==6)p->cm_reads=0;return 0;
}
static int tb_dp_wait_dprx(struct tb_tunnel*t,int timeout);
/* Capture only OS queue/refcount delivery, with actual source register wait. */
static int tb_dp_dprx_start(struct tb_tunnel*t){return tb_dp_wait_dprx(t,25);}
static void tb_dp_dprx_stop(struct tb_tunnel*t){(void)t;}
'''
main = r'''
int main(void){
 static const unsigned budgets[]={0,1296,2160,2592,4320,5184,6480,8640,12960,17280,25920};
 for(unsigned mode=0;mode<2;mode++)for(unsigned stale=0;stale<2;stale++)for(unsigned seed=0;seed<32;seed++){
  struct tb domain={0};
  struct tb_switch sw[2]={{.tb=&domain,.route=0,.generation=4,.credit_allocation=mode,.min_dp_aux_credits=4,.min_dp_main_credits=17,.config={.thunderbolt_version=32,.vendor_id=0x8086,.device_id=0x1234,.depth=0}},{.tb=&domain,.route=2,.generation=4,.credit_allocation=mode,.min_dp_aux_credits=3,.min_dp_main_credits=17,.config={.thunderbolt_version=32,.vendor_id=0x8086,.device_id=0x1234,.depth=1}}};
  struct tb_port ports[4]={{.sw=&sw[0],.port=6,.cap_adap=0x50,.total_credits=100,.bonded=true},{.sw=&sw[0],.port=2,.lane=true,.bonded=true,.total_credits=100,.ctl_credits=8,.config={.nfc_credits=(100U<<20)|8}},{.sw=&sw[1],.port=1,.lane=true,.bonded=true,.total_credits=100,.ctl_credits=8,.config={.nfc_credits=(100U<<20)|8}},{.sw=&sw[1],.port=4,.cap_adap=0x50,.total_credits=100,.bonded=true}};
  u32 initial_ep[4]={(0x00123456U^(seed*0x1001U))&~0xc0000000U,0x789abcd1U^(seed*0x10101U),(0x00567321U^(seed*0x10111U))&~0xc0000000U,0x13579bdfU^(seed*0x10203U)};
  u32 local[2]={(0x0020235aU^(seed*0x01000001U))&~DP_COMMON_CAP_BW_MODE,0x006023a5U^(seed*0x00800001U)};
  ports[0].csr[0]=initial_ep[0];ports[0].csr[1]=initial_ep[1];ports[0].csr[3]=0x00100220;ports[0].csr[4]=local[0];ports[0].csr[6]=0x0015005a;
  ports[3].csr[0]=initial_ep[2];ports[3].csr[1]=initial_ep[3];ports[3].csr[4]=local[1];ports[3].csr[6]=0x004400a5;
  struct tb_path*paths[3];u32 initial[12];
  for(unsigned d=0;d<3;d++){paths[d]=calloc(1,sizeof(*paths[d])+2*sizeof(paths[d]->hops[0]));if(!paths[d])abort();paths[d]->path_length=2;
   for(unsigned i=0;i<2;i++){struct tb_port*in=&ports[d==2?(i?1:3):(i?2:0)];struct tb_port*out=&ports[d==2?(i?0:2):(i?3:1)];unsigned s=seed+d*2;u32 raw[2]={((0x12345678U^(s*0x104001U)^(i*0x13579U))&~0x80000000U)|(stale?0x80000000U:0),(0xabcdef12U^(s*0x104101U)^(i*0x13579U))|(stale?0x10000000U:0)};memcpy(initial+d*4+i*2,raw,8);unsigned ingress=i?30+d:(d?8:9),next=i?(d?8:9):30+d;memcpy(&in->hop[hop_slot(in,ingress*2)],raw,8);paths[d]->hops[i]=(struct tb_path_hop){.in_port=in,.out_port=out,.in_hop_index=ingress,.next_hop_index=next,.in_counter_index=-1};}
   if(d){tb_dp_init_aux_path(paths[d],false);}else if(tb_dp_init_video_path(paths[d],false))abort();
  }
  struct tb_tunnel t={.tb=&domain,.npaths=3,.max_down=budgets[seed%11],.src_port=&ports[0],.dst_port=&ports[3],.paths={paths[0],paths[1],paths[2]},.pre_activate=tb_dp_pre_activate,.activate=tb_dp_activate,.post_deactivate=tb_dp_post_deactivate};
  nw=0;now=0;events=0;if(tb_tunnel_activate(&t)||t.state!=TB_TUNNEL_ACTIVE||events!=1)abort();tb_tunnel_deactivate(&t);if(t.state!=TB_TUNNEL_INACTIVE||events!=2)abort();
  printf("D %u %u %u %u",mode,stale,seed,budgets[seed%11]);for(unsigned i=0;i<4;i++)printf(" %u",initial_ep[i]);for(unsigned i=0;i<2;i++)printf(" %u",local[i]);for(unsigned i=0;i<12;i++)printf(" %u",initial[i]);printf(" %u",nw);
  for(unsigned i=0;i<nw;i++){printf(" %u %u %u %u %u",writes[i].route,writes[i].port,writes[i].space,writes[i].offset,writes[i].count);for(unsigned j=0;j<writes[i].count;j++)printf(" %u",writes[i].words[j]);}
  printf(" %u %u %u %u %u %u %u %u",ports[0].csr[5],ports[3].csr[5],ports[0].csr[0],ports[0].csr[1],ports[3].csr[0],ports[3].csr[1],ports[2].config.nfc_credits,ports[0].csr[7]);
  for(unsigned d=0;d<3;d++)for(unsigned i=0;i<2;i++){u32 final[2];memcpy(final,&paths[d]->hops[i].in_port->hop[hop_slot(paths[d]->hops[i].in_port,paths[d]->hops[i].in_hop_index*2)],8);printf(" %u %u",final[0],final[1]);}puts("");for(unsigned d=0;d<3;d++)free(paths[d]);
 }
}
'''
functions = [
    *[("tb.h", n) for n in ["usb4_switch_version", "tb_switch_is_usb4", "tb_switch_is_titan_ridge", "tb_port_use_credit_allocation", "tb_port_path_direction_downstream"]],
    ("tunnel.h", "tb_tunnel_direction_downstream"),
    ("switch.c", "tb_port_add_nfc_credits"),
    *[("path.c", n) for n in ["tb_dump_hop", "__tb_path_deallocate_nfc", "__tb_path_deactivate_hop", "__tb_path_deactivate_hops", "tb_path_activate", "tb_path_deactivate"]],
    *[("usb4.c", n) for n in ["is_usb4_dpin", "usb4_dp_port_bandwidth_mode_supported"]],
    *[("switch.c", n) for n in ["tb_dp_port_set_hops", "tb_dp_port_enable", "tb_dp_port_hpd_clear"]],
    *[("tunnel.c", n) for n in ["tb_usable_credits", "tb_available_credits", "tb_init_pm_support", "tb_dp_is_usb4", "tb_dp_cm_handshake", "tb_dp_cap_get_rate", "tb_dp_is_uhbr_rate", "tb_dp_cap_set_rate", "tb_dp_cap_get_lanes", "tb_dp_cap_set_lanes", "tb_dp_bandwidth", "tb_dp_reduce_bandwidth", "tb_dp_xchg_caps", "tb_dp_pre_activate", "tb_dp_post_deactivate", "dprx_timeout_to_ktime", "tb_dp_wait_dprx", "tb_dp_activate", "tb_dp_init_aux_credits", "tb_dp_init_aux_path", "tb_dp_init_video_credits", "tb_dp_init_video_path", "tb_tunnel_set_active", "tb_tunnel_deactivate", "tb_tunnel_activate"]],
]
unit = out / "linux-dp-tunnel.c"
helper_bodies = [(file, name, function(file, name)) for file, name in functions]
unit.write_text("\n".join([
    prelude, macros, declaration("tb_regs.h", "struct tb_regs_hop", True),
    declaration("tb.h", "struct tb_path_hop"), declaration("tb.h", "enum tb_path_port"),
    declaration("tb.h", "struct tb_path"), stubs,
    *[body for _, _, body in helper_bodies], main,
]))
sha = lambda path: hashlib.sha256(Path(path).read_bytes()).hexdigest()
wrapper = Path(__file__).resolve()
compiler = Path(shutil.which("cc") or sys.exit("C compiler unavailable")).resolve()
version = subprocess.run([str(compiler), "--version"], capture_output=True, text=True, check=True, timeout=10)
exe = out / "linux-dp-tunnel"
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
    assert len(trace.read_text().splitlines()) == 128
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

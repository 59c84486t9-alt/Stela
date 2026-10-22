#!/usr/bin/env python3
"""Execute unchanged Linux Gen2/3 two-ended bonding/credit/configure helpers.

Usage: thunderbolt_link_oracle.py PINNED_SOURCE_DIRECTORY FRESH_OUTPUT_DIRECTORY
Actual helper bodies and register structs run with explicit observed reciprocal
port pointers and hardware/clock captures. Only normal Gen2/3 USB4-router paths
are covered, not LC/Gen4/asym/recovery, native discovery or security providers.
"""
import hashlib
from pathlib import Path
import re
import subprocess
import sys
source,out=map(Path,sys.argv[1:])
hashes={
 "switch.c":"cb3e11c220daa808183d072415e1904ea1b5bcf44ad37bb9db869e36a4b65c66",
 "usb4.c":"bd8b943a5ab4eeb59ad0f8151fd45a748657cd461d945509cef1a029320597e5",
 "tb_regs.h":"44fa3c1df358a675f23c3fd86af7467fd0541aa8f4822c116d2eb81b0f566300",
 "tb.h":"eb885b01adee9ec24cf5cdc4c3aecf5ecd7dc6b5a84c9f300c42af6f9c41db7c",
 "include_linux_thunderbolt.h":"77314f7a9762cbd0296024a1cfe7a1fc54c9ef2568db0229ad614758e1cd22eb",
}
texts={}
for name,digest in hashes.items():
 raw=(source/name).read_bytes();assert hashlib.sha256(raw).hexdigest()==digest,name;texts[name]=raw.decode()
trace=out/"trace.txt"
if trace.exists():raise SystemExit("refusing to replace historical trace; select fresh output")
out.mkdir(parents=True,exist_ok=True)
def function(filename,name):
 text=texts[filename];match=re.search(r"^(?:static )?(?:inline )?(?:void|int|bool|unsigned int)\s+"+name+r"\([^;{}]*?\)\n\{",text,re.M);assert match,name
 at,depth=match.end(),1
 while depth:depth+=(text[at]=="{")-(text[at]=="}");at+=1
 return text[match.start():at]
def declaration(filename,name,packed=False):
 return re.search(re.escape(name)+r" \{.*?\n\}"+(r" __packed;"if packed else ";"),texts[filename],re.S).group()
macros="\n".join(line for line in texts["tb_regs.h"].splitlines()if line.startswith(("#define LANE_ADP_CS_","#define ADP_CS_4","#define PORT_CS_18","#define PORT_CS_19","#define USB4_VERSION_MAJOR_MASK")))
prelude=r'''// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2014 Andreas Noever <andreas.noever@gmail.com>
// Copyright (C) 2018-2019 Intel Corporation
// Authors: Mika Westerberg <mika.westerberg@linux.intel.com>
//          Rajmohan Mani <rajmohan.mani@intel.com>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
typedef uint8_t u8;typedef uint16_t u16;typedef uint32_t u32;typedef uint64_t u64;typedef uint64_t ktime_t;
#define __packed __attribute__((packed))
#define BIT(n) (1U<<(n))
#define GENMASK(h,l) ((~0U>>(31-(h)))&(~0U<<(l)))
#define FIELD_GET(mask,value) (((value)&(mask))>>__builtin_ctz(mask))
#define tb_port_WARN(...) ((void)0)
#define tb_port_warn(...) ((void)0)
#define tb_port_dbg(...) ((void)0)
#define tb_sw_warn(...) ((void)0)
#define tb_sw_dbg(...) ((void)0)
#define TB_CFG_PORT 1
#define KOBJ_CHANGE 1
'''
stubs=r'''
struct tb_switch;
struct tb_port{struct tb_switch *sw;struct tb_port *remote,*dual_link_port;unsigned port,cap_phy,cap_usb4,total_credits;struct tb_regs_port_header config;bool bonded,mode;u32 phy[2],credit,pc;};
struct device{int kobj;};
struct tb_switch{struct tb_regs_switch_header config;struct tb_port ports[6];struct tb_switch *parent;struct device dev;unsigned downport,side;u32 link_speed;enum tb_link_width link_width;};
static struct tb_switch switches[2];
static bool bonding;
static unsigned bonded_reads;
static ktime_t now;
static unsigned nw;
static struct{unsigned side,port,offset;u32 value;}writes[16];
static bool tb_is_upstream_port(const struct tb_port*p){return p->port==p->sw->config.upstream_port_number;}
static struct tb_port *tb_upstream_port(struct tb_switch*sw){return &sw->ports[sw->config.upstream_port_number];}
static struct tb_port *tb_switch_downstream_port(struct tb_switch*sw){return &sw->parent->ports[sw->downport];}
static u64 tb_route(struct tb_switch*sw){return sw->config.route_lo;}
static bool tb_switch_is_icm(struct tb_switch*sw){(void)sw;return false;}
static bool tb_lc_lane_bonding_possible(struct tb_switch*sw){(void)sw;return false;}
static int tb_lc_configure_port(struct tb_port*p){(void)p;return -EOPNOTSUPP;}
static bool usb4_port_asym_supported(struct tb_port*p){(void)p;return false;}
static int usb4_port_asym_set_link_width(struct tb_port*p,enum tb_link_width w){(void)p;(void)w;return -EOPNOTSUPP;}
static int tb_switch_asym_enable(struct tb_switch*sw,enum tb_link_width w){(void)sw;(void)w;return -EOPNOTSUPP;}
static int tb_switch_asym_disable(struct tb_switch*sw){(void)sw;return -EOPNOTSUPP;}
static bool device_is_registered(struct device*d){(void)d;return false;}
static void kobject_uevent(int*k,int event){(void)k;(void)event;abort();}
static ktime_t ktime_get(void){return now;}
static ktime_t ktime_add_ms(ktime_t n,unsigned ms){return n+ms;}
static bool ktime_before(ktime_t a,ktime_t b){return a<b;}
static void usleep_range(unsigned a,unsigned b){(void)a;(void)b;now++;}
static void msleep(unsigned ms){now+=ms;}
static struct tb_port *lanes[4];
static void complete_bond(void){for(unsigned i=0;i<4;i++){lanes[i]->phy[1]=(lanes[i]->phy[1]&~LANE_ADP_CS_1_CURRENT_WIDTH_MASK)|(2U<<20);lanes[i]->credit+=32U<<20;}bonding=false;}
static int tb_port_read(struct tb_port*p,void*out,int space,unsigned offset,unsigned count){
 if(space!=1)abort();
 if(offset==9&&p==lanes[2]&&bonding&&++bonded_reads>=2)complete_bond();
 if(offset==8&&count==2)memcpy(out,p->phy,8);
 else if(offset==8&&count==1)memcpy(out,&p->phy[0],4);
 else if(offset==9&&count==1)memcpy(out,&p->phy[1],4);
 else if(offset==4&&count==1)memcpy(out,&p->credit,4);
 else if(offset==0x42&&count==1){u32 value=PORT_CS_18_BE|(p->mode?PORT_CS_18_TCM:0);memcpy(out,&value,4);}
 else if(offset==0x43&&count==1)memcpy(out,&p->pc,4);else abort();return 0;
}
static int tb_port_write(struct tb_port*p,const void*in,int space,unsigned offset,unsigned count){
 if(space!=1||count!=1||nw>=16)abort();u32 value;memcpy(&value,in,4);
 writes[nw].side=p->sw->side;writes[nw].port=p->port;writes[nw].offset=offset;writes[nw++].value=value;
 if(offset==9){p->phy[1]=value;if(p==lanes[2]&&(value&LANE_ADP_CS_1_LB)){bonding=true;bonded_reads=0;}}
 else if(offset==0x43)p->pc=value;else abort();return 0;
}
'''
main=r'''
int main(void){
 for(unsigned map=0;map<2;map++)for(unsigned gen=2;gen<=3;gen++)for(unsigned dual=0;dual<2;dual++)for(unsigned mode=0;mode<2;mode++)for(unsigned seed=0;seed<32;seed++){
  memset(switches,0,sizeof(switches));struct tb_switch*up=&switches[0],*down=&switches[1];
  up->side=0;down->side=1;up->parent=down;up->downport=map?2:1;
  up->config.upstream_port_number=1;up->config.route_lo=up->downport;up->config.thunderbolt_version=32;down->config.thunderbolt_version=32;
  up->link_width=dual?TB_LINK_WIDTH_DUAL:TB_LINK_WIDTH_SINGLE;
  unsigned ports[4]={1,map?3:2,map?2:1,map?5:2};
  lanes[0]=&up->ports[ports[0]];lanes[1]=&up->ports[ports[1]];lanes[2]=&down->ports[ports[2]];lanes[3]=&down->ports[ports[3]];
  u32 init[4],credits[4],pcs[2],cap[4];
  for(unsigned i=0;i<4;i++){
   struct tb_port*p=lanes[i];p->sw=i<2?up:down;p->port=ports[i];p->cap_phy=8;p->cap_usb4=(i%2)?0:0x30;p->mode=mode;
   p->dual_link_port=lanes[i^1];p->remote=lanes[i^2];
   u32 word=(0x104234abU^(seed*0x01804109U)^(i*0x01010001U))&~(0xfU<<16|0x3fU<<20|0xfU<<26|0x30U|0xc000U);
   word|=(gen==2?8U:4U)<<16;word|=(dual?2U:1U)<<20;word|=2U<<26;word|=1U<<4;if(dual&&i==2)word|=LANE_ADP_CS_1_LB;
   p->phy[0]=((i%2)?0x100U:0x130U)|(2U<<20)|((gen==2?8U:12U)<<16)|(mode?0x80000000U:0);p->phy[1]=word;
   p->credit=((64+seed+i)<<20)|(8+(seed+i)%4);p->config.nfc_credits=0;p->total_credits=0;
   p->pc=0x14050101U^(seed*0x10001U);init[i]=word;credits[i]=p->credit;cap[i]=p->phy[0];
  }
  pcs[0]=lanes[0]->pc;pcs[1]=lanes[2]->pc;bonding=false;bonded_reads=0;now=0;nw=0;
  if(tb_switch_set_link_width(up,TB_LINK_WIDTH_DUAL)||tb_switch_configure_link(up))abort();
  printf("L %u %u %u %u %u",map,gen,dual,mode,seed);
  for(unsigned i=0;i<4;i++)printf(" %u",cap[i]);for(unsigned i=0;i<4;i++)printf(" %u",init[i]);for(unsigned i=0;i<4;i++)printf(" %u",credits[i]);
  printf(" %u %u",pcs[0],pcs[1]);for(unsigned i=0;i<4;i++)printf(" %u",lanes[(unsigned[]){2,3,0,1}[i]]->config.nfc_credits);
  printf(" %u",nw);for(unsigned i=0;i<nw;i++)printf(" %u %u %u %u",writes[i].side,writes[i].port,writes[i].offset,writes[i].value);puts("");
 }
}
'''
functions=[("tb.h","usb4_switch_version"),("tb.h","tb_switch_is_usb4"),
 *[("switch.c",name)for name in ["tb_port_state","tb_wait_for_port","tb_port_get_link_speed","tb_port_get_link_generation","tb_port_get_link_width","tb_port_width_supported","tb_port_set_link_width","tb_port_set_lane_bonding","tb_port_lane_bonding_enable","tb_port_lane_bonding_disable","tb_port_wait_for_link_width","tb_port_do_update_credits","tb_port_update_credits"]],
 ("usb4.c","usb4_switch_lane_bonding_possible"),
 *[("switch.c",name)for name in ["tb_switch_lane_bonding_possible","tb_switch_lane_bonding_enable","tb_switch_lane_bonding_disable","tb_switch_update_link_attributes","tb_switch_set_link_width"]],
 ("usb4.c","usb4_port_set_configured"),("usb4.c","usb4_port_configure"),("switch.c","tb_switch_configure_link")]
parts=[prelude,declaration("tb_regs.h","enum tb_port_type"),declaration("tb_regs.h","enum tb_port_state"),declaration("include_linux_thunderbolt.h","enum tb_link_width"),declaration("tb_regs.h","struct tb_cap_basic",True),declaration("tb_regs.h","struct tb_cap_phy",True),declaration("tb_regs.h","struct tb_regs_switch_header",True),declaration("tb_regs.h","struct tb_regs_port_header",True),macros,stubs,*[function(file,name)for file,name in functions],main]
unit=out/"linux-thunderbolt-link.c";unit.write_text("\n".join(parts));exe=out/"linux-thunderbolt-link"
subprocess.run(["cc","-std=gnu11","-O1","-g","-fsanitize=address,undefined",str(unit),"-o",str(exe)],check=True)
with trace.open("wb")as stream:subprocess.run([str(exe.resolve())],stdout=stream,check=True)
print(f"{len(functions)} unchanged helpers; {trace}: {hashlib.sha256(trace.read_bytes()).hexdigest()}")

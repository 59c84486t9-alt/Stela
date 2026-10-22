#!/usr/bin/env python3
"""Run unchanged pinned AX88772 reset and MII command helpers under sanitizers.

The harness supplies a synthetic embedded PHY, control replies and elapsed-time
recording. No Linux kernel, PHY framework lifecycle or physical proof is implied.
Generated tools/traces stay ignored under .stela.
"""
import hashlib
from pathlib import Path
import re
import subprocess
import sys
common,devices,header,out=map(Path,sys.argv[1:])
for p,digest in [(common,"2174300347b7ee862d3ed24fe5ba7423a45111377d6232acbc812ea1cc3706f8"),(devices,"b908ea9c09c7981c215c6ed2647b8facb83fa4b676e1cefda2b135968cfbb00a"),(header,"4d04e4b63d0884bce00d5d8a8bf01504e4114b844d875d2bc79dc24f6d29b278")]:
 assert hashlib.sha256(p.read_bytes()).hexdigest()==digest
out.mkdir(parents=True,exist_ok=True)
def function(p,name):
 text=p.read_text();m=re.search(r"^(?:static )?(?:int|u16|void|int __must_check)[^;{}]*?\b"+name+r"\([^;{}]*?\)\n\{",text,re.M);assert m,name
 at,depth=m.end(),1
 while depth:
  depth+=(text[at]=="{")-(text[at]=="}");at+=1
 return text[m.start():at]
def defines(text):
 result=[];continuation=False
 for line in text.splitlines():
  if line.startswith("#define") or continuation:
   result.append(line);continuation=line.endswith("\\")
 return "\n".join(result)
names=["asix_read_cmd","asix_write_cmd","asix_set_sw_mii","asix_set_hw_mii","asix_check_host_enable","asix_sw_reset","asix_read_rx_ctl","asix_write_rx_ctl","asix_read_medium_status","asix_write_medium_mode","asix_write_gpio","__asix_mdio_read","__asix_mdio_write","asix_mdio_read_nopm","asix_mdio_write_nopm"]
prelude=r'''// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2003-2006 David Hollis; 2005 Phil Chang;
// 2006 James Painter; 2002-2003 TiVo Inc.
#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
typedef uint8_t u8;typedef uint16_t u16;typedef uint16_t __u16;typedef uint16_t __le16;
#define __must_check
#define USB_DIR_IN 0x80
#define USB_DIR_OUT 0
#define USB_TYPE_VENDOR 0x40
#define USB_RECIP_DEVICE 0
#define BUG_ON(x) assert(!(x))
#define unlikely(x) (x)
#define netdev_warn(...) ((void)0)
#define netdev_err(...) ((void)0)
#define netdev_dbg(...) ((void)0)
#define mutex_lock(x) ((void)(x))
#define mutex_unlock(x) ((void)(x))
#define le16_to_cpu(x) (x)
#define cpu_to_le16(x) (x)
#define MII_PHYSID1 2
#define ETH_ALEN 6
struct usbnet;
struct net_device {unsigned char dev_addr[6];struct usbnet*owner;};
struct asix_common_private {int embd_phy;u8 chipcode;};
struct usbnet {struct net_device*net;struct asix_common_private*driver_priv;unsigned long data[5];int phy_mutex;struct{int phy_id;}mii;};
#define netdev_priv(n) ((n)->owner)
#define ether_addr_copy(d,s) memcpy(d,s,6)
static u16 phy[32],rx,medium;static unsigned grants,code;static char queries[65536];static unsigned query_len;static unsigned delays[256],delay_n;
static void delay(unsigned us){assert(delay_n<256);delays[delay_n++]=us;}
#define usleep_range(a,b) delay(a)
#define msleep(ms) delay((ms)*1000)
static void query(u8 type,u8 cmd,u16 v,u16 i,u16 n,const void*data){
 const u8 q[]={type,cmd,v,v>>8,i,i>>8,n,n>>8};
 for(unsigned j=0;j<8;j++)query_len+=sprintf(queries+query_len,"%02x",q[j]);
 query_len+=sprintf(queries+query_len,":");
 if(data)for(unsigned j=0;j<n;j++)query_len+=sprintf(queries+query_len,"%02x",((const u8*)data)[j]);
 query_len+=sprintf(queries+query_len,";");
 assert(query_len<sizeof queries-1024);
}
static int usbnet_read_cmd(struct usbnet*d,u8 cmd,u8 type,u16 v,u16 i,void*out,u16 n){
 (void)d;query(type,cmd,v,i,n,NULL);
 if(cmd==9){u8 x=code|(grants>=3);assert(n==1);memcpy(out,&x,1);}
 else if(cmd==7){assert(v==16&&i<32&&n==2);memcpy(out,&phy[i],2);}
 else if(cmd==15)memcpy(out,&rx,2);
 else if(cmd==26)memcpy(out,&medium,2);
 else assert(0);
 return n;
}
static int usbnet_write_cmd(struct usbnet*d,u8 cmd,u8 type,u16 v,u16 i,const void*data,u16 n){
 (void)d;query(type,cmd,v,i,n,data);
 if(cmd==6)grants++;else if(cmd==10)grants=0;
 else if(cmd==8){assert(v==16&&i<32&&n==2);memcpy(&phy[i],data,2);}
 else if(cmd==16)rx=v;else if(cmd==27)medium=v;
 return n;
}
#define usbnet_read_cmd_nopm usbnet_read_cmd
#define usbnet_write_cmd_nopm usbnet_write_cmd
'''
# The data layout is copied whole and unchanged, rather than re-encoding fields.
structure=re.search(r"struct asix_data \{.*?\n\};",header.read_text(),re.S).group()
main=r'''
int main(void){
 for(code=0;code<=0x20;code+=0x10)for(unsigned mask=0;mask<8;mask++){
  memset(phy,0,sizeof phy);rx=medium=grants=query_len=delay_n=0;
  const u16 defaults[]={0x442c,0x03c8,0x4044};for(unsigned j=0;j<3;j++)phy[0x14+j]=mask&(1<<j)?defaults[j]:0;
  struct asix_common_private p={.embd_phy=1,.chipcode=code};struct net_device net={.dev_addr={2,0x27,0x72,0x43,0x54,0x65}};
  struct usbnet d={.net=&net,.driver_priv=&p,.mii={.phy_id=16}};net.owner=&d;
  int ret=code?ax88772a_hw_reset(&d,0):ax88772_hw_reset(&d,0);assert(!ret);
  printf("%u %u %s ",code,mask,queries);for(unsigned j=0;j<delay_n;j++)printf("%s%u",j?",":"",delays[j]);puts("");
 }
}
'''
unit=out/"linux-asix-legacy-reset.c"
unit.write_text(prelude+defines(header.read_text().split("/* This structure")[0])+"\n#define AX_HOST_EN_RETRIES 30\n"+defines(devices.read_text().split("static int ax88172_link_reset")[0])+"\n"+structure+"\n"+"\n".join(function(common,n)for n in names)+"\n"+"\n".join(function(devices,n)for n in ["ax88772_hw_reset","ax88772a_hw_reset"])+main)
exe=out/"linux-asix-legacy-reset"
subprocess.run(["cc","-std=gnu11","-O1","-g","-fsanitize=address,undefined",str(unit),"-o",str(exe)],check=True)
with(out/"trace.txt").open("wb")as f:subprocess.run([str(exe.resolve())],stdout=f,check=True)
print(out/"trace.txt")

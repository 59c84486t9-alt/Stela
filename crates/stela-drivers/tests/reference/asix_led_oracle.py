#!/usr/bin/env python3
"""Execute unchanged pinned ASIX command/EEPROM/LED/MMD helpers.

Generated C, binaries and immutable field traces belong under ignored .stela.
The device register storage and Linux logging/time services are harness code;
this is a field-effect oracle, not a physical/full-driver qualification.
"""
import hashlib
from pathlib import Path
import re
import subprocess
import sys
source,mii,out=map(Path,sys.argv[1:4])
link_mode=len(sys.argv)==5 and sys.argv[4]=="--link"
checksum_mode=len(sys.argv)==5 and sys.argv[4]=="--checksums"
assert hashlib.sha256(source.read_bytes()).hexdigest()=="fa49b818e1051cf13e765792a8a386aa828e4ac9bd516f16c2b134c6edf6a6c8"
assert hashlib.sha256(mii.read_bytes()).hexdigest()=="b0260b7f7d093788954660a8cdc3eda738673690604e7528db121c860c3905ae"
text=source.read_text();out.mkdir(parents=True,exist_ok=True)
def function(name):
 m=re.search(r"^static[^;{}]*?\b"+name+r"\([^;{}]*?\)\n\{",text,re.M);assert m,name
 at,depth=m.end(),1
 while depth:
  depth+=(text[at]=="{")-(text[at]=="}");at+=1
 return text[m.start():at]
names=["ax88179_in_pm","__ax88179_read_cmd","__ax88179_write_cmd","ax88179_read_cmd","ax88179_write_cmd","ax88179_auto_detach","ax88179_phy_mmd_indirect","ax88179_phy_read_mmd_indirect","ax88179_phy_write_mmd_indirect","ax88179_disable_eee","ax88179_check_eeprom","ax88179_check_efuse","ax88179_convert_old_led","ax88179_led_setting"]
defines="\n".join(line.strip() for line in text[:text.index("static int ax88179_reset")].splitlines() if line.lstrip().startswith("#define"))
for name in ["MII_PHYADDR","MII_MMD_CTRL","MII_MMD_DATA","MII_MMD_CTRL_NOINCR"]:
 defines+="\n"+re.search(r"^#define\s+"+name+r"\b[^\n]*",mii.read_text(),re.M).group()
structure=re.search(r"struct ax88179_data \{.*?\n\};",text,re.S).group()
prelude=r'''// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2011-2013 ASIX
// Numeric MII definitions: GPL-2.0 WITH Linux-syscall-note,
// Copyright (C) 1996, 1999, 2001 David S. Miller.
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
typedef uint8_t u8;typedef uint16_t u16;typedef uint32_t u32;
#define BIT(n) (1U<<(n))
#define HZ 1000
#define USB_DIR_IN 0x80
#define USB_DIR_OUT 0
#define USB_TYPE_VENDOR 0x40
#define USB_RECIP_DEVICE 0
#define BUG_ON(x) ((void)(x))
#define unlikely(x) (x)
#define netdev_warn(...) ((void)0)
#define le16_to_cpus(p) ((void)0)
#define le32_to_cpus(p) ((void)0)
#define cpu_to_le16s(p) ((void)0)
#define time_after(a,b) ((a)>(b))
static unsigned long ticks;
#define jiffies (++ticks)
struct net_device {unsigned mtu;};
struct usbnet {void *driver_priv;struct net_device *net;unsigned rx_urb_size;};
static unsigned fifo;
static int ax88179_chk_eee(struct usbnet*d){(void)d;return 0;}
#define netdev_info(...) ((void)0)
#define netif_carrier_on(n) ((void)(n))
static u8 mac[256],efuse[64];static u16 eeprom[256],phy[8][64][32],mmd[32][64];
static u16 page,bank,mmd_control,mmd_address;static unsigned srom_busy;
static int usbnet_read_cmd(struct usbnet*d,u8 cmd,u8 type,u16 value,u16 index,void*out,u16 n){
 (void)d;(void)type;
 if(cmd==1){
  if(value==0x0a&&srom_busy&&!--srom_busy){mac[0x0a]&=~0x10;memcpy(&mac[8],&eeprom[mac[7]],2);}
  memcpy(out,&mac[value],n);
 }else if(cmd==4)memcpy(out,&eeprom[value],n);
 else if(cmd==5)memcpy(out,efuse,n);
 else if(cmd==2){
  u16 v=index==31?page:index==30?bank:(page==0&&index==14&&(mmd_control&0x4000))?mmd[mmd_control&31][mmd_address]:phy[page][page==7?bank:0][index];
  memcpy(out,&v,n);
 }else if(cmd==0x81){u32 status=fifo?0x40000000:0;if(fifo)fifo--;memcpy(out,&status,n);}
 else return -EINVAL;
 return n;
}
static int usbnet_write_cmd(struct usbnet*d,u8 cmd,u8 type,u16 value,u16 index,const void*input,u16 n){
 (void)d;(void)type;(void)value;
 if(cmd==1){memcpy(&mac[value],input,n);if(value==0x0a&&(*(const u8*)input&4)){srom_busy=3;mac[0x0a]|=0x10;}}
 else if(cmd==2){u16 v;memcpy(&v,input,2);
  if(index==31)page=v;else if(index==30)bank=v;
  else if(page==0&&index==13)mmd_control=v;
  else if(page==0&&index==14){if(mmd_control&0x4000)mmd[mmd_control&31][mmd_address]=v;else mmd_address=v;}
  else phy[page][page==7?bank:0][index]=v;
 }else return -EINVAL;
 return n;
}
#define usbnet_read_cmd_nopm usbnet_read_cmd
#define usbnet_write_cmd_nopm usbnet_write_cmd
'''
main=r'''
static void run(unsigned kind,unsigned raw,unsigned ua2,unsigned detach){
 struct ax88179_data a={0};struct usbnet d={.driver_priv=&a};u16 data;
 memset(mac,0,sizeof mac);memset(phy,0,sizeof phy);memset(mmd,0,sizeof mmd);
 memset(eeprom,0xff,sizeof eeprom);memset(efuse,0xff,sizeof efuse);
 page=bank=mmd_control=mmd_address=0;ticks=srom_busy=0;
 mac[3]=ua2?4:0;mac[0x33]=3;data=0x20;memcpy(&mac[0x26],&data,2);
 eeprom[0x43]=detach?0x100:0xffff;eeprom[0x3c]=raw<<8;
 if(kind==0){memset(eeprom,0,sizeof eeprom);eeprom[5]=0xff;eeprom[0x42]=raw;eeprom[0x43]=detach?0x100:0xffff;eeprom[0x3c]=0xff00;}
 if(kind==1){memset(efuse,0,sizeof efuse);efuse[51]=raw>>8;efuse[52]=raw;efuse[63]=255-((efuse[51]+efuse[52])%255);}
 phy[7][0x2c][0x1a]=0xa55a;phy[7][0x2c][0x1c]=0x5aa5;
 if(ax88179_auto_detach(&d)||ax88179_led_setting(&d))__builtin_trap();
 ax88179_disable_eee(&d);
 if(ax88179_phy_write_mmd_indirect(&d,0x3c,7,0))__builtin_trap();
 unsigned adv=ax88179_phy_read_mmd_indirect(&d,0x3c,7);
 memcpy(&data,&mac[0x26],2);
 printf("%u %u %u %u %u %u %u %u %u %u %u %u %u\n",kind,raw,ua2,detach,phy[7][0x2c][0x1a],phy[7][0x2c][0x1c],mac[0x73],mac[0x25],mac[0x33],data,phy[3][0][0x19],adv,page);
}
int main(void){
 for(unsigned raw=0;raw<65536;raw++)run(0,raw,raw&1,!!(raw&2));
 for(unsigned ua2=0;ua2<2;ua2++)for(unsigned d=0;d<2;d++){
  unsigned values[]={0x8000,0x8c23,0,0xffff};for(unsigned i=0;i<4;i++)run(1,values[i],ua2,d);
  for(unsigned old=0;old<256;old++)run(2,old,ua2,d);
 }
 return 0;
}
'''
if checksum_mode:
 main=r'''
int main(void){
 struct ax88179_data a={0};struct usbnet d={.driver_priv=&a};
 for(unsigned kind=0;kind<2;kind++){
  unsigned n=kind?64:12;u8 original[64]={0};
  if(kind){original[51]=0x8c;original[52]=0x23;original[63]=0x50;}else original[10]=0xff;
  for(unsigned at=0;at<=n;at++)for(unsigned bit=0;bit<(at==n?1:9);bit++){
   u8 data[64];memcpy(data,original,n);if(at<n)data[at]^=bit==8?0xff:1<<bit;
   memset(eeprom,0,sizeof eeprom);memcpy(eeprom,data,kind?0:n);memcpy(efuse,data,kind?n:0);ticks=srom_busy=0;
   u16 led=0;unsigned valid=(kind?ax88179_check_efuse(&d,&led):ax88179_check_eeprom(&d))==0;
   printf("%u ",kind);for(unsigned i=0;i<n;i++)printf("%02x",data[i]);printf(" %u\n",valid);
  }
 }
 return 0;
}
'''
if link_mode:
 names.append("ax88179_link_reset")
 structure+="\n"+re.search(r"static const struct \{\n\s*unsigned char ctrl.*?\n\};",text,re.S).group()
 main=r'''
int main(void){
 const unsigned buses[]={0,2,4,6},speeds[]={0,0x4000,0x8000};
 for(unsigned b=0;b<4;b++)for(unsigned s=0;s<3;s++)for(unsigned f=0;f<2;f++){
  struct ax88179_data a={.rxctl=0x3aa};struct net_device n={1500};struct usbnet d={.driver_priv=&a,.net=&n};
  memset(mac,0,sizeof mac);memset(phy,0,sizeof phy);page=bank=0;ticks=0;fifo=3;
  mac[2]=buses[b];unsigned status=speeds[s]|(f?0x2000:0)|0x400;phy[0][0][0x11]=status;
  if(ax88179_link_reset(&d))return 1;
  u16 mode;memcpy(&mode,&mac[0x22],2);
  printf("%u %u %u",buses[b],status,mode);
  for(unsigned j=0;j<5;j++)printf(" %u",mac[0x2e + j]);
  printf(" %u\n",d.rx_urb_size);
 }
 return 0;
}
'''
unit=out/"linux-asix-led.c";unit.write_text(prelude+"\n"+defines+"\n"+structure+"\n"+"\n".join(function(n) for n in names)+main)
exe=out/"linux-asix-led"
subprocess.run(["cc","-std=gnu11","-O1","-g","-fsanitize=address,undefined",str(unit),"-o",str(exe)],check=True)
with(out/"fields.txt").open("wb")as f:subprocess.run([str(exe.resolve())],stdout=f,check=True)
print(out/"fields.txt")

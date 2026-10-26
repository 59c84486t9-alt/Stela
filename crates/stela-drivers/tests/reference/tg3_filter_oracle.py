#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Complete original tg3 receive-mode, address, CRC and table-generator helpers.

Arguments: verified original Linux root, fresh ignored output directory.
The callback profile is unmanaged, raw-tag Ethernet; no extra Linux ABI runtime.
"""
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
from tg3_transport_oracle import DONORS

PIN="cc9de5d4b5ab6459f5774946aa3195ad51236fa8"
EXTRA={
 "lib/crc/crc32-main.c":"83cf1aab62cf8a05e352fb4acc1fa8cda514ebd4f5601c95e42fa9126a7fb2cb",
 "lib/crc/gen_crc32table.c":"b2d4fe27ca5ae1cdd14bc3fc2919b62568817dd9dccd9da8a35b41a24f3df3fe",
 "include/linux/crc32poly.h":"c977dc568f0d746b6184dd1230cc922fd1a300c6813892f40b3a2efffd76c92f",
 "include/linux/crc32.h":"1e9d1d38fecd017f477975f5da59a6ae6c81e9b55274c33dc1f39302ac6ce9ca",
 "include/uapi/linux/if.h":"7fb6b621b61c3e9794dfe0a3295df700c04ddaF2d2aaab4753a2426646a7b307".lower(),
 "include/uapi/linux/if_ether.h":"3b8e80de0d836b872edf92a63e1c9cf3db0a6faf65637c56fb3210ce0afc895b",
 "Makefile":"77d977b5a40efd0338d6aca5d4fa932db44c76635b96b103b3b338e829484a22",
}
def digest(raw):return hashlib.sha256(raw).hexdigest()
def section(text,marker):
 start=text.index(marker);end=text.index('{',start)+1;depth=1
 while depth:
  depth+=(text[end]=='{')-(text[end]=='}');end+=1
 return text[start:end]

def main():
 original,output=map(Path,sys.argv[1:])
 root=Path(__file__).resolve().parents[4]
 if not output.resolve().is_relative_to(root/'.stela'):raise ValueError('output must be ignored .stela')
 donors={'drivers/net/ethernet/broadcom/'+name:sha for name,sha in DONORS.items()};donors.update(EXTRA)
 texts={}
 for name,sha in donors.items():
  raw=(original/name).read_bytes()
  if digest(raw)!=sha:raise ValueError('changed original '+name)
  texts[name]=raw.decode()
 tg3=texts['drivers/net/ethernet/broadcom/tg3.c'];crc=texts['lib/crc/crc32-main.c'];gen=texts['lib/crc/gen_crc32table.c']
 selections={
  'crc32init_le_generic':section(gen,'static void crc32init_le_generic('),
  'crc32init_le':section(gen,'static void crc32init_le(void)'),
  'crc32_le_base':section(crc,'static inline u32 __maybe_unused\ncrc32_le_base('),
  'crc32_le':section(crc,'u32 crc32_le('),
  'crc32':section(texts['include/linux/crc32.h'],'static inline u32 crc32('),
  'calc_crc':section(tg3,'static inline u32 calc_crc('),
  '__tg3_set_one_mac_addr':section(tg3,'static void __tg3_set_one_mac_addr('),
  'tg3_set_multi':section(tg3,'static void tg3_set_multi('),
  '__tg3_set_rx_mode':section(tg3,'static void __tg3_set_rx_mode(struct net_device *dev)'),
 }
 enum=section(texts['include/uapi/linux/if.h'],'enum net_device_flags {')+';'
 macros=[]
 for name in ['TG3_MAX_UCAST_ADDR','TG3_UCAST_ADDR_IDX']:
  macros.append(re.search(r'^#define '+name+r'[^\n]+',tg3,re.M).group())
 macros.append(re.search(r'^#define ETH_ALEN\s+[^\n]+',texts['include/uapi/linux/if_ether.h'],re.M).group())
 buildflag=next(line for line in texts['Makefile'].splitlines() if line.strip()=='KBUILD_CFLAGS\t+= -fno-strict-overflow')
 wrapper=r'''
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint32_t u32;typedef uint8_t u8;
#define __maybe_unused
#define __UAPI_DEF_IF_NET_DEVICE_FLAGS 1
#define __UAPI_DEF_IF_NET_DEVICE_FLAGS_LOWER_UP_DORMANT_ECHO 1
#include "donor_constants.h"
#include "crc32poly.h"
'''
 wrapper+=enum+'\n'+'\n'.join(macros)+'\n'
 wrapper+=r'''
static uint32_t crc32table_le[256];
#define crc32_le_arch crc32_le_base
struct netdev_hw_addr {u8 addr[6];};
struct tg3;
struct net_device {unsigned flags,mc_count,uc_count;struct netdev_hw_addr mc[256],uc[4];struct tg3*private;};
struct tg3 {u32 chip,rx_mode;struct net_device*dev;};
#define netdev_priv(dev) ((dev)->private)
#define tg3_flag(tp,name) ((void)(tp),0)
#define netdev_mc_empty(dev) ((dev)->mc_count==0)
#define netdev_uc_count(dev) ((dev)->uc_count)
#define netdev_for_each_mc_addr(ha,dev) for(unsigned _m=0;_m<(dev)->mc_count&&((ha)=&(dev)->mc[_m],1);_m++)
#define netdev_for_each_uc_addr(ha,dev) for(unsigned _u=0;_u<(dev)->uc_count&&((ha)=&(dev)->uc[_u],1);_u++)
static u32 registers[0x8000/4];static int trace;
static void write_reg(struct tg3*tp,u32 at,u32 value){(void)tp;if(at>=0x8000||at%4)abort();registers[at/4]=value;if(trace)printf("W %08x %08x\n",at,value);}
#define tw32(at,value) write_reg(tp,at,value)
#define tw32_f(at,value) write_reg(tp,at,value)
static void udelay(unsigned us){if(trace)printf("D %u\n",us);}
'''
 wrapper+='\n\n'.join(selections.values())
 wrapper+=r'''
int main(void){
 const u32 chips[]={CHIPREV_ID_5720_A0,CHIPREV_5761_AX<<8,CHIPREV_ID_5762_A0};
 const u32 extra[]={0,0x100,0x10000,0x10100};
 const u8 station[]={2,0x11,0x22,0x33,0x44,0x55};
 const u8 groups[2][6]={{1,0,0x5e,0,0,1},{0x33,0x33,0,0,0,0x16}};
 const u8 aliases[4][6]={{0x0a,0x77,0x88,0x99,0xaa,0xbb},{2,0xfe,0xdc,0xba,0x98,0x76},{2,1,0xff,0xff,0xff,0xff},{2,1,2,3,4,6}};
 crc32init_le();puts("TG3_FILTER_V1 108");
 for(unsigned c=0;c<3;c++)for(unsigned i=0;i<4;i++)for(unsigned mode=0;mode<9;mode++){
  struct net_device dev={0};struct tg3 tp={.chip=chips[c],.dev=&dev};dev.private=&tp;
  tp.rx_mode=0x01000402|(c==2?0x02000000:0)|extra[i];registers[MAC_RX_MODE/4]=tp.rx_mode;
  trace=0;for(int slot=0;slot<4;slot++)__tg3_set_one_mac_addr(&tp,station,slot);
  for(unsigned h=0;h<4;h++)registers[(MAC_HASH_REG_0+h*4)/4]=0x12340000+h;
  if(mode==1)dev.flags=IFF_ALLMULTI;
  if(mode==2||mode==8)dev.flags=IFF_PROMISC;
  if(mode==3||mode>=5){dev.mc_count=2;memcpy(dev.mc,groups,sizeof(groups));}
  if(mode==4){dev.mc_count=256;for(unsigned m=0;m<256;m++){const u8 group[]={1,0,0x5e,0,3,(u8)m};memcpy(dev.mc[m].addr,group,6);}}
  dev.uc_count=mode==5?1:(mode==6||mode==8)?3:mode==7?4:0;
  memcpy(dev.uc,aliases,sizeof(aliases));
  printf("CASE %08x %08x %u\n",tp.chip,tp.rx_mode,mode);trace=1;__tg3_set_rx_mode(&dev);trace=0;
  printf("STATE %08x",tp.rx_mode);
  for(unsigned h=0;h<4;h++)printf(" %08x",registers[(MAC_HASH_REG_0+h*4)/4]);
  for(unsigned u=1;u<4;u++){printf(" %08x %08x",registers[(MAC_ADDR_0_HIGH+u*8)/4],registers[(MAC_ADDR_0_LOW+u*8)/4]);}
  puts("\nEND");
 }
}
'''
 output.mkdir(parents=True,exist_ok=False)
 header=texts['drivers/net/ethernet/broadcom/tg3.h'].split('struct tg3_tx_buffer_desc {',1)[0]+'\n#endif\n'
 (output/'donor_constants.h').write_text(header);(output/'crc32poly.h').write_text(texts['include/linux/crc32poly.h']);(output/'filter.c').write_text(wrapper)
 compiler=Path(shutil.which('clang') or 'clang').resolve(strict=True);exe=output/'filter'
 command=[str(compiler),'-std=c11','-O1','-g','-Wall','-Wextra','-Werror','-fno-strict-overflow','-fsanitize=address,undefined','-fno-sanitize-recover=all',str(output/'filter.c'),'-o',str(exe)]
 report={'pin':PIN,'sources':donors,'cases':108,'kernel_build_flag':buildflag,'script_sha256':digest(Path(__file__).read_bytes()),
  'unchanged_sections':{name:digest(value.encode()) for name,value in selections.items()},'enum_sha256':digest(enum.encode()),'wrapper_sha256':digest(wrapper.encode()),'constants_sha256':digest(header.encode()),
  'compiler':str(compiler),'compiler_sha256':digest(compiler.read_bytes()),'compiler_version':subprocess.run([str(compiler),'--version'],check=True,capture_output=True,timeout=15).stdout.decode(),
  'command':command,'python':sys.executable,'cwd':str(Path.cwd()),'status':'Admitted originals; compilation pending',
  'scope':'Complete selected receive-mode/address/CRC helpers under unmanaged/raw-tag profile; callbacks supply lists/register/time; no physical packet/IRQ/platform claim'}
 def save():(output/'report.json').write_text(json.dumps(report,indent=2)+'\n')
 save()
 try:
  result=subprocess.run(command,check=True,capture_output=True,timeout=60);(output/'compile.log').write_bytes(result.stdout+result.stderr)
  report.update(status='Compiled; execution pending',binary_sha256=digest(exe.read_bytes()));save()
  result=subprocess.run([str(exe)],check=True,capture_output=True,timeout=20);(output/'records.txt').write_bytes(result.stdout);(output/'stderr.log').write_bytes(result.stderr)
  report.update(status='PASS108 unchanged source cases under ASan/UBSan',records_sha256=digest(result.stdout));save()
 except (subprocess.CalledProcessError,subprocess.TimeoutExpired) as error:
  (output/'failure-stdout.log').write_bytes(error.stdout or b'');(output/'failure-stderr.log').write_bytes(error.stderr or b'');report['status']='FAILED: '+str(error);save();raise
 print('PASS108 receive filter source cases')
if __name__=='__main__':main()

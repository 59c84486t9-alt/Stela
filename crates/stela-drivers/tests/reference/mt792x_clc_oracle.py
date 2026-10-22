#!/usr/bin/env python3
"""Run full unchanged PCI CLC loaders on synthetic and pinned actual RAM images.
Usage: mt792x_clc_oracle.py MT76_DIRECTORY FRESH_OUTPUT_DIRECTORY FIRMWARE_DIRECTORY
EEPROM byte, firmware provider/allocation and regd_init are modeled; no country,
transmit power, radio readiness or production firmware ownership is inferred.
"""
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import sys
source,out,images=map(Path,sys.argv[1:]);out.mkdir(parents=True,exist_ok=False)
hashes={
 'mt7921/mcu.c':'3b356eeef80727c27ad5f179e277a9d434297d14ac6df8297c98f4ce445e91b6',
 'mt7925/mcu.c':'cca76caa6429584b0b37f2772f5132e754a9e26b71660fb0e362ead4ee01dde6',
 'mt7921/mt7921.h':'370d21968a2fd423f4b745be820e83d06f336b17913616da487551a52797baab',
 'mt7925/mt7925.h':'b6fec2103954269927b44b095944120dd22a5a0503fa8930e49a8ecc044844dc',
 'mt76_connac_mcu.h':'2448b6c145f17397a717965eadf50c591934902f0b09684d37a8b0ae290b31ed',
 'mt792x.h':'8e235c73c8c155e1aba21e4e871a921319c1e670c76ef913faaf9ba72d13111d',
}
texts={}
for name,digest in hashes.items():
 raw=(source/name).read_bytes();assert hashlib.sha256(raw).hexdigest()==digest,name;texts[name]=raw.decode()
def function(file,name):
 text=texts[file];m=re.search(r'\b'+name+r'\([^;{}]*?\)\n\{',text);assert m,name
 start=text.rfind('\n\n',0,m.start())+2;at,depth=m.end(),1
 while depth:depth+=(text[at]=='{')-(text[at]=='}');at+=1
 return text[start:at]+'\n'
def record(file,name):
 text=texts[file];start=text.index('struct '+name+' {');end=text.index('} __packed;',start)+len('} __packed;')
 return text[start:end]+'\n'
def enum(file,needle):
 text=texts[file];start=text.rfind('enum {',0,text.index(needle));return text[start:text.index('};',start)+2]+'\n'
def macro(file,name):
 return re.search(r'^#define\s+'+name+r'\b[^\n]*',texts[file],re.M).group()+'\n'
prelude=r'''// SPDX-License-Identifier: BSD-3-Clause-Clear
// Copyright (C) 2020-2023 MediaTek Inc.
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint8_t u8;typedef uint32_t u32;typedef uint32_t __le32;
#define __packed __attribute__((packed))
#define BIT(x) (1U<<(x))
#define GENMASK(h,l) (((~0U)>>(31-(h)))&((~0U)<<(l)))
#define ARRAY_SIZE(x) (sizeof(x)/sizeof((x)[0]))
#define le32_to_cpu(x) (x)
#define u8_get_bits(x,m) (((x)&(m))>>__builtin_ctz(m))
#define EINVAL 22
#define ENOMEM 12
#define GFP_KERNEL 0
#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error Requires little endian host.
#endif
'''
parts=enum('mt792x.h','MT792x_CLC_POWER')+enum('mt76_connac_mcu.h','FW_TYPE_CLC')+enum('mt7921/mt7921.h','MT7921_CLC_POWER')+macro('mt76_connac_mcu.h','FW_FEATURE_NON_DL')
for file,name in [('mt76_connac_mcu.h','mt76_connac2_fw_trailer'),('mt76_connac_mcu.h','mt76_connac2_fw_region'),('mt7921/mt7921.h','mt7921_clc'),('mt7925/mt7925.h','mt7925_clc_type0'),('mt7925/mt7925.h','mt7925_clc_type2'),('mt7925/mt7925.h','mt7925_clc')]:parts+=record(file,name)
scaffold=r'''
struct firmware { u8 *data;size_t size; };
struct mt76_dev {void *dev;};
struct mt792x_phy {u8 clc_chan_conf;void *clc[MT792x_CLC_MAX_NUM];};
struct mt792x_dev {struct mt76_dev mt76;struct mt792x_phy phy;bool regd_user;};
static struct firmware input;
static u8 eeprom;
static bool mt76_is_mmio(struct mt76_dev *d){(void)d;return true;}
static bool mt7921_regd_clc_supported(struct mt792x_dev *d){(void)d;return true;}
static bool mt7925_regd_clc_supported(struct mt792x_dev *d){(void)d;return true;}
static int mt7921_mcu_read_eeprom(struct mt792x_dev *d,u32 off,u8 *v){(void)d;if(off!=0x55b)abort();*v=eeprom;return 0;}
static int mt7925_mcu_read_eeprom(struct mt792x_dev *d,u32 off,u8 *v){(void)d;if(off!=0xa71)abort();*v=eeprom;return 0;}
static int request_firmware(const struct firmware **fw,const char *name,void *dev){(void)dev;if(strcmp(name,"exact-input"))abort();*fw=&input;return 0;}
static void release_firmware(const struct firmware *fw){if(fw!=&input)abort();}
static void *devm_kmemdup(void *d,const void *p,size_t n,int flags){(void)d;if(flags)abort();void *r=malloc(n);if(!r)abort();memcpy(r,p,n);return r;}
static int mt7921_regd_init(struct mt792x_phy *p){(void)p;return 0;}
static int mt7925_regd_init(struct mt792x_phy *p){(void)p;return 0;}
#define dev_err(d,...) ((void)(d))
'''
helpers=''
for chip in [7921,7925]:
 h=f'mt{chip}/mt{chip}.h';text=texts[h];m=re.search(r'MT_EE_HW_TYPE\s*=\s*(0x[0-9a-f]+)',text);assert m
 helpers+='#define MT_EE_HW_TYPE '+m[1]+'\n'+macro(h,'MT_EE_HW_TYPE_ENCAP')+function(f'mt{chip}/mcu.c',f'mt{chip}_load_clc')+'#undef MT_EE_HW_TYPE\n#undef MT_EE_HW_TYPE_ENCAP\n'
main=r'''
int main(int argc,char **argv){
 if(argc!=2)return 1;int chip=atoi(argv[1]);
 for(;;){
  u32 size;if(fread(&size,1,4,stdin)==0)break;if(!size||size>16*1024*1024)abort();
  if(fread(&eeprom,1,1,stdin)!=1)abort();input.size=size;input.data=malloc(size);if(!input.data)abort();
  if(fread(input.data,1,size,stdin)!=size)abort();struct mt792x_dev d={0};
  int rc=chip==7925?mt7925_load_clc(&d,"exact-input"):mt7921_load_clc(&d,"exact-input");if(rc)abort();
  if(fwrite(&size,1,4,stdout)!=4||fwrite(&eeprom,1,1,stdout)!=1||fwrite(input.data,1,size,stdout)!=size)abort();
  for(int i=0;i<MT792x_CLC_MAX_NUM;i++){
   u32 n=0;if(d.phy.clc[i])memcpy(&n,d.phy.clc[i],4);
   if(fwrite(&n,1,4,stdout)!=4||(n&&fwrite(d.phy.clc[i],1,n,stdout)!=n))abort();free(d.phy.clc[i]);
  }free(input.data);
 }
 return 0;
}
'''
unit=out/'linux-mt792x-clc.c';unit.write_text(prelude+parts+scaffold+helpers+main)
exe=out/'linux-mt792x-clc';subprocess.run(['cc','-std=gnu11','-O1','-g','-fsanitize=address,undefined','-fno-sanitize-recover=all',str(unit),'-o',str(exe)],check=True)
def clc(index,variant,seed):
 body=bytes((seed+j)&255 for j in range(seed%19));return struct.pack('<I',16+len(body))+bytes([index,seed%3,(variant>>2)&3,variant&3])+bytes([seed&255])*8+body
def ram(regions,seed):
 payload=b''.join(r[2] for r in regions);release=b'release:'+bytes([seed&255])*9
 table=b''
 for kind,features,body in regions:
  desc=bytearray(40);struct.pack_into('<II',desc,16,0 if features&64 else 0x100000,len(body));desc[24:26]=bytes([features,kind]);table+=desc
 trailer=bytearray(36);trailer[:4]=bytes([0x79,1,len(regions),2]);return payload+release+table+trailer
firmware={
 7921:('mediatek/WIFI_RAM_CODE_MT7961_1.bin','b94217a951518a9c14095765f367bc5dd7698f2dc033941d6f18fc2ebd6a2ab9'),
 7922:('mediatek/WIFI_RAM_CODE_MT7922_1.bin','d100e5e04c324fc8da6302112d1e0b4fac952286447d2419eabcd8fb0a1f5b93'),
 7925:('mediatek/mt7925/WIFI_RAM_CODE_MT7925_1_1.bin','329c0e27f780550789e4eba47452731b1723f69f9e67f525d0e50bf3cd2978ac'),
}
cases=[]
for chip in [7921,7922,7925]:
 inputs=[]
 for i in range(256):
  # Known slots, all selector variants, duplicates, an unknown record, a
  # non-CLC region, a later CLC region that must never replace the first.
  records=b''.join(clc(slot,v,i+slot+v) for slot in range(4) for v in range(16 if slot==2 else 4))
  unknown=clc(9,0,i);records=records[:0]+unknown+records if i%7==0 else records+unknown
  records+=clc(0,i%4,i+93)
  regions=[(0,0,b'actual-download'),(1,64,b'other-nondownload')]
  if i%11:regions += [(2,64,records),(2,64,clc(3,i%4,i))]
  else:regions += [(2,0,records)] # Downloaded type2 is not a CLC source.
  data=ram(regions,i);inputs.append(struct.pack('<IB',len(data),i)+data)
 name,digest=firmware[chip];data=(images/name).read_bytes();assert hashlib.sha256(data).hexdigest()==digest,name
 for raw in range(4):inputs.append(struct.pack('<IB',len(data),raw)+data)
 trace=subprocess.run([str(exe.resolve()),str(chip)],input=b''.join(inputs),stdout=subprocess.PIPE,check=True).stdout
 (out/f'{chip}.trace').write_bytes(trace);cases.append({'chip':chip,'reports':len(inputs),'bytes':len(trace),'sha256':hashlib.sha256(trace).hexdigest(),'ram_name':name,'ram_sha256':digest})
(out/'manifest.json').write_text(json.dumps({'linux_commit':'a804c5742bff224d4cb4d25dd383554d598be32b','sources':hashes,'firmware_commit':'59f9fc2ef8d1e312d2a613d4e1ffad2ff31a0a01','cases':cases},indent=2)+'\n')
print(json.dumps(cases,indent=2))

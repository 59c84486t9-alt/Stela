#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
# Copyright (C) 2005-2014, 2018-2026 Intel Corporation
# Copyright (C) 2013-2015 Intel Mobile Communications GmbH
# Copyright (C) 2016-2017 Intel Deutschland GmbH
"""Exact MCC layouts and unchanged global regulatory capability interpreter.
Usage: iwlwifi_mcc_oracle.py SOURCE_DIRECTORY OUTPUT_DIRECTORY
The wrapper fills source structures; no firmware command, channel authorization,
regulatory database or RF behavior executes here.
"""
import hashlib,json,re,subprocess,sys
from pathlib import Path
source,out=map(Path,sys.argv[1:])
expected={
 'fw/api/nvm-reg.h':'78f09e7a89c3396801c82cfc89b9c4eaf52792ecd2839ac4e483615433ac3f31',
 'iwl-nvm-parse.c':'74c228762c2e74d85a1731314d5fd867584b9eab0008bede2afc8a1166055d7d',
 'iwl-nvm-parse.h':'f65b8bef3df63ceffd5c6a995c4af3e00d5082d817c73ed89ae2a2eb856fef36',
}
texts={}
for name,digest in expected.items():
 data=(source/name).read_bytes();assert hashlib.sha256(data).hexdigest()==digest,name;texts[name]=data.decode()
def body(text,name,kind):
 pattern=(r'^'+kind+r' '+name+r'\s*\{') if kind else (r'^static struct iwl_reg_capa '+name+r'\([^;{}]*?\)\n\{')
 match=re.search(pattern,text,re.M);assert match,name
 at,depth=match.end(),1
 while depth:depth+=(text[at]=='{')-(text[at]=='}');at+=1
 if kind:at=text.index(';',at)+1
 return text[match.start():at]
prelude=r'''
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
typedef uint8_t u8;typedef uint16_t __le16;typedef uint32_t __le32;typedef uint32_t u32;
#define __packed __attribute__((packed))
#define BIT(n) (1U<<(n))
#define REG_CAPA_V2_RESP_VER 6
#define REG_CAPA_V4_RESP_VER 8
#define REG_CAPA_V6_RESP_VER 10
'''
for n in ['iwl_mcc_update_cmd','iwl_mcc_update_resp_v3','iwl_mcc_update_resp_v4','iwl_mcc_update_resp_v8']:
 prelude+=body(texts['fw/api/nvm-reg.h'],n,'struct')+'\n'
for n in ['iwl_reg_capa_flags_v1','iwl_reg_capa_flags_v2','iwl_reg_capa_flags_v5','iwl_reg_capa_flags_v6']:
 prelude+=body(texts['iwl-nvm-parse.c'],n,'enum')+'\n'
prelude+=body(texts['iwl-nvm-parse.h'],'iwl_puncturing_status','enum')+'\n'
prelude+=body(texts['iwl-nvm-parse.h'],'iwl_reg_capa','struct')+'\n'
prelude+=body(texts['iwl-nvm-parse.c'],'iwl_get_reg_capa','')+'\n'
main=r'''
static void hex(void *p,size_t n){for(size_t i=0;i<n;i++)printf("%02x",((u8*)p)[i]);puts("");}
int main(void){
 printf("sizes %zu %zu %zu %zu\n",sizeof(struct iwl_mcc_update_cmd),sizeof(struct iwl_mcc_update_resp_v3),sizeof(struct iwl_mcc_update_resp_v4),sizeof(struct iwl_mcc_update_resp_v8));
 struct iwl_mcc_update_cmd cmd={.mcc=0x5553,.source_id=16};printf("request ");hex(&cmd,sizeof(cmd));
 unsigned versions[]={3,5,6,8,10},counts[]={0,1,51,110,115};
 for(unsigned v=0;v<5;v++)for(unsigned c=0;c<5;c++)for(unsigned world=0;world<2;world++){
  unsigned ver=versions[v],count=counts[c],layout=ver==3?3:ver<8?4:8,header=layout==3?16:layout==4?20:24;
  size_t len=header+count*4;void *memory=calloc(1,len);u32 *channels;__le16 country=world?0:0x5553;
  if(layout==3){struct iwl_mcc_update_resp_v3 *r=memory;r->status=4;r->mcc=country;r->cap=0x9c;r->source_id=16;r->time=0x1234;r->geo_info=0x5678;r->n_channels=count;channels=r->channels;}
  else if(layout==4){struct iwl_mcc_update_resp_v4 *r=memory;r->status=4;r->mcc=country;r->cap=0xa19c;r->source_id=16;r->time=0x1234;r->geo_info=0x5678;r->n_channels=count;channels=r->channels;}
  else{struct iwl_mcc_update_resp_v8 *r=memory;r->status=4;r->mcc=country;r->cap=0x00a7a19c;r->source_id=16;r->time=0x1234;r->geo_info=0x5678;r->n_channels=count;channels=r->channels;}
  for(unsigned i=0;i<count;i++)channels[i]=0x80000109U+i*0x10000;
  printf("response %u %u %u %u ",ver,layout,count,country);hex(memory,len);free(memory);
 }
 u32 flags=0;
 for(unsigned version=3;version<=10;version++)for(unsigned i=0;i<128;i++){
  struct iwl_reg_capa c=iwl_get_reg_capa(flags,version);
  printf("caps %u %u %u %u %u %u %u %u %u %u\n",version,flags,c.allow_40mhz,c.allow_80mhz,c.allow_160mhz,c.allow_320mhz,c.disable_11ax,c.disable_11be,c.disable_11bn,c.puncturing_status);
  flags=flags*1664525+1013904223;
 }
 return 0;
}
'''
out.mkdir(parents=True,exist_ok=True);unit=out/'linux-iwlwifi-mcc.c';unit.write_text(prelude+main);exe=out/'linux-iwlwifi-mcc'
subprocess.run(['cc','-std=gnu11','-O1','-g','-fsanitize=address,undefined',str(unit),'-o',str(exe)],check=True)
with (out/'trace.txt').open('wb') as trace:subprocess.run([str(exe.resolve())],stdout=trace,check=True)
manifest={'linux_commit':'a804c5742bff224d4cb4d25dd383554d598be32b','sources':expected,'trace_sha256':hashlib.sha256((out/'trace.txt').read_bytes()).hexdigest()};(out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');print(json.dumps(manifest,indent=2))

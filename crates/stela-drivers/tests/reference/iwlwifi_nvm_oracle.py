#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
# Copyright (C) 2012-2014, 2018-2026 Intel Corporation
# Copyright (C) 2013-2015 Intel Mobile Communications GmbH
# Copyright (C) 2015-2017 Intel Deutschland GmbH
"""Exact source NVM packed layouts and unchanged MAC byte permutation.
Usage: iwlwifi_nvm_oracle.py SOURCE_DIRECTORY OUTPUT_DIRECTORY
No firmware command, regulatory permission or physical CSR access is executed.
"""
import hashlib,json,re,subprocess,sys
from pathlib import Path
source,out=map(Path,sys.argv[1:])
expected={
 'iwl-nvm-parse.c':'74c228762c2e74d85a1731314d5fd867584b9eab0008bede2afc8a1166055d7d',
 'fw/api/nvm-reg.h':'78f09e7a89c3396801c82cfc89b9c4eaf52792ecd2839ac4e483615433ac3f31',
 'fw/api/alive.h':'7542590e6b33b4a32a501e217d357f52f1bc0ca64399a0675a79ed3b27d7dde8',
}
texts={}
for name,digest in expected.items():
 data=(source/name).read_bytes();assert hashlib.sha256(data).hexdigest()==digest,name;texts[name]=data.decode()
def body(text,name,kind):
 pattern=(r'^'+kind+r' '+name+r'\s*\{')if kind else (r'^static void '+name+r'\([^;{}]*?\)\n\{')
 match=re.search(pattern,text,re.M);assert match,name
 at,depth=match.end(),1
 while depth:depth+=(text[at]=='{')-(text[at]=='}');at+=1
 if kind:at=text.index(';',at)+1
 return text[match.start():at]
prelude=r'''
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stddef.h>
typedef uint8_t u8;typedef uint16_t __le16;typedef uint32_t u32;typedef uint32_t __le32;
#define __packed __attribute__((packed))
#define IWL_NUM_CHANNELS_V1 51
#define IWL_NUM_CHANNELS_V2 110
#define IWL_NUM_CHANNELS_V3 115
#define BIT(n) (1U<<(n))
'''
for n in ['iwl_nvm_get_info','iwl_nvm_get_info_general','iwl_nvm_get_info_sku','iwl_nvm_get_info_phy','iwl_nvm_get_info_regulatory_v1','iwl_nvm_get_info_regulatory_v2','iwl_nvm_get_info_rsp_v3','iwl_nvm_get_info_rsp_v4','iwl_nvm_get_info_regulatory','iwl_nvm_get_info_rsp','iwl_nvm_access_complete_cmd']:
 prelude+=body(texts['fw/api/nvm-reg.h'],n,'struct')+'\n'
prelude+=body(texts['fw/api/alive.h'],'iwl_extended_cfg_flags','enum')+'\n'
prelude+=body(texts['fw/api/alive.h'],'iwl_init_extended_cfg_cmd','struct')+'\n'
prelude+=body(texts['iwl-nvm-parse.c'],'iwl_flip_hw_address','')+'\n'
main=r'''
static void hex(void *p,size_t n){for(size_t i=0;i<n;i++)printf("%02x",((u8*)p)[i]);puts("");}
static void common(struct iwl_nvm_get_info_general *g,struct iwl_nvm_get_info_sku *s,struct iwl_nvm_get_info_phy *p){
 *g=(struct iwl_nvm_get_info_general){.flags=1,.nvm_version=0x1234,.board_type=0xa5,.n_hw_addrs=4};
 s->mac_sku_flags=0x9944803f;p->tx_chains=3;p->rx_chains=2;
}
int main(void){
 printf("sizes %zu %zu %zu %zu %zu %zu\n",sizeof(struct iwl_nvm_get_info_rsp_v3),sizeof(struct iwl_nvm_get_info_rsp_v4),sizeof(struct iwl_nvm_get_info_rsp),sizeof(struct iwl_init_extended_cfg_cmd),sizeof(struct iwl_nvm_access_complete_cmd),sizeof(struct iwl_nvm_get_info));
 struct iwl_init_extended_cfg_cmd c={.init_flags=BIT(IWL_INIT_NVM)};printf("init ");hex(&c,sizeof(c));
 struct iwl_nvm_get_info_rsp_v3 a={0};common(&a.general,&a.mac_sku,&a.phy_sku);a.regulatory.lar_enabled=1;
 for(unsigned n=0;n<51;n++)a.regulatory.channel_profile[n]=n*0x101+0x4321;
 printf("info 3 ");hex(&a,sizeof(a));
 struct iwl_nvm_get_info_rsp_v4 b={0};common(&b.general,&b.mac_sku,&b.phy_sku);b.regulatory.lar_enabled=1;b.regulatory.n_channels=110;
 for(unsigned n=0;n<110;n++)b.regulatory.channel_profile[n]=n*0x101+0x4321;
 printf("info 4 ");hex(&b,sizeof(b));
 struct iwl_nvm_get_info_rsp d={0};common(&d.general,&d.mac_sku,&d.phy_sku);d.regulatory.lar_enabled=1;d.regulatory.n_channels=115;
 for(unsigned n=0;n<115;n++)d.regulatory.channel_profile[n]=n*0x101+0x4321;
 printf("info 5 ");hex(&d,sizeof(d));
 u32 pairs[][2]={{0,0},{0xffffffff,0xffffffff},{0x02123456,0xa5a5789a},{0x01234567,0x89abcdef},{0xfedcba98,0x76543210}};
 for(unsigned i=0;i<5;i++){u8 mac[6]={0};iwl_flip_hw_address(pairs[i][0],pairs[i][1],mac);printf("mac %u %u ",pairs[i][0],pairs[i][1]);hex(mac,sizeof(mac));}
 return 0;
}
'''
out.mkdir(parents=True,exist_ok=True);unit=out/'linux-iwlwifi-nvm.c';unit.write_text(prelude+main);exe=out/'linux-iwlwifi-nvm'
subprocess.run(['cc','-std=gnu11','-O1','-g','-fsanitize=address,undefined',str(unit),'-o',str(exe)],check=True)
with (out/'trace.txt').open('wb') as trace:subprocess.run([str(exe.resolve())],stdout=trace,check=True)
manifest={'linux_commit':'a804c5742bff224d4cb4d25dd383554d598be32b','sources':expected,'trace_sha256':hashlib.sha256((out/'trace.txt').read_bytes()).hexdigest()};(out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');print(json.dumps(manifest,indent=2))

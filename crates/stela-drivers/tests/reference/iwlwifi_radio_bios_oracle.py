#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
# Copyright (C) 2012-2014, 2018-2026 Intel Corporation
# Copyright (C) 2013-2015 Intel Mobile Communications GmbH
# Copyright (C) 2016-2017 Intel Deutschland GmbH
"""Complete source UEFI scalar/DSM/PHY getters over bounded byte fixtures.
Usage: iwlwifi_radio_bios_oracle.py SOURCE_DIRECTORY OUTPUT_DIRECTORY
Return codes use portable semantic witnesses (invalid=-1, unsupported=-2),
not Linux or host errno numbers. EFI reads copy the fixture; no GetVariable, GLAI,
ACPI fallback, firmware commands, power programming or RF executes.
"""
import hashlib,json,re,subprocess,sys
from pathlib import Path
source,out=map(Path,sys.argv[1:])
expected={
'fw/uefi.c':'7e57fe0ff11291e6f3c77aedd2f5ca539e825b279497f7a7e89f796d8f829738',
'fw/uefi.h':'68ec89d9660c9a7de8acde98af29abcabf00a8ed4cc8057def5e6fbcb452a1e0',
'fw/regulatory.h':'914bd35057a79788de2a1ca9f35f27211b4419c75a138f9e0191a5c499c1bc5e',
'fw/api/config.h':'e3b2c4c651e9959ef32d1bf98c88d04591b9895ce2f526344989d6789b5f4a99',
'fw/api/nvm-reg.h':'78f09e7a89c3396801c82cfc89b9c4eaf52792ecd2839ac4e483615433ac3f31',
}
texts={}
for name,digest in expected.items():
 data=(source/name).read_bytes();assert hashlib.sha256(data).hexdigest()==digest,name;texts[name]=data.decode()
def extract(text,pattern):
 m=re.search(pattern,text,re.M);assert m,pattern
 at,depth=m.end(),1
 while depth:depth+=(text[at]=='{')-(text[at]=='}');at+=1
 return text[m.start():at]
def function(name):return extract(texts['fw/uefi.c'],r'^(?:static )?(?:int|void \*\n) ?'+name+r'\([^;{}]*?\)\n\{')+'\n'
prelude=r'''
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
typedef uint8_t u8;typedef uint16_t u16;typedef uint32_t u32;typedef uint64_t u64;typedef uint32_t __le32;
typedef uint16_t efi_char16_t;typedef unsigned efi_guid_t;
#define __packed __attribute__((packed))
#define BIT(n) (1U<<(n))
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#define BUILD_BUG_ON(x) _Static_assert(!(x),"source assertion")
#define IWL_DEBUG_RADIO(...)
#define cpu_to_le32(x) (x)
#define kfree free
#define ERR_PTR(e) ((void*)(intptr_t)(e))
#define IS_ERR(p) ((uintptr_t)(p)>=(uintptr_t)-4095)
static void oracle_cleanup(void *p){void *v=*(void**)p;if(!IS_ERR(v))free(v);}
#define __free(fn) __attribute__((cleanup(oracle_cleanup)))
#define BIOS_MCC_CHINA 0x434e
#define UEFI_MAX_DSM_FUNCS 32
#define IWL_UEFI_WRDD_REVISION 0
#define IWL_UEFI_ECKV_REVISION 0
#define IWL_UEFI_WBEM_REVISION 0
#define IWL_UEFI_SPLC_REVISION 0
#define IWL_UEFI_DSM_REVISION 4
#define IWL_UEFI_WBEM_REV0_MASK (BIT(0)|BIT(1))
#define IWL_UEFI_WRDD_NAME NULL
#define IWL_UEFI_ECKV_NAME NULL
#define IWL_UEFI_WBEM_NAME NULL
#define IWL_UEFI_SPLC_NAME NULL
#define IWL_UEFI_DSM_NAME NULL
#define IWL_UEFI_WPFC_NAME NULL
static efi_guid_t IWL_EFI_WIFI_GUID,IWL_EFI_WIFI_BT_GUID;
struct iwl_trans {int unused;};
static u8 input[4096];static unsigned input_size;
static void *iwl_uefi_get_variable(efi_char16_t *n,efi_guid_t *g,unsigned long *size){(void)n;(void)g;*size=input_size;void *p=malloc(input_size?input_size:1);memcpy(p,input,input_size);return p;}
'''
for name in ['iwl_dsm_funcs']:
 prelude+=extract(texts['fw/regulatory.h'],r'^enum '+name+r'\s*\{')+';\n'
prelude+=extract(texts['fw/api/nvm-reg.h'],r'^enum bios_source\s*\{')+';\n'
for file,name in [('fw/api/config.h','iwl_phy_specific_cfg'),('fw/uefi.h','uefi_cnv_var_wrdd'),('fw/uefi.h','uefi_cnv_var_eckv'),('fw/uefi.h','uefi_cnv_wlan_wbem_data'),('fw/uefi.h','uefi_cnv_var_splc'),('fw/uefi.h','uefi_cnv_var_general_cfg'),('fw/uefi.h','uefi_cnv_wpfc_data')]:
 prelude+=extract(texts[file],r'^struct '+name+r'\s*\{')+' __packed;\n'
prelude+='struct iwl_fw_runtime {struct iwl_trans *trans;u8 wbem_source,wbem_revision,dsm_revision,dsm_source;u32 dsm_funcs_valid;u32 dsm_values[DSM_FUNC_NUM_FUNCS];struct iwl_phy_specific_cfg phy_filters;};\n'
for n in ['iwl_uefi_get_verified_variable_guid','iwl_uefi_get_verified_variable','iwl_uefi_get_mcc','iwl_uefi_get_eckv','iwl_uefi_get_wbem','iwl_uefi_get_pwr_limit','iwl_uefi_load_dsm_values','iwl_uefi_get_dsm','iwl_uefi_get_phy_filters']:prelude+=function(n)
main=r'''
static void fill(unsigned seed,unsigned rev,unsigned len){for(unsigned i=0;i<4096;i++)input[i]=(u8)(i*37+seed);input[0]=rev;input_size=len;}
static int category(int ret){return ret==-EINVAL?-1:ret==-EOPNOTSUPP?-2:ret;}
int main(void){
 unsigned sizes[]={0,1,4,5,6,17,129,4096};u32 values[]={0,1,2,0xffffffff,0x434e,0x5553};
 for(unsigned k=0;k<4;k++)for(unsigned rev=0;rev<256;rev++)for(unsigned l=0;l<8;l++)for(unsigned v=0;v<6;v++){
  fill(k*11+rev,rev,sizes[l]);memcpy(input+1,&values[v],4);struct iwl_fw_runtime fw={0};int ret;u32 value=0;u64 limit=0;char mcc[3]={0};
  if(k==0){ret=iwl_uefi_get_mcc(&fw,mcc);value=((u8)mcc[0]<<8)|(u8)mcc[1];}
  else if(k==1)ret=iwl_uefi_get_eckv(&fw,&value);
  else if(k==2)ret=iwl_uefi_get_wbem(&fw,&value);
  else{ret=iwl_uefi_get_pwr_limit(&fw,&limit);value=limit;}
  printf("scalar %u %u %u %u %d %u\n",k,rev,sizes[l],values[v],category(ret),value);
 }
 unsigned dsizes[]={0,1,128,129,130,4096};u32 masks[]={0,1,0xffffffff,0xaaaaaaaa,0x55555555,1<<5,1<<14,1<<31};
 for(unsigned rev=0;rev<256;rev++)for(unsigned m=0;m<8;m++)for(unsigned l=0;l<6;l++){
  if(rev!=0 && rev!=4 && rev!=255 && (m!=0 || l!=3))continue;
  fill(0,rev,dsizes[l]);for(unsigned i=0;i<32;i++){u32 value=(0x9e3779b9U*(i+1))^masks[m];memcpy(input+1+i*4,&value,4);}memcpy(input+1,&masks[m],4);
  for(unsigned f=0;f<32;f++){
   struct iwl_fw_runtime fw={0};u32 value=0;int ret=iwl_uefi_get_dsm(&fw,f,&value);
   printf("dsm %u %u %u %u %d %u\n",rev,dsizes[l],masks[m],f,category(ret),value);
  }
 }
 unsigned psizes[]={0,1,16,17,18,4096};
 for(unsigned rev=0;rev<256;rev++)for(unsigned l=0;l<6;l++){
  fill(13,rev,psizes[l]);struct iwl_fw_runtime fw={0};int ret=iwl_uefi_get_phy_filters(&fw);
  printf("phy %u %u %d %u %u %u %u\n",rev,psizes[l],category(ret),fw.phy_filters.filter_cfg_chains[0],fw.phy_filters.filter_cfg_chains[1],fw.phy_filters.filter_cfg_chains[2],fw.phy_filters.filter_cfg_chains[3]);
 }
 return 0;
}
'''
out.mkdir(parents=True,exist_ok=True);unit=out/'linux-iwlwifi-radio-bios.c';unit.write_text(prelude+main);exe=out/'linux-iwlwifi-radio-bios'
subprocess.run(['cc','-std=gnu11','-O1','-g','-fsanitize=address,undefined',str(unit),'-o',str(exe)],check=True)
with (out/'trace.txt').open('wb') as trace:subprocess.run([str(exe.resolve())],stdout=trace,check=True)
manifest={'linux_commit':'a804c5742bff224d4cb4d25dd383554d598be32b','sources':expected,'trace_sha256':hashlib.sha256((out/'trace.txt').read_bytes()).hexdigest()};(out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');print(json.dumps(manifest,indent=2))

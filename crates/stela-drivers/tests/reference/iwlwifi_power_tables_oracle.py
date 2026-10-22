#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
# Copyright (C) 2012-2014, 2018-2026 Intel Corporation
# Copyright (C) 2013-2015 Intel Mobile Communications GmbH
# Copyright (C) 2016-2017 Intel Deutschland GmbH
"""Unchanged UEFI SAR/geo/PPAG/TAS/SGOM/UATS helpers over exact fixtures.
Usage: iwlwifi_power_tables_oracle.py SOURCE_DIRECTORY OUTPUT_DIRECTORY
EFI read and debug functions are fixture boundaries; snapshots are semantic
witnesses, not Linux structure ABI or actual programmed power/regulatory data.
"""
import hashlib,json,re,subprocess,sys
from pathlib import Path
source,out=map(Path,sys.argv[1:])
expected={
'fw/uefi.c':'7e57fe0ff11291e6f3c77aedd2f5ca539e825b279497f7a7e89f796d8f829738',
'fw/uefi.h':'68ec89d9660c9a7de8acde98af29abcabf00a8ed4cc8057def5e6fbcb452a1e0',
'fw/regulatory.h':'914bd35057a79788de2a1ca9f35f27211b4419c75a138f9e0191a5c499c1bc5e',
'fw/regulatory.c':'80d4387ac8fb6069c8dc042f77ca3bf6129bb19e1543eaaecc495d024f4419bc',
'fw/api/nvm-reg.h':'78f09e7a89c3396801c82cfc89b9c4eaf52792ecd2839ac4e483615433ac3f31',
'fw/api/power.h':'8182c5583306e9c35628991815d63233c70c333a58f14eac42069af75b1fe7f4',
}
texts={}
for name,digest in expected.items():
 data=(source/name).read_bytes();assert hashlib.sha256(data).hexdigest()==digest,name;texts[name]=data.decode()
def extract(text,pattern):
 m=re.search(pattern,text,re.M);assert m,pattern
 at,depth=m.end(),1
 while depth:depth+=(text[at]=='{')-(text[at]=='}');at+=1
 return text[m.start():at]
def macro(file,name):
 lines=texts[file].splitlines();at=next(i for i,l in enumerate(lines) if re.match(r'^#define '+name+r'\b',l));found=[lines[at]]
 while found[-1].endswith('\\'):at+=1;found.append(lines[at])
 return '\n'.join(found)+'\n'
prelude=r'''
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <errno.h>
typedef uint8_t u8;typedef int8_t s8;typedef uint16_t u16;typedef uint32_t u32;typedef uint16_t __le16;
typedef uint16_t efi_char16_t;typedef unsigned efi_guid_t;
#define __packed __attribute__((packed))
#define BIT(n) (1U<<(n))
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#define BUILD_BUG_ON(x) _Static_assert(!(x),"source assertion")
#define IWL_DEBUG_RADIO(...)
#define IWL_DEBUG_FW(...)
#define IWL_DEBUG_INFO(...)
static bool oracle_warn(bool value){return value;}
#define WARN_ON(x) oracle_warn(x)
#define u32_get_bits(value,mask) (((value)&(mask))>>__builtin_ctz(mask))
#define kfree free
#define ERR_PTR(e) ((void*)(intptr_t)(e))
#define IS_ERR(p) ((uintptr_t)(p)>=(uintptr_t)-4095)
static efi_guid_t IWL_EFI_WIFI_GUID;
struct iwl_trans {int unused;};
static u8 input[4096];static unsigned input_size;
static void *iwl_uefi_get_variable(efi_char16_t *n,efi_guid_t *g,unsigned long *size){(void)n;(void)g;*size=input_size;void *p=malloc(input_size?input_size:1);memcpy(p,input,input_size);return p;}
'''
for file,names in [('fw/regulatory.h',['BIOS_SAR_MAX_PROFILE_NUM','BIOS_SAR_MAX_CHAINS_PER_PROFILE','BIOS_SAR_MAX_SUB_BANDS_NUM','BIOS_PPAG_MAX_SUB_BANDS_NUM','BIOS_GEO_NUM_CHAINS','BIOS_GEO_MAX_NUM_BANDS','BIOS_GEO_MAX_PROFILE_NUM','BIOS_GEO_MIN_PROFILE_NUM','IWL_SAR_ENABLE_MSK','IWL_PPAG_ETSI_CHINA_MASK','IWL_PPAG_REV3_MASK','IWL_WTAS_ENABLED_MSK','IWL_WTAS_OVERRIDE_IEC_MSK','IWL_WTAS_ENABLE_IEC_MSK','IWL_WTAS_CANADA_UHB_MSK','IWL_WTAS_USA_UHB_MSK']),('fw/api/nvm-reg.h',['IWL_WTAS_BLACK_LIST_MAX','UATS_TABLE_ROW_SIZE','UATS_TABLE_COL_SIZE']),('fw/api/power.h',['MCC_TO_SAR_OFFSET_TABLE_ROW_SIZE','MCC_TO_SAR_OFFSET_TABLE_COL_SIZE'])]:
 for name in names:prelude+=macro(file,name)
for name in ['UEFI_PPAG_SUB_BANDS_NUM_REV4','UEFI_PPAG_SUB_BANDS_NUM_REV5','UEFI_PPAG_NUM_CHAINS','UEFI_SAR_SUB_BANDS_NUM_REV2','UEFI_SAR_SUB_BANDS_NUM_REV3','UEFI_SAR_MAX_CHAINS_PER_PROFILE','UEFI_GEO_NUM_BANDS_REV3','UEFI_GEO_NUM_BANDS_REV4','IWL_UEFI_MIN_WTAS_REVISION','IWL_UEFI_MAX_WTAS_REVISION','IWL_SGOM_MAP_SIZE','IWL_UATS_MAP_SIZE']:
 prelude+=macro('fw/uefi.h',name)
for file,names in [('fw/regulatory.h',['iwl_sar_profile_chain','iwl_sar_profile','iwl_geo_profile_band','iwl_geo_profile','iwl_ppag_chain','iwl_tas_data','iwl_tas_selection_data']),('fw/uefi.h',['uefi_cnv_var_wrds','uefi_cnv_var_ewrd','uefi_cnv_var_wgds','uefi_cnv_var_ppag','uefi_cnv_var_wtas','uefi_cnv_wlan_sgom_data','uefi_cnv_wlan_uats_data']),('fw/api/power.h',['iwl_sar_offset_mapping_cmd']),('fw/api/nvm-reg.h',['iwl_mcc_allowed_ap_type_cmd'])]:
 for name in names:prelude+=extract(texts[file],r'^struct '+name+r'\s*\{')+(' __packed;\n' if file!='fw/regulatory.h' else ';\n')
for name in ['UEFI_SAR_PROFILE_SIZE_REV2','UEFI_SAR_PROFILE_SIZE_REV3','UEFI_SAR_WRDS_TABLE_SIZE_REV2','UEFI_SAR_WRDS_TABLE_SIZE_REV3','UEFI_SAR_EWRD_TABLE_SIZE_REV2','UEFI_SAR_EWRD_TABLE_SIZE_REV3','UEFI_WGDS_PROFILE_SIZE_REV3','UEFI_WGDS_PROFILE_SIZE_REV4','UEFI_WGDS_TABLE_SIZE_REV3','UEFI_WGDS_TABLE_SIZE_REV4','UEFI_PPAG_DATA_SIZE_V4','UEFI_PPAG_DATA_SIZE_V5']:
 prelude+=macro('fw/uefi.h',name)
prelude+=extract(texts['fw/api/nvm-reg.h'],r'^enum bios_source\s*\{')+';\n'
prelude+=r'''
#define IWL_UEFI_WRDS_NAME NULL
#define IWL_UEFI_EWRD_NAME NULL
#define IWL_UEFI_WGDS_NAME NULL
#define IWL_UEFI_PPAG_NAME NULL
#define IWL_UEFI_WTAS_NAME NULL
#define IWL_UEFI_SGOM_NAME NULL
#define IWL_UEFI_UATS_NAME NULL
struct iwl_fw_runtime {struct iwl_trans *trans;struct iwl_sar_profile sar_profiles[4];struct iwl_geo_profile geo_profiles[8];u8 geo_rev,geo_bios_source,geo_num_profiles;bool geo_enabled;struct iwl_ppag_chain ppag_chains[2];u32 ppag_flags;u8 ppag_bios_rev,ppag_bios_source;struct iwl_sar_offset_mapping_cmd sgom_table;bool sgom_enabled;struct iwl_mcc_allowed_ap_type_cmd ap_type_cmd;bool ap_type_cmd_valid;};
static void iwl_bios_print_ppag(struct iwl_fw_runtime *rt,int bands){(void)rt;(void)bands;}
'''
prelude+=extract(texts['fw/regulatory.h'],r'^static inline u32 iwl_bios_get_ppag_flags\([^{};]*?\)\n\{')+'\n'
prelude+=extract(texts['fw/regulatory.c'],r'^struct iwl_tas_selection_data\niwl_parse_tas_selection\([^{};]*?\)\n\{')+'\n'
for name in ['iwl_uefi_get_verified_variable_guid','iwl_uefi_get_verified_variable','iwl_uefi_set_sar_profile','iwl_uefi_get_wrds_table','iwl_uefi_get_ewrd_table','iwl_uefi_get_wgds_table','iwl_uefi_get_ppag_table','iwl_uefi_get_tas_table','iwl_uefi_sgom_parse','iwl_uefi_get_sgom_table','iwl_uefi_uats_parse','iwl_uefi_get_uats_table']:
 prelude+=extract(texts['fw/uefi.c'],r'^(?:static )?(?:int|void|void \*\n) ?'+name+r'\([^{};]*?\)\n\{')+'\n'
main=r'''
static void hex(const void *p,size_t n){for(size_t i=0;i<n;i++)printf("%02x",((const u8*)p)[i]);}
int main(void){
 unsigned counts[]={0,1,2,3,4,7,8,9,255,0xffffffff};u32 modes[]={0,1,2,0xffffffff};
 for(unsigned kind=0;kind<7;kind++)for(unsigned seed=0;seed<1024;seed++){
  unsigned rev=kind<2?2+seed%2:kind==2?3+seed%2:kind==3?1+seed%5:kind==4?1+seed%2:1;
  if(seed&16)rev=(seed>>2)&255;
  unsigned good=kind==0?(rev==3?53:49):kind==1?(rev==3?153:141):kind==2?(rev==4?98:74):kind==3?(rev==5?29:27):kind==4?38:339;
  unsigned lengths[]={0,1,good-1,good,good+1,good,good,4096};unsigned len=lengths[seed%8];u32 mode=modes[(seed>>2)%4],num=counts[(seed>>5)%10];unsigned geo=seed%9;
  for(unsigned i=0;i<4096;i++)input[i]=(u8)(i*37+seed);input[0]=rev;memcpy(input+1,&mode,4);
  if(kind==1)memcpy(input+5,&num,4);if(kind==2)input[1]=num;if(kind==4)input[5]=num;input_size=len;
  struct iwl_fw_runtime fw={.geo_enabled=true,.geo_num_profiles=geo};struct iwl_tas_data tas={0};int ret=0;u32 meta[8]={0};u8 snapshot[338]={0};unsigned size=0;
  if(kind<2){ret=kind==0?iwl_uefi_get_wrds_table(&fw):iwl_uefi_get_ewrd_table(&fw);size=196;for(unsigned p=0;p<4;p++){snapshot[p*49]=fw.sar_profiles[p].enabled;for(unsigned c=0;c<4;c++)memcpy(snapshot+p*49+1+c*12,fw.sar_profiles[p].chains[c].subbands,12);}}
  else if(kind==2){fw.geo_enabled=false;fw.geo_num_profiles=0;ret=iwl_uefi_get_wgds_table(&fw);meta[0]=fw.geo_rev;meta[1]=fw.geo_bios_source;meta[2]=fw.geo_num_profiles;meta[3]=fw.geo_enabled;size=96;for(unsigned p=0;p<8;p++)for(unsigned b=0;b<4;b++){unsigned at=(p*4+b)*3;snapshot[at]=fw.geo_profiles[p].bands[b].max;memcpy(snapshot+at+1,fw.geo_profiles[p].bands[b].chains,2);}}
  else if(kind==3){ret=iwl_uefi_get_ppag_table(&fw);meta[0]=fw.ppag_bios_rev;meta[1]=fw.ppag_flags;meta[2]=fw.ppag_bios_source;size=24;memcpy(snapshot,fw.ppag_chains,sizeof(fw.ppag_chains));}
  else if(kind==4){ret=iwl_uefi_get_tas_table(&fw,&tas);meta[0]=tas.block_list_size;meta[1]=tas.tas_selection;meta[2]=tas.table_source;meta[3]=tas.table_revision;struct iwl_tas_selection_data sel=iwl_parse_tas_selection(tas.tas_selection,tas.table_revision);meta[4]=sel.override_tas_iec|(sel.enable_tas_iec<<1)|(sel.usa_tas_uhb_allowed<<2)|(sel.canada_tas_uhb_allowed<<3);size=32;memcpy(snapshot,tas.block_list_array,32);}
  else if(kind==5){iwl_uefi_get_sgom_table(NULL,&fw);meta[0]=fw.sgom_enabled;size=338;memcpy(snapshot,fw.sgom_table.offset_map,338);}
  else {iwl_uefi_get_uats_table(NULL,&fw);meta[0]=fw.ap_type_cmd_valid;size=338;memcpy(snapshot,fw.ap_type_cmd.mcc_to_ap_type_map,338);}
  printf("case %u %u %u %u %u %u %u %d",kind,seed,rev,len,mode,num,geo,ret<0?-1:ret);for(unsigned i=0;i<8;i++)printf(" %u",meta[i]);printf(" ");hex(snapshot,size);puts("");
 }
 return 0;
}
'''
out.mkdir(parents=True,exist_ok=True);unit=out/'linux-iwlwifi-power-tables.c';unit.write_text(prelude+main);exe=out/'linux-iwlwifi-power-tables'
subprocess.run(['cc','-std=gnu11','-O1','-g','-fsanitize=address,undefined',str(unit),'-o',str(exe)],check=True)
with (out/'trace.txt').open('wb') as trace:subprocess.run([str(exe.resolve())],stdout=trace,check=True)
manifest={'linux_commit':'a804c5742bff224d4cb4d25dd383554d598be32b','sources':expected,'trace_sha256':hashlib.sha256((out/'trace.txt').read_bytes()).hexdigest()};(out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');print(json.dumps(manifest,indent=2))

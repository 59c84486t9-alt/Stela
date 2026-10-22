#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
# Copyright (C) 2012-2014, 2018-2026 Intel Corporation
# Copyright (C) 2013-2015 Intel Mobile Communications GmbH
# Copyright (C) 2016-2017 Intel Deutschland GmbH
"""Unchanged complete mvm LARI preparation/ordered send helpers.
Usage: iwlwifi_lari_oracle.py SOURCE_DIRECTORY OUTPUT_DIRECTORY
Qualified BIOS values/absence are fixture inputs; no EFI, AML, real firmware
command, regulatory admission, power programming or RF executes.
"""
import hashlib,json,re,subprocess,sys
from pathlib import Path
source,out=map(Path,sys.argv[1:])
expected={
'mvm/fw.c':'b08bbfe33ba78e332c1084917ab320b2a7efb54aa8c491602ff087554b77467c',
'fw/regulatory.h':'914bd35057a79788de2a1ca9f35f27211b4419c75a138f9e0191a5c499c1bc5e',
'fw/api/nvm-reg.h':'78f09e7a89c3396801c82cfc89b9c4eaf52792ecd2839ac4e483615433ac3f31',
'fw/file.h':'f3859d195bd190427e490f6b7c82e924b6e79f2e9cc7243ea2f5097a3195b1c3',
'iwl-csr.h':'9bc1643e0fa9725450e88f1235172b9d4326bb77a9df3c5b6fb1d56c15d134e7',
'iwl-config.h':'b37b175d2b80eb7a9309792d22f41e8cc94a60246420948e1e7a5b5aff65c4c9',
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
typedef uint8_t u8;typedef uint16_t u16;typedef uint32_t u32;typedef uint32_t __le32;
typedef unsigned iwl_ucode_tlv_capa_t;
#define __force
#define __packed __attribute__((packed))
#define BIT(n) (1U<<(n))
#define cpu_to_le32(x) (x)
#define le32_to_cpu(x) (x)
#define IWL_DEBUG_RADIO(...)
#define WIDE_ID(g,o) (((g)<<8)|(o))
#define REGULATORY_AND_NVM_GROUP 12
#define LARI_CONFIG_CHANGE 1
#define LARI_CONFIG_EXTENSION 8
'''
for file,name in [('fw/file.h','iwl_ucode_tlv_capa'),('fw/regulatory.h','iwl_dsm_funcs'),('fw/regulatory.h','iwl_dsm_values_srd'),('fw/regulatory.h','iwl_dsm_values_indonesia'),('fw/regulatory.h','iwl_dsm_unii4_bitmap'),('fw/regulatory.h','iwl_dsm_masks_reg'),('fw/api/nvm-reg.h','iwl_lari_config_masks')]:
 prelude+=extract(texts[file],r'^enum '+name+r'\s*\{')+';\n'
for name in ['iwl_bios_config_hdr','iwl_lari_config_change_cmd_v1','iwl_lari_config_change_cmd_v6','iwl_lari_config_change_cmd_v8','iwl_lari_config_change_cmd','iwl_lari_config_extension_cmd']:
 prelude+=extract(texts['fw/api/nvm-reg.h'],r'^struct '+name+r'\s*\{')+' __packed;\n'
for file,names in [('iwl-csr.h',['CSR_HW_RFID_TYPE']),('iwl-config.h',['IWL_CFG_RF_TYPE_HR1','IWL_CFG_RF_TYPE_HR2','IWL_CFG_RF_TYPE_JF1','IWL_CFG_RF_TYPE_JF2']),('fw/regulatory.h',['DSM_UNII4_ALLOW_BITMAP','DSM_11AX_ALLOW_BITMAP','DSM_EDT_ALLOWED_BITMAP','DSM_FORCE_DISABLE_CHANNELS_ALLOWED_BITMAP']),('fw/api/nvm-reg.h',['ACTIVATE_5G2_IN_WW_MASK','CHAN_STATE_ACTIVE_BITMAP_CMD_V8','CHAN_STATE_ACTIVE_BITMAP_CMD_V12'])]:
 for name in names:prelude+=macro(file,name)
prelude+=r'''
struct fw {unsigned ucode_capa,schema,extension;};
struct trans {struct {u32 hw_rf_id;} info;};
struct iwl_fw_runtime {struct fw *fw;struct trans *trans;u8 dsm_source,dsm_revision;};
struct iwl_mvm {struct fw *fw;struct iwl_fw_runtime fwrt;};
static unsigned mask,source_kind,revision,wbem_present;static u32 values[15],wbem;
static struct {unsigned id,len;u8 bytes[256];} sent[2];static unsigned count;
static bool fw_has_capa(unsigned *flags,unsigned bit){switch(bit){case 117:return *flags&1;case 123:return *flags&2;case 96:return *flags&4;case 129:return *flags&8;default:return false;}}
static unsigned iwl_fw_lookup_cmd_ver(struct fw *fw,u32 id,unsigned fallback){if(id==WIDE_ID(12,1))return fw->schema;if(id==WIDE_ID(12,8))return fw->extension;return fallback;}
static int iwl_bios_get_dsm(struct iwl_fw_runtime *rt,unsigned index,u32 *value){if(!(mask&(1U<<index)))return -ENOENT;*value=values[index];rt->dsm_source=source_kind;rt->dsm_revision=revision;return 0;}
static int iwl_bios_get_wbem(struct iwl_fw_runtime *rt,u32 *value){(void)rt;if(!wbem_present)return -ENOENT;*value=wbem;return 0;}
static int iwl_mvm_send_cmd_pdu(struct iwl_mvm *m,u32 id,unsigned flags,unsigned len,void *bytes){(void)m;(void)flags;if(count>=2||len>256)abort();sent[count].id=id;sent[count].len=len;memcpy(sent[count].bytes,bytes,len);count++;return 0;}
'''
for name in ['iwl_mvm_get_lari_config_bitmap','iwl_mvm_get_lari_config_cmd_size','iwl_mvm_fill_lari_config','iwl_mvm_send_lari_cfg_extension','iwl_mvm_lari_cfg']:
 prelude+=extract(texts['mvm/fw.c'],r'^static (?:__le32|size_t|int|void) '+name+r'\([^{};]*?\)\n\{')+'\n'
main=r'''
static void hex(const void *p,size_t n){for(size_t i=0;i<n;i++)printf("%02x",((const u8*)p)[i]);}
int main(void){
 unsigned schemas[]={1,6,8,12};u32 radios[]={0x10a000,0x10d000,0x10c000,0x108000,0x105000,0x200000};
 unsigned masks[]={0,0x7fff,0x5555,0x2aaa,1<<4,1<<2,(1<<1)|(1<<4),(1<<6)|(1<<7)|(1<<8)|(1<<9)|(1<<10)|(1<<12)};
 for(unsigned s=0;s<4;s++)for(unsigned ext=0;ext<2;ext++)for(unsigned cap=0;cap<16;cap++)for(unsigned r=0;r<6;r++)for(unsigned scene=0;scene<16;scene++){
  struct fw fw={.ucode_capa=cap,.schema=schemas[s],.extension=ext};struct trans tr={.info.hw_rf_id=radios[r]};struct iwl_mvm m={.fw=&fw,.fwrt={.fw=&fw,.trans=&tr}};
  mask=masks[scene%8];source_kind=scene%2?2:1;revision=source_kind==2?4:0;wbem_present=(scene&4)!=0;wbem=scene&8?3:0;
  for(unsigned i=0;i<15;i++)values[i]=scene<8?0:0xffffffffU^(scene*0x01234567U+i*0x10203U);
  values[1]=scene%4;values[2]=scene%3;values[4]=scene&1?4:0;
  struct iwl_lari_config_change_cmd cmd;size_t size;int ret=iwl_mvm_fill_lari_config(&m.fwrt,&cmd,&size);
  count=0;iwl_mvm_lari_cfg(&m);
  printf("case %u %u %u %u %u %d %zu ",schemas[s],ext,cap,radios[r],scene,ret,size);hex(&cmd,36);printf(" %u",count);
  for(unsigned i=0;i<count;i++){printf(" %u %u ",sent[i].id,sent[i].len);hex(sent[i].bytes,sent[i].len);}puts("");
 }
 return 0;
}
'''
out.mkdir(parents=True,exist_ok=True);unit=out/'linux-iwlwifi-lari.c';unit.write_text(prelude+main);exe=out/'linux-iwlwifi-lari'
subprocess.run(['cc','-std=gnu11','-O1','-g','-fsanitize=address,undefined',str(unit),'-o',str(exe)],check=True)
with (out/'trace.txt').open('wb') as trace:subprocess.run([str(exe.resolve())],stdout=trace,check=True)
manifest={'linux_commit':'a804c5742bff224d4cb4d25dd383554d598be32b','sources':expected,'trace_sha256':hashlib.sha256((out/'trace.txt').read_bytes()).hexdigest()};(out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');print(json.dumps(manifest,indent=2))

#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
# Copyright (C) 2017 Intel Deutschland GmbH
# Copyright (C) 2019-2026 Intel Corporation
"""Unchanged BIOS selection/cache helpers with modeled raw ACPI/EFI reads.
Usage: iwlwifi_bios_selection_oracle.py SOURCE_DIRECTORY OUTPUT_DIRECTORY
No real AML, GetVariable, device, firmware command or RF runs. Full source
helpers/macros perform GLAI, UEFI-first selection, shared DSM cache and fallback.
The raw service shim deliberately excludes Stela's Unavailable/bound refusal.
"""
import hashlib,json,re,subprocess,sys
from pathlib import Path
source,out=map(Path,sys.argv[1:])
expected={
'fw/acpi.c':'826dc8c9fe1adedd7556a27f75f1e7c0f58423e7f49795f0f82d83585f812669',
'fw/acpi.h':'ceaa02d9e9c995f34bddcbd29438b6989cc19ec5db2d3ac0f1da2fc4ebcaf37a',
'fw/uefi.c':'7e57fe0ff11291e6f3c77aedd2f5ca539e825b279497f7a7e89f796d8f829738',
'fw/uefi.h':'68ec89d9660c9a7de8acde98af29abcabf00a8ed4cc8057def5e6fbcb452a1e0',
'fw/regulatory.c':'80d4387ac8fb6069c8dc042f77ca3bf6129bb19e1543eaaecc495d024f4419bc',
'fw/regulatory.h':'914bd35057a79788de2a1ca9f35f27211b4419c75a138f9e0191a5c499c1bc5e',
'fw/api/nvm-reg.h':'78f09e7a89c3396801c82cfc89b9c4eaf52792ecd2839ac4e483615433ac3f31',
}
texts={}
for name,digest in expected.items():
    data=(source/name).read_bytes();assert hashlib.sha256(data).hexdigest()==digest,name;texts[name]=data.decode()
helpers={}
def extract(file,pattern,key):
    m=re.search(pattern,texts[file],re.M);assert m,pattern
    at,depth=m.end(),1
    while depth:depth+=(texts[file][at]=='{')-(texts[file][at]=='}');at+=1
    result=texts[file][m.start():at];helpers[key]=hashlib.sha256(result.encode()).hexdigest();return result

def function(file,name):
    return extract(file,r'^(?:static )?(?:int |void |void \*\n|union acpi_object \*\n)'+name+r'\([^;{}]*?\)\n\{',name)+'\n'
p=r'''
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
typedef uint8_t u8;typedef uint32_t u32;typedef uint64_t u64;typedef uint64_t __le64;
typedef unsigned guid_t;typedef unsigned efi_guid_t;typedef uint16_t efi_char16_t;
#define __packed __attribute__((packed))
#define BIT(n) (1U<<(n))
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#define BITS_PER_TYPE(t) (sizeof(t)*8)
#define BUILD_BUG_ON(x) _Static_assert(!(x),"source assertion")
#define IWL_DEBUG_RADIO(...)
#define IWL_DEBUG_DEV_RADIO(...)
#define IWL_EXPORT_SYMBOL(...)
#define WARN_ON_ONCE(x) (x)
#define WARN_ON(x) (x)
#define min_t(t,a,b) ((t)(a)<(t)(b)?(t)(a):(t)(b))
#define le64_to_cpu(x) (x)
#define kfree free
#define ACPI_FREE free
#define ERR_PTR(e) ((void*)(intptr_t)(e))
#define IS_ERR(p) ((uintptr_t)(p)>=(uintptr_t)-4095)
#define ACPI_TYPE_INTEGER 1
#define ACPI_TYPE_BUFFER 3
#define ACPI_TYPE_PACKAGE 4
#define ACPI_WIFI_DOMAIN 7
#define ACPI_GLAI_METHOD "GLAI"
#define ACPI_WBEM_METHOD "WBEM"
#define ACPI_GLAI_WIFI_DATA_SIZE 2
#define ACPI_WBEM_WIFI_DATA_SIZE 2
#define ACPI_GLAI_MAX_STATUS 2
#define ACPI_DSM_REV 0
#define IWL_ACPI_WBEM_REVISION 0
#define IWL_ACPI_WBEM_REV0_MASK 3
#define IWL_UEFI_WBEM_REVISION 0
#define IWL_UEFI_WBEM_REV0_MASK 3
#define IWL_UEFI_DSM_REVISION 4
#define UEFI_MAX_DSM_FUNCS 32
#define UEFI_WIFI_GUID_UNLOCKED 0
#define IWL_UEFI_DSM_NAME ((efi_char16_t*)1)
#define IWL_UEFI_WBEM_NAME ((efi_char16_t*)2)
static efi_guid_t IWL_EFI_WIFI_GUID;static guid_t iwl_guid;
union acpi_object {
 unsigned type;
 struct {unsigned type;u64 value;} integer;
 struct {unsigned type;unsigned length;u8 *pointer;} buffer;
 struct {unsigned type;unsigned count;union acpi_object *elements;} package;
};
struct device {int unused;};struct iwl_trans {int unused;};
'''
p+=extract('fw/regulatory.h',r'^enum iwl_dsm_funcs\s*\{','iwl_dsm_funcs')+';\n'
p+=extract('fw/api/nvm-reg.h',r'^enum bios_source\s*\{','bios_source')+';\n'
for name in ['uefi_cnv_var_general_cfg','uefi_cnv_wlan_wbem_data']:
    p+=extract('fw/uefi.h',r'^struct '+name+r'\s*\{',name)+' __packed;\n'
p+='struct iwl_fw_runtime {struct device *dev;struct iwl_trans *trans;u8 uefi_tables_lock_status,wbem_source,wbem_revision,dsm_source,dsm_revision;u32 dsm_funcs_valid,dsm_values[DSM_FUNC_NUM_FUNCS];};\n'
m=re.search(r'^static const size_t acpi_dsm_size.*?^};',texts['fw/acpi.c'],re.M|re.S);assert m;p+=m[0]+'\n';helpers['acpi_dsm_size']=hashlib.sha256(m[0].encode()).hexdigest()
p+=r'''
static unsigned scenario,calls,call_ids[64];static u64 callhash;
static void called(unsigned id){call_ids[calls++]=id;callhash=callhash*131+id;}
static u32 pattern(unsigned f){return 0x9e3779b9U*(f+1)^scenario;}
static union acpi_object *integer_object(u64 value){union acpi_object *o=calloc(1,sizeof(*o));o->integer.type=ACPI_TYPE_INTEGER;o->integer.value=value;return o;}
static union acpi_object *buffer_object(u64 value,unsigned length){union acpi_object *o=calloc(1,sizeof(*o)+8);o->buffer.type=ACPI_TYPE_BUFFER;o->buffer.length=length;o->buffer.pointer=(u8*)(o+1);memcpy(o->buffer.pointer,&value,8);return o;}
static union acpi_object *package_object(u64 revision,u64 value,unsigned domain){
 union acpi_object *o=calloc(5,sizeof(*o));o[0].package.type=ACPI_TYPE_PACKAGE;o[0].package.count=2;o[0].package.elements=o+1;
 o[1].integer.type=ACPI_TYPE_INTEGER;o[1].integer.value=revision;o[2].package.type=ACPI_TYPE_PACKAGE;o[2].package.count=2;o[2].package.elements=o+3;
 o[3].integer.type=ACPI_TYPE_INTEGER;o[3].integer.value=domain;o[4].integer.type=ACPI_TYPE_INTEGER;o[4].integer.value=value;return o;
}
static void *iwl_acpi_get_object(struct device *d,const char *method){
 (void)d;bool glai=!strcmp(method,"GLAI");called(glai?1:2);
 if(glai){unsigned mode=scenario%8;if(mode==0)return ERR_PTR(-ENOENT);unsigned statuses[]={0,0,1,2,3,1,1,1};return package_object(mode==5?1:mode==7?0x100000000ULL:0,statuses[mode],mode==6?8:7);}
 unsigned mode=(scenario/512)%8;if(mode==0)return ERR_PTR(-ENOENT);return package_object(mode==1?1:0,pattern(31),mode==2?8:7);
}
static union acpi_object *iwl_acpi_get_dsm_object(struct device *d,int rev,int func,void *arg,const guid_t *guid){
 (void)d;(void)rev;(void)arg;(void)guid;called(10+func);unsigned mode=(scenario/64)%8;
 if(func==0){if(mode==0)return ERR_PTR(-ENOENT);if(mode==1)return calloc(1,sizeof(union acpi_object));if(mode==2)return integer_object(0);if(mode==3)return integer_object(0x7fff);if(mode==4)return buffer_object(0x7fff,1);if(mode==5)return buffer_object(0x7fff,3);if(mode==6)return buffer_object(0x7fff,8);return integer_object(0xffffffff00007fffULL);}
 unsigned kind=(func+(scenario/512)%8)%6;u64 value=0x1234567800000000ULL|pattern(func);
 if(kind==0)return ERR_PTR(-ENOENT);if(kind==1)return calloc(1,sizeof(union acpi_object));if(kind==2)return integer_object(value);return buffer_object(value,kind==3?0:kind==4?1:8);
}
static void *iwl_uefi_get_variable(efi_char16_t *name,efi_guid_t *guid,unsigned long *size){
 (void)guid;bool dsm=name==IWL_UEFI_DSM_NAME;called(dsm?3:4);unsigned mode=(scenario/(dsm?8:512))%8;
 if(mode==0)return ERR_PTR(-ENOENT);unsigned len=dsm?129:5;if(mode==1)len--;
 u8 *raw=calloc(1,len+8);*size=len;raw[0]=dsm?(mode==2?3:4):(mode==2?1:0);
 if(dsm){u32 masks[]={0,0,0,0,0x7fff,0xaaaa,0x5555,1<<4};for(unsigned f=0;f<32;f++){u32 value=f?pattern(f):masks[mode];memcpy(raw+1+f*4,&value,4);}}
 else {u32 value=pattern(30);memcpy(raw+1,&value,4);}return raw;
}
'''
for name in ['iwl_acpi_get_dsm_integer','iwl_acpi_load_dsm_values','iwl_acpi_get_dsm','iwl_acpi_get_wifi_pkg_range','iwl_acpi_get_wifi_pkg','iwl_acpi_get_guid_lock_status','iwl_acpi_get_wbem']:
    p+=function('fw/acpi.c',name)
for name in ['iwl_uefi_get_verified_variable_guid','iwl_uefi_get_verified_variable','iwl_uefi_get_wbem','iwl_uefi_load_dsm_values','iwl_uefi_get_dsm']:
    p+=function('fw/uefi.c',name)
m=re.search(r'^#define GET_BIOS_TABLE.*?(?=^IWL_BIOS_TABLE_LOADER\(wrds_table\))',texts['fw/regulatory.c'],re.M|re.S);assert m;p+=m[0]+'\n';helpers['GET_BIOS_TABLE_AND_LOADERS']=hashlib.sha256(m[0].encode()).hexdigest()
p+=function('fw/regulatory.c','iwl_bios_get_dsm')
p+='IWL_BIOS_TABLE_LOADER_DATA(wbem, u32);\n'
p+=r'''
int main(void){
 unsigned order[]={4,2,1,6,7,8,3,9,10,12,11,13,14,4,1};
 for(scenario=0;scenario<4096;scenario++){
  struct iwl_fw_runtime fw={0};calls=0;callhash=0;iwl_acpi_get_guid_lock_status(&fw);
  for(unsigned i=0;i<ARRAY_SIZE(order)+1;i++){
   bool wbem=i==ARRAY_SIZE(order);unsigned f=wbem?99:order[i];u32 value=0;int ret=wbem?iwl_bios_get_wbem(&fw,&value):iwl_bios_get_dsm(&fw,f,&value);
   printf("%u %u %u %u %u %u %u %u %llu",scenario,f,ret?0:1,value,wbem?fw.wbem_source:fw.dsm_source,wbem?fw.wbem_revision:fw.dsm_revision,fw.uefi_tables_lock_status,calls,(unsigned long long)callhash);
   for(unsigned j=0;j<calls;j++)printf(" %u",call_ids[j]);puts("");
  }
 }
 return 0;
}
'''
out.mkdir(parents=True,exist_ok=False);unit=out/'linux-iwlwifi-bios-selection.c';unit.write_text(p);exe=out/'linux-iwlwifi-bios-selection'
subprocess.run(['cc','-std=gnu11','-O1','-g','-fsanitize=address,undefined',str(unit),'-o',str(exe)],check=True,timeout=120)
with (out/'trace.txt').open('wb') as trace:subprocess.run([str(exe.resolve())],stdout=trace,check=True,timeout=60)
manifest={'linux_commit':'a804c5742bff224d4cb4d25dd383554d598be32b','sources':expected,'helpers':helpers,'scenarios':4096,'observations':65536,'trace_sha256':hashlib.sha256((out/'trace.txt').read_bytes()).hexdigest(),'unit_sha256':hashlib.sha256(unit.read_bytes()).hexdigest()}
(out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');print(json.dumps(manifest,indent=2))

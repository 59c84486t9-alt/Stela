#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
# Copyright (C) 2012-2014, 2018-2026 Intel Corporation
# Copyright (C) 2013-2015 Intel Mobile Communications GmbH
# Copyright (C) 2016-2017 Intel Deutschland GmbH
"""Complete source DQA/thermal/cTDP/LTR/device power helpers.
Usage: iwlwifi_control_oracle.py SOURCE_DIRECTORY OUTPUT_DIRECTORY
BIOS reads, thermal-trip walk and firmware send/status are explicit fixture
boundaries; no native services, BIOS source authority, power or RF executes.
"""
import hashlib,json,re,subprocess,sys
from pathlib import Path
source,out=map(Path,sys.argv[1:])
expected={
'mvm/fw.c':'b08bbfe33ba78e332c1084917ab320b2a7efb54aa8c491602ff087554b77467c',
'mvm/tt.c':'9e9215ecaff9eb8d2e80c7935b912d60ce72d553e559811bf5fe9a48ec9463ac',
'mvm/power.c':'1897b18f1b2da963504206c3a8c2a021e990a6a918708fa8b25ab4963087ffed',
'fw/api/config.h':'e3b2c4c651e9959ef32d1bf98c88d04591b9895ce2f526344989d6789b5f4a99',
'fw/api/phy.h':'a4c17fc7e3cf8445649a12abede1ed91cbce96ff5b79c0293c101fd76a20dde6',
'fw/api/power.h':'8182c5583306e9c35628991815d63233c70c333a58f14eac42069af75b1fe7f4',
'iwl-csr.h':'9bc1643e0fa9725450e88f1235172b9d4326bb77a9df3c5b6fb1d56c15d134e7',
'iwl-config.h':'b37b175d2b80eb7a9309792d22f41e8cc94a60246420948e1e7a5b5aff65c4c9',
'fw/file.h':'f3859d195bd190427e490f6b7c82e924b6e79f2e9cc7243ea2f5097a3195b1c3',
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
#include <limits.h>
typedef uint8_t u8;typedef int16_t s16;typedef uint32_t u32;typedef uint64_t u64;typedef uint16_t __le16;typedef uint32_t __le32;
#define __packed __attribute__((packed))
#define CONFIG_THERMAL
#define BIT(n) (1U<<(n))
#define cpu_to_le16(x) (x)
#define le16_to_cpu(x) (x)
#define cpu_to_le32(x) (x)
#define lockdep_assert_held(...)
#define IWL_ERR(...)
#define IWL_DEBUG_FW(...)
#define IWL_DEBUG_TEMP(...)
#define IWL_DEBUG_POWER(...)
#define IWL_MVM_STATUS_IN_D3 0
#define IWL_POWER_SCHEME_CAM 1
#define IWL_MVM_DQA_CMD_QUEUE 0
#define DATA_PATH_GROUP 5
#define DQA_ENABLE_CMD 0
#define PHY_OPS_GROUP 4
#define CTDP_CONFIG_CMD 3
#define TEMP_REPORTING_THRESHOLDS_CMD 4
#define POWER_TABLE_CMD 0x77
#define LTR_CONFIG 0xee
#define WIDE_ID(g,o) (((g)<<8)|(o))
#define THERMAL_TEMP_INVALID INT_MIN
#define sort(base,n,size,compare,unused) qsort(base,n,size,compare)
#define for_each_thermal_trip(zone,callback,arg) do {for(unsigned t=0;t<trip_count;t++)callback(&trips[t],arg);}while(0)
static bool test_bit(unsigned bit,unsigned long *word){return ((*word>>bit)&1)!=0;}
'''
for file,name in [('fw/api/power.h','iwl_device_power_flags'),('fw/api/power.h','iwl_ltr_config_flags'),('fw/api/phy.h','iwl_ctdp_cmd_operation')]:prelude+=extract(texts[file],r'^enum '+name+r'\s*\{')+';\n'
for file,name in [('fw/api/config.h','iwl_dqa_enable_cmd'),('fw/api/power.h','iwl_device_power_cmd'),('fw/api/power.h','iwl_ltr_config_cmd'),('fw/api/phy.h','iwl_ctdp_cmd'),('fw/api/phy.h','temp_report_ths_cmd')]:
 if name=='iwl_ltr_config_cmd':prelude+=macro('fw/api/power.h','LTR_VALID_STATES_NUM')
 if name=='temp_report_ths_cmd':prelude+=macro('fw/api/phy.h','IWL_MAX_DTS_TRIPS')
 prelude+=extract(texts[file],r'^struct '+name+r'\s*\{')+' __packed;\n'
for file,names in [('iwl-csr.h',['CSR_HW_RFID_TYPE','CSR_HW_RFID_IS_CDB']),('iwl-config.h',['IWL_CFG_RF_TYPE_JF1','IWL_CFG_RF_TYPE_JF2','IWL_CFG_RF_TYPE_HR1','IWL_CFG_RF_TYPE_HR2','IWL_CFG_RF_TYPE_GF','IWL_CFG_RF_TYPE_FM']),('mvm/tt.c',['IWL_MVM_NUM_CTDP_STEPS','IWL_MVM_MIN_CTDP_BUDGET_MW'])]:
 for name in names:prelude+=macro(file,name)
prelude+=r'''
struct fw {unsigned power_schema;};struct trans {struct {u32 hw_rf_id;} info;bool ltr;};struct iwl_fw_runtime {int unused;};
struct thermal_trip {int temperature;};static struct thermal_trip trips[8];static unsigned trip_count;
struct iwl_mvm {struct fw *fw;struct trans *trans;struct iwl_fw_runtime fwrt;bool ps_disabled;u32 ext_clock_valid;unsigned long status;struct {u32 power_budget_mw;} thermal_throttle;struct {u32 cur_state;} cooling_dev;struct {void *tzone;} tz_device;};
static struct {unsigned power_scheme;} iwlmvm_mod_params;
static u64 bios;static u8 wire[256];static unsigned wire_len,wire_id,sends;
static unsigned iwl_fw_lookup_cmd_ver(struct fw *fw,u32 id,unsigned fallback){return id==POWER_TABLE_CMD?fw->power_schema:fallback;}
static bool iwl_trans_is_ltr_enabled(struct trans *tr){return tr->ltr;}
static int iwl_bios_get_pwr_limit(struct iwl_fw_runtime *rt,u64 *v){(void)rt;*v=bios;return 0;}
static int iwl_mvm_send_cmd_pdu(struct iwl_mvm *m,u32 id,unsigned flags,unsigned n,const void *data){(void)m;(void)flags;if(n>256)abort();wire_id=id;wire_len=n;memcpy(wire,data,n);sends++;return 0;}
static int iwl_mvm_send_cmd_pdu_status(struct iwl_mvm *m,u32 id,unsigned n,const void *data,u32 *status){*status=33;return iwl_mvm_send_cmd_pdu(m,id,0,n,data);}
'''
prelude+=extract(texts['mvm/tt.c'],r'^struct iwl_trip_walk_data\s*\{')+';\n'
for file,name in [('mvm/fw.c','iwl_mvm_send_dqa_cmd'),('mvm/fw.c','iwl_mvm_config_ltr'),('mvm/tt.c','iwl_mvm_ctdp_get_max_budget'),('mvm/tt.c','iwl_mvm_ctdp_command'),('mvm/power.c','iwl_mvm_power_update_device'),('mvm/tt.c','compare_temps'),('mvm/tt.c','iwl_trip_temp_cb'),('mvm/tt.c','iwl_mvm_send_temp_report_ths_cmd')]:
 prelude+=extract(texts[file],r'^(?:static )?(?:int|u32) '+name+r'\([^{};]*?\)\n\{')+'\n'
main=r'''
static void hex(void){for(unsigned i=0;i<wire_len;i++)printf("%02x",wire[i]);puts("");}
int main(void){
 struct fw fw={.power_schema=6};struct trans tr={0};struct iwl_mvm m={.fw=&fw,.trans=&tr};
 iwl_mvm_send_dqa_cmd(&m);printf("dqa %u ",wire_id);hex();
 for(unsigned enabled=0;enabled<2;enabled++){tr.ltr=enabled;sends=0;iwl_mvm_config_ltr(&m);printf("ltr %u %u",enabled,sends);if(sends){printf(" %u ",wire_id);hex();}else puts("");}
 u32 clocks[]={0,1,2,0xffffffff};
 for(unsigned ver=6;ver<=7;ver++)for(unsigned cam=0;cam<2;cam++)for(unsigned ps=0;ps<2;ps++)for(unsigned c=0;c<4;c++)for(unsigned d3=0;d3<2;d3++){
  fw.power_schema=ver;iwlmvm_mod_params.power_scheme=cam;m.ps_disabled=ps;m.ext_clock_valid=clocks[c];m.status=d3;iwl_mvm_power_update_device(&m);printf("power %u %u %u %u %u %u ",ver,cam,ps,clocks[c],d3,wire_id);hex();
 }
 for(unsigned n=0;n<=8;n++)for(unsigned scene=0;scene<16;scene++){
  trip_count=n;m.tz_device.tzone=n?(void*)1:NULL;for(unsigned i=0;i<n;i++)trips[i].temperature=((int)((scene*13+i*29)%171)-40)*1000;
  iwl_mvm_send_temp_report_ths_cmd(&m);printf("thresholds %u %u %u ",n,scene,wire_id);hex();
 }
 u32 radios[]={0x105000,0x108000,0x10a000,0x10c000,0x10d000,0x1010d000,0x112000,0x200000};
 u64 budgets[]={0,1,149,150,151,1999,2000,2400,2880,3450,5200,5550,5551,0xffff,0xffffffff,0xffffffffffffffffULL};
 for(unsigned r=0;r<8;r++)for(unsigned b=0;b<16;b++){
  tr.info.hw_rf_id=radios[r];bios=budgets[b];u32 max=iwl_mvm_ctdp_get_max_budget(&m);m.thermal_throttle.power_budget_mw=max;printf("budget %u %llu %u\n",radios[r],(unsigned long long)bios,max);
  for(unsigned state=0;state<20;state++)for(unsigned op=1;op<=4;op*=2){int ret=iwl_mvm_ctdp_command(&m,op,state);printf("ctdp %u %llu %u %u %d %u ",radios[r],(unsigned long long)bios,op,state,ret,wire_id);hex();}
 }
 return 0;
}
'''
out.mkdir(parents=True,exist_ok=True);unit=out/'linux-iwlwifi-control.c';unit.write_text(prelude+main);exe=out/'linux-iwlwifi-control'
subprocess.run(['cc','-std=gnu11','-O1','-g','-fsanitize=address,undefined',str(unit),'-o',str(exe)],check=True)
with (out/'trace.txt').open('wb') as trace:subprocess.run([str(exe.resolve())],stdout=trace,check=True)
manifest={'linux_commit':'a804c5742bff224d4cb4d25dd383554d598be32b','sources':expected,'trace_sha256':hashlib.sha256((out/'trace.txt').read_bytes()).hexdigest()};(out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');print(json.dumps(manifest,indent=2))

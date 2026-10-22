#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
# Copyright (C) 2012-2014, 2018-2025 Intel Corporation
# Copyright (C) 2013-2015 Intel Mobile Communications GmbH
# Copyright (C) 2015-2017 Intel Deutschland GmbH
"""Unchanged complete RX MPDU packed structures and enum layout oracle.
Usage: iwlwifi_mpdu_oracle.py SOURCE_DIRECTORY OUTPUT_DIRECTORY
This is source ABI evidence, not execution of RX MAC/crypto/replay/DMA helpers.
"""
import hashlib,json,re,subprocess,sys
from pathlib import Path
source,out=map(Path,sys.argv[1:])
expected={
'fw/api/rx.h':'5bfbab2457de067f13c01158014d336b09803024d96e17dea58742293bbd57dc',
'mvm/rxmq.c':'aa35ae948dd468ee78cb870c2d9f4bc7d99fe5e8e5ff23eeef53b36ac7fdc32d',
'mvm/mvm.h':'613e549d15c1c3d79f661621f058f94efe9312642a6af9605a351152742cf751',
'iwl-trans.h':'96d1daa1a251e4c1c4d96a3f625db7cc207d0051375010aa7790830cf730a3c4',
'fw/file.h':'f3859d195bd190427e490f6b7c82e924b6e79f2e9cc7243ea2f5097a3195b1c3',
}
texts={}
for name,digest in expected.items():
 data=(source/name).read_bytes();assert hashlib.sha256(data).hexdigest()==digest,name;texts[name]=data.decode()
def extract(pattern):
 text=texts['fw/api/rx.h'];m=re.search(pattern,text,re.M);assert m,pattern
 at,depth=m.end(),1
 while depth:depth+=(text[at]=='{')-(text[at]=='}');at+=1
 return text[m.start():at]
prelude=r'''
#include <stdint.h>
#include <stdio.h>
#include <stddef.h>
#include <string.h>
typedef uint8_t u8;typedef uint16_t __le16;typedef uint32_t __le32;typedef uint64_t __le64;typedef uint16_t __be16;
#define __packed __attribute__((packed))
#define BIT(n) (1U<<(n))
'''
for name in ['iwl_rx_mpdu_mac_flags1','iwl_rx_mpdu_mac_flags2','iwl_rx_mpdu_amsdu_info','iwl_rx_mpdu_mac_phy_band','iwl_rx_mpdu_status','iwl_rx_mpdu_reorder_data','iwl_rx_mpdu_phy_info']:
 prelude+=extract(r'^enum '+name+r'\s*\{')+';\n'
for name in ['iwl_rx_mpdu_desc_v1','iwl_rx_mpdu_desc_v3','iwl_rx_mpdu_desc']:
 prelude+=extract(r'^struct '+name+r'\s*\{')+' __packed;\n'
main=r'''
int main(void){
 printf("layout %zu %zu %zu %zu %zu %zu %zu %zu\n",offsetof(struct iwl_rx_mpdu_desc,v1)+sizeof(struct iwl_rx_mpdu_desc_v1),sizeof(struct iwl_rx_mpdu_desc),offsetof(struct iwl_rx_mpdu_desc,v1.rate_n_flags),offsetof(struct iwl_rx_mpdu_desc,v3.rate_n_flags),offsetof(struct iwl_rx_mpdu_desc,v1.tsf_on_air_rise),offsetof(struct iwl_rx_mpdu_desc,v3.tsf_on_air_rise),offsetof(struct iwl_rx_mpdu_desc,status),offsetof(struct iwl_rx_mpdu_desc,reorder_data));
 for(unsigned family=0;family<2;family++)for(unsigned scene=0;scene<2048;scene++){
  struct iwl_rx_mpdu_desc d;u8 *raw=(void*)&d;for(unsigned i=0;i<sizeof(d);i++)raw[i]=(u8)(scene*37+i*59+(scene>>3));
  d.mpdu_len=scene%257;d.phy_info=(scene*73)&0x1ff;d.mac_flags1=(u8)scene;d.mac_flags2=(u8)(scene>>2);d.amsdu_info=(u8)(scene>>1);d.mac_phy_band=(u8)scene;
  d.status=((scene*151)^0xa55aa55aU);d.reorder_data=(scene*0x102037U)^0xfedcba98;
  unsigned len=family?sizeof(d):offsetof(struct iwl_rx_mpdu_desc,v1)+sizeof(d.v1);
  printf("case %u %u ",family,scene);for(unsigned i=0;i<len;i++)printf("%02x",raw[i]);
  printf(" %u %u %u %u %u %u %u %u",d.mpdu_len,d.mac_flags1,d.mac_flags2,d.amsdu_info,d.phy_info,d.mac_phy_band,d.status,d.reorder_data);
  if(family)printf(" %u %u %u %u %u %u %llu %u %u %u %u %u",d.v3.rate_n_flags,d.v3.energy_a,d.v3.energy_b,d.v3.channel,d.v3.mac_context,d.v3.gp2_on_air_rise,(unsigned long long)d.v3.tsf_on_air_rise,d.v3.phy_data0,d.v3.phy_data1,d.v3.phy_data2,d.v3.phy_data3,d.v3.phy_data5);
  else printf(" %u %u %u %u %u %u %llu %u %u %u %u -",d.v1.rate_n_flags,d.v1.energy_a,d.v1.energy_b,d.v1.channel,d.v1.mac_context,d.v1.gp2_on_air_rise,(unsigned long long)d.v1.tsf_on_air_rise,d.v1.phy_data0,d.v1.phy_data1,d.v1.phy_data2,d.v1.phy_data3);
  printf(" %u %u %u %u %u %u %u %u %u %u %u\n",d.phy_eht_data4,(d.status&IWL_RX_MPDU_STATUS_SEC_MASK)>>8,(d.status&IWL_RX_MPDU_STATUS_STA_ID)>>24,(d.reorder_data&IWL_RX_MPDU_REORDER_NSSN_MASK),(d.reorder_data&IWL_RX_MPDU_REORDER_SN_MASK)>>IWL_RX_MPDU_REORDER_SN_SHIFT,(d.reorder_data&IWL_RX_MPDU_REORDER_BAID_MASK)>>IWL_RX_MPDU_REORDER_BAID_SHIFT,(d.reorder_data&IWL_RX_MPDU_REORDER_BA_OLD_SN)!=0,(d.mac_flags1&IWL_RX_MPDU_MFLG1_MIC_CRC_LEN_MASK)>>IWL_RX_MPDU_MFLG1_MIC_CRC_LEN_SHIFT,(d.mac_flags2&IWL_RX_MPDU_MFLG2_HDR_LEN_MASK)*2,(d.mac_flags2&IWL_RX_MPDU_MFLG2_PAD)?2:0,(d.mac_phy_band&IWL_RX_MPDU_MAC_PHY_BAND_BAND_MASK)>>6);
 }
 return 0;
}
'''
out.mkdir(parents=True,exist_ok=True);unit=out/'linux-iwlwifi-mpdu.c';unit.write_text(prelude+main);exe=out/'linux-iwlwifi-mpdu'
subprocess.run(['cc','-std=gnu11','-O1','-g','-fsanitize=address,undefined',str(unit),'-o',str(exe)],check=True)
with (out/'trace.txt').open('wb') as trace:subprocess.run([str(exe.resolve())],stdout=trace,check=True)
manifest={'linux_commit':'a804c5742bff224d4cb4d25dd383554d598be32b','sources':expected,'trace_sha256':hashlib.sha256((out/'trace.txt').read_bytes()).hexdigest()};(out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');print(json.dumps(manifest,indent=2))

#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
# Copyright (C) 2003-2014, 2018-2026 Intel Corporation
# Copyright (C) 2013-2015 Intel Mobile Communications GmbH
# Copyright (C) 2016-2017 Intel Deutschland GmbH
"""Compile unchanged donor receive/ALIVE structs; compare layout and raw fields.
Usage: iwlwifi_receive_oracle.py SOURCE_DIRECTORY OUTPUT_DIRECTORY
This is a wire-layout oracle, not execution of Linux's interrupt/DMA/ALIVE path.
"""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
source,out=map(Path,sys.argv[1:])
expected={
 'fw/api/alive.h':'7542590e6b33b4a32a501e217d357f52f1bc0ca64399a0675a79ed3b27d7dde8',
 'pcie/gen1_2/internal.h':'572df25a5a22b0dbd03a3b2e83d553768d0af4e09a9071e2b6002f276bd41d10',
}
texts={}
for name,digest in expected.items():
 data=(source/name).read_bytes();assert hashlib.sha256(data).hexdigest()==digest,name;texts[name]=data.decode()
def structure(name,filename):
 match=re.search(r'struct '+name+r' \{.*?\} __packed;',texts[filename],re.S);assert match,name
 return match.group(0)+'\n'
prelude=r'''// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
typedef uint8_t u8;typedef uint16_t __le16;typedef uint32_t __le32;typedef uint64_t __le64;
#define __packed __attribute__((packed))
'''
for name in ['iwl_lmac_debug_addrs','iwl_lmac_alive','iwl_umac_debug_addrs','iwl_umac_alive','iwl_sku_id','iwl_imr_alive_info','iwl_alive_ntf_v7','iwl_alive_ntf']:
 prelude+=structure(name,'fw/api/alive.h')
for name in ['iwl_rx_transfer_desc','iwl_rx_completion_desc']:
 prelude+=structure(name,'pcie/gen1_2/internal.h')
main=r'''
int main(void){
 printf("layout %zu %zu %zu %zu %zu %zu %zu %zu %zu\n",sizeof(struct iwl_alive_ntf_v7),sizeof(struct iwl_alive_ntf),sizeof(struct iwl_lmac_alive),offsetof(struct iwl_alive_ntf_v7,umac_data),offsetof(struct iwl_alive_ntf_v7,sku_id),offsetof(struct iwl_alive_ntf_v7,imr),sizeof(struct iwl_rx_transfer_desc),offsetof(struct iwl_rx_transfer_desc,addr),offsetof(struct iwl_rx_completion_desc,rbid));
 struct iwl_alive_ntf p;unsigned char *bytes=(void*)&p;for(unsigned i=0;i<sizeof(p);i++)bytes[i]=(unsigned char)(i+17);p.status=0xcafe;
 printf("flags %x\n",p.flags);
 for(unsigned j=0;j<2;j++){
  struct iwl_lmac_alive *l=&p.lmac_data[j];printf("lmac %x %x %x %x %x %x %x",l->ucode_major,l->ucode_minor,l->ver_subtype,l->ver_type,l->mac,l->opt,l->timestamp);
  printf(" %x %x %x %x %x %x %x %x\n",l->dbg_ptrs.error_event_table_ptr,l->dbg_ptrs.log_event_table_ptr,l->dbg_ptrs.cpu_register_ptr,l->dbg_ptrs.dbgm_config_ptr,l->dbg_ptrs.alive_counter_ptr,l->dbg_ptrs.scd_base_ptr,l->dbg_ptrs.st_fwrd_addr,l->dbg_ptrs.st_fwrd_size);
 }
 printf("umac %x %x %x %x\n",p.umac_data.umac_major,p.umac_data.umac_minor,p.umac_data.dbg_ptrs.error_info_addr,p.umac_data.dbg_ptrs.dbg_print_buff_addr);
 printf("sku %x %x %x\n",p.sku_id.data[0],p.sku_id.data[1],p.sku_id.data[2]);
 printf("imr %llx %x %x\n",(unsigned long long)p.imr.base_addr,p.imr.size,p.imr.enabled);printf("platform %llx\n",(unsigned long long)p.platform_id);
 struct iwl_rx_transfer_desc td={.rbid=0xabc,.addr=0x123456789000};printf("free ");bytes=(void*)&td;for(unsigned i=0;i<sizeof(td);i++)printf("%02x",bytes[i]);printf("\n");
 struct iwl_rx_completion_desc cd;memset(&cd,0xaa,sizeof(cd));cd.rbid=0xabc;cd.flags=0xfd;printf("used ");bytes=(void*)&cd;for(unsigned i=0;i<sizeof(cd);i++)printf("%02x",bytes[i]);printf("\n");
 for(unsigned id=0x1000;id<=0xffff;id+=0xefff){struct iwl_rx_transfer_desc extra={.rbid=id,.addr=0x123456789800};printf("widefree ");bytes=(void*)&extra;for(unsigned i=0;i<sizeof(extra);i++)printf("%02x",bytes[i]);printf("\n");}
 return 0;
}
'''
out.mkdir(parents=True,exist_ok=True);unit=out/'linux-iwlwifi-receive.c';unit.write_text(prelude+main);exe=out/'linux-iwlwifi-receive'
subprocess.run(['cc','-std=gnu11','-O1','-g','-fsanitize=address,undefined',str(unit),'-o',str(exe)],check=True)
with (out/'trace.txt').open('wb') as trace:subprocess.run([str(exe.resolve())],stdout=trace,check=True)
manifest={'linux_commit':'a804c5742bff224d4cb4d25dd383554d598be32b','sources':expected,'trace_sha256':hashlib.sha256((out/'trace.txt').read_bytes()).hexdigest()};(out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');print(json.dumps(manifest,indent=2))

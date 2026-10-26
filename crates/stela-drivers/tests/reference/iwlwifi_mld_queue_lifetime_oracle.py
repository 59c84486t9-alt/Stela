#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
# Copyright (C) 2022-2025 Intel Corporation
"""Original MLD scheduler removal body and explicit queue-free callback.

Usage: SCRIPT IWLWIFI_SOURCE QUALIFIED_ORIGINAL_QUEUE_ORACLE OUTPUT_DIRECTORY
This records the original remove command and host free call. It does not prove
native DMA quiescence, queue ownership, descriptor completion or frame behavior.
"""
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path
source, base, out = map(Path, sys.argv[1:])
raw = (base / 'linux-iwlwifi-tx-queue.c').read_bytes()
assert hashlib.sha256(raw).hexdigest() == '3d2c2b96da9df4e60350fe78665e4d32b2d473371aebbb18e7110ab8103ce764'
expected = {
    'mvm/mld-sta.c': 'f73b9d22de00ca5a16717628af967fd7f7b710f9b3336cd96d73ba8cdcb60e7e',
    'mvm/mvm.h': '2fdeb7f77b7127a48a27ec864ec5d04e474dc15d8d9d473379f59a0a11bfe8c8',
    'iwl-trans.h': '96d1daa1a251e4c1c4d96a3f625db7cc207d0051375010aa7790830cf730a3c4',
    'iwl-trans.c': '8f9e38c3553069830d6995a358063bb6cb0e9da7136f8fe9c8d3fbf64e4f077d',
    'mvm/sta.c': '0335c897c356d1c923b850139c97634a1f4299c08e6b1eaa289ee994d830a095',
    'pcie/gen1_2/tx.c': '3a312a9736437a7b1d7437ef72cb575f9dd48d07db83c7f0e38ceb8577d72d53',
    'pcie/gen1_2/tx-gen2.c': 'd6c9de307d2ea363be82f623989036e30a57de03c021e5d0f1ea496ed66ced3c',
    'pcie/gen1_2/trans.c': '8ed5c442313a5c2858f3e42b84d68bec726c7f4061e6f34db13c5ce0137a59ee',
    'pcie/gen1_2/internal.h': '572df25a5a22b0dbd03a3b2e83d553768d0af4e09a9071e2b6002f276bd41d10',
}
texts = {}
for file, digest in expected.items():
    data = (source / file).read_bytes()
    assert hashlib.sha256(data).hexdigest() == digest, file
    texts[file] = data.decode()
prefix = raw.decode().split('int main(void)')[0]
old = 'struct iwl_mvm {struct iwl_trans *trans;};'
assert prefix.count(old) == 1
prefix = prefix.replace(old, 'struct iwl_mvm {struct iwl_trans *trans;bool sta_remove_requires_queue_remove;};')
for file, name in [('iwl-trans.h', 'IWL_MAX_TID_COUNT'), ('iwl-trans.h', 'IWL_MGMT_TID'), ('mvm/mvm.h', 'IWL_MVM_INVALID_QUEUE')]:
    prefix += re.search(r'^#define ' + name + r'[^\n]+', texts[file], re.M)[0] + '\n'
prefix += r'''
#define lockdep_assert_held(...)
static unsigned native_frees,native_queue;static int command_failure;
static void iwl_trans_txq_free(struct iwl_trans *t,int queue){(void)t;native_frees++;native_queue=queue;}
static int iwl_mvm_send_cmd_pdu(struct iwl_mvm *m,u32 id,u32 flags,unsigned length,const void *data){
 (void)m;if(flags||length>sizeof(captured))abort();captured_id=id;captured_length=length;
 memcpy(captured,data,length);return command_failure;
}
'''
text = texts['mvm/mld-sta.c']
match = re.search(r'^static int iwl_mvm_mld_disable_txq\([^{};]*?\)\n\{', text, re.M)
assert match
at, depth = match.end(), 1
while depth:
    depth += (text[at] == '{') - (text[at] == '}')
    at += 1
function = text[match.start():at]
prefix += function + '\n'
main = r'''
int main(void){
 struct iwl_trans trans={0};struct iwl_mvm mvm={.trans=&trans};
 const u32 masks[]={1,3,0x80000000U};const u16 queues[]={1,31,511};
 for(unsigned remove=0;remove<2;remove++)for(unsigned tid_case=0;tid_case<2;tid_case++)
 for(unsigned mask=0;mask<3;mask++)for(unsigned queue=0;queue<3;queue++)for(unsigned failure=0;failure<2;failure++){
  mvm.sta_remove_requires_queue_remove=remove;u16 queueptr=queues[queue];
  u8 tid=tid_case?IWL_MGMT_TID:IWL_MAX_TID_COUNT;command_failure=failure?-5:0;
  captured_length=captured_id=native_frees=native_queue=0;
  int result=iwl_mvm_mld_disable_txq(&mvm,masks[mask],&queueptr,tid);
  if(native_frees!=1||native_queue!=queues[queue])abort();
  printf("R %u %u %u %u %u %d %u %u %u %u ",remove,tid,masks[mask],queues[queue],failure,result,queueptr,native_frees,captured_id,captured_length);
  if(!captured_length)printf("-");else for(unsigned i=0;i<captured_length;i++)printf("%02x",captured[i]);puts("");
 }
 return 0;
}
'''
out.mkdir(parents=True, exist_ok=False)
# Additional complete original allocation/reclaim/free branches are retained
# for source review only. They are not compiled or presented as executed DMA.
callbacks=[('mvm/sta.c','iwl_mvm_tvqm_enable_txq'),
           ('mvm/sta.c','iwl_mvm_sta_alloc_queue_tvqm'),
           ('pcie/gen1_2/tx.c','iwl_pcie_txq_alloc'),
           ('pcie/gen1_2/tx.c','iwl_txq_init'),
           ('pcie/gen1_2/tx.c','iwl_queue_init'),
           ('pcie/gen1_2/tx.c','iwl_pcie_reclaim'),
           ('pcie/gen1_2/tx-gen2.c','iwl_txq_dyn_alloc_dma'),
           ('pcie/gen1_2/tx-gen2.c','iwl_txq_gen2_unmap'),
           ('pcie/gen1_2/tx-gen2.c','iwl_txq_gen2_free_memory'),
           ('pcie/gen1_2/tx-gen2.c','iwl_txq_gen2_free'),
           ('pcie/gen1_2/tx-gen2.c','iwl_txq_dyn_free'),
           ('pcie/gen1_2/trans.c','iwl_trans_pcie_wait_txq_empty'),
           ('pcie/gen1_2/trans.c','iwl_pcie_alloc_invalid_tx_cmd'),
           ('iwl-trans.c','iwl_trans_wait_txq_empty'),
           ('pcie/gen1_2/internal.h','iwl_txq_get_cmd_index'),
           ('pcie/gen1_2/internal.h','iwl_txq_set_tfd_invalid_gen2')]
spans=''
for file,name in callbacks:
    text=texts[file]
    match=re.search(r'^(?:static\s+)?(?:inline\s+)?(?:void|int|u16|struct iwl_txq \*)\s*'+name+r'\([^;{}]*?\)\s*\n\{',text,re.M)
    assert match,(file,name)
    at,depth=match.end(),1
    while depth:
        depth+=(text[at]=='{')-(text[at]=='}');at+=1
    spans+='/* Original '+file+':'+name+' (source review only) */\n'+text[match.start():at]+'\n'
(out/'original-memory-lifetime-source-review.c').write_text(spans)
unit = out / 'linux-iwlwifi-mld-queue-lifetime.c'
unit.write_text(prefix + main)
exe = out / 'linux-iwlwifi-mld-queue-lifetime'
subprocess.run(['cc', '-std=gnu11', '-O1', '-g', '-fsanitize=address,undefined', str(unit), '-o', str(exe)], check=True, timeout=60)
with (out / 'trace.txt').open('wb') as trace:
    subprocess.run([str(exe.resolve())], stdout=trace, check=True, timeout=60)
data = (out / 'trace.txt').read_bytes()
manifest = {'linux_commit': 'cc9de5d4b5ab6459f5774946aa3195ad51236fa8', 'base_unit_sha256': hashlib.sha256(raw).hexdigest(),
            'sources': expected, 'whole_function': 'iwl_mvm_mld_disable_txq', 'whole_function_sha256': hashlib.sha256(function.encode()).hexdigest(),
            'records': len(data.splitlines()), 'trace_sha256': hashlib.sha256(data).hexdigest(), 'scope': __doc__}
manifest['source_review_only_callbacks']=callbacks
manifest['source_review_only_sha256']=hashlib.sha256(spans.encode()).hexdigest()
(out / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
print(json.dumps(manifest, indent=2))

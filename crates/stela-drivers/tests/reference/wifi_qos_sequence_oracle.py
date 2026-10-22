#!/usr/bin/env python3
"""Unchanged Linux per-TID software sequence helper; no on-air SSN claim."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from wifi_data_oracle import complete_function
from wifi_mac_oracle import PIN

SHA = '199a2fff76dc09416866c9899d9e1e7e071532099b4d59acddc26f63d68ef4b8'

def main():
    output, cache = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve()
    output.mkdir(parents=True, exist_ok=True)
    donor = (cache / 'net/mac80211/tx.c').read_bytes()
    assert hashlib.sha256(donor).hexdigest() == SHA
    helper = complete_function(donor.decode(), 'static __le16 ieee80211_tx_next_seq(')
    code = '''#include <stdint.h>\n#include <stdio.h>\ntypedef uint16_t u16; typedef u16 __le16;\n#define cpu_to_le16(x) (x)\n#define IEEE80211_SCTL_SEQ 0xfff0\nstruct sta_info {u16 tid_seq[16];};\n''' + helper + '''\nint main(void) {struct sta_info station={0};
for(unsigned tid=0;tid<16;tid++) for(unsigned n=0;n<8194;n++) {
    u16 input=ieee80211_tx_next_seq(&station,tid), next=station.tid_seq[tid];
    unsigned char trace[4]={input&255,input>>8,next&255,next>>8};
    if(fwrite(trace,1,4,stdout)!=4)return 2;
} return 0;}\n'''
    source = output / 'qos-sequence.c'; source.write_text(code)
    receipt = {'pin':PIN,'donor_sha256':SHA,'donor_git_blob_sha1':hashlib.sha1(b'blob '+str(len(donor)).encode()+b'\0'+donor).hexdigest(),
        'complete_helper_sha256':hashlib.sha256(helper.encode()).hexdigest(),'harness_sha256':hashlib.sha256(code.encode()).hexdigest(),'executed':False}
    if '--source-only' not in sys.argv[3:]:
        binary=output/'qos-sequence.bin'
        subprocess.run(['clang','-std=c11','-O1','-g','-fsanitize=address,undefined','-fno-sanitize-recover=all',str(source),'-o',str(binary)],check=True)
        trace=subprocess.run([str(binary)],check=True,stdout=subprocess.PIPE).stdout
        assert len(trace)==16*8194*4
        (output/'qos-sequence.trace').write_bytes(trace)
        receipt.update(executed=True,cases=16*8194,trace_sha256=hashlib.sha256(trace).hexdigest(),binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest())
    (output/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
    print(json.dumps(receipt))
if __name__=='__main__':main()

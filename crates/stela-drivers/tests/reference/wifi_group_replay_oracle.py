#!/usr/bin/env python3
"""Complete unchanged mt76 parent-PN helper for the retained QoS data profile.

Usage: wifi_group_replay_oracle.py OUTPUT VERIFIED_AGGREGATE_CACHE [--source-only]
The source-only option emits no execution claim. Full execution uses ASan/UBSan.
No hardware, crypto substitute, member-PN synthesis or BA proof is supplied.
"""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from wifi_data_oracle import complete_function
from wifi_mac_oracle import PIN

SOURCES = {
    'drivers/net/wireless/mediatek/mt76/mac80211.c': '4a88a2105def248340f237377f698300478e1352dfc81a955e8a5e61f91d07df',
    'include/net/mac80211.h': '3d1dd58c0b2ae0ea144f978b1141348274bcf3976e348847b298f2b5827038f9',
}

def main():
    output, cache = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve()
    output.mkdir(parents=True, exist_ok=True)
    receipt = {'pin': PIN, 'sources': [], 'executed': False}
    source = {}
    for name, sha in SOURCES.items():
        data = (cache / name).read_bytes()
        if hashlib.sha256(data).hexdigest() != sha:
            raise RuntimeError('donor mismatch: ' + name)
        source[name] = data.decode()
        receipt['sources'].append({'path': name, 'sha256': sha,
            'git_blob_sha1': hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()})
    helper = complete_function(source['drivers/net/wireless/mediatek/mt76/mac80211.c'], 'static void\nmt76_check_ccmp_pn(')
    flags = complete_function(source['include/net/mac80211.h'], 'enum mac80211_rx_flags {') + ';'
    receipt['complete_helper_sha256'] = hashlib.sha256(helper.encode()).hexdigest()
    receipt['complete_flags_sha256'] = hashlib.sha256(flags.encode()).hexdigest()
    code = r'''
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
typedef uint8_t u8; typedef uint16_t u16; typedef uint64_t u64;
#define BIT(x) (1ULL << (x))
#define BUILD_BUG_ON(x) _Static_assert(!(x), #x)
#define IEEE80211_QOS_CTL_TID_MASK 15
#define IEEE80211_NUM_TIDS 16
''' + flags + r'''
struct mt76_wcid { bool rx_check_pn; u8 rx_key_pn[17][6]; };
struct mt76_rx_status { u64 flag; struct mt76_wcid *wcid; u16 qos_ctl; u8 iv[6]; };
struct ieee80211_hdr {u16 frame_control;u16 duration;u8 addresses[18];u16 seq_ctrl;};
struct sk_buff {u8 cb[128] __attribute__((aligned(8)));struct ieee80211_hdr header;};
static struct ieee80211_hdr *mt76_skb_get_hdr(struct sk_buff *skb) {return &skb->header;}
static bool ieee80211_is_frag(struct ieee80211_hdr *h) {return (h->frame_control & 0x400) || (h->seq_ctrl & 15);}
static bool ieee80211_is_first_frag(u16 seq) {return !(seq & 15);}
static bool ieee80211_is_mgmt(u16 fc) {return !(fc & 12);}
static bool ieee80211_has_tods(u16 fc) {return !!(fc & 0x100);}
''' + helper + r'''
static u64 value(unsigned i) {
    if (i == 0) return 0;
    if (i == 1) return 1;
    if (i == 2) return (1ULL << 48) - 1;
    if (i == 3) return (1ULL << 48) - 2;
    return (i * 0x010203040507ULL) & ((1ULL << 48) - 1);
}
static void pn(u8 out[6], u64 value) {for(unsigned n=0;n<6;n++)out[n]=(u8)(value >> (8*(5-n)));}
int main(void) {
    for (unsigned tid=0;tid<16;tid++) for (unsigned i=0;i<256;i++) for (unsigned j=0;j<256;j++) {
        struct mt76_wcid w = {.rx_check_pn=true}; struct sk_buff skb = {0};
        struct mt76_rx_status *s=(void *)skb.cb;
        skb.header.frame_control=0x0288; // actual ordinary QoS FromDS, no fragment
        s->flag=RX_FLAG_DECRYPTED | RX_FLAG_IV_STRIPPED;
        s->wcid=&w; s->qos_ctl=tid; pn(w.rx_key_pn[tid],value(i)); pn(s->iv,value(j));
        mt76_check_ccmp_pn(&skb);
        u8 trace[8]; trace[0]=!(s->flag & RX_FLAG_ONLY_MONITOR);
        memcpy(trace+1,w.rx_key_pn[tid],6); trace[7]=!!(s->flag & RX_FLAG_PN_VALIDATED);
        if (fwrite(trace,1,sizeof(trace),stdout)!=sizeof(trace)) return 2;
    }
    return 0;
}
'''
    c_file = output / 'group-replay.c'
    c_file.write_text(code)
    receipt['harness_sha256'] = hashlib.sha256(c_file.read_bytes()).hexdigest()
    if '--source-only' not in sys.argv[3:]:
        binary = output / 'group-replay.bin'
        subprocess.run(['clang', '-std=c11', '-O1', '-g', '-fsanitize=address,undefined',
                        '-fno-sanitize-recover=all', str(c_file), '-o', str(binary)], check=True)
        trace = subprocess.run([str(binary)], check=True, stdout=subprocess.PIPE).stdout
        if len(trace) != 16 * 256 * 256 * 8:
            raise RuntimeError('incomplete parent-PN trace')
        receipt.update(executed=True, cases=16 * 256 * 256,
                       trace_sha256=hashlib.sha256(trace).hexdigest(),
                       binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest())
    (output / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps(receipt))

if __name__ == '__main__':
    main()

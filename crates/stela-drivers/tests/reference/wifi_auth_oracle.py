#!/usr/bin/env python3
"""Run the unchanged pinned Linux ieee80211_send_auth for 1,024 open-system PDUs.

Reproduce: python3 crates/stela-drivers/tests/reference/wifi_auth_oracle.py .stela/wifi-mac/auth
OS skb/transmit scaffolding captures actual output. MLO and WEP paths abort if
entered; this fixture covers open-system authentication, not their behavior.
No downloaded source or executable belongs in Git.
"""

import hashlib
import json
from pathlib import Path
import subprocess
import sys
from urllib.request import urlopen

PIN = "a804c5742bff224d4cb4d25dd383554d598be32b"
EXPECTED = "40be00a3ec50e372842238c4fbd6c1f61e5f6554ac205a2d55c905dd0d848bed"


def main():
    root = Path(sys.argv[1]).resolve()
    root.mkdir(parents=True, exist_ok=True)
    donor = root / "util.c"
    if not donor.exists():
        donor.write_bytes(urlopen(f"https://raw.githubusercontent.com/torvalds/linux/{PIN}/net/mac80211/util.c").read())
    data = donor.read_bytes()
    if hashlib.sha256(data).hexdigest() != EXPECTED:
        raise RuntimeError("donor hash mismatch")
    source = data.decode()
    start = source.index("void ieee80211_send_auth(")
    body = source.index("{", start)
    depth, end = 1, body + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    function = source[start:end]
    harness = r"""
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
#define __packed __attribute__((packed))
#define ETH_ALEN 6
#define cpu_to_le16(x) (x)
#define IEEE80211_WEP_IV_LEN 4
#define IEEE80211_WEP_ICV_LEN 4
#define IEEE80211_FTYPE_MGMT 0
#define IEEE80211_STYPE_AUTH 0xb0
#define IEEE80211_FCTL_PROTECTED 0x4000
#define WLAN_AUTH_SHARED_KEY 1
#define WLAN_EID_EXTENSION 255
#define WLAN_EID_EXT_EHT_MULTI_LINK 107
#define IEEE80211_ML_CONTROL_TYPE_BASIC 0
#define IEEE80211_TX_INTFL_DONT_ENCRYPT 1
#define WARN_ON(x) (x)
struct ieee80211_multi_link_elem { u16 control; } __packed;
struct ieee80211_mle_basic_common_info { u8 len; u8 mld_mac_addr[6]; } __packed;
struct ieee80211_mgmt {
    u16 frame_control, duration; u8 da[6],sa[6],bssid[6]; u16 sequence;
    union { struct { u16 auth_alg,auth_transaction,status_code; } auth; } u;
} __packed;
_Static_assert(offsetof(struct ieee80211_mgmt,u.auth.auth_alg)==24,"auth offset");
struct ieee80211_local { struct { size_t extra_tx_headroom; } hw; };
struct vif { u8 addr[6]; bool mld; };
struct ieee80211_sub_if_data { struct ieee80211_local *local; struct vif vif; };
struct sk_buff { size_t capacity,length,offset; struct { u32 flags; } cb; u8 data[]; };
static struct sk_buff *dev_alloc_skb(size_t capacity) {
    struct sk_buff *skb = calloc(1,sizeof(*skb)+capacity);
    if (skb) skb->capacity=capacity;
    return skb;
}
static void skb_reserve(struct sk_buff *skb,size_t amount) {
    if(amount>skb->capacity) abort(); skb->offset=amount;
}
static void *skb_put_zero(struct sk_buff *skb,size_t amount) {
    if(amount>skb->capacity-skb->offset-skb->length) abort();
    void *result=skb->data+skb->offset+skb->length;
    memset(result,0,amount);skb->length+=amount;return result;
}
static void skb_put_data(struct sk_buff *skb,const void *data,size_t amount) {
    memcpy(skb_put_zero(skb,amount),data,amount);
}
static bool ieee80211_vif_is_mld(const struct vif *vif) { return vif->mld; }
static const void *cfg80211_find_ext_elem(u8 id,const u8 *extra,size_t length) {
    (void)id;(void)extra;(void)length;abort();
}
static int ieee80211_wep_encrypt(struct ieee80211_local *local,struct sk_buff *skb,
                               const u8 *key,u8 length,u8 index) {
    (void)local;(void)skb;(void)key;(void)length;(void)index;abort();
}
static void kfree_skb(struct sk_buff *skb) { free(skb); }
#define IEEE80211_SKB_CB(skb) (&(skb)->cb)
static void ieee80211_tx_skb(struct ieee80211_sub_if_data *sdata,struct sk_buff *skb) {
    (void)sdata;if(skb->length!=30 || fwrite(skb->data+skb->offset,1,skb->length,stdout)!=skb->length) abort();free(skb);
}
""" + function + r"""
int main(void) {
    struct ieee80211_local local={0};
    for(unsigned i=0;i<1024;++i) {
        struct ieee80211_sub_if_data sdata={.local=&local,.vif={.addr={2,(u8)i,(u8)(i>>8),(u8)(i*3),(u8)(i>>2),(u8)(i*7)},.mld=false}};
        u8 ap[6]={4,(u8)(i>>3),(u8)(i>>1),(u8)(i*11),(u8)(i*13),(u8)(i*17)};
        ieee80211_send_auth(&sdata,1,0,0,NULL,0,ap,ap,NULL,0,0,0);
    }
    return fflush(stdout)!=0;
}
"""
    target = root / "auth.c"
    target.write_text(harness)
    command = ["clang", "-std=c11", "-Wall", "-Wextra", "-Werror", "-O1", "-g", "-fsanitize=address,undefined", str(target), "-o", str(root / "auth")]
    subprocess.run(command, check=True)
    output = subprocess.run([str(root / "auth")], check=True, capture_output=True).stdout
    if len(output) != 1024 * 30:
        raise RuntimeError("incomplete auth stream")
    (root / "auth.bin").write_bytes(output)
    receipt = {"pin":PIN,"donor":"net/mac80211/util.c","donor_sha256":EXPECTED,
        "donor_git_blob_sha1":hashlib.sha1(b"blob "+str(len(data)).encode()+b"\0"+data).hexdigest(),
        "unchanged_function_sha256":hashlib.sha256(function.encode()).hexdigest(),
        "harness_sha256":hashlib.sha256(harness.encode()).hexdigest(),
        "output_sha256":hashlib.sha256(output).hexdigest(),"cases":1024,"command":command,
        "limits":"Open-system single-link auth only; MLO and WEP scaffolding aborts if entered; actual MAC TX sequence assignment tested separately"}
    (root / "receipt.json").write_text(json.dumps(receipt,indent=2)+"\n")
    print(receipt["output_sha256"])


if __name__ == "__main__":
    main()

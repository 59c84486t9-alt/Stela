#!/usr/bin/env python3
"""Run unchanged pinned Linux station 802.11 -> 802.3 conversion with sanitizers.

Usage: wifi_data_oracle.py OUTPUT_DIR [VERIFIED_LINUX_CACHE]
Only the reproducer is committed; donor source, executable and output stay ignored.
The skb scaffold supplies checked linear storage, not replacement conversion logic.
GPL-2.0-only donor functions retain their original source notices in src/net/wifi/THIRD_PARTY.md.
"""

import hashlib
import json
from pathlib import Path
import subprocess
import sys
from urllib.request import urlopen

from wifi_mac_oracle import PIN, function

SOURCES = {
    "include/linux/ieee80211.h": "a65c9f90c87f66509a8fb31c0a77bdbbfae019cd0199edf131cbd798f140bdaa",
    "net/wireless/util.c": "634e0be5dc138ee467b2b08a287480cd7b639cd0c498ba742b0c7a703621ae22",
}


def complete_function(source, signature):
    start = source.index(signature)
    body = source.index("{", start)
    end, depth = body + 1, 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end]


def main():
    root = Path(sys.argv[1]).resolve()
    root.mkdir(parents=True, exist_ok=True)
    cache = Path(sys.argv[2]).resolve() if len(sys.argv) > 2 else root / "linux"
    source, manifest = {}, {"pin": PIN, "sources": []}
    for name, expected in SOURCES.items():
        path = cache / name
        if not path.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(urlopen(f"https://raw.githubusercontent.com/torvalds/linux/{PIN}/{name}").read())
        data = path.read_bytes()
        if hashlib.sha256(data).hexdigest() != expected:
            raise RuntimeError(f"donor hash mismatch: {name}")
        source[name] = data.decode()
        manifest["sources"].append({"path": name, "sha256": expected,
            "git_blob_sha1": hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()})
    header = source["include/linux/ieee80211.h"]
    helpers = [function(header, name) for name in [
        "ieee80211_has_a4", "ieee80211_has_order", "ieee80211_has_tods", "ieee80211_has_fromds",
        "ieee80211_is_mgmt", "ieee80211_is_ctl", "ieee80211_is_data", "ieee80211_is_ext",
        "ieee80211_is_data_qos", "ieee80211_is_data_present", "ieee80211_get_SA", "ieee80211_get_DA"]]
    helpers.append(function(source["net/wireless/util.c"], "ieee80211_hdrlen"))
    helpers += [complete_function(source["net/wireless/util.c"], signature) for signature in [
        "bool ieee80211_get_8023_tunnel_proto(", "int ieee80211_data_to_8023_exthdr("]]
    harness = r"""
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint16_t __le16;
typedef uint16_t __be16;
#define __attribute_const__
#define __aligned(n) __attribute__((aligned(n)))
#define cpu_to_le16(x) (x)
#define likely(x) (x)
#define unlikely(x) (x)
#define ETH_ALEN 6
#define ETH_P_AARP 0x80f3
#define ETH_P_IPX 0x8137
#define IEEE80211_FCTL_FTYPE 0x000c
#define IEEE80211_FCTL_STYPE 0x00f0
#define IEEE80211_FCTL_TODS 0x0100
#define IEEE80211_FCTL_FROMDS 0x0200
#define IEEE80211_FCTL_ORDER 0x8000
#define IEEE80211_FTYPE_MGMT 0x0000
#define IEEE80211_FTYPE_CTL 0x0004
#define IEEE80211_FTYPE_DATA 0x0008
#define IEEE80211_FTYPE_EXT 0x000c
#define IEEE80211_STYPE_QOS_DATA 0x0080
#define IEEE80211_QOS_CTL_LEN 2
#define IEEE80211_HT_CTL_LEN 4
struct ieee80211_hdr { __le16 frame_control, duration; u8 addr1[6],addr2[6],addr3[6]; u16 seq; u8 addr4[6]; } __attribute__((packed));
struct ethhdr { u8 h_dest[6],h_source[6]; __be16 h_proto; } __attribute__((packed));
enum nl80211_iftype { NL80211_IFTYPE_AP, NL80211_IFTYPE_AP_VLAN, NL80211_IFTYPE_P2P_GO,
    NL80211_IFTYPE_MESH_POINT, NL80211_IFTYPE_STATION, NL80211_IFTYPE_P2P_CLIENT,
    NL80211_IFTYPE_ADHOC, NL80211_IFTYPE_OCB, NL80211_IFTYPE_NAN_DATA };
static const u8 rfc1042_header[6]={0xaa,0xaa,3,0,0,0};
static const u8 bridge_tunnel_header[6]={0xaa,0xaa,3,0,0,0xf8};
static bool ether_addr_equal(const void *a,const void *b) { return memcmp(a,b,6)==0; }
static bool is_multicast_ether_addr(const u8 *a) { return a[0]&1; }
struct sk_buff { u8 *data; size_t len; u8 storage[128]; };
static int skb_copy_bits(const struct sk_buff *skb,size_t offset,void *to,size_t length) {
    if(offset>skb->len || length>skb->len-offset) return -1;
    memcpy(to,skb->data+offset,length);return 0;
}
static void skb_postpull_rcsum(struct sk_buff *skb,const void *start,size_t length) {
    (void)skb;(void)start;(void)length; /* No CHECKSUM_COMPLETE offload in this fixture. */
}
static void pskb_pull(struct sk_buff *skb,size_t length) {
    if(length>skb->len) abort();skb->data+=length;skb->len-=length;
}
static void *skb_push(struct sk_buff *skb,size_t length) {
    if(length>(size_t)(skb->data-skb->storage)) abort();skb->data-=length;skb->len+=length;return skb->data;
}
""" + "\n\n".join(helpers) + r"""
int main(void) {
    const u8 local[6]={2,1,2,3,4,5}, ap[6]={2,6,7,8,9,10}, source[6]={4,1,2,3,4,5};
    const u8 prefixes[3][6]={{0xaa,0xaa,3,0,0,0},{0xaa,0xaa,3,0,0,0xf8},{0xab,0xaa,3,0,0,0}};
    for(unsigned prefix=0;prefix<3;++prefix) for(unsigned protocol=0;protocol<65536;++protocol) {
        struct sk_buff skb={0};skb.data=skb.storage+32;skb.len=35;
        struct ieee80211_hdr *hdr=(void *)skb.data;hdr->frame_control=0x0208;
        memcpy(hdr->addr1,local,6);memcpy(hdr->addr2,ap,6);memcpy(hdr->addr3,source,6);
        memcpy(skb.data+24,prefixes[prefix],6);skb.data[30]=protocol>>8;skb.data[31]=protocol;
        skb.data[32]=1;skb.data[33]=2;skb.data[34]=3;
        if(ieee80211_data_to_8023_exthdr(&skb,NULL,local,NL80211_IFTYPE_STATION,0,false)) abort();
        if(putchar(skb.len&255)==EOF || putchar(skb.len>>8)==EOF || fwrite(skb.data,1,skb.len,stdout)!=skb.len) abort();
    }
    return fflush(stdout)!=0;
}
"""
    c_file, executable = root / "data.c", root / "data"
    c_file.write_text(harness)
    command = ["clang", "-std=c11", "-Wall", "-Wextra", "-Werror", "-Wno-address-of-packed-member", "-O1", "-g",
        "-fsanitize=address,undefined", str(c_file), "-o", str(executable)]
    subprocess.run(command, check=True)
    output = subprocess.run([str(executable)], check=True, capture_output=True).stdout
    cursor = 0
    for _ in range(3 * 65536):
        length = int.from_bytes(output[cursor:cursor + 2], "little")
        if length not in (17, 25):
            raise RuntimeError("invalid or truncated output frame")
        cursor += 2 + length
    if cursor != len(output):
        raise RuntimeError("incomplete or extra oracle output")
    (root / "data.bin").write_bytes(output)
    manifest.update({"cases": 3 * 65536, "output_sha256": hashlib.sha256(output).hexdigest(),
        "harness_sha256": hashlib.sha256(harness.encode()).hexdigest(), "command": command,
        "helpers_sha256": [hashlib.sha256(helper.encode()).hexdigest() for helper in helpers],
        "limits": "Single-MSDU FromDS station conversion, all 16-bit protocols under RFC1042/bridge/unknown LLC prefixes; no aggregate, crypto or radio path"})
    (root / "receipt.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(manifest["output_sha256"])


if __name__ == "__main__":
    main()

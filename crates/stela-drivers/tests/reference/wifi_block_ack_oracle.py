#!/usr/bin/env python3
"""One pinned Linux Block Ack source fixture; preparation is the default.

Usage: wifi_block_ack_oracle.py OUT --ba-sources DIR --mac-sources DIR
       --parse-source FILE --mesh-source FILE --parser-matrix FILE [--execute]

The complete outer ACTION parser and BA wire functions are unchanged. The RX
fresh hardware-reorder path is assembled from three unchanged regions; omitted
existing-session/software-reorder paths are NOT qualified. Extension/TPE capture
is projected away only under the explicitly checked no-inheritance, no-CRC,
outer ACTION/HIGHEST profile: those captures cannot affect parse_error/ADDBA.
This is not a full mac80211 runtime, crypto, DMA, BA lifetime or native clock test.
Donor files, generated C, corpus and outputs must remain ignored.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

from wifi_data_oracle import complete_function

PIN = "a804c5742bff224d4cb4d25dd383554d598be32b"
SOURCES = {
    "agg-rx.c": "a917bbf7747d0c0ac2dfcbe7aedb8b2b77dfcd3cdbed28d410f77f6178a6f9c0",
    "agg-tx.c": "b6c90cdd1229b6e490c9b8b9e6e5ee354563481d8da9e57295944c57fabcd0d9",
    "ieee80211_i.h": "f8875ff901826b64ed2b5131f955c9861c91430d3c5b81e0d794a93569029e5a",
    "sta_info.h": "ed2e2525580cb2cf825438163c883450e5eb7fe2138e346908742359b1af4f26",
    "parse.c": "1016c098a0b9a273c9d130c8666e3738e89cef87131db19acd506b3a8f783fb9",
    "ieee80211.h": "a65c9f90c87f66509a8fb31c0a77bdbbfae019cd0199edf131cbd798f140bdaa",
    "ieee80211-ht.h": "0e25fe12bd20064f3eafc2aaadf9b7df4f0d577bc887762169ac042985b9d09b",
    "ieee80211-vht.h": "eaae1e52bcaed0ecb9bbcf1c87a65e03a7ac5ea29733111a90e92bb993741775",
    "ieee80211-mesh.h": "fff66c953fdc1466d761a039e0310848eca278f1b9af83fef8647a954d8451e3",
}


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def declaration(source: str, signature: str) -> str:
    """Retain the source's full closing attributes as well as its body."""
    body = complete_function(source, signature)
    start = source.index(body)
    end = source.index(";", start + len(body))
    return source[start:end + 1]


def macro(source: str, name: str) -> str:
    match = re.search(r"^#define\s+" + re.escape(name) + r"(?:\(|\s)", source, re.M)
    if match is None:
        raise ValueError("missing source macro " + name)
    end = source.index("\n", match.start())
    while source[end - 1] == "\\":
        end = source.index("\n", end + 1)
    return source[match.start():end]


def corpus(matrix: dict) -> list[dict]:
    """Inputs, not expected native decisions. Linux C produces all results."""
    streams: list[tuple[str, bytes]] = []

    def ie(identifier: int, body: bytes) -> bytes:
        assert len(body) <= 255
        return bytes((identifier, len(body))) + body

    def add(label: str, tail: bytes) -> None:
        streams.append((label, tail))

    ext = ie(159, b"\x21")
    add("empty", b"")
    add("addba", ext)
    for label, tail in [("short-header", b"\x03"), ("short-body", b"\x03\x02\x01")]:
        add(label, ext + tail)
    for values in matrix["test_vectors"]["errors_suppress_extension"]:
        add("review-error", bytes(values))
    for values in matrix["test_vectors"]["valid_positive_tails"]:
        add("review-positive", bytes(values))
    lengths = {101: 18, 104: 4, 3: 1, 5: 4, 42: 1, 45: 26, 61: 22,
               191: 12, 192: 5, 199: 1, 113: 7, 126: 21, 37: 3, 60: 4,
               62: 1, 118: 6, 194: 3, 32: 1, 159: 1, 56: 5}
    bodies = {i: bytes(n) for i, n in lengths.items()}
    preq = bytearray(37)
    preq[25] = 1
    bodies.update({130: bytes(preq), 131: bytes(31), 132: bytes(2)})
    for entry in matrix["duplicate_id_set"]:
        identifier = entry["id"]
        body = bodies.get(identifier, b"")
        add("duplicate-" + str(identifier), ext + ie(identifier, body) * 2)
    for identifier, size in lengths.items():
        for n in (size - 1, size, size + 1):
            add(f"size-{identifier}-{n}", ext + ie(identifier, bytes(n)))
    for n in range(9):
        for recognized in (False, True):
            body = (b"\x00\x40\x96\x00" if recognized else b"\x01\x02\x03\x04")
            add(f"cisco-{n}-{recognized}", ext + ie(150, (body + bytes(8))[:n]))
    for ae in (False, True):
        for count in (0, 1, 2, 3):
            body = bytearray(26 + 6 * ae + 11 * count)
            body[0] = 0x40 if ae else 0
            body[25 + 6 * ae] = count
            for delta in (-1, 0, 1):
                value = bytes(body[:-1] if delta == -1 else body) + bytes(max(delta, 0))
                add(f"preq-{ae}-{count}-{delta}", ext + ie(130, value))
        body = bytes((0x40 if ae else 0,)) + bytes(30 + 6 * ae)
        for delta in (-1, 0, 1):
            add(f"prep-{ae}-{delta}", ext + ie(131, body[:-1] if delta == -1 else body + bytes(delta)))
    for flags in ((), (0,), (0x40,), (0, 0x40), (0x40, 0)):
        body = bytes((0, len(flags))) + b"".join(bytes((f,)) + bytes(12 + (6 if f else 0)) for f in flags)
        for n in sorted({0, 1, max(0, len(body) - 1), len(body), len(body) + 1}):
            add(f"perr-{flags}-{n}", ext + ie(132, (body + bytes(1))[:n]))
    for tail in (ie(196, b""), ie(196, ie(194, bytes(3))), ie(194, bytes(3)),
                 ie(255, b""), ie(255, b"\xff"), ie(255, b"\x6b\xff"),
                 ie(195, b""), ie(195, b"\xff"), ie(211, b""), ie(232, b""),
                 ie(221, b""), ie(150, b"\x01\x02\x03\x04"),
                 ie(159, b"\x21") + ie(159, b"\x41"), ie(159, b"") + ext,
                 ie(242, b"\xff") * 2, ie(222, b"") * 2):
        add("whole-action-tail", ext + tail)
    rows: list[dict] = []

    def row(kind: int, label: str, **values) -> None:
        r = dict(kind=kind, label=label, he=1, eht=0, ht=1, blocked=0,
                 delayed=0, tid=3, window=32, maximum=64, token=7, timeout=10,
                 ssn=4095, policy=1, amsdu=1, outcome=0, status=0,
                 response_token=7, state=0, retries=0, now=20000, last=0, tail="")
        r.update(values)
        r["index"] = len(rows)
        rows.append(r)

    for label, stream in streams:
        for he, eht in ((0, 0), (1, 0), (1, 1)):
            row(0, label, he=he, eht=eht, tail=stream.hex())
            row(2, label, he=he, eht=eht, tail=stream.hex())
    for data in (0, 1, 0x20, 0x21, 0x41, 0xff):
        for maximum in (64, 256, 1024):
            for kind in (0, 2):
                row(kind, "extended-zero-window", he=1, eht=1, window=0,
                    maximum=maximum, tail=ie(159, bytes((data,))).hex())
    for identifier, body in ((0, bytes(33)), (1, b""), (48, b"\xff"),
                             (244, b""), (7, b"")):
        row(0, "generic-not-association-policy", tail=(ext + ie(identifier, body)).hex())
    for he, eht, ht in ((0, 0, 0), (0, 0, 1), (1, 0, 1), (1, 1, 1)):
        for window in (0, 1, 32, 64, 65, 256, 257, 1023):
            for maximum in (1, 32, 64, 256, 1024):
                row(0, "rx-window", he=he, eht=eht, ht=ht, window=window, maximum=maximum)
    for tid in (0, 7, 8, 15):
        for blocked, policy, outcome in ((1, 1, 0), (0, 0, 0), (0, 1, -1), (0, 1, 0)):
            row(0, "rx-admission", tid=tid, blocked=blocked, policy=policy, outcome=outcome)
    for he, eht in ((0, 0), (1, 0), (1, 1)):
        for maximum in (1, 32, 64, 255, 256, 257, 1024):
            for ssn in (0, 1, 4095):
                row(1, "tx-request", he=he, eht=eht, maximum=maximum, ssn=ssn)
    for window in (0, 1, 32, 64, 1023):
        for maximum in (1, 32, 64, 256, 1024):
            for state in (0, 1, 2, 8, 32):
                row(2, "tx-response", window=window, maximum=maximum, state=state)
    for status, token, amsdu in ((37, 7, 1), (0, 8, 1), (0, 7, 0)):
        row(2, "tx-response-status", status=status, response_token=token, amsdu=amsdu)
    for retries in (0, 3, 4, 15, 16):
        for now in (14999, 15000, 15001):
            row(3, "retry-boundary", retries=retries, now=now)
    for timeout in (1, 10, 65535):
        # TU conversion is modeled at explicit HZ1000; not a clock qualification.
        ticks = (timeout * 1024 + 999) // 1000
        for now in (ticks - 1, ticks, ticks + 1):
            for state in (0, 8):
                row(4, "session-timer", timeout=timeout, now=now, state=state)
    return rows


PREAMBLE = r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32; typedef uint64_t u64;
typedef uint16_t __le16; typedef uint32_t __le32; typedef uint64_t __le64;
#define __packed __attribute__((packed))
#define __aligned(n) __attribute__((aligned(n)))
#ifndef __counted_by
#define __counted_by(n)
#endif
#define DECLARE_FLEX_ARRAY(t,n) t n[0]
#define ETH_ALEN 6
#define BIT(n) (1UL << (n))
#define GENMASK(h,l) (((~0UL) >> (63-(h))) & ((~0UL) << (l)))
#define ARRAY_SIZE(x) (sizeof(x)/sizeof((x)[0]))
#define BUILD_BUG_ON(x) _Static_assert(!(x), #x)
#define cpu_to_le16(x) ((u16)(x))
#define le16_to_cpu(x) ((u16)(x))
#define u16_get_bits(x,m) (((x)&(m)) >> __builtin_ctzl(m))
#define u8_get_bits(x,m) u16_get_bits(x,m)
#define u16_encode_bits(x,m) (((u16)(x) << __builtin_ctzl(m)) & (m))
#define u8_encode_bits(x,m) u16_encode_bits(x,m)
#define DECLARE_BITMAP(n,b) unsigned long n[((b)+63)/64]
#define bitmap_zero(n,b) memset(n,0,sizeof(unsigned long)*(((b)+63)/64))
static bool test_bit(unsigned n,const unsigned long *b) { return !!(b[n/64]&BIT(n%64)); }
static void __set_bit(unsigned n,unsigned long *b) { b[n/64]|=BIT(n%64); }
static void __clear_bit(unsigned n,unsigned long *b) { b[n/64]&=~BIT(n%64); }
static bool test_and_set_bit(unsigned n,unsigned long *b) { bool r=test_bit(n,b);__set_bit(n,b);return r; }
#define set_bit __set_bit
#define WARN(...) ((void)0)
#define WARN_ON(x) (!!(x))
#define WARN_ON_ONCE(x) (!!(x))
#define ht_dbg(...) ((void)0)
#define ht_dbg_ratelimited(...) ((void)0)
#define lockdep_assert_wiphy(x) ((void)0)
#define spin_lock_bh(x) ((void)0)
#define spin_unlock_bh(x) ((void)0)
#define min(a,b) ((a)<(b)?(a):(b))
#define min_t(t,a,b) ((t)min(a,b))
#define kfree(x) free(x)
#define HZ 1000UL
static unsigned long jiffies;
static unsigned long usecs_to_jiffies(u64 x) { return (unsigned long)((x+999)/1000); }
#define time_before(a,b) ((long)((a)-(b)) < 0)
#define time_is_after_jiffies(a) time_before(jiffies,a)
#define container_of(p,t,m) ((t *)((char *)(p)-offsetof(t,m)))
#define timer_container_of(v,t,m) container_of(t,typeof(*v),m)
struct timer_list { unsigned long expiry; bool active; };
static void mod_timer(struct timer_list *t,unsigned long e) { t->expiry=e;t->active=true; }
static void timer_delete_sync(struct timer_list *t) { t->active=false; }
struct ieee80211_parsed_tpe { unsigned char not_observed; };
/* Only pointer storage/never-reached sizeof in this UHR ACTION projection. */
struct ieee80211_s1g_cap { unsigned char unreachable; };
struct ieee80211_s1g_oper_ie { unsigned char unreachable; };
struct ieee80211_s1g_bcn_compat_ie { unsigned char unreachable; };
struct ieee80211_aid_response_ie { unsigned char unreachable; };
#define IEEE80211_TTLM_MAX_CNT 8
'''


PARSER_SCAFFOLD = r'''
/* The discarded extension/TPE outputs cannot set a parse_error for this exact
 * outer, no-inheritance, no-CRC profile. Never call this fixture in other modes. */
static void ieee80211_parse_extension_element(u32 *crc,const struct element *e,
    struct ieee80211_elems_parse *p,struct ieee80211_elems_parse_params *params) {
    (void)e; assert(!crc && !p->inside_multilink && !params->bss && params->link_id==-1);
}
static void ieee80211_parse_tpe(struct ieee80211_parsed_tpe *p,const u8 *d,u8 n) { (void)p;(void)d;(void)n; }
static bool cfg80211_is_element_inherited(const struct element *e,const struct element *p) { (void)e;(void)p;abort(); }
static u32 crc32_be(u32 c,const void *d,size_t n) { (void)c;(void)d;(void)n;abort(); }
static const struct element *cfg80211_find_elem(unsigned id,const u8 *p,size_t n) { (void)id;(void)p;(void)n;abort(); }
static const struct element *cfg80211_find_ext_elem(unsigned id,const u8 *p,size_t n) { (void)id;(void)p;(void)n;abort(); }
static bool ieee80211_bandwidth_indication_size_ok(const void *d,u8 n) { (void)d;(void)n;abort(); }
static unsigned last_parse_error;
'''


BA_SCAFFOLD = r'''
enum { NL80211_IFTYPE_STATION,NL80211_IFTYPE_AP,NL80211_IFTYPE_AP_VLAN,NL80211_IFTYPE_MESH_POINT,NL80211_IFTYPE_ADHOC };
enum { SUPPORTS_AMSDU_IN_AMPDU,SUPPORTS_REORDERING_BUFFER,STRICT };
enum { WLAN_STA_BLOCK_BA };
enum { IEEE80211_AMPDU_RX_START,IEEE80211_TXQ_NO_AMSDU,AGG_STOP_DECLINED };
struct ieee80211_txq { unsigned long flags; };
#define to_txq_info(q) (q)
struct ieee80211_sta { u8 addr[6]; unsigned valid_links; u16 max_rx_aggregation_subframes;
 struct { struct { bool ht_supported;u16 cap; } ht_cap;struct {bool has_he;}he_cap;
 struct {bool has_eht;}eht_cap;struct {bool s1g;u8 cap[4];}s1g_cap; } deflink;
 struct ieee80211_txq *txq[16]; };
struct ieee80211_local { struct {void *wiphy;unsigned flags;u16 max_tx_aggregation_subframes;unsigned extra_tx_headroom;}hw; };
struct ieee80211_sub_if_data { struct ieee80211_local *local;
 struct {u8 addr[6];unsigned type;struct{u8 ap_addr[6];}cfg;}vif;
 struct {struct{u8 bssid[6];}ibss;}u; };
struct sta_info;
struct tid_ampdu_tx { struct sta_info *sta;u8 tid,dialog_token;u16 ssn,timeout,buf_size;bool ndp,amsdu;
 unsigned long state,last_tx;struct timer_list addba_resp_timer,session_timer; };
struct sta_info { struct ieee80211_sta sta;struct ieee80211_sub_if_data *sdata;struct ieee80211_local *local;
 bool blocked;int lock;struct {unsigned addba_req_num[16];unsigned long last_addba_req_time[16];
 unsigned long agg_session_valid[1],unexpected_agg[1];u8 tid_rx_token[16];
 struct tid_ampdu_tx *tid_tx[16];}ampdu_mlme; };
struct ieee80211_ampdu_params { struct ieee80211_sta *sta;unsigned action,tid;bool amsdu;u16 timeout,ssn,buf_size; };
struct sk_buff { size_t len,capacity;u8 bytes[512]; };
static u8 air[512];static size_t air_len;static int driver_result,driver_calls,stop_calls,operational_calls;
static struct ieee80211_ampdu_params captured;
static bool ieee80211_hw_check_(unsigned flags,unsigned flag) { return !!(flags&BIT(flag)); }
#define ieee80211_hw_check(hw,flag) ieee80211_hw_check_((hw)->flags,flag)
static bool ieee80211_s1g_use_ndp_ba(struct ieee80211_sub_if_data *s,struct sta_info *p) { (void)s;(void)p;return false; }
static bool test_sta_flag(struct sta_info *s,unsigned flag) { assert(flag==WLAN_STA_BLOCK_BA);return s->blocked; }
static struct sk_buff *dev_alloc_skb(size_t n) { struct sk_buff *b=calloc(1,sizeof(*b));assert(b&&n<=sizeof(b->bytes));b->capacity=sizeof(b->bytes);return b; }
static void skb_reserve(struct sk_buff *b,size_t n) { assert(n==0);(void)b; }
static void *skb_put(struct sk_buff *b,size_t n) { assert(b->len+n<=b->capacity);void *p=b->bytes+b->len;b->len+=n;return p; }
static void *skb_put_zero(struct sk_buff *b,size_t n) { void *p=skb_put(b,n);memset(p,0,n);return p; }
#define ether_addr_copy(d,s) memcpy(d,s,6)
static void ieee80211_tx_skb(struct ieee80211_sub_if_data *s,struct sk_buff *b) { (void)s;air_len=b->len;memcpy(air,b->bytes,b->len);free(b); }
static void ieee80211_tx_skb_tid(struct ieee80211_sub_if_data *s,struct sk_buff *b,unsigned t,int l) { assert(t<16&&l==-1);ieee80211_tx_skb(s,b); }
static int drv_ampdu_action(struct ieee80211_local *l,struct ieee80211_sub_if_data *s,struct ieee80211_ampdu_params *p) { (void)l;(void)s;driver_calls++;captured=*p;return driver_result; }
static struct tid_ampdu_tx *rcu_dereference_protected_tid_tx(struct sta_info *s,unsigned tid) { assert(tid<16);return s->ampdu_mlme.tid_tx[tid]; }
static void ieee80211_agg_tx_operational(struct ieee80211_local *l,struct sta_info *s,unsigned t) { (void)l;(void)s;(void)t;operational_calls++; }
static int __ieee80211_stop_tx_ba_session(struct sta_info *s,unsigned t,unsigned reason) { (void)s;(void)t;assert(reason==AGG_STOP_DECLINED);stop_calls++;return 0; }
static int ieee80211_stop_tx_ba_session(struct ieee80211_sta *s,unsigned t) { (void)s;(void)t;stop_calls++;return 0; }
'''


def prepare(args) -> dict:
    root = args.output.resolve()
    root.mkdir(parents=True, exist_ok=True)
    if (root / "receipt.json").exists():
        raise ValueError("use a fresh output directory; historical receipts are immutable")
    paths = {n: args.ba_sources / "net/mac80211" / n for n in ("agg-tx.c", "ieee80211_i.h", "sta_info.h")}
    paths.update({n: args.mac_sources / "include/linux" / n for n in ("ieee80211.h", "ieee80211-ht.h", "ieee80211-vht.h")})
    paths.update({"agg-rx.c": args.mac_sources / "net/mac80211/agg-rx.c", "parse.c": args.parse_source,
                  "ieee80211-mesh.h": args.mesh_source})
    sources, bindings, regions = {}, [], []
    for name, path in paths.items():
        raw = path.read_bytes()
        if sha(raw) != SOURCES[name]:
            raise ValueError("wrong pinned donor: " + str(path))
        sources[name] = raw.decode()
        bindings.append(dict(name=name, sha256=sha(raw), bytes=len(raw),
                             git_blob_sha1=hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()))
        (root / name).write_bytes(raw)
    matrix = json.loads(args.parser_matrix.read_text())
    assert matrix["pin"] == PIN

    def keep(name: str, label: str, text: str) -> str:
        assert text in sources[name], label
        regions.append(dict(file=name, label=label, sha256=sha(text.encode()),
                            start_line=sources[name][:sources[name].index(text)].count("\n") + 1,
                            bytes=len(text.encode())))
        return text

    def fun(name: str, signature: str) -> str:
        return keep(name, signature, complete_function(sources[name], signature))

    def decl(name: str, signature: str) -> str:
        return keep(name, signature, declaration(sources[name], signature))

    h, internal, rx, tx = (sources[n] for n in ("ieee80211.h", "ieee80211_i.h", "agg-rx.c", "agg-tx.c"))
    code = [PREAMBLE]
    for name, signature in [("ieee80211.h", "enum ieee80211_eid {"),
                            ("ieee80211.h", "enum ieee80211_eid_ext {"),
                            ("ieee80211.h", "enum ieee80211_statuscode {"),
                            ("ieee80211.h", "enum ieee80211_category {"),
                            ("ieee80211-ht.h", "enum ieee80211_back_actioncode {"),
                            ("ieee80211_i.h", "enum ieee80211_conn_mode {"),
                            ("ieee80211_i.h", "enum ieee80211_elems_parse_error {")]:
        code.append(decl(name, signature))
    # Source macros used by the selected functions, not copied numeric substitutes.
    wanted = ["IEEE80211_FIRST_TSPEC_TSID", "IEEE80211_FTYPE_MGMT", "IEEE80211_FTYPE_EXT",
              "IEEE80211_STYPE_ASSOC_REQ", "IEEE80211_STYPE_REASSOC_REQ", "IEEE80211_STYPE_ASSOC_RESP",
              "IEEE80211_STYPE_REASSOC_RESP", "IEEE80211_STYPE_PROBE_REQ", "IEEE80211_STYPE_PROBE_RESP",
              "IEEE80211_STYPE_BEACON", "IEEE80211_STYPE_ACTION", "IEEE80211_STYPE_S1G_BEACON",
              "WLAN_SA_QUERY_TR_ID_LEN", "WLAN_MEMBERSHIP_LEN", "WLAN_USER_POSITION_LEN",
              "IEEE80211_ADDBA_EXT_FRAG_LEVEL_MASK", "IEEE80211_ADDBA_EXT_FRAG_LEVEL_SHIFT",
              "IEEE80211_ADDBA_EXT_NO_FRAG", "IEEE80211_ADDBA_EXT_BUF_SIZE_MASK",
              "IEEE80211_ADDBA_EXT_BUF_SIZE_SHIFT", "IEEE80211_MIN_ACTION_SIZE", "TU_TO_JIFFIES", "TU_TO_EXP_TIME"]
    for name in wanted:
        code.append(keep("ieee80211.h", name, macro(h, name)))
    for name in ("IEEE80211_HT_MCS_MASK_LEN", "IEEE80211_HT_CAP_DELAY_BA", "IEEE80211_ADDBA_PARAM_AMSDU_MASK",
                 "IEEE80211_ADDBA_PARAM_POLICY_MASK", "IEEE80211_ADDBA_PARAM_TID_MASK", "IEEE80211_ADDBA_PARAM_BUF_SIZE_MASK",
                 "IEEE80211_MAX_AMPDU_BUF_HT", "IEEE80211_MAX_AMPDU_BUF_HE", "IEEE80211_MAX_AMPDU_BUF_EHT"):
        code.append(keep("ieee80211-ht.h", name, macro(sources["ieee80211-ht.h"], name)))
    for name in ("ADDBA_RESP_INTERVAL", "HT_AGG_MAX_RETRIES", "HT_AGG_BURST_RETRIES", "HT_AGG_RETRIES_PERIOD",
                 "HT_AGG_STATE_DRV_READY", "HT_AGG_STATE_RESPONSE_RECEIVED", "HT_AGG_STATE_STOPPING",
                 "HT_AGG_STATE_WANT_STOP", "HT_AGG_STATE_SENT_ADDBA"):
        code.append(keep("sta_info.h", name, macro(sources["sta_info.h"], name)))
    code += ["#define offsetofend(t,m) (offsetof(t,m)+sizeof(((t *)0)->m))",
             "#define S1G_CAP3_HT_DELAYED_BA 0x10 /* unobserved S1G-only bit; S1G cap is fixedzero */",
             keep("ieee80211_i.h", "HIGHEST", macro(internal, "IEEE80211_CONN_MODE_HIGHEST")),
             keep("ieee80211-mesh.h", "AE_F", macro(sources["ieee80211-mesh.h"], "AE_F"))]
    # Topological order for real packed layouts; validate every original declaration.
    layouts = matrix["packed_layouts"]
    layouts.sort(key=lambda d: (0 if any(name in d["source"].split("{")[0] for name in
        ("struct ieee80211_mcs_info", "struct ieee80211_vht_mcs_info", "struct ieee80211_mesh_hwmp_preq_target")) else 1))
    for item in layouts:
        code.append(keep(item["file"], "packed layout", item["source"]))
    for name in ("ieee80211_msrment_ie", "ieee80211_tpc_report_ie", "ieee80211_bss_max_idle_period_ie"):
        code.append(decl("ieee80211.h", "struct " + name + " {"))
    code += [decl("ieee80211.h", "struct ieee80211_mgmt {"), decl("ieee80211.h", "struct element {"),
             keep("ieee80211.h", "element iterator", macro(h, "for_each_element")),
             fun("ieee80211.h", "static inline bool for_each_element_completed("),
             decl("ieee80211_i.h", "struct ieee802_11_elems {"),
             decl("ieee80211_i.h", "struct ieee80211_elems_parse_params {"),
             decl("parse.c", "struct ieee80211_elem_defrag {"), decl("parse.c", "struct ieee80211_elems_parse {")]
    for signature in ("static inline bool ieee80211_mesh_preq_prep_ae_enabled(",
                      "static inline struct ieee80211_mesh_hwmp_preq_bottom *\nieee80211_mesh_hwmp_preq_get_bottom(",
                      "static inline bool ieee80211_mesh_preq_size_ok(", "static inline bool ieee80211_mesh_prep_size_ok(",
                      "static inline bool ieee80211_mesh_perr_size_ok("):
        code.append(fun("ieee80211-mesh.h", signature))
    code += [PARSER_SCAFFOLD, fun("parse.c", "static u32\n_ieee802_11_parse_elems_full(")]
    code.append(r'''
static struct ieee802_11_elems *ieee802_11_parse_elems(const u8 *p,size_t n,u8 type,void *bss) {
 assert(type==(IEEE80211_FTYPE_MGMT|IEEE80211_STYPE_ACTION)&&!bss);
 struct ieee80211_elems_parse *out=calloc(1,sizeof(*out));assert(out);
 struct ieee80211_elems_parse_params params={.mode=IEEE80211_CONN_MODE_HIGHEST,.start=p,.len=n,.type=type,.link_id=-1};
 _ieee802_11_parse_elems_full(&params,out,NULL);last_parse_error=out->elems.parse_error;return &out->elems;
}
''')
    code += [BA_SCAFFOLD, fun("ieee80211_i.h", "static inline struct ieee80211_mgmt *\nieee80211_mgmt_ba("),
             fun("agg-rx.c", "void ieee80211_add_addbaext("), fun("agg-rx.c", "u8 ieee80211_retrieve_addba_ext_data("),
             fun("agg-rx.c", "static void ieee80211_send_addba_resp(")]
    full = complete_function(rx, "void __ieee80211_start_rx_ba_session(")
    prefix = full[:full.index("\n\tht_dbg(sta->sdata, \"AddBA Req buf_size=")]
    hw_start = full.index("\tif (ieee80211_hw_check(&local->hw, SUPPORTS_REORDERING_BUFFER))")
    hw = full[hw_start:full.index("\n\t/* prepare A-MPDU", hw_start)]
    end = full[full.index("end:\n"):]
    code.append(keep("agg-rx.c", "RX fresh admission prefix", prefix) + "\n" +
                keep("agg-rx.c", "RX actual hardware reorder callback branch", hw) +
                "\n abort(); /* unsupported software-reorder path */\n" + keep("agg-rx.c", "RX response/end", end))
    code += [fun("agg-rx.c", "void ieee80211_process_addba_request("),
             fun("agg-tx.c", "static void ieee80211_send_addba_request("),
             fun("agg-tx.c", "static void ieee80211_send_addba_with_timeout("),
             fun("agg-tx.c", "void ieee80211_process_addba_resp("),
             fun("agg-tx.c", "static void sta_addba_resp_timer_expired("),
             fun("agg-tx.c", "static void sta_tx_agg_session_timer_expired(")]
    start = tx.index("\t/* we have tried too many times")
    stop = tx.index("\n\ttid_tx = rcu_dereference_protected_tid_tx", start)
    retry = keep("agg-tx.c", "actual retry and spread checks", tx[start:stop])
    code.append("static int fixture_retry(struct sta_info *sta,unsigned tid) { int ret=0;\n" + retry +
                "\nerr_unlock_sta: return ret;\n}")
    rows = corpus(matrix)
    code.append("struct fixture { unsigned kind,he,eht,ht,blocked,delayed,tid,window,maximum,token,timeout,ssn,policy,amsdu; int outcome; unsigned status,response_token,state,retries; unsigned long now,last; const u8 *tail;size_t len; };\nstatic const struct fixture fixtures[]={")
    for r in rows:
        fields = ",".join("." + k + "=" + str(v) for k, v in r.items() if k not in ("index", "label", "tail"))
        data = bytes.fromhex(r["tail"])
        code.append("{" + fields + ",.tail=(const u8[]){" + ",".join(map(str, data or b"\0")) + "},.len=" + str(len(data)) + "},")
    code.append("};")
    code.append(RUNNER)
    source = "\n\n".join(code) + "\n"
    (root / "block-ack.c").write_text(source)
    (root / "corpus.json").write_text(json.dumps(rows, indent=2) + "\n")
    receipt = dict(pin=PIN, executed=False, sources=bindings, unchanged_regions=regions,
                   generator_sha256=sha(Path(__file__).read_bytes()), harness_sha256=sha(source.encode()),
                   corpus_sha256=sha((root / "corpus.json").read_bytes()), cases=len(rows),
                   parser_matrix_sha256=sha(args.parser_matrix.read_bytes()),
                   limits=["Complete unchanged outer parser; projection compares only generic parse_error and ADDBA capture/extraction, not other parsed fields.",
                           "Exact fixed profile ACTION/HIGHEST, bssNULL/link_id-1/from_apfalse/filter0/crc0/inside_multilinkfalse; no inheritance or allocation failure.",
                           "Extension/TPE capture and outer MLE defrag projected out: no applicable parse_error or ADDBA changes; S1G sizeof-only scaffold is never reached in HIGHEST mode.",
                           "RX only fresh empty agreement with actual hardware-reordering callback; three unchanged regions, not complete start/lifecycle/software reorder.",
                           "Full TX request/send-timeout/response and session/response-timer functions; callbacks/driver/scheduler/locks captured, not native execution.",
                           "Only retry-region predicates from start_tx; other authorization/session creation branches not covered.",
                           "Explicit HZ1000, 64-bit jiffies and modeled tick conversion; not an actual timebase qualification.",
                           "Ordinary non-S1G, single-link station, unprotected management profile; no MLD/NDP/PMF/crypto/reorder/data or hardware readiness claim."])
    return receipt


RUNNER = r'''
_Static_assert(offsetof(struct ieee80211_mgmt,u.action.addba_req.variable)==33,"actual request layout");
_Static_assert(offsetof(struct ieee80211_mgmt,u.action.addba_resp.variable)==33,"actual response layout");
int main(void) {
 for(size_t index=0;index<ARRAY_SIZE(fixtures);index++) {
  const struct fixture *f=&fixtures[index];
  struct ieee80211_local local={0};struct ieee80211_sub_if_data sdata={.local=&local};
  struct sta_info sta={.sdata=&sdata,.local=&local};struct tid_ampdu_tx tid={.sta=&sta};
  struct ieee80211_txq queue={0};
  assert(f->tid<16);sdata.vif.type=NL80211_IFTYPE_STATION;
  memcpy(sta.sta.addr,"\x02\x11\x22\x33\x44\x55",6);
  memcpy(sdata.vif.addr,"\x02\xaa\xbb\xcc\xdd\xee",6);memcpy(sdata.vif.cfg.ap_addr,sta.sta.addr,6);
  sta.sta.deflink.ht_cap.ht_supported=f->ht;sta.sta.deflink.he_cap.has_he=f->he;sta.sta.deflink.eht_cap.has_eht=f->eht;
  sta.sta.deflink.ht_cap.cap=f->delayed ? IEEE80211_HT_CAP_DELAY_BA : 0;
  sta.sta.max_rx_aggregation_subframes=f->maximum;local.hw.max_tx_aggregation_subframes=f->maximum;
  local.hw.flags=BIT(SUPPORTS_AMSDU_IN_AMPDU)|BIT(SUPPORTS_REORDERING_BUFFER);sta.blocked=f->blocked;
  tid.tid=f->tid;tid.dialog_token=f->token;tid.ssn=f->ssn;tid.timeout=f->timeout;tid.state=f->state;
  tid.addba_resp_timer.active=true;
  sta.ampdu_mlme.addba_req_num[f->tid]=f->retries;sta.ampdu_mlme.last_addba_req_time[f->tid]=f->last;
  jiffies=f->now;air_len=0;last_parse_error=0;driver_calls=stop_calls=operational_calls=0;driver_result=f->outcome;
  memset(&captured,0,sizeof(captured));int retry=0;u8 extracted=0;u16 extended=f->window;unsigned generic_error=0;
  if(f->kind==0 || f->kind==2) {
   struct ieee802_11_elems *projection=ieee802_11_parse_elems(f->tail,f->len,
       IEEE80211_FTYPE_MGMT|IEEE80211_STYPE_ACTION,NULL);
   generic_error=projection->parse_error;free(projection);last_parse_error=0;
   extracted=ieee80211_retrieve_addba_ext_data(&sta,f->tail,f->len,&extended);
  }
  union {max_align_t align;u8 bytes[2048];} input={0};struct ieee80211_mgmt *m=(void *)input.bytes;
  m->u.action.category=WLAN_CATEGORY_BACK;
  if(f->kind==0) {
   m->u.action.action_code=WLAN_ACTION_ADDBA_REQ;m->u.action.addba_req.dialog_token=f->token;
   m->u.action.addba_req.capab=(f->window<<6)|(f->tid<<2)|(f->policy<<1)|f->amsdu;
   m->u.action.addba_req.timeout=f->timeout;m->u.action.addba_req.start_seq_num=f->ssn<<4;
   memcpy(m->u.action.addba_req.variable,f->tail,f->len);
   ieee80211_process_addba_request(&local,&sta,m,33+f->len);
  } else if(f->kind==1) { ieee80211_send_addba_with_timeout(&sta,&tid);
  } else if(f->kind==2) {
   sta.ampdu_mlme.tid_tx[f->tid]=&tid;sta.sta.txq[f->tid]=&queue;
   m->u.action.action_code=WLAN_ACTION_ADDBA_RESP;m->u.action.addba_resp.dialog_token=f->response_token;
   m->u.action.addba_resp.capab=(f->window<<6)|(f->tid<<2)|2|f->amsdu;
   m->u.action.addba_resp.status=f->status;m->u.action.addba_resp.timeout=f->timeout;
   memcpy(m->u.action.addba_resp.variable,f->tail,f->len);
   ieee80211_process_addba_resp(&local,&sta,m,33+f->len);
  } else if(f->kind==3) { retry=fixture_retry(&sta,f->tid);
  } else if(f->kind==4) { sta_tx_agg_session_timer_expired(&tid.session_timer);
  } else { abort(); }
  printf("{\"index\":%zu,\"kind\":%u,\"generic_error\":%u,\"parse_error\":%u,\"extracted_data\":%u,\"extended_window\":%u,\"driver_calls\":%d,\"driver_window\":%u,\"stop_calls\":%d,\"operational_calls\":%d,\"state\":%lu,\"window\":%u,\"amsdu\":%u,\"no_amsdu\":%u,\"retries\":%u,\"retry_result\":%d,\"response_timer\":%lu,\"response_active\":%u,\"session_timer\":%lu,\"session_active\":%u,\"air\":\"",
   index,f->kind,generic_error,last_parse_error,extracted,extended,driver_calls,captured.buf_size,stop_calls,operational_calls,tid.state,tid.buf_size,tid.amsdu,
   (unsigned)test_bit(IEEE80211_TXQ_NO_AMSDU,&queue.flags),sta.ampdu_mlme.addba_req_num[f->tid],retry,
   tid.addba_resp_timer.expiry,tid.addba_resp_timer.active,tid.session_timer.expiry,tid.session_timer.active);
  for(size_t n=0;n<air_len;n++)printf("%02x",air[n]);puts("\"}");
 }
 return fflush(stdout)!=0;
}
'''


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    for name in ("ba-sources", "mac-sources", "parse-source", "mesh-source", "parser-matrix"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--execute", action="store_true", help="explicitly compile/run prepared actual C source")
    args = parser.parse_args()
    receipt = prepare(args)
    root = args.output.resolve()
    if args.execute:
        command = ["clang", "-std=gnu11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
                   "-Wno-unused-parameter", "-Wno-unused-function", "-Wno-unused-variable",
                   "-Wno-sign-compare", "-Wno-unused-value", "-Wno-gnu-variable-sized-type-not-at-end",
                   "-fsanitize=address,undefined", "-fno-sanitize-recover=all",
                   str(root / "block-ack.c"), "-o", str(root / "block-ack")]
        result = subprocess.run(command, capture_output=True)
        (root / "compile.log").write_bytes(result.stdout + result.stderr)
        receipt["command"] = command
        receipt["compile_exit_code"] = result.returncode
        if result.returncode == 0:
            run = subprocess.run([str(root / "block-ack")], capture_output=True)
            (root / "trace.jsonl").write_bytes(run.stdout)
            (root / "run.stderr").write_bytes(run.stderr)
            receipt["run_exit_code"] = run.returncode
            if run.returncode == 0:
                records = [json.loads(line) for line in run.stdout.splitlines()]
                assert len(records) == receipt["cases"]
                assert all(record["index"] == i for i, record in enumerate(records))
                receipt.update(executed=True, trace_sha256=sha(run.stdout), binary_sha256=sha((root / "block-ack").read_bytes()))
    (root / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps({key: receipt[key] for key in ("executed", "cases", "harness_sha256")}))
    if args.execute and not receipt["executed"]:
        raise SystemExit("C comparison failed; preserve logs/receipt and use a fresh output for correction")


if __name__ == "__main__":
    main()

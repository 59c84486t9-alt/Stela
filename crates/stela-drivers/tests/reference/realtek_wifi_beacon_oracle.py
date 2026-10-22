#!/usr/bin/env python3
"""Source-owned RTL8822C reserved-page TX descriptor/TXBD oracle.

Usage: script reference-dir output-dir
Extracts unchanged pinned functions; models skb, DMA mapping and empty prior
beacon queue only. No Linux ABI/runtime, actual DMA or radio is exercised.
"""
import hashlib
import json
import pathlib
import re
import subprocess
import sys

reference, out = map(pathlib.Path, sys.argv[1:])
out.mkdir(parents=True, exist_ok=True)
manifest = []


def extract(file, name, kind=None):
    text = (reference / 'rtw88' / file).read_text()
    if kind:
        match = re.search(r'\b' + kind + r' ' + name + r'\s*\{', text)
        start, brace = match.start(), text.index('{', match.start())
    else:
        for match in re.finditer(r'\b' + name + r'\s*\(', text):
            end, depth = text.index('(', match.start()) + 1, 1
            while depth:
                depth += (text[end] == '(') - (text[end] == ')')
                end += 1
            while text[end].isspace():
                end += 1
            if text[end] != '{':
                continue
            start, brace = text.rfind('\n\n', 0, match.start()) + 2, end
            break
        else:
            raise ValueError(name)
    end, depth = brace + 1, 1
    while depth:
        depth += (text[end] == '{') - (text[end] == '}')
        end += 1
    if kind:
        end = text.index(';', end) + 1
    body = text[start:end]
    manifest.append(dict(path='rtw88/' + file, symbol=name, sha256=hashlib.sha256(body.encode()).hexdigest()))
    return body


definitions = '\n'.join([
    extract('main.h', 'rtw_tx_pkt_info', 'struct'),
    extract('main.h', 'rtw_tx_queue_type', 'enum'),
    extract('fw.h', 'rtw_rsvd_packet_type', 'enum'),
    extract('tx.h', 'rtw_tx_desc', 'struct'),
    extract('tx.h', 'rtw_tx_desc_queue_select', 'enum'),
    extract('pci.h', 'rtw_pci_tx_buffer_desc', 'struct'),
])
header = (reference / 'rtw88/tx.h').read_text()
macros = '\n'.join(line for line in header.splitlines() if line.startswith('#define RTW_TX_DESC_W'))
preamble = r'''
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error little endian source oracle required
#endif
typedef uint8_t u8;typedef uint16_t u16;typedef uint32_t u32;
typedef uint16_t __le16;typedef uint32_t __le32;typedef uint64_t dma_addr_t;
#define __packed __attribute__((packed))
#define BIT(n) (1U<<(n))
#define GENMASK(h,l) ((~0U>>(31-(h)))&(~0U<<(l)))
#define le32_encode_bits(v,m) (((u32)(v)<<__builtin_ctz(m))&(m))
#define cpu_to_le16(v) (v)
#define cpu_to_le32(v) (v)
#define RTW_BAND_2G 0
#define RTW_RATEID_B_20M 8
#define RTW_RATEID_G 7
#define DESC_RATE1M 0
#define DESC_RATE6M 4
#define DESC_RATE24M 8
#define RTW_FLAG_FORCE_LOWEST_RATE 0
#define WLAN_CIPHER_SUITE_WEP40 1
#define WLAN_CIPHER_SUITE_WEP104 2
#define WLAN_CIPHER_SUITE_TKIP 3
#define WLAN_CIPHER_SUITE_CCMP 4
#define RTK_PCI_TXBD_OWN_OFFSET 15
#define DMA_TO_DEVICE 0
#define EXPORT_SYMBOL(...)
#define rtw_err(...) ((void)0)
#define list_first_entry_or_null(...) NULL
#define spin_lock_bh(...) ((void)0)
#define spin_unlock_bh(...) ((void)0)
#define skb_queue_tail(...) ((void)0)
#define set_bit(...) ((void)0)
'''
models = r'''
struct ieee80211_hdr {u16 frame_control,duration;u8 addr1[6];} __packed;
struct ieee80211_hdr_3addr {u8 bytes[24];};
struct ieee80211_vif {struct {u32 basic_rates;} bss_conf;};
struct ieee80211_key_conf {u32 cipher;};
struct ieee80211_tx_info {struct{struct ieee80211_vif*vif;struct ieee80211_key_conf*hw_key;}control;};
struct rtw_pci_tx_data {dma_addr_t dma;u8 sn;};
struct sk_buff {u8 *data;u32 len;u8 priority;struct ieee80211_tx_info info;struct rtw_pci_tx_data tx;};
#define IEEE80211_SKB_CB(skb) (&(skb)->info)
struct rtw_rsvd_page {u8 tim_offset;};
struct rtw_chip_info {u32 tx_pkt_desc_sz,tx_buf_desc_sz;bool old_datarate_fb_limit;};
struct rtw_pci_tx_ring {struct{u32 wp,rp,len;}r;int queue;};
struct pci_dev {int dev;};
struct rtw_pci {struct pci_dev*pdev;struct rtw_pci_tx_ring tx_rings[8];u32 tx_queued[1];};
struct rtw_dev {const struct rtw_chip_info *chip;void *priv;struct{u8 current_band_type;}hal;u32 flags[1];};
static struct rtw_pci_tx_buffer_desc bd[2];
static bool test_bit(u32 n,u32*p){return (*p&BIT(n))!=0;}
static int __ffs(u32 v){return __builtin_ctz(v);}
static bool is_broadcast_ether_addr(const u8*a){static const u8 b[6]={255,255,255,255,255,255};return memcmp(a,b,6)==0;}
static bool is_multicast_ether_addr(const u8*a){return a[0]&1;}
static void rtw_pci_release_rsvd_page(struct rtw_pci*p,struct rtw_pci_tx_ring*r){(void)p;(void)r;}
static int avail_desc(u32 w,u32 r,u32 n){(void)w;(void)r;(void)n;return 1;}
static u8 *skb_push(struct sk_buff*s,u32 n){s->data-=n;s->len+=n;return s->data;}
static dma_addr_t dma_map_single(int*d,u8*p,u32 n,int dir){(void)d;(void)p;(void)n;(void)dir;return 0x12340000;}
static bool dma_mapping_error(int*d,dma_addr_t a){(void)d;(void)a;return false;}
static struct rtw_pci_tx_buffer_desc *get_tx_buffer_desc(struct rtw_pci_tx_ring*r,u32 n){(void)r;if(n!=16)abort();return bd;}
static struct rtw_pci_tx_data *rtw_pci_get_tx_data(struct sk_buff*s){return &s->tx;}
'''
functions = '\n'.join(extract('tx.c', name) for name in [
    'rtw_tx_fill_tx_desc', 'rtw_get_mgmt_rate', 'rtw_tx_pkt_info_update_rate',
    'rtw_tx_pkt_info_update_sec', 'rtw_tx_rsvd_page_pkt_info_update'])
functions += '\n' + '\n'.join(extract('pci.c', name) for name in ['rtw_pci_get_tx_qsel', 'rtw_pci_tx_write_data'])
main = r'''
int main(int argc,char**argv){if(argc!=2)return 2;FILE*f=fopen(argv[1],"wb");if(!f)abort();
struct rtw_chip_info chip={48,16,false};struct pci_dev pci={0};struct rtw_pci pc={.pdev=&pci};struct rtw_dev dev={.chip=&chip,.priv=&pc};
for(u32 band=0;band<2;band++)for(u32 n=8;n<=4096;n++)for(u32 multicast=0;multicast<2;multicast++){
u8 *allocation=calloc(1,48+4096);if(!allocation)abort();u8*data=allocation+48;for(u32 i=0;i<n;i++)data[i]=i;data[4]=multicast;
struct sk_buff skb={.data=data,.len=n};struct rtw_tx_pkt_info info={0};dev.hal.current_band_type=band;
rtw_tx_rsvd_page_pkt_info_update(&dev,&info,&skb,RSVD_BEACON);memset(bd,0,sizeof(bd));if(rtw_pci_tx_write_data(&dev,&info,&skb,RTW_TX_QUEUE_BCN))abort();
if(fwrite(allocation,1,48,f)!=48||fwrite(bd,1,16,f)!=16)abort();free(allocation);}
if(fclose(f))abort();return 0;}
'''
source = out / 'oracle.c'
source.write_text(preamble + definitions + '\n' + macros + '\n' + models + functions + '\n' + main)
exe = out / 'oracle'
subprocess.run(['clang', '-std=gnu11', '-O1', '-g', '-fsanitize=address,undefined', str(source), '-o', str(exe)], check=True)
trace = out / 'trace.bin'
subprocess.run([str(exe), str(trace)], check=True)
receipt = dict(linux_commit='a804c5742bff224d4cb4d25dd383554d598be32b', symbols=manifest,
               trace_bytes=trace.stat().st_size, trace_sha256=hashlib.sha256(trace.read_bytes()).hexdigest(),
               generated_source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
               cases=2 * 4089 * 2, oracle_limit=[
                   'skb, native DMA map and initially empty prior beacon queue modeled; no hardware',
                   'prior source band configuration supplied; no VIF/key/TIM/old-datarate-fallback',
                   'full zeroed maximum packet allocation bounds source header reads for tiny logical chunks',
                   'native pin/ownership/fault handling verified by separate Rust IOVA model'])
(out / 'manifest.json').write_text(json.dumps(receipt, indent=2) + '\n')
print(json.dumps({k: receipt[k] for k in ['cases', 'trace_bytes', 'trace_sha256']}))

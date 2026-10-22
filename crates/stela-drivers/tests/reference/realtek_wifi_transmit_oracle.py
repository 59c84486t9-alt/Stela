#!/usr/bin/env python3
"""Source-owned RTL8822C H2C firmware packet/descriptor oracle.

Usage: script reference-dir output-dir
Extracts unchanged pinned functions; models skb, DMA mapping and empty prior
command queue only. No Linux ABI/runtime, actual DMA or radio is exercised.
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

# Direct firmware-header macros are extracted with their continuation lines.
fwheader=(reference/'rtw88/fw.h').read_text().splitlines()
selected=[]
for i,line in enumerate(fwheader):
    if re.match(r'#define (SET_PKT_H2C_|FW_OFFLOAD_H2C_SET_SEQ_NUM|GENERAL_INFO_SET_FW_TX_BOUNDARY)',line):
        block=[line]
        while block[-1].endswith('\\'):
            i+=1;block.append(fwheader[i])
        selected.append('\n'.join(block))
preamble += r'''
#define H2C_PKT_CATEGORY 1
#define H2C_PKT_CMD_ID 255
#define H2C_PKT_GENERAL_INFO 13
#define H2C_PKT_SIZE 32
#define H2C_PKT_HDR_SIZE 8
#define le32p_replace_bits(p,v,m) (*(p)=(*(p)&~(m))|le32_encode_bits(v,m))
#define lockdep_assert_held(...) ((void)0)
#define TRX_BD_IDX_MASK 0xfff
#define FW_FEATURE_TX_WAKE 0
'''
# Hardware geometry and serialized awake firmware/H2C state, not Linux ABI.
models=models.replace('struct rtw_dev {','struct rtw_fifo_conf {u16 rsvd_fw_txbuf_addr,rsvd_boundary;};\nstruct rtw_dev {struct rtw_fifo_conf fifo;struct{u16 seq;}h2c;int mutex;int fw;')
models += r'''
static struct sk_buff active;static u8*allocation;static u16 published;
static const u32 rtw_pci_tx_queue_idx_addr[8]={[RTW_TX_QUEUE_H2C]=0x132c};
static struct sk_buff*dev_alloc_skb(u32 n){allocation=calloc(1,n);if(!allocation)abort();memset(&active,0,sizeof(active));active.data=allocation;return &active;}
static void skb_reserve(struct sk_buff*s,u32 n){s->data+=n;}
static void skb_put_data(struct sk_buff*s,u8*b,u32 n){memcpy(s->data+s->len,b,n);s->len+=n;}
static bool rtw_fw_feature_check(int*f,int flag){(void)f;(void)flag;return true;}
static void rtw_pci_deep_ps_leave(struct rtw_dev*d){(void)d;abort();}
static bool rtw_chip_wcpu_8051(struct rtw_dev*d){(void)d;return false;}
static void rtw_write16(struct rtw_dev*d,u32 reg,u16 value){(void)d;if(reg!=0x132c)abort();published=value;}
static int rtw_hci_write_data_h2c(struct rtw_dev*d,u8*b,u32 n);
'''
functions = '\n'.join(extract('tx.c',name) for name in ['rtw_tx_fill_tx_desc','rtw_tx_write_data_h2c_get'])
functions += '\n'+'\n'.join(extract('pci.c',name) for name in ['rtw_pci_get_tx_qsel','rtw_pci_tx_write_data','rtw_pci_tx_kick_off_queue','rtw_pci_write_data_h2c'])
functions += '\nstatic int rtw_hci_write_data_h2c(struct rtw_dev*d,u8*b,u32 n){return rtw_pci_write_data_h2c(d,b,n); }\n'
functions += '\n' + extract('fw.h','rtw_h2c_pkt_set_header')
functions += '\n' + '\n'.join(extract('fw.c',name) for name in ['rtw_fw_send_h2c_packet','rtw_fw_send_general_info'])
main = r'''
int main(int argc,char**argv){if(argc!=2)return 2;FILE*f=fopen(argv[1],"wb");if(!f)abort();
struct rtw_chip_info chip={48,16,false};struct pci_dev pci={0};struct rtw_pci pc={.pdev=&pci};struct rtw_dev dev={.chip=&chip,.priv=&pc,.fifo={0x7ca,0x792}};
for(u32 sequence=0;sequence<65536;sequence++){
struct rtw_pci_tx_ring*r=&pc.tx_rings[RTW_TX_QUEUE_H2C];r->r.len=128;r->r.wp=sequence%128;r->r.rp=sequence%128;
memset(bd,255,sizeof(bd));rtw_fw_send_general_info(&dev);
if(active.len!=80||dev.h2c.seq!=(u16)(sequence+1)||published!=(sequence+1)%128)abort();
if(fwrite(allocation,80,1,f)!=1||fwrite(bd,16,1,f)!=1)abort();free(allocation);}
if(fclose(f))abort();return 0;}
'''
source=out/'oracle.c';source.write_text(preamble+definitions+'\n'+macros+'\n'+'\n'.join(selected)+'\n'+models+functions+'\n'+main)
exe=out/'oracle';subprocess.run(['clang','-std=gnu11','-O1','-g','-fsanitize=address,undefined',str(source),'-o',str(exe)],check=True)
trace=out/'trace.bin';subprocess.run([str(exe),str(trace)],check=True)
receipt=dict(linux_commit='a804c5742bff224d4cb4d25dd383554d598be32b',symbols=manifest,cases=65536,trace_bytes=trace.stat().st_size,trace_sha256=hashlib.sha256(trace.read_bytes()).hexdigest(),generated_source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),oracle_limit=[
    'serialized awake firmware and coherent queue/skb/DMA map are models, not actual Linux ABI/hardware',
    'source full command and both descriptors compared at all16-bit sequence values and all128 producer positions',
    'native lifetime/IOMMU/visibility/failure ownership verified separately',
    'no command reply, firmware acknowledgement, radio data or air ACK exercised'])
(out/'manifest.json').write_text(json.dumps(receipt,indent=2)+'\n')
print(json.dumps({k:receipt[k] for k in ['cases','trace_bytes','trace_sha256']}))

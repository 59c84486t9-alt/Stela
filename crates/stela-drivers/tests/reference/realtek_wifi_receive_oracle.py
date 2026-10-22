#!/usr/bin/env python3
"""Source-owned RTL8822C RX descriptor, rearm, index and tag oracle.
Usage: script reference-dir output-dir. No Linux ABI or real DMA/radio.
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
    extract('rx.h', 'rtw_rx_desc_enc', 'enum'),
    extract('rx.h', 'rtw_rx_desc', 'struct'),
    extract('main.h', 'rtw_rx_pkt_stat', 'struct'),
    extract('pci.h', 'rtw_pci_rx_buffer_desc', 'struct'),
])
macros = '\n'.join(line for line in (reference / 'rtw88/rx.h').read_text().splitlines() if line.startswith('#define RTW_RX_DESC_'))
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
typedef uint8_t u8;typedef uint16_t u16;typedef uint32_t u32;typedef int8_t s8;typedef int32_t s32;
typedef uint16_t __le16;typedef uint32_t __le32;typedef uint64_t dma_addr_t;
#define __packed __attribute__((packed))
#define BIT(n) (1U<<(n))
#define GENMASK(h,l) ((~0U>>(31-(h)))&(~0U<<(l)))
#define le32_get_bits(v,m) (((v)&(m))>>__builtin_ctz(m))
#define u32_get_bits(v,m) le32_get_bits(v,m)
#define cpu_to_le16(v) (v)
#define cpu_to_le32(v) (v)
#define le16_to_cpu(v) (v)
#define RTW_RF_PATH_MAX 4
#define RTK_PCI_RX_BUF_SIZE 11478
#define RTW_RX_QUEUE_MPDU 0
#define RTK_PCI_RXBD_IDX_MPDUQ 0x3b4
#define TRX_BD_HW_IDX_MASK GENMASK(27,16)
#define RX_TAG_MAX 8192
#define PHY_STATUS_SIZE 4
#define DESC_RATE_MAX 84
#define IEEE80211_MAX_MPDU_LEN_VHT_11454 11454
#define FCS_LEN 4
#define DMA_FROM_DEVICE 1
#define unlikely(v) (v)
#define EXPORT_SYMBOL(...)
'''
models = r'''
struct ieee80211_hdr {u8 bytes[24];};
struct ieee80211_rx_status {u8 unused;};
struct rtw_dev;
static void query_phy(struct rtw_dev*d,void*p,struct rtw_rx_pkt_stat*s){(void)d;(void)p;(void)s;}
struct chip_ops {void(*query_phy_status)(struct rtw_dev*,void*,struct rtw_rx_pkt_stat*);};
struct rtw_chip_info {u32 rx_pkt_desc_sz,rx_buf_desc_sz;const struct chip_ops*ops;};
struct rtw_pci_rx_ring {struct{u8*head;u32 wp,len;}r;};
struct rtw_pci {struct rtw_pci_rx_ring rx_rings[1];u16 rx_tag;};
struct rtw_dev {const struct rtw_chip_info*chip;void*priv;void*dev;};
static u32 hardware_index, warning, syncs;
static u32 rtw_read32(struct rtw_dev*d,u32 reg){(void)d;if(reg!=0x3b4)abort();return hardware_index;}
static void rtw_rx_fill_rx_status(struct rtw_dev*d,struct rtw_rx_pkt_stat*s,struct ieee80211_hdr*h,struct ieee80211_rx_status*r){(void)d;(void)s;(void)h;(void)r;}
#define rtw_warn(...) (warning++)
static void dma_sync_single_for_device(void*d,dma_addr_t a,u32 n,int dir){(void)d;if(a!=0x12340000||n!=11478||dir!=DMA_FROM_DEVICE)abort();syncs++;}
static void emit(FILE*f,u32 value){if(fwrite(&value,4,1,f)!=1)abort();}
static u32 random_state=0x1326ac39;
static u32 random_word(void){random_state^=random_state<<13;random_state^=random_state>>17;random_state^=random_state<<5;return random_state;}
'''
functions = extract('rx.c', 'rtw_rx_query_rx_desc') + '\n'
functions += '\n'.join(extract('pci.c', n) for n in ['rtw_pci_sync_rx_desc_device','rtw_pci_dma_check','rtw_pci_get_hw_rx_ring_nr'])
main = r'''
int main(int argc,char**argv){if(argc!=2)return 2;FILE*f=fopen(argv[1],"wb");if(!f)abort();
struct chip_ops ops={query_phy};struct rtw_chip_info chip={24,8,&ops};
struct rtw_pci_rx_buffer_desc bd[512];struct rtw_pci pci={.rx_rings={{{(u8*)bd,0,512}}}};
struct rtw_dev dev={.chip=&chip,.priv=&pci};u8 bytes[11542]={0};
for(u32 i=0;i<131072;i++){
struct rtw_rx_desc*desc=(struct rtw_rx_desc*)bytes;
for(u32 j=0;j<6;j++)((u32*)bytes)[j]=random_word();
if(i%4==0){u32 units=(i>>2)&1?4:0;desc->w0=(random_word()&0xf8f0c000)|(8+i%11391)|(units<<16)|((i&4)&&units?BIT(26):0);desc->w0&=~BIT(26);if(units&&(i&4))desc->w0|=BIT(26);desc->w3=(desc->w3&~127U)|(i%84);}
if(i%4==1){desc->w0=(desc->w0&~0x3fffU)|(i%6);desc->w3&=~127U;}
struct rtw_rx_pkt_stat s;struct ieee80211_rx_status status;
int ret=rtw_rx_query_rx_desc(&dev,bytes,&s,&status);
/* Same independent buffer bound as source PCI rx_napi after the query. */
if(!ret&&24U+s.drv_info_sz+s.shift+s.pkt_len>RTK_PCI_RX_BUF_SIZE)ret=-EINVAL;
if(fwrite(bytes,24,1,f)!=1)abort();emit(f,(u32)ret);
emit(f,s.pkt_len);emit(f,s.crc_err);emit(f,s.icv_err);emit(f,s.drv_info_sz);emit(f,s.shift);emit(f,s.phy_status);emit(f,s.decrypted);emit(f,s.cam_id);emit(f,s.is_c2h);emit(f,s.ppdu_cnt);emit(f,s.rate);emit(f,s.bw);emit(f,s.tsf_low);
}
for(u32 i=0;i<8192;i++){
u32 slot=i%512;memset(&bd[slot],255,8);syncs=0;
rtw_pci_sync_rx_desc_device(&dev,0x12340000,&pci.rx_rings[0],slot,8);
if(syncs!=1||fwrite(&bd[slot],8,1,f)!=1)abort();
pci.rx_tag=i;bd[slot].total_pkt_size=i;warning=0;rtw_pci_dma_check(&dev,&pci.rx_rings[0],slot);emit(f,pci.rx_tag);emit(f,warning);
pci.rx_tag=i;bd[slot].total_pkt_size=i^1;warning=0;rtw_pci_dma_check(&dev,&pci.rx_rings[0],slot);emit(f,pci.rx_tag);emit(f,warning);
}
for(u32 consumer=0;consumer<512;consumer++)for(u32 producer=0;producer<512;producer++){
pci.rx_rings[0].r.wp=consumer;hardware_index=(producer<<16)|consumer;emit(f,rtw_pci_get_hw_rx_ring_nr(&dev,&pci));}
if(fclose(f))abort();return 0;}
'''
source = out / 'oracle.c'
source.write_text(preamble + definitions + '\n' + macros + '\n' + models + functions + '\n' + main)
exe = out / 'oracle'
subprocess.run(['clang','-std=gnu11','-O1','-g','-fsanitize=address,undefined',str(source),'-o',str(exe)],check=True)
trace = out / 'trace.bin'
subprocess.run([str(exe),str(trace)],check=True)
receipt = dict(linux_commit='a804c5742bff224d4cb4d25dd383554d598be32b', symbols=manifest,
    parser_cases=131072, rearm_tag_cases=8192, index_cases=512*512,
    trace_bytes=trace.stat().st_size, trace_sha256=hashlib.sha256(trace.read_bytes()).hexdigest(),
    generated_source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),oracle_limit=[
        'PHY decoder and OS RX status filler are inert; only unchanged raw descriptor/query semantics compared',
        'source PCI buffer bound applied after unchanged query; full allocation avoids unchecked donor pointer UB',
        'device registers, coherent RXBD and DMA visibility modeled; no actual requester or radio',
        'source tag mismatch warns and advances; native driver deliberately quarantines without advancing',
        'native buffer pin lifetime/visibility failures and callback borrowing verified separately'])
(out / 'manifest.json').write_text(json.dumps(receipt,indent=2)+'\n')
print(json.dumps({k:receipt[k] for k in ['parser_cases','rearm_tag_cases','index_cases','trace_bytes','trace_sha256']}))

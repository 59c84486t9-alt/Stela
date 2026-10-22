#!/usr/bin/env python3
"""Pinned unchanged RTL8822C HCI reset/base/index/tag register oracle.
Usage: script reference-dir output-dir. No hardware, stop ACK or Linux ABI.
"""
import hashlib
import json
import pathlib
import re
import subprocess
import sys
reference,out=map(pathlib.Path,sys.argv[1:]);out.mkdir(parents=True,exist_ok=True)
manifest=[]

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

definitions=extract('main.h','rtw_tx_queue_type','enum')
header=(reference/'rtw88/pci.h').read_text().splitlines()
macros='\n'.join(line for line in header if re.match(r'#define (RTK_PCI_|BIT_CLR_H2CQ_|BIT_RST_TRXDMA_INTF|BIT_RX_TAG_EN|TRX_BD_IDX_MASK)',line))
preamble=r'''
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint8_t u8;typedef uint16_t u16;typedef uint32_t u32;typedef uint64_t dma_addr_t;
#define BIT(n) (1U<<(n))
#define GENMASK(h,l) ((~0U>>(31-(h)))&(~0U<<(l)))
#define RTW_RX_QUEUE_MPDU 0
'''
models=r'''
struct ring {u32 len,wp,rp;dma_addr_t dma;};
struct rtw_pci {struct{struct ring r;}tx_rings[8],rx_rings[1];u16 rx_tag;};
struct rtw_dev {void*priv;};
static u8 bytes[0x1400];static FILE*trace;
static void event(u32 write,u32 reg,u32 n,u32 value){u32 e[4]={write,reg,n,value};if(fwrite(e,16,1,trace)!=1)abort();}
static u32 read_width(u32 reg,u32 n){u32 v=0;memcpy(&v,bytes+reg,n);event(0,reg,n,v);return v;}
static void write_width(u32 reg,u32 n,u32 v){memcpy(bytes+reg,&v,n);event(1,reg,n,v);}
static u8 rtw_read8(struct rtw_dev*d,u32 reg){(void)d;return read_width(reg,1);}
static u32 rtw_read32(struct rtw_dev*d,u32 reg){(void)d;return read_width(reg,4);}
static void rtw_write8(struct rtw_dev*d,u32 reg,u8 v){(void)d;write_width(reg,1,v);}
static void rtw_write16(struct rtw_dev*d,u32 reg,u16 v){(void)d;write_width(reg,2,v);}
static void rtw_write32(struct rtw_dev*d,u32 reg,u32 v){(void)d;write_width(reg,4,v);}
static void rtw_write32_set(struct rtw_dev*d,u32 reg,u32 mask){rtw_write32(d,reg,rtw_read32(d,reg)|mask);}
static bool rtw_chip_wcpu_8051(struct rtw_dev*d){(void)d;return false;}
static bool rtw_chip_wcpu_3081(struct rtw_dev*d){(void)d;return true;}
'''
functions='\n'.join(extract('pci.c',n) for n in ['rtw_pci_reset_buf_desc','rtw_pci_reset_trx_ring','rtw_pci_dma_reset','rtw_pci_setup'])
main=r'''
int main(int argc,char**argv){if(argc!=2)return 2;trace=fopen(argv[1],"wb");if(!trace)abort();
for(u32 c=0;c<16;c++){
for(u32 i=0;i<sizeof(bytes);i++)bytes[i]=(i*17+c*23)&255;
struct rtw_pci pci={0};struct rtw_dev dev={.priv=&pci};
u32 dma[8]={0x10020000,0x10030000,0x10040000,0x10050000,0x10010000,0x10060000,0x10070000,0x10080000};
for(u32 i=0;i<8;i++){pci.tx_rings[i].r.dma=dma[i];pci.tx_rings[i].r.len=i==1?256:i==4?1:128;pci.tx_rings[i].r.wp=89;pci.tx_rings[i].r.rp=13;}
pci.rx_rings[0].r.dma=0x10090000;pci.rx_rings[0].r.len=512;pci.rx_rings[0].r.wp=77;pci.rx_rings[0].r.rp=19;pci.rx_tag=8000;
if(rtw_pci_setup(&dev)||pci.rx_tag!=0||pci.rx_rings[0].r.wp!=0||pci.rx_rings[0].r.rp!=0)abort();
for(u32 i=0;i<8;i++)if(i!=4&&(pci.tx_rings[i].r.wp||pci.tx_rings[i].r.rp))abort();
}
if(fclose(trace))abort();return 0;}
'''
source=out/'oracle.c';source.write_text(preamble+definitions+'\n'+macros+'\n'+models+functions+'\n'+main)
exe=out/'oracle';subprocess.run(['clang','-std=gnu11','-O1','-g','-fsanitize=address,undefined',str(source),'-o',str(exe)],check=True)
trace=out/'trace.bin';subprocess.run([str(exe),str(trace)],check=True)
receipt=dict(linux_commit='a804c5742bff224d4cb4d25dd383554d598be32b',symbols=manifest,cases=16,trace_bytes=trace.stat().st_size,trace_sha256=hashlib.sha256(trace.read_bytes()).hexdigest(),generated_source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),oracle_limit=[
    'source register effects and retained ring addresses modeled; no hardware/stop acknowledgement or Linux ABI',
    'native adds independent actual base/count readbacks, identity/removal/zero-index and pin-visibility guards',
    'native initial-only ring preparation/lifetime checked by actual native RX/TX/beacon allocation integration model',
    'reset/index equality cannot prove DMA stop; caller requires independent acknowledged stop/drain',
    'IRQ/start/PHY/radio and live recovery excluded'])
(out/'manifest.json').write_text(json.dumps(receipt,indent=2)+'\n');print(json.dumps({k:receipt[k] for k in ['cases','trace_bytes','trace_sha256']}))

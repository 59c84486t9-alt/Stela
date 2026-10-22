#!/usr/bin/env python3
"""Pinned unchanged RTL8822C interrupt mask/cause/W1C oracle.
Usage: script reference-dir output-dir. No actual route, DMA or Linux ABI.
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

header=(reference/'rtw88/pci.h').read_text().splitlines()
macros='\n'.join(line for line in header if re.match(r'#define (RTK_PCI_HI|IMR_)',line))
preamble=r'''
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
typedef uint8_t u8;typedef uint16_t u16;typedef uint32_t u32;
#define BIT(n) (1U<<(n))
#define spin_lock_init(p) ((void)(p))
#define spin_lock_irqsave(p,f) do{(void)(p);f=0;}while(0)
#define spin_unlock_irqrestore(p,f) do{(void)(p);(void)(f);}while(0)
'''
models=r'''
struct rtw_pci {u32 irq_mask[4];int irq_lock,hwirq_lock;bool irq_enabled;};
struct rtw_dev {void*priv;};
static u8 bytes[0x1100];static FILE*trace;
static void event(u32 w,u32 r,u32 v){u32 words[4]={w,r,4,v};if(fwrite(words,16,1,trace)!=1)abort();}
static u32 rtw_read32(struct rtw_dev*d,u32 r){(void)d;u32 v;memcpy(&v,bytes+r,4);event(0,r,v);return v;}
static void rtw_write32(struct rtw_dev*d,u32 r,u32 v){(void)d;event(1,r,v);if(r==0xb4||r==0xbc||r==0x10bc){u32 old;memcpy(&old,bytes+r,4);old&=~v;memcpy(bytes+r,&old,4);}else memcpy(bytes+r,&v,4);}
static bool rtw_chip_wcpu_3081(struct rtw_dev*d){(void)d;return true;}
static int rtw_pci_init_trx_ring(struct rtw_dev*d){(void)d;return 0;}
static u32 rotate(u32 v,u32 n){return(v<<n)|(v>>(32-n));}
'''
functions='\n'.join(extract('pci.c',n) for n in ['rtw_pci_init','rtw_pci_enable_interrupt','rtw_pci_disable_interrupt','rtw_pci_irq_recognized'])
main=r'''
int main(int argc,char**argv){if(argc!=2)return 2;trace=fopen(argv[1],"wb");if(!trace)abort();
for(u32 c=0;c<48;c++){
memset(bytes,0,sizeof(bytes));u32 raw[3];if(c<32){raw[0]=1U<<c;raw[1]=rotate(1U<<c,7);raw[2]=rotate(1U<<c,19);}else{raw[0]=c*0x13ac9571U;raw[1]=c*0x77235491U;raw[2]=c*0x129d2157U;}
u32 regs[3]={0xb4,0xbc,0x10bc};for(u32 i=0;i<3;i++)memcpy(bytes+regs[i],&raw[i],4);
struct rtw_pci pci={.irq_enabled=true};struct rtw_dev dev={.priv=&pci};if(rtw_pci_init(&dev))abort();
/* Native construction actively masks unknown prior route state. */
rtw_pci_disable_interrupt(&dev,&pci);
rtw_pci_enable_interrupt(&dev,&pci,false);rtw_pci_disable_interrupt(&dev,&pci);u32 status[4]={0};rtw_pci_irq_recognized(&dev,&pci,status);
rtw_pci_enable_interrupt(&dev,&pci,true);rtw_pci_disable_interrupt(&dev,&pci);rtw_pci_irq_recognized(&dev,&pci,status);if(status[0]||status[1]||status[3])abort();
rtw_pci_enable_interrupt(&dev,&pci,false);rtw_pci_disable_interrupt(&dev,&pci);
}
if(fclose(trace))abort();return 0;}
'''
source=out/'oracle.c';source.write_text(preamble+macros+'\n'+models+functions+'\n'+main)
exe=out/'oracle';subprocess.run(['clang','-std=gnu11','-O1','-g','-fsanitize=address,undefined',str(source),'-o',str(exe)],check=True)
trace=out/'trace.bin';subprocess.run([str(exe),str(trace)],check=True)
receipt=dict(linux_commit='a804c5742bff224d4cb4d25dd383554d598be32b',symbols=manifest,cases=48,trace_bytes=trace.stat().st_size,trace_sha256=hashlib.sha256(trace.read_bytes()).hexdigest(),generated_source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),oracle_limit=[
    'HIMR/HISR W1C, serialized locks and source3081 dispatch are modeled, not hardware/Linux ABI',
    'source ring-allocation hook inert; mask values are independently derived by unchanged source init',
    'initial enabled flag exercises actual disable, matching native active masking of unknown prior route state',
    'native identity/removal/mask readbacks are stricter additional guards, omitted from original source trace',
    'no native MSI route, IRQ registry delivery, deferred work, packet completion/FW ACK or DMA stop proven'])
(out/'manifest.json').write_text(json.dumps(receipt,indent=2)+'\n');print(json.dumps({k:receipt[k] for k in ['cases','trace_bytes','trace_sha256']}))

#!/usr/bin/env python3
"""Pinned unchanged RTL8822C initial AB/AB/false TRX path phase.
Usage: script reference-dir output-dir; no calibration/radio or Linux ABI.
"""
import hashlib,json,pathlib,re,subprocess,sys
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




def macro(file,name):
    text=(reference/'rtw88'/file).read_text();line=re.search(r'^#define\s+'+name+r'\s+[^\n]+',text,re.M).group();manifest.append(dict(path='rtw88/'+file,symbol=name,sha256=hashlib.sha256(line.encode()).hexdigest()));return line
macros='\n'.join(macro(file,name)for file,name in [('phy.h','MASK20BITS'),('reg.h','REG_SYS_FUNC_EN'),('reg.h','BIT_FEN_BB_RSTB')]+[('rtw8822c.h',name)for name in ['REG_ORITXCODE','REG_ORITXCODE2','REG_CCANRX','REG_RXCCKSEL','REG_RXFNCTL','REG_AGCSWSH','REG_ANTWTPD','REG_MRCM','REG_ANTMAP0','REG_TXLGMAP','REG_RXIGI']])
declaration=extract('main.h','rtw_bb_path','enum')
helpers='\n'.join(extract('hci.h',n)for n in ['rtw_read32_mask','rtw_write32_mask','rtw_write16_set','rtw_write16_clr'])
functions='\n'.join(extract('rtw8822c.c',n)for n in ['rtw8822c_bb_reset','rtw8822c_toggle_igi','rtw8822c_config_cck_rx_path','rtw8822c_config_ofdm_rx_path','rtw8822c_config_rx_path','rtw8822c_config_cck_tx_path','rtw8822c_config_ofdm_tx_path','rtw8822c_config_tx_path','rtw8822c_config_trx_mode'])
preamble=r'''#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint8_t u8;typedef uint16_t u16;typedef uint32_t u32;
#define BIT(n) (1U<<(n))
#define __ffs(x) __builtin_ctz(x)
#define WARN(x,...) do{if(x)abort();}while(0)
struct rtw_dev {u8 unused;};static u8 bytes[0x5000];static FILE*trace;static u32 events;
static void event(u32 k,u32 r,u32 w,u32 v){u32 words[4]={k,r,w,v};if(fwrite(words,16,1,trace)!=1)abort();events++;}
static u16 rtw_read16(struct rtw_dev*d,u32 r){(void)d;u16 v;memcpy(&v,bytes+r,2);event(0,r,2,v);return v;}
static u32 rtw_read32(struct rtw_dev*d,u32 r){(void)d;u32 v;memcpy(&v,bytes+r,4);event(0,r,4,v);return v;}
static void rtw_write16(struct rtw_dev*d,u32 r,u16 v){(void)d;event(1,r,2,v);memcpy(bytes+r,&v,2);}
static void rtw_write32(struct rtw_dev*d,u32 r,u32 v){(void)d;event(1,r,4,v);memcpy(bytes+r,&v,4);}
'''
main=r'''int main(int argc,char**argv){if(argc!=2)return 2;trace=fopen(argv[1],"wb+");if(!trace)abort();struct rtw_dev d={0};
for(u32 pattern=0;pattern<4;pattern++)for(u32 igi=0;igi<128;igi++){
for(u32 i=0;i<sizeof(bytes);i++)bytes[i]=(i*13+pattern*7)&255;u32 sys=(1U<<27)|(1<<12),ready=0xc078,wlrf;memcpy(bytes+0xf0,&sys,4);memcpy(bytes+0x80,&ready,4);bytes[2]|=3;bytes[0x1f]|=7;memcpy(&wlrf,bytes+0xec,4);wlrf|=0x07000000;memcpy(bytes+0xec,&wlrf,4);u32 raw;memcpy(&raw,bytes+REG_RXIGI,4);raw=(raw&~127U)|igi;memcpy(bytes+REG_RXIGI,&raw,4);
u32 header[3]={pattern,igi,0};long start=ftell(trace);if(fwrite(header,12,1,trace)!=1)abort();events=0;rtw8822c_config_trx_mode(&d,BB_PATH_AB,BB_PATH_AB,false);long end=ftell(trace);if(fseek(trace,start+8,SEEK_SET)||fwrite(&events,4,1,trace)!=1||fseek(trace,end,SEEK_SET))abort();if(fwrite(bytes,sizeof(bytes),1,trace)!=1)abort();
}
if(fclose(trace))abort();return 0;}
'''
source=out/'oracle.c';source.write_text(preamble+macros+'\n'+declaration+'\n'+helpers+'\n'+functions+'\n'+main);exe=out/'oracle';subprocess.run(['clang','-std=gnu11','-O1','-g','-fsanitize=address,undefined',str(source),'-o',str(exe)],check=True);trace=out/'trace.bin';subprocess.run([str(exe),str(trace)],check=True)
manifest.append(dict(cases=512,trace_bytes=trace.stat().st_size,trace_sha256=hashlib.sha256(trace.read_bytes()).hexdigest(),scope='only source initial AB/AB/false paths, all128 actualIGI values incl unsigned wrap0/1 and4 full register patterns'))
(out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');print(json.dumps(manifest[-1]))

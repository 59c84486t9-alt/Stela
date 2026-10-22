#!/usr/bin/env python3
"""Unchanged pinned RTL8822C direct/mixed RF register primitive oracle.
Usage: script reference-dir output-dir; no PHY, calibration or Linux ABI.
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



chip=(reference/'rtw88/rtw8822c.c').read_text()
arrays=[]
for field in ['rf_base_addr','rf_sipi_addr']:
    line=re.search(r'\.'+field+r'\s*=\s*\{[^}]+}',chip).group()
    values=re.findall(r'0x[0-9a-fA-F]+',line)
    assert len(values)==2
    arrays.append('.'+field+'={'+','.join(values)+'}')
    manifest.append(dict(path='rtw88/rtw8822c.c',symbol=field,sha256=hashlib.sha256(line.encode()).hexdigest()))
macros='\n'.join(re.search(r'^#define\s+'+name+r'\s+[^\n]+',(reference/'rtw88/main.h').read_text(),re.M).group() for name in ['RFREG_MASK','INV_RF_DATA'])
declaration=extract('main.h','rtw_rf_path','enum')
helpers='\n'.join(extract('hci.h',name) for name in ['rtw_read32_mask','rtw_write32_mask'])
functions='\n'.join(extract('phy.c',name) for name in ['rtw_phy_read_rf','rtw_phy_write_rf_reg_sipi','rtw_phy_write_rf_reg','rtw_phy_write_rf_reg_mix'])
preamble=r'''#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint8_t u8;typedef uint32_t u32;
#define __ffs(x) __builtin_ctz(x)
#define WARN(x,...) do{if(x)abort();}while(0)
#define rtw_err(...) ((void)0)
struct rtw_dev;
struct rtw_chip_ops {u32(*read_rf)(struct rtw_dev*,enum rtw_rf_path,u32,u32);};
struct rtw_chip_info {const struct rtw_chip_ops*ops;u32 rf_base_addr[2],rf_sipi_addr[2];};
struct rtw_hal {u8 rf_phy_num;};
struct rtw_dev {const struct rtw_chip_info*chip;struct rtw_hal hal;};
static u8 bytes[0x5000];static FILE*trace;
static void event(u32 k,u32 r,u32 width,u32 v){u32 words[4]={k,r,width,v};if(fwrite(words,16,1,trace)!=1)abort();}
static u32 rtw_read32(struct rtw_dev*d,u32 r){(void)d;u32 v;memcpy(&v,bytes+r,4);event(0,r,4,v);return v;}
static void rtw_write32(struct rtw_dev*d,u32 r,u32 v){event(1,r,4,v);memcpy(bytes+r,&v,4);for(u32 p=0;p<2;p++)if(r==d->chip->rf_sipi_addr[p]){u32 a=d->chip->rf_base_addr[p]+(((v>>20)&255)*4),old;memcpy(&old,bytes+a,4);old=(old&~0xfffffU)|(v&0xfffff);memcpy(bytes+a,&old,4);}}
static void udelay(u32 us){event(2,0,0,us);}
'''
main=r'''int main(int argc,char**argv){if(argc!=2)return 2;trace=fopen(argv[1],"wb");if(!trace)abort();
const u32 masks[32]={1,2,4,8,16,32,64,128,256,512,1024,2048,4096,8192,16384,32768,65536,131072,262144,524288,0xfffff,0xff,0xff00,0xf0000,0x55555,0xaaaaa,0x12345,0x80001,0x7ffff,0x3f0,0x78000,0xf0f0f};
struct rtw_chip_ops ops={.read_rf=rtw_phy_read_rf};struct rtw_chip_info chip={.ops=&ops,CHIP_ARRAYS};struct rtw_dev d={.chip=&chip,.hal={.rf_phy_num=2}};
for(u32 c=0;c<65536;c++){
u32 p=c&1,a=(c>>1)&255,m=masks[(c>>9)&31],old=(c*0x45d9f3bU+0x5317ac09U)&0x7fffffff,full=(c*0x13579U+0xa321eU)&0xfffff,data=(c*0x179bbU+0x13U)&(m>>__builtin_ctz(m));u32 header[6]={p,a,m,old,full,data};if(fwrite(header,24,1,trace)!=1)abort();
memset(bytes,0,sizeof(bytes));u32 target=chip.rf_base_addr[p]+a*4;memcpy(bytes+target,&old,4);
u32 before=rtw_phy_read_rf(&d,p,a,m);if(!rtw_phy_write_rf_reg_mix(&d,p,a,0xfffff,full)||!rtw_phy_write_rf_reg_mix(&d,p,a,m,data))abort();u32 after=rtw_phy_read_rf(&d,p,a,0xfffff),final;memcpy(&final,bytes+target,4);u32 result[3]={before,after,final};if(fwrite(result,12,1,trace)!=1)abort();
}
if(fclose(trace))abort();return 0;}
'''
preamble=preamble.replace('struct rtw_dev;',declaration+'\nstruct rtw_dev;',1)
main=main.replace('CHIP_ARRAYS',','.join(arrays))
source=out/'oracle.c';source.write_text(preamble+macros+'\n'+helpers+'\n'+functions+'\n'+main)
exe=out/'oracle';subprocess.run(['clang','-std=gnu11','-O1','-g','-fsanitize=address,undefined',str(source),'-o',str(exe)],check=True)
trace=out/'trace.bin';subprocess.run([str(exe),str(trace)],check=True)
manifest.append(dict(cases=65536,trace_bytes=trace.stat().st_size,trace_sha256=hashlib.sha256(trace.read_bytes()).hexdigest()))
(out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');print(json.dumps(manifest[-1]))

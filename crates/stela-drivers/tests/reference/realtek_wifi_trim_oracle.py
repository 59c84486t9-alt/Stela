#!/usr/bin/env python3
"""Unchanged pinned RTL8822C factory RF X2/thermal/power/PA trim oracle.
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



chip=(reference/'rtw88/rtw8822c.c').read_text();arrays=[]
for field in ['rf_base_addr','rf_sipi_addr']:
 line=re.search(r'\.'+field+r'\s*=\s*\{[^}]+}',chip).group();values=re.findall(r'0x[0-9a-fA-F]+',line);assert len(values)==2;arrays.append('.'+field+'={'+','.join(values)+'}');manifest.append(dict(path='rtw88/rtw8822c.c',symbol=field,sha256=hashlib.sha256(line.encode()).hexdigest()))
def macro(file,name):
 line=re.search(r'^#define\s+'+name+r'\s+[^\n]+',(reference/'rtw88'/file).read_text(),re.M).group();manifest.append(dict(path='rtw88/'+file,symbol=name,sha256=hashlib.sha256(line.encode()).hexdigest()));return line
names=['PPG_THERMAL_A','PPG_THERMAL_B','RF_THEMAL_MASK','PPG_2GL_TXAB','PPG_2GM_TXAB','PPG_2GH_TXAB','PPG_2G_A_MASK','PPG_2G_B_MASK','PPG_5G_MASK','PPG_PABIAS_2GA','PPG_PABIAS_2GB','PPG_PABIAS_5GA','PPG_PABIAS_5GB','PPG_PABIAS_MASK','RF_PA','RF_PABIAS_2G_MASK','RF_PABIAS_5G_MASK']+['PPG_5G'+g+'_TX'+p for p in ['A','B'] for g in ['L1','L2','M1','M2','H1']]
macros='\n'.join(macro(f,n)for f,n in [('main.h','RFREG_MASK'),('main.h','INV_RF_DATA'),('efuse.h','EFUSE_READ_FAIL')]+[('rtw8822c.h',n)for n in names]+[('reg.h',n)for n in ['REG_DIS_DPD','DIS_DPD_MASK','DIS_DPD_RATEALL']])
declarations=extract('main.h','rtw_rf_path','enum')
helpers='\n'.join(extract('hci.h',n)for n in ['rtw_read32_mask','rtw_write32_mask'])
rf_functions='\n'.join(extract('phy.c',n)for n in ['rtw_phy_read_rf','rtw_phy_write_rf_reg_sipi','rtw_phy_write_rf_reg','rtw_phy_write_rf_reg_mix'])
functions='\n'.join(extract('rtw8822c.c',n)for n in ['rtw8822c_rf_x2_check','rtw8822c_set_power_trim','rtw8822c_power_trim','rtw8822c_thermal_trim','rtw8822c_pa_bias'])
# Full callsite is immutable context, not reexecuted DAC calibration.
extract('rtw8822c.c','rtw8822c_rf_init')
preamble=r'''#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint8_t u8;typedef int8_t s8;typedef uint16_t u16;typedef uint32_t u32;
#define BIT(n) (1U<<(n))
#define GENMASK(h,l) ((~0U << (l)) & (~0U >> (31-(h))))
#define FIELD_GET(m,v) (((v)&(m))>>__builtin_ctz(m))
#define FIELD_PREP(m,v) (((v)<<__builtin_ctz(m))&(m))
#define ARRAY_SIZE(x) (sizeof(x)/sizeof((x)[0]))
#define __ffs(x) __builtin_ctz(x)
#define WARN(x,...) do{if(x)abort();}while(0)
#define rtw_err(...) ((void)0)
/*DECLARATIONS*/
struct rtw_dev;
struct rtw_chip_ops {u32(*read_rf)(struct rtw_dev*,enum rtw_rf_path,u32,u32);};
struct rtw_chip_info {struct rtw_chip_ops*ops;u32 rf_base_addr[2],rf_sipi_addr[2];};
struct rtw_hal {u8 rf_phy_num,rf_path_num;};
struct rtw_dev {struct rtw_chip_info*chip;struct rtw_hal hal;};
static u8 bytes[0x5000],otp[512];static FILE*trace;static u32 events;
static void event(u32 k,u32 r,u32 w,u32 v){u32 words[4]={k,r,w,v};if(fwrite(words,16,1,trace)!=1)abort();events++;}
static u32 get(u32 r){u32 v;memcpy(&v,bytes+r,4);return v;}
static void put(u32 r,u32 v){memcpy(bytes+r,&v,4);}
static u32 rtw_read32(struct rtw_dev*d,u32 r){(void)d;u32 v=get(r);event(0,r,4,v);return v;}
static void rtw_write32(struct rtw_dev*d,u32 r,u32 v){event(1,r,4,v);put(r,v);for(u32 p=0;p<2;p++)if(r==d->chip->rf_sipi_addr[p]){u32 a=d->chip->rf_base_addr[p]+(((v>>20)&255)*4);put(a,(get(a)&~0xfffffU)|(v&0xfffff));}}
static void udelay(u32 us){event(2,0,0,us);}
static void mdelay(u32 ms){udelay(ms*1000);}
/* Source trim read boundary supplies genuine immutable physical OTP bytes;
   transport IO/readiness is separately source/native-qualified, never mocked
   into production success. No timeout is converted to a blank byte. */
static int rtw_read8_physical_efuse(struct rtw_dev*d,u16 a,u8*out){(void)d;if(a>=512)abort();*out=otp[a];return 0;}
'''
wrappers=r'''static u32 rtw_read_rf(struct rtw_dev*d,enum rtw_rf_path p,u32 r,u32 m){return rtw_phy_read_rf(d,p,r,m);}
static void rtw_write_rf(struct rtw_dev*d,enum rtw_rf_path p,u32 r,u32 m,u32 v){if(!rtw_phy_write_rf_reg_mix(d,p,r,m,v))abort();}
'''
main=r'''int main(int argc,char**argv){if(argc!=2)return 2;trace=fopen(argv[1],"wb+");if(!trace)abort();struct rtw_chip_ops ops={rtw_phy_read_rf};struct rtw_chip_info chip={.ops=&ops,CHIP_ARRAYS};struct rtw_dev d={&chip,{2,2}};
const u32 addresses[19]={0x1ef,0x1b0,0x1d4,0x1ee,0x1d2,0x1ec,0x1e8,0x1e4,0x1e0,0x1dc,0x1eb,0x1e7,0x1e3,0x1df,0x1db,0x1d6,0x1d8,0x1d5,0x1d7};
for(u32 c=0;c<512;c++){for(u32 i=0;i<sizeof(bytes);i++)bytes[i]=(i*13+c*7)&255;put(0xf0,(1U<<27)|(1<<12));put(0x80,0xc078);bytes[2]|=3;bytes[0x1f]|=7;put(0xec,get(0xec)|0x07000000);put(0x3ee0,(get(0x3ee0)&~(1U<<15))|((c&1)<<15));memset(otp,255,sizeof(otp));
for(u32 i=0;i<19;i++){u8 v=(c*37+i*29)&255;if(c==0||((c>>(i%9))&1)==0)v=255;otp[addresses[i]]=v;}
u32 header[3]={c,c&1,0};long start=ftell(trace);if(fwrite(header,12,1,trace)!=1||fwrite(otp,sizeof(otp),1,trace)!=1)abort();events=0;rtw8822c_rf_x2_check(&d);rtw8822c_thermal_trim(&d);rtw8822c_power_trim(&d);rtw8822c_pa_bias(&d);long end=ftell(trace);if(fseek(trace,start+8,SEEK_SET)||fwrite(&events,4,1,trace)!=1||fseek(trace,end,SEEK_SET))abort();if(fwrite(bytes,sizeof(bytes),1,trace)!=1)abort();}
if(fclose(trace))abort();return 0;}
'''
main=main.replace('CHIP_ARRAYS',','.join(arrays));source=out/'oracle.c';source.write_text(preamble.replace('/*DECLARATIONS*/',macros+'\n'+declarations)+'\n'+helpers+'\n'+rf_functions+'\n'+wrappers+'\n'+functions+'\n'+main);exe=out/'oracle';subprocess.run(['clang','-std=gnu11','-O1','-g','-fsanitize=address,undefined',str(source),'-o',str(exe)],check=True);trace=out/'trace.bin';subprocess.run([str(exe),str(trace)],check=True)
manifest.append(dict(cases=512,trace_bytes=trace.stat().st_size,trace_sha256=hashlib.sha256(trace.read_bytes()).hexdigest(),scope='actual post-DAC source X2/thermal/power/PA effects, including optional blank fields and exact zero/f-nibble defaults; immutable successful OTP byte boundary; no analog lock/regulatory/TX credit'))
(out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');print(json.dumps(manifest[-1]))

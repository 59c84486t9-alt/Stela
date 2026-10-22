#!/usr/bin/env python3
"""Unchanged pinned RTL8822C initial thermal-tracking/beamforming PHY tail oracle.
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



def macro(file,name):
 line=re.search(r'^#define\s+'+name+r'\s+[^\n]+',(reference/'rtw88'/file).read_text(),re.M).group();manifest.append(dict(path='rtw88/'+file,symbol=name,sha256=hashlib.sha256(line.encode()).hexdigest()));return line
bf_names=['REG_MU_TX_CTL','BIT_MU_P1_WAIT_STATE_EN','BIT_MASK_R_MU_RL','BIT_SHIFT_R_MU_RL','R_MU_RL','BIT_EN_MU_MIMO','BIT_MASK_R_MU_TABLE_VALID','BIT_SHIFT_WMAC_TXMU_ACKPOLICY','BIT_WMAC_TXMU_ACKPOLICY_EN','REG_WMAC_MU_BF_OPTION','REG_WMAC_MU_BF_CTL','REG_TXBF_CTRL','BIT_USE_NDPA_PARAMETER','REG_NDPA_OPT_CTRL','BIT_MASK_CSI_RATE','BIT_MASK_CSI_RATE_VAL','BIT_SHIFT_CSI_RATE']
macros='\n'.join(macro(f,n)for f,n in [('main.h','RTW_RF_PATH_MAX'),('reg.h','REG_BBPSF_CTRL')]+[('bf.h',n)for n in bf_names])
declarations='\n'.join(extract('main.h',n,'enum')for n in ['rtw_rf_path','rtw_trx_desc_rate'])
average=(reference/'include/linux/average.h').read_text();average=average[average.index('#define DECLARE_EWMA'):average.index('\n#endif')]
manifest.append(dict(path='include/linux/average.h',symbol='DECLARE_EWMA',sha256=hashlib.sha256(average.encode()).hexdigest(),license='GPL-2.0 research oracle only'))
invocation=re.search(r'^DECLARE_EWMA\(thermal, 10, 4\);',(reference/'rtw88/main.h').read_text(),re.M).group();manifest.append(dict(path='rtw88/main.h',symbol='thermal EWMA invocation',sha256=hashlib.sha256(invocation.encode()).hexdigest()))
helpers='\n'.join(extract('hci.h',n)for n in ['rtw_write32_set','rtw_write32_mask'])
functions=extract('rtw8822c.c','rtw8822c_pwrtrack_init')+'\n'+extract('bf.c','rtw_bf_phy_init')
preamble=r'''#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint8_t u8;typedef int8_t s8;typedef uint16_t u16;typedef uint32_t u32;
#define BIT(n) (1U<<(n))
#define __ffs(x) __builtin_ctz(x)
#define WARN(x,...) do{if(x)abort();}while(0)
#define BUILD_BUG_ON(x) _Static_assert(!(x),"source compile-time condition")
#define BUILD_BUG_ON_NOT_POWER_OF_2(x) BUILD_BUG_ON((x)==0||((x)&((x)-1)))
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x,v) ((x)=(v))
#define ilog2(x) (31-__builtin_clz(x))
/*DECLARATIONS*/
struct rtw_dm_info {s8 delta_power_index[4];struct ewma_thermal avg_thermal[4];u8 thermal_avg[4];bool pwr_trk_triggered;u8 thermal_meter_k,thermal_meter_lck;};
struct rtw_dev {struct rtw_dm_info dm_info;struct {u8 thermal_meter_k;} efuse;};
static u8 bytes[0x5000];static FILE*trace;static u32 events;
static void event(u32 k,u32 r,u32 w,u32 v){u32 words[4]={k,r,w,v};if(fwrite(words,16,1,trace)!=1)abort();events++;}
static u32 rtw_read32(struct rtw_dev*d,u32 r){(void)d;u32 v;memcpy(&v,bytes+r,4);event(0,r,4,v);return v;}
static void rtw_write32(struct rtw_dev*d,u32 r,u32 v){(void)d;event(1,r,4,v);memcpy(bytes+r,&v,4);}
static void rtw_write8(struct rtw_dev*d,u32 r,u8 v){(void)d;event(1,r,1,v);bytes[r]=v;}
static void rtw_write16(struct rtw_dev*d,u32 r,u16 v){(void)d;event(1,r,2,v);memcpy(bytes+r,&v,2);}
'''
main=r'''int main(int argc,char**argv){if(argc!=2)return 2;trace=fopen(argv[1],"wb+");if(!trace)abort();for(u32 c=0;c<1024;c++){struct rtw_dev d;memset(&d,0xa5,sizeof(d));u32 pattern=c>>8,a=c&255,b=a^pattern;d.efuse.thermal_meter_k=(a+b)>>1;
for(u32 i=0;i<sizeof(bytes);i++)bytes[i]=(i*13+pattern*7)&255;u32 v=(1U<<27)|(1<<12);memcpy(bytes+0xf0,&v,4);v=0xc078;memcpy(bytes+0x80,&v,4);bytes[2]|=3;bytes[0x1f]|=7;memcpy(&v,bytes+0xec,4);v|=0x07000000;memcpy(bytes+0xec,&v,4);
u32 header[5]={pattern,a,b,d.efuse.thermal_meter_k,0};long start=ftell(trace);if(fwrite(header,20,1,trace)!=1)abort();events=0;rtw8822c_pwrtrack_init(&d);rtw_bf_phy_init(&d);long end=ftell(trace);if(fseek(trace,start+16,SEEK_SET)||fwrite(&events,4,1,trace)!=1||fseek(trace,end,SEEK_SET))abort();u32 state[15],j=0;for(u32 i=0;i<4;i++)state[j++]=(u32)d.dm_info.delta_power_index[i];for(u32 i=0;i<4;i++)state[j++]=d.dm_info.avg_thermal[i].internal;for(u32 i=0;i<4;i++)state[j++]=d.dm_info.thermal_avg[i];state[j++]=d.dm_info.pwr_trk_triggered;state[j++]=d.dm_info.thermal_meter_k;state[j++]=d.dm_info.thermal_meter_lck;if(j!=15)abort();if(fwrite(state,sizeof(state),1,trace)!=1||fwrite(bytes,sizeof(bytes),1,trace)!=1)abort();}
if(fclose(trace))abort();return 0;}
'''
source=out/'oracle.c';source.write_text(preamble.replace('/*DECLARATIONS*/',macros+'\n'+declarations+'\n'+average+'\n'+invocation)+'\n'+helpers+'\n'+functions+'\n'+main);exe=out/'oracle';subprocess.run(['clang','-std=gnu11','-O1','-g','-fsanitize=address,undefined',str(source),'-o',str(exe)],check=True);trace=out/'trace.bin';subprocess.run([str(exe),str(trace)],check=True)
manifest.append(dict(cases=1024,trace_bytes=trace.stat().st_size,trace_sha256=hashlib.sha256(trace.read_bytes()).hexdigest(),scope='initial thermal tracking reset and source beamforming defaults only; MU TX disabled; no sounding or runtime EWMA worker/TX policy'))
(out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');print(json.dumps(manifest[-1]))

#!/usr/bin/env python3
"""Pinned unchanged RTL8822C capability mailbox/decoder; no Linux ABI or PHY.
Usage: script reference-dir output-dir.
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


chip = (reference/'rtw88/rtw8822c.c').read_text().split('const struct rtw_chip_info rtw8822c_hw_spec = {', 1)[1].split('\n};', 1)[0]
assert '.hw_feature_report = true,' in chip and '.fix_rf_phy_num' not in chip
manifest.append(dict(path='rtw88/rtw8822c.c', symbol='rtw8822c_hw_spec', sha256=hashlib.sha256(chip.encode()).hexdigest()))
efuse = (reference/'rtw88/efuse.h').read_text()
macros = efuse[efuse.index('#define EFUSE_HW_CAP_IGNORE'):efuse.index('int rtw_parse_efuse_map')]
manifest.append(dict(path='rtw88/efuse.h', symbol='hardware capability macros', sha256=hashlib.sha256(macros.encode()).hexdigest()))
declarations = '\n'.join(extract(file, name, 'enum') for file,name in [('main.h','rtw_bandwidth'),('main.h','rtw_rf_type'),('main.h','rtw_bb_path'),('fw.h','rtw_c2h_cmd_id')])
source_macros = []
for file,name in [('main.h','HW_FEATURE_LEN'),('reg.h','REG_C2HEVT')]:
    line = re.search(r'^#define\s+'+name+r'\s+[^\n]+', (reference/'rtw88'/file).read_text(), re.M).group()
    source_macros.append(line)
    manifest.append(dict(path='rtw88/'+file,symbol=name,sha256=hashlib.sha256(line.encode()).hexdigest()))
functions = '\n'.join(extract('main.c', name) for name in ['hw_bw_cap_to_bitamp', 'rtw_hw_config_rf_ant_num', 'rtw_dump_hw_feature'])
preamble = r'''#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint8_t u8;typedef uint16_t u16;typedef uint32_t u32;typedef uint32_t __le32;
#define BIT(n) (1U<<(n))
#define GENMASK(h,l) ((~0U>>(31-(h)))&(~0U<<(l)))
#define le32_get_bits(w,m) (((w)&(m))>>__builtin_ctz(m))
#define fallthrough __attribute__((fallthrough))
#define WARN(x,...) do {if(x)abort();}while(0)
#define rtw_err(...) ((void)0)
#define rtw_dbg(...) ((void)0)
#define EBUSY 16
struct rtw_chip_info {bool hw_feature_report;u8 fix_rf_phy_num;};
struct rtw_hal {u8 rf_type,rf_path_num,rf_phy_num,antenna_tx,antenna_rx;};
struct rtw_efuse {struct {u8 bw,hci,nss,ptcl,ant_num;} hw_cap;};
struct rtw_dev {const struct rtw_chip_info*chip;struct rtw_hal hal;struct rtw_efuse efuse;};
static u8 bytes[0x200];static FILE*trace;
static void event(u32 w,u32 r,u32 v){u32 words[4]={w,r,1,v};if(fwrite(words,16,1,trace)!=1)abort();}
static u8 rtw_read8(struct rtw_dev*d,u32 r){(void)d;event(0,r,bytes[r]);return bytes[r];}
static void rtw_write8(struct rtw_dev*d,u32 r,u8 v){(void)d;event(1,r,v);bytes[r]=v;}
'''
main = r'''int main(int argc,char**argv){if(argc!=2)return 2;trace=fopen(argv[1],"wb");if(!trace)abort();
for(u32 c=0;c<32768;c++){
u32 sys=(c&1)?1U<<27:0, hci=(c>>1)&15,bw=(c>>5)&7,nss=(c>>8)&3,ant=(c>>10)&7,ptcl=(c>>13)&3;
u8 raw[13];for(u32 i=0;i<13;i++)raw[i]=(c*37+i*51)^(c>>3);
u32 word;memcpy(&word,raw+4,4);word=(word&~0x0cff000fU)|hci|(bw<<16)|(nss<<19)|(ant<<21)|(ptcl<<26);memcpy(raw+4,&word,4);
if(fwrite(&sys,4,1,trace)!=1||fwrite(raw,13,1,trace)!=1)abort();
struct rtw_chip_info chip={.hw_feature_report=true,.fix_rf_phy_num=0};struct rtw_dev d={.chip=&chip};
d.hal.rf_path_num=sys?2:1;d.hal.rf_phy_num=d.hal.rf_path_num;d.hal.rf_type=sys?RF_2T2R:RF_1T1R;d.hal.antenna_tx=sys?3:1;d.hal.antenna_rx=d.hal.antenna_tx;
bytes[REG_C2HEVT]=C2H_HW_FEATURE_REPORT;memcpy(bytes+REG_C2HEVT+2,raw,13);
if(rtw_dump_hw_feature(&d))abort();
u8 result[10]={d.efuse.hw_cap.bw,d.efuse.hw_cap.hci,d.efuse.hw_cap.ptcl,GET_EFUSE_HW_CAP_NSS(raw),d.efuse.hw_cap.ant_num,d.hal.rf_path_num,d.hal.rf_phy_num,d.hal.antenna_tx,d.hal.antenna_rx,d.efuse.hw_cap.nss};if(fwrite(result,10,1,trace)!=1)abort();
}
if(fclose(trace))abort();return 0;}
'''
source = out/'oracle.c'
preamble = preamble.replace('struct rtw_chip_info', declarations+'\n'+'\n'.join(source_macros)+'\nstruct rtw_chip_info', 1)
source.write_text(preamble+macros+'\n'+functions+'\n'+main)
exe=out/'oracle'
subprocess.run(['clang','-std=gnu11','-O1','-g','-fsanitize=address,undefined',str(source),'-o',str(exe)],check=True)
trace=out/'trace.bin'
subprocess.run([str(exe),str(trace)],check=True)
manifest.append(dict(trace_bytes=trace.stat().st_size,trace_sha256=hashlib.sha256(trace.read_bytes()).hexdigest(),cases=32768))
(out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
print(json.dumps(manifest[-1]))

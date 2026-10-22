#!/usr/bin/env python3
"""Pinned unchanged RTL8822C physical/logical efuse and board-data oracle.
Usage: script reference-dir output-dir. No hardware/Linux ABI/PHY policy.
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

chip_source=(reference/'rtw88/rtw8822c.c').read_text()
geometry={field:int(re.search(r'\.'+field+r'\s*=\s*(\d+)',chip_source).group(1)) for field in ['phy_efuse_size','log_efuse_size','ptct_efuse_size']}
assert geometry==dict(phy_efuse_size=512,log_efuse_size=768,ptct_efuse_size=124)
rfe_source=re.search(r'static const struct rtw_rfe_def rtw8822c_rfe_defs\[\] = \{.*?\n\};',chip_source,re.S).group()
rfe_indexes=[int(v) for v in re.findall(r'\[(\d+)\]\s*=\s*RTW_DEF_RFE',rfe_source)]
assert rfe_indexes==list(range(7))
definitions='\n'.join(extract('main.h',n,'struct') for n in ['rtw_2g_1s_pwr_idx_diff','rtw_2g_ns_pwr_idx_diff','rtw_2g_txpwr_idx','rtw_5g_ht_1s_pwr_idx_diff','rtw_5g_ht_ns_pwr_idx_diff','rtw_5g_ofdm_ns_pwr_idx_diff','rtw_5g_vht_ns_pwr_idx_diff','rtw_5g_txpwr_idx','rtw_txpwr_idx'])
definitions+='\n'+'\n'.join(extract('rtw8822c.h',n,'struct') for n in ['rtw8822cu_efuse','rtw8822cs_efuse','rtw8822ce_efuse','rtw8822c_efuse'])
# Direct efuse map-header macros, including multiline continuations.
lines=(reference/'rtw88/efuse.c').read_text().splitlines();selected=[]
for i,line in enumerate(lines):
    if re.match(r'#define (RTW_EFUSE_BANK_WIFI|invalid_efuse_|get_efuse_|block_idx_)',line):
        block=[line]
        while block[-1].endswith('\\'):i+=1;block.append(lines[i])
        selected.append('\n'.join(block))
macros='\n'.join(selected)
for file,pattern in [('reg.h',r'#define (REG_EFUSE_CTRL|BIT_EF_FLAG|BIT_SHIFT_EF_ADDR|BIT_MASK_EF_ADDR|BIT_MASK_EF_DATA|BITS_EF_ADDR|REG_LDO_EFUSE_CTRL|BIT_MASK_EFUSE_BANK_SEL)'),('rtw8822c.h',r'#define (REG_ANAPARLDO_POW_MAC|BIT_LDOE25_PON|XCAP_MASK)')]:
    macros+='\n'+'\n'.join(line for line in (reference/'rtw88'/file).read_text().splitlines() if re.match(pattern,line))
preamble=r'''
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <errno.h>
#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error little endian source oracle required
#endif
typedef uint8_t u8;typedef uint16_t u16;typedef uint32_t u32;typedef int8_t s8;typedef uint16_t __le16;
#define __packed __attribute__((packed))
#define __LITTLE_ENDIAN 1
#define ETH_ALEN 6
#define BIT(n) (1U<<(n))
#define GENMASK(h,l) ((~0U>>(31-(h)))&(~0U<<(l)))
#define u8_get_bits(v,m) (((v)&(m))>>__builtin_ctz(m))
#define RF_PATH_A 0
#define RF_PATH_B 1
#define RTW_HCI_TYPE_PCIE 0
#define RTW_HCI_TYPE_USB 1
#define RTW_HCI_TYPE_SDIO 2
#define ENOTSUPP 524
#define ether_addr_copy(a,b) memcpy(a,b,6)
'''
models=r'''
struct rtw_efuse {u32 physical_size,protect_size,logical_size;bool usb_mode_switch;u8 rfe_option,rf_board_option,crystal_cap,channel_plan,country_code[2],bt_setting,regd,thermal_meter[4],thermal_meter_k,power_track_type,addr[6];struct rtw_txpwr_idx txpwr_idx_table[4];};
struct rtw_dev;
struct ops {void(*efuse_grant)(struct rtw_dev*,bool);void(*cfg_ldo25)(struct rtw_dev*,bool);};
struct rtw_chip_info {const struct ops*ops;};
struct rtw_dev {struct rtw_efuse efuse;const struct rtw_chip_info*chip;};
static int rtw_hci_type(struct rtw_dev*d){(void)d;return RTW_HCI_TYPE_PCIE;}
static u8 phy[512],ldo;static u32 control,bank,selected,polls,active_case;static bool pending;static bool recording=true;static u32 override_ready,delays;
static u32 events[8192][4],event_count;
static void event(u32 kind,u32 reg,u32 n,u32 v){if(!recording)return;if(event_count>=8192)abort();u32*e=events[event_count++];e[0]=kind;e[1]=reg;e[2]=n;e[3]=v;}
static u32 rtw_read32(struct rtw_dev*d,u32 r){(void)d;u32 v;if(r==0x34)v=bank;else if(r==0x30){if(pending&&++polls>=(override_ready?override_ready:1+(selected+active_case)%3)){control=(control&~255U)|phy[selected]|BIT(31);pending=false;}v=control;}else abort();event(0,r,4,v);return v;}
static u8 rtw_read8(struct rtw_dev*d,u32 r){(void)d;if(r!=0x29)abort();event(0,r,1,ldo);return ldo;}
static void rtw_write32(struct rtw_dev*d,u32 r,u32 v){(void)d;event(1,r,4,v);if(r==0x34)bank=v;else if(r==0x30){if(v&BIT(31))abort();control=v;selected=(v>>8)&1023;if(selected>=512)abort();polls=0;pending=true;}else abort();}
static void rtw_write8(struct rtw_dev*d,u32 r,u8 v){(void)d;if(r!=0x29)abort();event(1,r,1,v);ldo=v;}
static void rtw_write32_mask(struct rtw_dev*d,u32 r,u32 mask,u32 v){u32 old=rtw_read32(d,r);rtw_write32(d,r,(old&~mask)|((v<<__builtin_ctz(mask))&mask));}
static void udelay(u32 us){if(us!=1)abort();delays++;event(2,0,0,1);}
static u32 state=0x3617ad2c;
static u32 random_word(void){state^=state<<13;state^=state>>17;state^=state<<5;return state;}
static void emit(FILE*f,u32 v){if(fwrite(&v,4,1,f)!=1)abort();}
_Static_assert(sizeof(struct rtw_txpwr_idx)==42,"source txpower stride");
_Static_assert(offsetof(struct rtw8822c_efuse,channel_plan)==0xb8,"source channel offset");
_Static_assert(offsetof(struct rtw8822c_efuse,rfe_option)==0xca,"source RFE offset");
_Static_assert(offsetof(struct rtw8822c_efuse,e.mac_addr)==0x120,"source PCI MAC offset");
'''
functions='\n'.join(extract('main.h',n) for n in ['rtw_chip_efuse_grant_on','rtw_chip_efuse_grant_off'])
functions+='\n'+'\n'.join(extract('efuse.c',n) for n in ['switch_efuse_bank','rtw_dump_logical_efuse_map','rtw_dump_physical_efuse_map'])
functions+='\n'+'\n'.join(extract('rtw8822c.c',n) for n in ['rtw8822ce_efuse_parsing','rtw8822cu_efuse_parsing','rtw8822cs_efuse_parsing','rtw8822c_read_efuse','rtw8822c_cfg_ldo25'])
main=r'''
int main(int argc,char**argv){if(argc!=2)return 2;FILE*f=fopen(argv[1],"wb");if(!f)abort();
struct ops ops={.cfg_ldo25=rtw8822c_cfg_ldo25};struct rtw_chip_info chip={&ops};struct rtw_dev dev={.efuse={.physical_size=512,.protect_size=124,.logical_size=768},.chip=&chip};
for(u32 c=0;c<6400;c++){
for(u32 i=0;i<512;i++)phy[i]=c<2304?(i*17+c*23)&255:random_word();
if(c<256)phy[0]=c;else if(c<2304){u32 n=c-256;phy[0]=((n/256)<<5)|15;phy[1]=n%256;}
/* No fixture consumes a protected-tail byte: padding bounds every possible
 * final eight-byte word payload; independent Rust tests harden donor edge. */
memset(phy+380,255,8);u8 log[768];memset(log,255,768);int ret=rtw_dump_logical_efuse_map(&dev,phy,log);
if(fwrite(phy,512,1,f)!=1)abort();emit(f,(u32)ret);if(fwrite(log,768,1,f)!=1)abort();
u8 zeros[228]={0};if(ret){if(fwrite(zeros,228,1,f)!=1)abort();continue;}
if(rtw8822c_read_efuse(&dev,log))abort();struct rtw_efuse*e=&dev.efuse;
u32 facts[]={e->usb_mode_switch,e->rfe_option,e->rf_board_option,e->crystal_cap,e->channel_plan,e->country_code[0],e->country_code[1],e->bt_setting,e->regd,e->thermal_meter[0],e->thermal_meter[1],e->thermal_meter_k,e->power_track_type};
for(u32 i=0;i<13;i++)emit(f,facts[i]);if(fwrite(e->addr,6,1,f)!=1||fwrite(e->txpwr_idx_table,168,1,f)!=1||fwrite(log,2,1,f)!=1)abort();
}
for(u32 c=0;c<4;c++){
active_case=c;for(u32 i=0;i<512;i++)phy[i]=(i*17+c*23)&255;control=0x5af4abcdU^(c*0x10304);bank=~0U-c*0x10304;ldo=255-c;pending=false;event_count=0;u8 map[512];
if(rtw_dump_physical_efuse_map(&dev,map)||memcmp(map,phy,512))abort();if(fwrite(map,512,1,f)!=1)abort();emit(f,event_count*16);if(fwrite(events,16,event_count,f)!=event_count)abort();
}
for(u32 late=0;late<2;late++){
recording=false;active_case=0;for(u32 i=0;i<512;i++)phy[i]=(i*17)&255;control=0x5af4abcd;bank=~0U;ldo=255;pending=false;delays=0;override_ready=1000000+late;u8 map[512];
int ret=rtw_dump_physical_efuse_map(&dev,map);if(ret!=-EBUSY)abort();emit(f,(u32)ret);emit(f,polls);emit(f,delays);emit(f,selected);emit(f,control>>31);
}
if(fclose(f))abort();return 0;}
'''
source=out/'oracle.c';source.write_text(preamble+definitions+'\n'+macros+'\n'+models+functions+'\n'+main)
exe=out/'oracle';subprocess.run(['clang','-std=gnu11','-O1','-g','-fsanitize=address,undefined',str(source),'-o',str(exe)],check=True)
trace=out/'trace.bin';subprocess.run([str(exe),str(trace)],check=True)
receipt=dict(chip_geometry=geometry,rfe_indexes=rfe_indexes,rfe_declaration_sha256=hashlib.sha256(rfe_source.encode()).hexdigest(),linux_commit='a804c5742bff224d4cb4d25dd383554d598be32b',symbols=manifest,logical_board_cases=6400,physical_cases=4,late_completion_cases=2,trace_bytes=trace.stat().st_size,trace_sha256=hashlib.sha256(trace.read_bytes()).hexdigest(),generated_source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),oracle_limit=[
    'serialized bank/LDO/OTP/timer source register model; no actual hardware/firmware/PHY policy or Linux ABI',
    'source grant hook null per actual RTL8822C ops; USB/SDIO board branches compiled but PCIe selected',
    'logical fixtures cover every one/two-header field plus4096 seeded maps, padded to avoid donor permissive protected-tail edge',
    'native independently rejects protected-boundary crossing; donor accepts some final protected bytes, covered as explicit stronger Rust guards',
    'native MCU-ready and fresh per-byte SYS_CFG identity probes are independent guards omitted from original source trace',
    'no source hardware-feature report/PHY/default power/regulatory policy/random MAC fallback/calibration/radio admission claimed'])
(out/'manifest.json').write_text(json.dumps(receipt,indent=2)+'\n');print(json.dumps({k:receipt[k] for k in ['logical_board_cases','physical_cases','trace_bytes','trace_sha256']}))

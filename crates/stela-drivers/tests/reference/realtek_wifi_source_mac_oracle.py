#!/usr/bin/env python3
"""Unchanged RTL8822C protocol/driver-info/PCI interface source oracle.
Usage: script reference-dir output-dir. FIFO is a separate real native phase.
"""
import ast,hashlib,json,pathlib,re,subprocess,sys
reference,out=map(pathlib.Path,sys.argv[1:]);out.mkdir(parents=True,exist_ok=True);manifest=[]
for filename in ['realtek_wifi_board_power_oracle.py','realtek_wifi_channel_oracle.py']:
 helper=pathlib.Path(__file__).with_name(filename)
 for node in ast.parse(helper.read_text()).body:
  if isinstance(node,ast.FunctionDef):exec(compile(ast.Module(body=[node],type_ignores=[]),str(helper),'exec'))
macrotext='\n'.join(macros(f)for f in ['phy.h','reg.h','rtw8822c.h','mac.h','main.h','bf.h'])
chiptext=(reference/'rtw88/rtw8822c.c').read_text();region=chiptext[chiptext.index('#define WLAN_TXQ_RPT_EN'):chiptext.index('static int rtw8822c_mac_init')];macrotext+='\n'+region
manifest.append(dict(path='rtw88/rtw8822c.c',symbol='protocol WLAN/clock constants',sha256=hashlib.sha256(region.encode()).hexdigest()))
protocol=extract('rtw8822c.c','rtw8822c_mac_init');driver=extract('mac.c','rtw_drv_info_cfg');interface=extract('pci.c','rtw_pci_interface_cfg')
for f,n in [('main.c','rtw_power_on'),('mac.c','rtw_mac_init')]:extract(f,n)
for key,value in [('wlan_cpu','RTW_WCPU_3081'),('id','RTW_CHIP_TYPE_8822C'),('mac_init','rtw8822c_mac_init'),('mac_postinit','NULL')]:
 line=re.search(r'^\s*\.'+key+r'\s*=\s*'+value+r',',chiptext,re.M).group()
 manifest.append(dict(path='rtw88/rtw8822c.c',symbol=key,sha256=hashlib.sha256(line.encode()).hexdigest()))
helpers='\n'.join(extract('hci.h',n)for n in ['rtw_write32_mask','rtw_write32_set','rtw_write32_clr','rtw_write8_set','rtw_write8_clr'])
constants=sorted(set(re.findall(r'\b(?:WLAN_|REG_|BIT_|BITS_|MAC_|FAST_)[A-Z0-9_]+\b',protocol+driver+interface)))
functions=set(re.findall(r'\b([A-Z][A-Z0-9_]+)\s*\(',protocol+driver+interface));constants=[n for n in constants if n not in functions]
# The source function-valued bit macros have only these constant invocations.
special={'RX_FIFO_THRESHOLDS':'(BIT_RXGCK_VHT_FIFOTHR(1)|BIT_RXGCK_HT_FIFOTHR(1)|BIT_RXGCK_OFDM_FIFOTHR(1)|BIT_RXGCK_CCK_FIFOTHR(1))>>16','RX_PACKET_LENGTH_ONE':'BIT_SET_RXPSF_PKTLENTHR(0,1)','RX_ERROR_THRESHOLD_MASK':'BITS_RXPSF_ERRTHR'}
expressions={n:n for n in constants};expressions.update(special)
preamble=r'''#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint8_t u8;typedef uint16_t u16;typedef uint32_t u32;
#define BIT(n) (1U<<(n))
#define GENMASK(h,l) ((0xffffffffU<<(l))&(0xffffffffU>>(31-(h))))
#define __ffs(x) __builtin_ctz(x)
#define WARN(x,...) do{if(x)abort();}while(0)
#define rtw_err(...) ((void)0)
#define EXPORT_SYMBOL(x)
/*DECLARATIONS*/
struct rtw_chip_info {u8 id;};struct rtw_hal {u8 cut_version;u16 rxfltmap1;};struct rtw_dev {const struct rtw_chip_info*chip;struct rtw_hal hal;};
static u8 bytes[0x5000];static FILE*trace;static u32 events;
static void event(u32 k,u32 r,u32 w,u32 v){u32 words[4]={k,r,w,v};if(fwrite(words,16,1,trace)!=1)abort();events++;}
static u8 rtw_read8(struct rtw_dev*d,u32 r){(void)d;u8 v=bytes[r];event(0,r,1,v);return v;}
static u16 rtw_read16(struct rtw_dev*d,u32 r){(void)d;u16 v;memcpy(&v,bytes+r,2);event(0,r,2,v);return v;}
static u32 rtw_read32(struct rtw_dev*d,u32 r){(void)d;u32 v;memcpy(&v,bytes+r,4);event(0,r,4,v);return v;}
static void rtw_write8(struct rtw_dev*d,u32 r,u8 v){(void)d;event(1,r,1,v);bytes[r]=v;}
static void rtw_write16(struct rtw_dev*d,u32 r,u16 v){(void)d;event(1,r,2,v);memcpy(bytes+r,&v,2);}
static void rtw_write32(struct rtw_dev*d,u32 r,u32 v){(void)d;event(1,r,4,v);memcpy(bytes+r,&v,4);}
static bool rtw_chip_wcpu_3081(struct rtw_dev*d){(void)d;return true;}
'''.replace('/*DECLARATIONS*/',extract('main.h','rtw_chip_ver','enum')+'\n'+extract('main.h','rtw_chip_type','enum'))
exports='static void export(FILE*f){\n'+''.join('fprintf(f,"pub(super) const '+name+': u32 = 0x%x;\\n",(u32)('+expr+'));\n' for name,expr in expressions.items())+'}\n'
main=r'''int main(int argc,char**argv){if(argc!=3)return 2;FILE*f=fopen(argv[2],"w");if(!f)abort();export(f);if(fclose(f))abort();trace=fopen(argv[1],"wb+");if(!trace)abort();struct rtw_chip_info chip={RTW_CHIP_TYPE_8822C};struct rtw_dev d={.chip=&chip};
for(u32 cut=0;cut<7;cut++)for(u32 pattern=0;pattern<128;pattern++){
for(u32 i=0;i<sizeof(bytes);i++)bytes[i]=(u8)(i*13+pattern*7);u32 sys=(1U<<27)|(cut<<12),ready=0xc078;memcpy(bytes+0xf0,&sys,4);memcpy(bytes+0x80,&ready,4);d.hal.cut_version=cut;d.hal.rxfltmap1=0;
u32 h[4]={cut,pattern,0,0};long start=ftell(trace);if(fwrite(h,sizeof(h),1,trace)!=1)abort();events=0;if(rtw8822c_mac_init(&d)||rtw_drv_info_cfg(&d))abort();rtw_pci_interface_cfg(&d);long end=ftell(trace);h[2]=events;h[3]=d.hal.rxfltmap1;if(fseek(trace,start,SEEK_SET)||fwrite(h,sizeof(h),1,trace)!=1||fseek(trace,end,SEEK_SET))abort();if(fwrite(bytes,sizeof(bytes),1,trace)!=1)abort();}
if(fclose(trace))abort();return 0;}
'''
source=out/'oracle.c';source.write_text(preamble+macrotext+'\n'+helpers+'\n'+protocol+'\n'+driver+'\n'+interface+'\n'+exports+main);exe=out/'oracle';subprocess.run(['clang','-std=gnu11','-fwrapv','-O1','-g','-Wno-macro-redefined','-fsanitize=address,undefined',str(source),'-o',str(exe)],check=True)
data=out/'data.rs';trace=out/'trace.bin';subprocess.run([str(exe),str(trace),str(data)],check=True)
license='// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause\n// Copyright(c) 2018-2019 Realtek Corporation\n// Source RTL8822C MAC register/bit/value constants, not a policy default.\n//! RTL8822C MAC register, bit and value constants.\n';data.write_text(license+data.read_text());subprocess.run(['rustfmt','--edition','2024',str(data)],check=True)
b=trace.read_bytes();manifest.append(dict(cases=896,constants=len(expressions),trace_bytes=len(b),trace_sha256=hashlib.sha256(b).hexdigest(),data_bytes=data.stat().st_size,data_sha256=hashlib.sha256(data.read_bytes()).hexdigest(),scope='source chip MAC protocol + driver info + PCI cut-dependent interface stores only; earlier real FIFO/HCI and later PHY/tuning/RFK/policy remain required'))
(out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');print(json.dumps(manifest[-1]))

#!/usr/bin/env python3
"""Unchanged RTL8822C BB/MAC/RF channel source oracle, no Linux services.
Usage: script reference-dir output-dir.
"""
import ast,hashlib,json,pathlib,re,subprocess,sys
reference,out=map(pathlib.Path,sys.argv[1:]);out.mkdir(parents=True,exist_ok=True);manifest=[]
helper=pathlib.Path(__file__).with_name('realtek_wifi_board_power_oracle.py')
for node in ast.parse(helper.read_text()).body:
 if isinstance(node,ast.FunctionDef):exec(compile(ast.Module(body=[node],type_ignores=[]),str(helper),'exec'))
def macros(file):
 lines=(reference/'rtw88'/file).read_text().splitlines();values=[];i=0
 while i<len(lines):
  if lines[i].startswith('#define'):
   body=lines[i]
   while body.endswith('\\'):i+=1;body+='\n'+lines[i]
   values.append(body)
  i+=1
 body='\n'.join(values);manifest.append(dict(path='rtw88/'+file,symbol='all source macro definitions',sha256=hashlib.sha256(body.encode()).hexdigest()));return body
macros_text='\n'.join(macros(f)for f in ['phy.h','reg.h','rtw8822c.h','mac.h','main.h'])
declarations='\n'.join(extract('main.h',n,'enum')for n in ['rtw_rf_path','rtw_bandwidth','rtw_sc_offset','rtw_supported_band','rtw_sar_bands'])
helpers='\n'.join(extract('hci.h',n)for n in ['rtw_read32_mask','rtw_write32_mask','rtw_write32_set','rtw_write32_clr','rtw_write8_set','rtw_write8_clr'])
rf='\n'.join(extract('phy.c',n)for n in ['rtw_phy_read_rf','rtw_phy_write_rf_reg_sipi','rtw_phy_write_rf_reg','rtw_phy_write_rf_reg_mix'])
functions=extract('main.h','rtw_hw_to_nl80211_band')+'\n'+extract('main.c','rtw_update_channel')+'\n'+'\n'.join(extract('rtw8822c.c',n)for n in ['rtw8822c_rstb_3wire','rtw8822c_set_channel_rf','rtw8822c_toggle_igi','rtw8822c_set_channel_bb'])+'\n'+extract('mac.c','rtw_set_channel_mac')+'\n'+extract('rtw8822c.c','rtw8822c_set_channel')
for f,n in [('main.c','rtw_set_channel'),('main.c','rtw_power_on'),('mac.c','rtw_mac_init')]:extract(f,n)
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
enum nl80211_band {NL80211_BAND_2GHZ,NL80211_BAND_5GHZ,NL80211_BAND_60GHZ};
/*DECLARATIONS*/
struct rtw_dev;
struct rtw_chip_ops {u32(*read_rf)(struct rtw_dev*,enum rtw_rf_path,u32,u32);bool(*write_rf)(struct rtw_dev*,enum rtw_rf_path,u32,u32,u32);};
struct rtw_chip_info {const struct rtw_chip_ops*ops;u32 rf_base_addr[2],rf_sipi_addr[2];};
struct rtw_hal {u8 rf_phy_num,cch_by_bw[3],current_primary_channel_index,current_band_width,primary_channel,current_channel,current_band_type,sar_band;};struct rtw_dev {const struct rtw_chip_info*chip;struct rtw_hal hal;};
static u8 bytes[0x5000];static FILE*trace;static u32 events;
static void event(u32 k,u32 r,u32 w,u32 v){u32 words[4]={k,r,w,v};if(fwrite(words,16,1,trace)!=1)abort();events++;}
static u8 rtw_read8(struct rtw_dev*d,u32 r){(void)d;u8 v=bytes[r];event(0,r,1,v);return v;}
static u16 rtw_read16(struct rtw_dev*d,u32 r){(void)d;u16 v;memcpy(&v,bytes+r,2);event(0,r,2,v);return v;}
static u32 rtw_read32(struct rtw_dev*d,u32 r){(void)d;u32 v;memcpy(&v,bytes+r,4);event(0,r,4,v);return v;}
static void rtw_write8(struct rtw_dev*d,u32 r,u8 v){(void)d;event(1,r,1,v);bytes[r]=v;}
static void rtw_write16(struct rtw_dev*d,u32 r,u16 v){(void)d;event(1,r,2,v);memcpy(bytes+r,&v,2);}
static void rtw_write32(struct rtw_dev*d,u32 r,u32 v){(void)d;event(1,r,4,v);memcpy(bytes+r,&v,4);}
static void udelay(u32 us){event(2,0,0,us);}
static u32 ieee80211_channel_to_frequency(u8 ch,enum nl80211_band band){return band==NL80211_BAND_2GHZ?(ch==14?2484:2407+5*ch):5000+5*ch;}
static bool rtw_chip_wcpu_8051(struct rtw_dev*d){(void)d;return false;}
static u32 rtw_read_rf(struct rtw_dev*d,enum rtw_rf_path p,u32 r,u32 m){return d->chip->ops->read_rf(d,p,r,m);}
static bool rtw_write_rf(struct rtw_dev*d,enum rtw_rf_path p,u32 r,u32 m,u32 v){return d->chip->ops->write_rf(d,p,r,m,v);}
'''.replace('/*DECLARATIONS*/',declarations)
main=r'''static void run(struct rtw_dev*d,u32 primary,u32 width,u32 c40,u32 c80,u32 pattern,u32 igi){
u32 ch=width==0?primary:width==1?c40:c80;memset(&d->hal,0,sizeof(d->hal));d->hal.rf_phy_num=2;rtw_update_channel(d,ch,primary,ch<=14?RTW_BAND_2G:RTW_BAND_5G,width);u32 idx=d->hal.current_primary_channel_index;if(d->hal.cch_by_bw[0]!=primary||(width>0&&d->hal.cch_by_bw[1]!=c40)||(width>1&&d->hal.cch_by_bw[2]!=c80))abort();
for(u32 i=0;i<sizeof(bytes);i++)bytes[i]=(u8)(i*13+pattern*7);u32 sys=(1U<<27)|(1<<12),ready=0xc078,wlrf;memcpy(bytes+0xf0,&sys,4);memcpy(bytes+0x80,&ready,4);bytes[2]|=3;bytes[0x1f]|=7;memcpy(&wlrf,bytes+0xec,4);wlrf|=0x07000000;memcpy(bytes+0xec,&wlrf,4);u32 raw;memcpy(&raw,bytes+REG_RXIGI,4);raw=(raw&~127U)|igi;memcpy(bytes+REG_RXIGI,&raw,4);
u32 h[8]={primary,width,c40,c80,pattern,igi,idx,0};long start=ftell(trace);if(fwrite(h,sizeof(h),1,trace)!=1)abort();events=0;rtw8822c_set_channel(d,ch,width,idx);long end=ftell(trace);if(fseek(trace,start+28,SEEK_SET)||fwrite(&events,4,1,trace)!=1||fseek(trace,end,SEEK_SET))abort();if(fwrite(bytes,sizeof(bytes),1,trace)!=1)abort();}
int main(int argc,char**argv){if(argc!=2)return 2;trace=fopen(argv[1],"wb+");if(!trace)abort();struct rtw_chip_ops ops={rtw_phy_read_rf,rtw_phy_write_rf_reg_mix};struct rtw_chip_info chip={&ops,{0x3c00,0x4c00},{0x1808,0x4108}};struct rtw_dev d={&chip,{2}};
const u32 channels[]={1,2,3,4,5,6,7,8,9,10,11,12,13,14,36,40,44,48,52,56,60,64,100,104,108,112,116,120,124,128,132,136,140,144,149,153,157,161,165,169,173,177},centers40[]={3,4,5,6,7,8,9,10,11,38,46,54,62,102,110,118,126,134,142,151,159,167,175},centers80[]={42,58,106,122,138,155,171};u32 c=0;
for(u32 p=0;p<sizeof(channels)/sizeof(*channels);p++)for(u32 w=0;w<3;w++)for(u32 j=0;j<(w?sizeof(centers40)/sizeof(*centers40):1);j++)for(u32 k=0;k<(w==2?sizeof(centers80)/sizeof(*centers80):1);k++){
u32 primary=channels[p],a=w?centers40[j]:0,b=w==2?centers80[k]:0;if(w&&((primary<15)!=(a<15)||primary==14||abs((int)primary-(int)a)!=2))continue;if(w==2&&(primary<15||abs((int)a-(int)b)!=4))continue;for(u32 pattern=0;pattern<2;pattern++)run(&d,primary,w,a,b,pattern,c++%128);}
for(u32 igi=0;igi<128;igi++)run(&d,36,2,38,42,3,igi);
if(fclose(trace))abort();return 0;}
'''
source=out/'oracle.c';source.write_text(preamble+macros_text+'\n'+helpers+'\n'+rf+'\n'+functions+'\n'+main);exe=out/'oracle';subprocess.run(['clang','-std=gnu11','-fwrapv','-O1','-g','-Wno-macro-redefined','-fsanitize=address,undefined',str(source),'-o',str(exe)],check=True)
trace=out/'trace.bin';subprocess.run([str(exe),str(trace)],check=True);b=trace.read_bytes();offset=cases=0
while offset<len(b):ec=int.from_bytes(b[offset+28:offset+32],'little');offset+=32+ec*16+0x5000;cases+=1
assert offset==len(b)
manifest.append(dict(cases=cases,trace_bytes=len(b),trace_sha256=hashlib.sha256(b).hexdigest(),scope='source BB/MAC/both RF channel writes and actual IGI latch only, no observed tuning, calibration, OS authority or TX admission'))
(out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');print(json.dumps(manifest[-1]))

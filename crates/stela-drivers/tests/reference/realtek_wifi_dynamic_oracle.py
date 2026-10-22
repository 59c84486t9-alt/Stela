#!/usr/bin/env python3
"""Pinned unchanged RTL8822C initial dynamic PHY hardware/tracking phase.
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
macros='\n'.join(macro(f,n)for f,n in [('phy.h','CCK_FA_AVG_RESET'),('main.h','RTW_RF_PATH_MAX'),('main.h','EDCCA_TH_L2H_IDX'),('main.h','EDCCA_TH_H2L_IDX'),('rtw8822c.h','RTW8822C_EDCCA_MAX'),('reg.h','REG_TX_PTCL_CTRL'),('reg.h','BIT_DIS_EDCCA'),('reg.h','REG_RD_CTRL'),('reg.h','BIT_EDCCA_MSK_CNTDOWN_EN'),('rtw8822c.h','REG_EDCCA_DECISION'),('rtw8822c.h','BIT_EDCCA_OPTION')])
declarations='\n'.join(extract(f,n,'enum')for f,n in [('phy.h','rtw_phy_cck_pd_lv'),('main.h','rtw_rf_path'),('main.h','rtw_bb_path'),('main.h','rtw_bandwidth')])
types='\n'.join(extract('main.h',n,'struct')for n in ['rtw_cfo_track','rtw_path_div'])
# Actual chip table bodies, exact source spans with separate immutable hashes.
text=(reference/'rtw88/rtw8822c.c').read_text()
def span(start,end,symbol):
    body=text[text.index(start):text.index(end,text.index(start))]
    manifest.append(dict(path='rtw88/rtw8822c.c',symbol=symbol,sha256=hashlib.sha256(body.encode()).hexdigest()))
    return body
dig=span('static const struct rtw_hw_reg rtw8822c_dig[] = {','\nstatic const struct rtw_ltecoex_addr','rtw8822c_dig')
default_path=re.search(r'^\s*\.default_1ss_tx_path\s*=\s*BB_PATH_A,',text,re.M).group()
manifest.append(dict(path='rtw88/rtw8822c.c',symbol='default_1ss_tx_path',sha256=hashlib.sha256(default_path.encode()).hexdigest()))
arrays=span('static const struct rtw_hw_reg_offset rtw8822c_edcca_th[] = {','\n#ifdef CONFIG_PM','rtw8822c_edcca_th')
cck=span('\tcck_gi_u_bnd_msb = (u8)rtw_read32_mask','\n\trtw8822c_rf_init','CCK GI observations within rtw8822c_phy_set_param')
helpers='\n'.join(extract('hci.h',n)for n in ['rtw_read32_mask','rtw_write32_mask','rtw_write32_clr','rtw_write32_set'])
functions='\n'.join(extract(f,n)for f,n in [('phy.c','rtw_phy_cck_pd_init'),('phy.c','rtw_phy_set_edcca_th'),('rtw8822c.c','rtw8822c_adaptivity_init'),('phy.c','rtw_phy_adaptivity_init'),('rtw8822c.c','rtw8822c_cfo_init'),('phy.c','rtw_phy_cfo_init'),('phy.c','rtw_phy_tx_path_div_init'),('phy.c','rtw_phy_init')])
preamble=r'''#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint8_t u8;typedef uint16_t u16;typedef uint32_t u32;typedef int32_t s32;
#define BIT(n) (1U<<(n))
#define GENMASK(h,l) ((~0U << (l)) & (~0U >> (31-(h))))
#define MASKBYTE2 0x00ff0000U
#define MASKBYTE3 0xff000000U
#define __ffs(x) __builtin_ctz(x)
#define WARN(x,...) do{if(x)abort();}while(0)
/*SOURCE_TYPES*/
struct rtw_dev;
struct rtw_hw_reg {u32 addr,mask;};struct rtw_hw_reg_offset {struct rtw_hw_reg hw_reg;u32 offset;};
struct rtw_dm_info {u16 fa_history[4];u8 igi_bitmap,igi_history[4],cck_pd_lv[2][4];u32 cck_fa_avg;struct {bool done;} iqk;struct rtw_cfo_track cfo_track;u8 cck_gi_u_bnd,cck_gi_l_bnd;};
struct rtw_chip_ops {void(*adaptivity_init)(struct rtw_dev*);void(*cfo_init)(struct rtw_dev*);};
struct rtw_chip_info {const struct rtw_hw_reg *dig;struct rtw_chip_ops *ops;const struct rtw_hw_reg_offset *edcca_th;u8 default_1ss_tx_path;};
struct rtw_dev {struct rtw_chip_info *chip;struct rtw_dm_info dm_info;struct rtw_path_div dm_path_div;struct {u8 crystal_cap;} efuse;};
static u8 bytes[0x5000];static FILE*trace;static u32 events,unqualified_mode_requests;
static void event(u32 k,u32 r,u32 w,u32 v){u32 words[4]={k,r,w,v};if(fwrite(words,16,1,trace)!=1)abort();events++;}
static u32 rtw_read32(struct rtw_dev*d,u32 r){(void)d;u32 v;memcpy(&v,bytes+r,4);event(0,r,4,v);return v;}
static void rtw_write32(struct rtw_dev*d,u32 r,u32 v){(void)d;event(1,r,4,v);memcpy(bytes+r,&v,4);}
/* OS jurisdiction is outside this bounded oracle. This stub deliberately
   selects no mode and performs no IO; source common hardware setup is exact. */
static void rtw_phy_adaptivity_set_mode(struct rtw_dev*d){(void)d;unqualified_mode_requests++;}
'''
wrapper='''static void cck_bounds(struct rtw_dev *rtwdev){struct rtw_dm_info *dm_info=&rtwdev->dm_info;u8 cck_gi_u_bnd_msb,cck_gi_u_bnd_lsb,cck_gi_l_bnd_msb,cck_gi_l_bnd_lsb;\n'''+cck+'\n}\n'
main=r'''int main(int argc,char**argv){if(argc!=2)return 2;trace=fopen(argv[1],"wb+");if(!trace)abort();struct rtw_chip_ops ops={rtw8822c_adaptivity_init,rtw8822c_cfo_init};struct rtw_chip_info chip={rtw8822c_dig,&ops,rtw8822c_edcca_th,BB_PATH_A};
for(u32 pattern=0;pattern<4;pattern++)for(u32 igi=0;igi<128;igi++){
struct rtw_dev d;memset(&d,0xa5,sizeof(d));d.chip=&chip;d.efuse.crystal_cap=(igi+pattern*23)%128;
for(u32 i=0;i<sizeof(bytes);i++)bytes[i]=(i*13+pattern*7)&255;u32 sys=(1U<<27)|(1<<12),ready=0xc078,wlrf;memcpy(bytes+0xf0,&sys,4);memcpy(bytes+0x80,&ready,4);bytes[2]|=3;bytes[0x1f]|=7;memcpy(&wlrf,bytes+0xec,4);wlrf|=0x07000000;memcpy(bytes+0xec,&wlrf,4);u32 raw;memcpy(&raw,bytes+0x1d70,4);raw=(raw&~127U)|igi;memcpy(bytes+0x1d70,&raw,4);
u32 upper=igi%64,lower=(igi/2+pattern*17)%64;memcpy(&raw,bytes+0x1a98,4);raw=(raw&~0xc0c0U)|((upper>>4)<<14)|((lower>>4)<<6);memcpy(bytes+0x1a98,&raw,4);memcpy(&raw,bytes+0x1aa8,4);raw=(raw&~0xf0000U)|((upper&15)<<16);memcpy(bytes+0x1aa8,&raw,4);memcpy(&raw,bytes+0x1a70,4);raw=(raw&~0xf000000U)|((lower&15)<<24);memcpy(bytes+0x1a70,&raw,4);
u32 header[6]={pattern,igi,d.efuse.crystal_cap,upper,lower,0};long start=ftell(trace);if(fwrite(header,24,1,trace)!=1)abort();events=0;unqualified_mode_requests=0;rtw_phy_init(&d);cck_bounds(&d);if(unqualified_mode_requests!=1)abort();long end=ftell(trace);if(fseek(trace,start+20,SEEK_SET)||fwrite(&events,4,1,trace)!=1||fseek(trace,end,SEEK_SET))abort();
u32 state[27];u32 j=0;for(u32 i=0;i<4;i++)state[j++]=d.dm_info.fa_history[i];state[j++]=d.dm_info.igi_bitmap;for(u32 i=0;i<4;i++)state[j++]=d.dm_info.igi_history[i];for(u32 i=0;i<2;i++)for(u32 k=0;k<4;k++)state[j++]=d.dm_info.cck_pd_lv[i][k];state[j++]=d.dm_info.cck_fa_avg;state[j++]=d.dm_info.iqk.done;state[j++]=d.dm_info.cfo_track.crystal_cap;state[j++]=d.dm_info.cfo_track.is_adjust;state[j++]=d.dm_path_div.current_tx_path;state[j++]=d.dm_path_div.path_a_cnt;state[j++]=d.dm_path_div.path_a_sum;state[j++]=d.dm_path_div.path_b_cnt;state[j++]=d.dm_path_div.path_b_sum;state[j++]=d.dm_info.cck_gi_u_bnd;/*lower is explicit next word*/if(j!=27)abort();if(fwrite(state,sizeof(state),1,trace)!=1)abort();u32 lo=d.dm_info.cck_gi_l_bnd;if(fwrite(&lo,4,1,trace)!=1)abort();if(fwrite(bytes,sizeof(bytes),1,trace)!=1)abort();
}if(fclose(trace))abort();return 0;}
'''
source=out/'oracle.c';source.write_text(preamble.replace('/*SOURCE_TYPES*/', macros+'\n'+declarations+'\n'+types)+'\n'+dig+'\n'+arrays+'\n'+helpers+'\n'+functions+'\n'+wrapper+'\n'+main);exe=out/'oracle';subprocess.run(['clang','-std=gnu11','-O1','-g','-fsanitize=address,undefined',str(source),'-o',str(exe)],check=True);trace=out/'trace.bin';subprocess.run([str(exe),str(trace)],check=True)
manifest.append(dict(cases=512,trace_bytes=trace.stat().st_size,trace_sha256=hashlib.sha256(trace.read_bytes()).hexdigest(),scope='initial common hardware/tracking only; OS mode deliberately unqualified; 128 IGI/crystal values, complete CCK bound ranges, 4 full BAR patterns'))
(out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');print(json.dumps(manifest[-1]))

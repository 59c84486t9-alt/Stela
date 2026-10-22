#!/usr/bin/env python3
"""Pinned unchanged RTL8822C initial ADCK/DACK phase.
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
chip=(reference/'rtw88/rtw8822c.c').read_text()
arrays=[]
for field in ['rf_base_addr','rf_sipi_addr']:
 line=re.search(r'\.'+field+r'\s*=\s*\{[^}]+}',chip).group();values=re.findall(r'0x[0-9a-fA-F]+',line);assert len(values)==2;arrays.append('.'+field+'={'+','.join(values)+'}');manifest.append(dict(path='rtw88/rtw8822c.c',symbol=field,sha256=hashlib.sha256(line.encode()).hexdigest()))
macros='\n'.join(macro(f,n)for f,n in [('main.h',n)for n in ['RFREG_MASK','INV_RF_DATA','RTW_RF_PATH_MAX','DACK_MSBK_BACKUP_NUM','DACK_DCK_BACKUP_NUM']]+[('rtw8822c.h',n)for n in ['DACK_PATH_8822C','DACK_REG_8822C','DACK_RF_8822C','DACK_SN_8822C','REG_DCKA_I_0','REG_DCKA_I_1','REG_DCKA_Q_0','REG_DCKA_Q_1','REG_DCKB_I_0','REG_DCKB_I_1','REG_DCKB_Q_0','REG_DCKB_Q_1']])
declarations=extract('main.h','rtw_rf_path','enum')+'\n'+extract('main.h','rtw_backup_info','struct')
helpers='\n'.join(extract('hci.h',n)for n in ['rtw_read32_mask','rtw_write32_mask','rtw_write32_clr','rtw_write32_set'])
rf_functions='\n'.join(extract('phy.c',n)for n in ['rtw_phy_read_rf','rtw_phy_write_rf_reg_sipi','rtw_phy_write_rf_reg','rtw_phy_write_rf_reg_mix'])
util='\n'.join(extract('util.c',n)for n in ['check_hw_ready','rtw_restore_reg'])
# Preserve all source bodies, including unused cache-restore dependencies.
names=['rtw8822c_dac_backup_reg','rtw8822c_dac_restore_reg','rtw8822c_rf_minmax_cmp','__rtw8822c_dac_iq_sort','rtw8822c_dac_iq_sort','rtw8822c_dac_iq_offset','rtw8822c_get_path_write_addr','rtw8822c_get_path_read_addr','rtw8822c_dac_iq_check','rtw8822c_dac_cal_iq_sample','rtw8822c_dac_cal_iq_search','rtw8822c_dac_cal_rf_mode','rtw8822c_dac_bb_setting','rtw8822c_dac_cal_adc','rtw8822c_dac_cal_step1','rtw8822c_dac_cal_step2','rtw8822c_dac_cal_step3','rtw8822c_dac_cal_step4','rtw8822c_dac_cal_backup_vec','rtw8822c_dac_cal_backup_path','rtw8822c_dac_cal_backup_dck','rtw8822c_dac_cal_backup','rtw8822c_dac_cal_restore_dck','rtw8822c_dac_cal_restore_prepare','rtw8822c_dac_cal_restore_wait','rtw8822c_dac_cal_restore_path','__rtw8822c_dac_cal_restore','rtw8822c_dac_cal_restore','rtw8822c_rf_dac_cal']
functions='\n'.join(extract('rtw8822c.c',n)for n in names)
preamble=r'''#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint8_t u8;typedef uint16_t u16;typedef uint32_t u32;
#define BIT(n) (1U<<(n))
#define __ffs(x) __builtin_ctz(x)
#define WARN(x,...) do{if(x)abort();}while(0)
#define WARN_ON(x) ((x)?(abort(),1):0)
#define swap(x,y) do{u32 t=(x);(x)=(y);(y)=t;}while(0)
#define rtw_err(...) ((void)0)
#define rtw_dbg(...) ((void)0)
/*DECLARATIONS*/
struct rtw_dev;
struct rtw_chip_ops {u32(*read_rf)(struct rtw_dev*,enum rtw_rf_path,u32,u32);};
struct rtw_chip_info {struct rtw_chip_ops*ops;u32 rf_base_addr[2],rf_sipi_addr[2];};
struct rtw_dm_info {u32 dack_adck[RTW_RF_PATH_MAX];u16 dack_msbk[RTW_RF_PATH_MAX][2][DACK_MSBK_BACKUP_NUM];u8 dack_dck[RTW_RF_PATH_MAX][2][DACK_DCK_BACKUP_NUM];};
struct rtw_hal {u8 rf_phy_num;};
struct rtw_dev {struct rtw_chip_info*chip;struct rtw_hal hal;struct rtw_dm_info dm_info;};
static u8 bytes[0x5000];static FILE*trace;static u32 events,phase,active,seed,ready_reads;static bool record=true;static int adc_input;static u32 forced_sample=0xffffffff;
static void event(u32 k,u32 r,u32 w,u32 v){if(!record)return;u32 words[4]={k,r,w,v};if(fwrite(words,16,1,trace)!=1)abort();events++;}
static u32 get(u32 r){u32 v;memcpy(&v,bytes+r,4);return v;}
static void put(u32 r,u32 v){memcpy(bytes+r,&v,4);}
static u32 rtw_read32(struct rtw_dev*d,u32 r){(void)d;u32 v=get(r);
if(r==0x2dbc){u32 sample=forced_sample!=0xffffffff?forced_sample:(phase==0?(adc_input&1023):(phase==1?0:(phase==2?53:16)));v=(sample<<12)|sample;}
for(u32 p=0;p<2;p++){u32 b=p?0x4100:0x1800,rd=p?0x4500:0x2800;
if(r==rd+8||r==rd+0x34)v=(v&~0x7fff80U)|(0xffffU<<7);
if(r==rd+0x24||r==rd+0x50){u32 off=r==rd+0x24?0xbc:0xd8,iq=(get(b+off)>>28)|((get(b+off+4)&15)<<4);v=(v&~0x07f80000U)|(iq<<19);}
if(r==rd+0x10||r==rd+0x3c){u32 vec=r==rd+0x10?0:1,index=get(b+0xb0+vec*0x1c)>>28,actual=(seed*17+p*71+vec*29+index*7)&511;v=(v&~0x7fc0000U)|(actual<<18);}}
if(r==0x2808&&ready_reads++<seed%4)v&=~0x7fff80U;
event(0,r,4,v);return v;}
static void rtw_write32(struct rtw_dev*d,u32 r,u32 v){event(1,r,4,v);put(r,v);if(r==0x1810)active=0;if(r==0x4110)active=1;
if(r==0x1c3c){if((v&0xffff)==0x8003)phase=0;else if((v&0xffff)==0x8103)phase=get((active?0x4100:0x1800)+0x10)==0x02dd08c4?1:2;}
if(r==(active?0x4100:0x1800)+0x68&&get((active?0x4100:0x1800)+0x10)==0x02d508c5)phase=3;
for(u32 p=0;p<2;p++)if(r==d->chip->rf_sipi_addr[p]){u32 a=d->chip->rf_base_addr[p]+(((v>>20)&255)*4);put(a,(get(a)&~0xfffffU)|(v&0xfffff));}}
static void rtw_write8(struct rtw_dev*d,u32 r,u8 v){(void)d;event(1,r,1,v);bytes[r]=v;}
static void rtw_write16(struct rtw_dev*d,u32 r,u16 v){(void)d;event(1,r,2,v);memcpy(bytes+r,&v,2);}
static void udelay(u32 us){event(2,0,0,us);}
static void mdelay(u32 ms){udelay(ms*1000);}
'''
wrappers=r'''static u32 rtw_read_rf(struct rtw_dev*d,enum rtw_rf_path p,u32 r,u32 m){return rtw_phy_read_rf(d,p,r,m);}
static void rtw_write_rf(struct rtw_dev*d,enum rtw_rf_path p,u32 r,u32 m,u32 v){if(!rtw_phy_write_rf_reg_mix(d,p,r,m,v))abort();}
'''
main=r'''int main(int argc,char**argv){if(argc!=2)return 2;trace=fopen(argv[1],"wb+");if(!trace)abort();struct rtw_chip_ops ops={rtw_phy_read_rf};struct rtw_chip_info chip={.ops=&ops,CHIP_ARRAYS};struct rtw_dev d;
for(u32 c=0;c<64;c++){seed=c;phase=0;active=0;ready_reads=0;adc_input=(int)c-32;memset(&d,0,sizeof(d));d.chip=&chip;d.hal.rf_phy_num=2;for(u32 i=0;i<sizeof(bytes);i++)bytes[i]=(i*13+c*7)&255;
put(0xf0,(1U<<27)|(1<<12));put(0x80,0xc078);bytes[2]|=3;bytes[0x1f]|=7;put(0xec,get(0xec)|0x07000000);put(0x3e3c,0x12345678);put(0x4e3c,0x12345678);
u32 header[3]={c,(u32)adc_input,0};long start=ftell(trace);if(fwrite(header,12,1,trace)!=1)abort();events=0;rtw8822c_rf_dac_cal(&d);long end=ftell(trace);if(fseek(trace,start+8,SEEK_SET)||fwrite(&events,4,1,trace)!=1||fseek(trace,end,SEEK_SET))abort();
u32 state[70];u32 j=0;for(u32 p=0;p<2;p++)state[j++]=d.dm_info.dack_adck[p];for(u32 p=0;p<2;p++)for(u32 v=0;v<2;v++)for(u32 i=0;i<15;i++)state[j++]=d.dm_info.dack_msbk[p][v][i];for(u32 p=0;p<2;p++)for(u32 v=0;v<2;v++)for(u32 i=0;i<2;i++)state[j++]=d.dm_info.dack_dck[p][v][i];if(j!=70)abort();if(fwrite(state,sizeof(state),1,trace)!=1||fwrite(bytes,sizeof(bytes),1,trace)!=1)abort();}
/* Actual step2 helpers cover all 201 accepted constant signed sample values,
   including source u32 compensation underflow; no readiness claim involved. */
record=false;for(int s=-100;s<=100;s++){forced_sample=s&1023;u32 i,q;rtw8822c_dac_cal_step2(&d,RF_PATH_A,&i,&q);u32 row[3]={(u32)s,i,q};if(fwrite(row,sizeof(row),1,trace)!=1)abort();}forced_sample=0xffffffff;
/* Unchanged donor negative: distinct RF 8f values alias, and distinct B
   DCK nibble fields transpose I-high and Q-low relative to restore. */
struct rtw_backup_info bb[16],rf[2];memset(rf,0,sizeof(rf));put(0x3e3c,0x12345);put(0x4e3c,0x6789a);rtw8822c_dac_backup_reg(&d,bb,rf);rtw8822c_dac_restore_reg(&d,bb,rf);put(0x41bc,0x10000000);put(0x41c0,2);put(0x41d8,0x30000000);put(0x41dc,4);memset(d.dm_info.dack_dck,0,sizeof(d.dm_info.dack_dck));rtw8822c_dac_cal_backup_dck(&d);u32 negative[6]={get(0x3e3c)&0xfffff,get(0x4e3c)&0xfffff,d.dm_info.dack_dck[1][0][0],d.dm_info.dack_dck[1][0][1],d.dm_info.dack_dck[1][1][0],d.dm_info.dack_dck[1][1][1]};if(fwrite(negative,sizeof(negative),1,trace)!=1)abort();
for(u32 c=0;c<2048;c++){u32 iv[100],qv[100];for(u32 i=0;i<100;i++){iv[i]=(c*73+i*29)&1023;qv[i]=(c*139+i*47)&1023;}u32 imin=iv[0],imax=iv[0],qmin=qv[0],qmax=qv[0];for(u32 i=0;i<100;i++){rtw8822c_rf_minmax_cmp(&d,iv[i],&imin,&imax);rtw8822c_rf_minmax_cmp(&d,qv[i],&qmin,&qmax);}rtw8822c_dac_iq_sort(&d,iv,qv);u32 io,qo;rtw8822c_dac_iq_offset(&d,iv,&io);rtw8822c_dac_iq_offset(&d,qv,&qo);u32 row[7]={c,imin,imax,qmin,qmax,io,qo};if(fwrite(row,sizeof(row),1,trace)!=1||fwrite(iv,sizeof(iv),1,trace)!=1||fwrite(qv,sizeof(qv),1,trace)!=1)abort();}
if(fclose(trace))abort();return 0;}
'''
main=main.replace('CHIP_ARRAYS',','.join(arrays));source=out/'oracle.c';source.write_text(preamble.replace('/*DECLARATIONS*/',macros+'\n'+declarations)+'\n'+helpers+'\n'+rf_functions+'\n'+wrappers+'\n'+util+'\n'+functions+'\n'+main)
exe=out/'oracle';subprocess.run(['clang','-std=gnu11','-O1','-g','-fsanitize=address,undefined',str(source),'-o',str(exe)],check=True);trace=out/'trace.bin';subprocess.run([str(exe),str(trace)],check=True)
manifest.append(dict(cases=64,compensation_cases=201,signed_vector_cases=2048,trace_bytes=trace.stat().st_size,trace_sha256=hashlib.sha256(trace.read_bytes()).hexdigest(),scope='initial empty-cache DAC only; source RF/DCK alias negative evidence; no cached restore qualification'))
(out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');print(json.dumps(manifest[-1]))

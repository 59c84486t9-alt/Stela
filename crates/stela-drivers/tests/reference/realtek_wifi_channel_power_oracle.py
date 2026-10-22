#!/usr/bin/env python3
"""Unchanged RTL8822C channel gain/SAR/TXAGC helper oracle; no Linux ABI.
Usage: script reference-dir output-dir. Reuses exact board oracle preparation.
"""
import ast
import hashlib
import json
import pathlib
import re
import subprocess
import sys
reference, out = map(pathlib.Path, sys.argv[1:])
out.mkdir(parents=True, exist_ok=True)
manifest = []
board_script = pathlib.Path(__file__).with_name('realtek_wifi_board_power_oracle.py')
# Reuse the existing source preparation fixture, not a native implementation.
subprocess.run([sys.executable, str(board_script), str(reference), str(out/'board')], check=True)
base = (out/'board/oracle.c').read_text().split('int main(int argc,char**argv)')[0]
# Load only its extraction functions, without rerunning its script body.
tree = ast.parse(board_script.read_text())
for node in tree.body:
    if isinstance(node, ast.FunctionDef):
        exec(compile(ast.Module(body=[node], type_ignores=[]), str(board_script), 'exec'))
structs = '\n'.join(extract(f,n,k) for f,n,k in [
 ('main.h','rtw_rf_path','enum'),('main.h','rtw_sar_sources','enum'),('main.h','rtw_sar_bands','enum'),
 ('main.h','rtw_sar_cfg','union'),('main.h','rtw_sar','struct'),
 ('sar.h','rtw_sar_arg','struct'),('phy.h','rtw_power_params','struct')]+[('main.h', n, 'struct') for n in [
 'rtw_2g_1s_pwr_idx_diff','rtw_2g_ns_pwr_idx_diff','rtw_2g_txpwr_idx','rtw_5g_ht_1s_pwr_idx_diff','rtw_5g_ht_ns_pwr_idx_diff','rtw_5g_ofdm_ns_pwr_idx_diff','rtw_5g_vht_ns_pwr_idx_diff','rtw_5g_txpwr_idx','rtw_txpwr_idx']])
base=base.replace('struct rtw_hal {',structs+'\nstruct rtw_dm_info {s8 txagc_remnant_cck,txagc_remnant_ofdm[4];};\nstruct rtw_hal {')
base=base.replace('u8 cch_by_bw[3];','u8 cch_by_bw[3];u8 current_band_width,current_band_type,rf_path_num,sar_band;u8 tx_pwr_tbl[4][DESC_RATE_MAX];struct rtw_sar sar;')
base=base.replace('bool is_pwr_by_rate_dec;','bool is_pwr_by_rate_dec;u8 txgi_factor;bool en_dis_dpd;u32 dpd_ratemask;')
base=base.replace('struct rtw_hal hal;};','struct rtw_hal hal;struct {struct rtw_txpwr_idx txpwr_idx_table[4];}efuse;struct rtw_dm_info dm_info;u8 regd;};')
base=base.replace('/*DECLARATIONS*/','')
base=base.replace('typedef uint8_t u8;', 'typedef int32_t s32;typedef uint16_t u16;typedef uint8_t u8;')
base='#define __LITTLE_ENDIAN 1\n#define __packed __attribute__((packed))\n'+base
macros='\n'.join(macro('reg.h',n)for n in ['DIS_DPD_RATE6M','DIS_DPD_RATE9M','DIS_DPD_RATEMCS0','DIS_DPD_RATEMCS1','DIS_DPD_RATEMCS8','DIS_DPD_RATEMCS9','DIS_DPD_RATEVHT1SS_MCS0','DIS_DPD_RATEVHT1SS_MCS1','DIS_DPD_RATEVHT2SS_MCS0','DIS_DPD_RATEVHT2SS_MCS1'])
helpers='\n'.join(extract('hci.h',n)for n in ['rtw_write32_set','rtw_write32_mask'])
functions=extract('sar.c','rtw_query_sar')+'\n'+extract('sar.c','rtw_sar_to_phy')+'\n'+'\n'.join(extract('phy.c',n)for n in ['rtw_get_channel_group','rtw_phy_get_dis_dpd_by_rate_diff','rtw_phy_get_2g_tx_power_index','rtw_phy_get_5g_tx_power_index','rtw_phy_rate_to_rate_section','rtw_phy_get_tx_power_limit','rtw_phy_get_tx_power_sar','rtw_get_tx_power_params','rtw_phy_get_tx_power_index','rtw_phy_set_tx_power_index_by_rs','rtw_phy_set_tx_power_level_by_path','rtw_phy_set_tx_power_level'])+'\n'+'\n'.join(extract('rtw8822c.c',n)for n in ['rtw8822c_set_write_tx_power_ref','rtw8822c_set_tx_power_diff','rtw8822c_set_tx_power_index'])
# Actual whole callsites and source chip constants retained in the ledger.
for f,n in [('rtw8822c.c','rtw8822c_read_efuse'),('main.c','rtw_set_channel'),('main.c','rtw_chip_prepare_tx')]: extract(f,n)
chip_context=(reference/'rtw88/rtw8822c.c').read_text()
for key,value in [('en_dis_dpd','true'),('dpd_ratemask','DIS_DPD_RATEALL')]:
    line=re.search(r'^\s*\.'+key+r'\s*=\s*'+value+r',',chip_context,re.M).group()
    manifest.append(dict(path='rtw88/rtw8822c.c',symbol=key,sha256=hashlib.sha256(line.encode()).hexdigest()))
manifest.append(dict(build_signed_arithmetic='-fwrapv selects explicit signed shift/wrap behavior for source C reference; sanitizer checks remain enabled',board_manifest_sha256=hashlib.sha256((out/'board/manifest.json').read_bytes()).hexdigest()))
# The real ops table is a harness dispatch to the unchanged chip helper.
base=base.replace('struct rtw_chip_info {','struct rtw_dev;struct ops {void (*set_tx_power_index)(struct rtw_dev*);};\nstruct rtw_chip_info {const struct ops *ops;')
shim=r'''
#define MASKDWORD 0xffffffffU
#define RTW_BAND_2G 0
#define IS_CH_2G_BAND(c) ((c)<=14)
#define min(a,b) ((a)<(b)?(a):(b))
#define min3(a,b,c) min(min(a,b),c)
#define fallthrough __attribute__((fallthrough))
#define mutex_lock(x) ((void)0)
#define mutex_unlock(x) ((void)0)
#define EXPORT_SYMBOL(x)
static u8 rtw_regd_get(struct rtw_dev*d){return d->regd;}
static u32 regs[0x5000/4], events[256][4], ec;
static void event(u32 k,u32 r,u32 v){if(ec>=256)abort();events[ec][0]=k;events[ec][1]=r;events[ec][2]=4;events[ec++][3]=v;}
static u32 rtw_read32(struct rtw_dev*d,u32 r){(void)d;u32 v=regs[r/4];event(0,r,v);return v;}
static void rtw_write32(struct rtw_dev*d,u32 r,u32 v){(void)d;event(1,r,v);regs[r/4]=v;}
static u32 __ffs(u32 x){if(!x)abort();return __builtin_ctz(x);}
static void rtw8822c_set_tx_power_index(struct rtw_dev*d);
'''
main=r'''
static void prep(struct rtw_dev*d,u32 c){
 memset(&d->hal,0,sizeof(d->hal));memset(&d->dm_info,0,sizeof(d->dm_info));struct rtw_table pg={rtw8822c_bb_pg_type0,ARRAY_SIZE(rtw8822c_bb_pg_type0)},lmt=c%7==5?(struct rtw_table){rtw8822c_txpwr_lmt_type5,ARRAY_SIZE(rtw8822c_txpwr_lmt_type5)}:(struct rtw_table){rtw8822c_txpwr_lmt_type0,ARRAY_SIZE(rtw8822c_txpwr_lmt_type0)};
 rtw_phy_init_tx_power(d);rtw_parse_tbl_bb_pg(d,&pg);rtw_parse_tbl_txpwr_lmt(d,&lmt);rtw_phy_tx_power_by_rate_config(&d->hal);rtw_phy_tx_power_limit_config(&d->hal);
 for(u32 p=0;p<4;p++){u8*n=(u8*)&d->efuse.txpwr_idx_table[p];for(u32 i=0;i<42;i++)n[i]=(u8)((c*7+p*3+i*5)%6+62);for(u32 i=11;i<18;i++)n[i]=0x11;for(u32 i=32;i<42;i++)n[i]=0x11;}
 d->hal.rf_path_num=2;d->regd=c%13;
}
static void put(FILE*f,const void*p,size_t n){if(fwrite(p,n,1,f)!=1)abort();}
int main(int argc,char**argv){if(argc!=2)return 2;FILE*f=fopen(argv[1],"wb");if(!f)abort();struct ops ops={rtw8822c_set_tx_power_index};struct rtw_chip_info chip={.ops=&ops,.max_power_index=127,.is_pwr_by_rate_dec=false,.txgi_factor=2,.en_dis_dpd=true,.dpd_ratemask=1023};struct rtw_dev d={.chip=&chip};
/* 512 whole prepared board/rate/SAR/IO/BAR cases, all three source widths. */
for(u32 c=0;c<512;c++){
 prep(&d,c);u8 bw=c%3,primary=bw==0?(c%2?1+(c%11):36):bw==1?(c%2?6:36):36;u8 centers[3]={primary,bw? (primary<=14?8:38):0,bw==2?42:0};d.hal.current_band_width=bw;d.hal.current_band_type=primary<=14?0:1;memcpy(d.hal.cch_by_bw,centers,3);d.hal.sar_band=primary<=14?0:1;
 s32 cap=80+c%25;d.hal.sar.src=RTW_SAR_SOURCE_COMMON;
 for(u8 p=0;p<4;p++)for(u8 rs=0;rs<RTW_RATE_SECTION_NUM;rs++){struct rtw_sar_arg a={.sar_band=d.hal.sar_band,.path=p,.rs=rs};d.hal.sar.cfg[p][rs].common[a.sar_band]=rtw_sar_to_phy(&d,2,cap-p,&a);}
 d.dm_info.txagc_remnant_cck=c%3;d.dm_info.txagc_remnant_ofdm[0]=c%3;d.dm_info.txagc_remnant_ofdm[1]=c%2;
 for(u32 i=0;i<sizeof(regs);i++)((u8*)regs)[i]=(u8)(i*13+c*7);regs[0x80/4]=0xc078;regs[0xf0/4]=0x08001000;ec=0;rtw_phy_set_tx_power_level(&d,centers[bw]);
 u32 h[9]={c,primary,bw,centers[1],centers[2],d.regd,(u32)cap,ec,sizeof(regs)};put(f,h,sizeof(h));put(f,&d.efuse.txpwr_idx_table,sizeof(d.efuse.txpwr_idx_table));put(f,d.hal.tx_pwr_tbl,sizeof(d.hal.tx_pwr_tbl));put(f,events,ec*sizeof(events[0]));put(f,regs,sizeof(regs));
}
/* Full signed packed-NVM boundary/seed samples across all source rate codes. */
for(u32 c=0;c<65536;c++){
 struct rtw_txpwr_idx n;u8*b=(u8*)&n;for(u32 i=0;i<42;i++)b[i]=(u8)(c*17+i*29+(c>>8));u8 rate=c%84;u8 bw=c%3;bool two=c&1;u8 ch=two?(bw?6:14):(bw==2?42:36);u8 g=rtw_get_channel_group(ch,rate);u8 val=two?rtw_phy_get_2g_tx_power_index(&d,&n.pwr_idx_2g,bw==2?0:bw,rate,g):rtw_phy_get_5g_tx_power_index(&d,&n.pwr_idx_5g,bw,rate,g);put(f,&val,1);
}
/* Adverse signed SAR and final gain wrap, preserved as real source outputs. */
prep(&d,0);d.hal.current_band_width=0;d.hal.cch_by_bw[0]=1;d.hal.sar_band=0;d.regd=0;
for(s32 cap=-256;cap<=127;cap++){struct rtw_sar_arg a={.sar_band=0,.path=0,.rs=0};s8 delta=rtw_sar_to_phy(&d,2,cap,&a);d.hal.sar.src=RTW_SAR_SOURCE_COMMON;d.hal.sar.cfg[0][0].common[0]=delta;u8 gain=rtw_phy_get_tx_power_index(&d,0,0,0,1,0);put(f,&delta,1);put(f,&gain,1);}
if(fclose(f))abort();return 0;}
'''
source=out/'oracle.c';source.write_text(base+'\n'+macros+'\n'+shim+'\n'+helpers+'\n'+functions+'\n'+main)
exe=out/'oracle';subprocess.run(['clang','-std=gnu11','-fwrapv','-O1','-g','-Wno-pointer-sign','-Wno-macro-redefined','-fsanitize=address,undefined',str(source),'-o',str(exe)],check=True)
trace=out/'trace.bin';subprocess.run([str(exe),str(trace)],check=True)
manifest.append(dict(whole_cases=512,packed_base_cases=65536,adverse_cases=384,trace_bytes=trace.stat().st_size,trace_sha256=hashlib.sha256(trace.read_bytes()).hexdigest(),scope='source board preparation plus channel gain/SAR/source TXAGC IO only; no OS authority, channel tune or TX admission'))
(out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');print(json.dumps(manifest[-1]))

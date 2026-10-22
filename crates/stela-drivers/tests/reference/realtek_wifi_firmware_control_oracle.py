#!/usr/bin/env python3
"""Unchanged RTL8822C native H2C mailbox/PHYDM/IQK/RFK source oracle.
Usage: script reference-dir output-dir. Kernel iopoll is research/oracle only.
"""
import ast,hashlib,json,pathlib,re,subprocess,sys
reference,out=map(pathlib.Path,sys.argv[1:]);out.mkdir(parents=True,exist_ok=True);manifest=[]
for filename in ['realtek_wifi_board_power_oracle.py','realtek_wifi_channel_oracle.py']:
 helper=pathlib.Path(__file__).with_name(filename)
 for node in ast.parse(helper.read_text()).body:
  if isinstance(node,ast.FunctionDef):exec(compile(ast.Module(body=[node],type_ignores=[]),str(helper),'exec'))
macros_text='\n'.join(macros(f)for f in ['phy.h','reg.h','rtw8822c.h','mac.h','main.h','fw.h'])
header=(reference/'include/linux/iopoll.h').read_text();poll=[];lines=header.splitlines();i=0
while i<len(lines):
 if lines[i].startswith('#define'):
  body=lines[i]
  while body.endswith('\\'):i+=1;body+='\n'+lines[i]
  poll.append(body)
 i+=1
poll='\n'.join(poll);manifest.append(dict(path='include/linux/iopoll.h',symbol='unchanged polling macros',sha256=hashlib.sha256(poll.encode()).hexdigest(),license='GPL-2.0-only research/oracle only'))
declarations='\n'.join(extract(f,n,k)for f,n,k in [('fw.h','rtw_h2c_cmd','struct'),('fw.h','rtw_iqk_para','struct'),('fw.h','rtw_fw_rf_type','enum'),('main.h','rtw_rf_type','enum')])
helpers='\n'.join(extract('hci.h',n)for n in ['rtw_read8_mask','rtw_read32_mask'])+'\n'+extract('fw.h','rtw_h2c_pkt_set_header')
functions='\n'.join(extract('fw.c',n)for n in ['rtw_fw_send_h2c_command','rtw_fw_send_h2c_packet','rtw_fw_send_phydm_info','rtw_fw_do_iqk','rtw_fw_inform_rfk_status'])+'\n'+'\n'.join(extract('rtw8822c.c',n)for n in ['rtw8822c_rfk_handshake','rtw8822c_do_iqk'])
line=re.search(r'^#define IQK_DONE_8822C[^\n]+',(reference/'rtw88/rtw8822c.c').read_text(),re.M).group();macros_text+='\n'+line;manifest.append(dict(path='rtw88/rtw8822c.c',symbol='IQK_DONE_8822C',sha256=hashlib.sha256(line.encode()).hexdigest()))
for f,n in [('main.c','rtw_power_on'),('rtw8822c.c','rtw8822c_do_gapk'),('rtw8822c.c','rtw8822c_phy_calibration')]:extract(f,n)
preamble=r'''#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
typedef uint8_t u8;typedef uint16_t u16;typedef uint32_t u32;typedef uint64_t u64;typedef int64_t s64;typedef int64_t ktime_t;typedef uint32_t __le32;
#define __packed __attribute__((packed))
#define BIT(n) (1U<<(n))
#define GENMASK(h,l) ((0xffffffffU<<(l))&(0xffffffffU>>(31-(h))))
#define __ffs(x) __builtin_ctz(x)
#define WARN(x,...) do{if(x)abort();}while(0)
#define rtw_err(...) ((void)0)
#define rtw_warn(...) ((void)0)
#define rtw_dbg(...) ((void)0)
#define EXPORT_SYMBOL(x)
#define lockdep_assert_held(x) ((void)0)
#define le32_to_cpu(x) (x)
#define NSEC_PER_USEC 1000
#define might_sleep_if(x) ((void)0)
#define barrier() __asm__ __volatile__("":::"memory")
#define cpu_relax() ((void)0)
static void le32p_replace_bits(__le32*p,u32 v,u32 m){*p=(*p&~m)|((v<<__builtin_ctz(m))&m);}
/*DECLARATIONS*/
struct rtw_dm_info {bool is_bt_iqk_timeout;};
struct rtw_hal {u8 rf_type,cut_version,antenna_tx,antenna_rx;};struct rtw_efuse {u8 rfe_option;};struct rtw_dev {struct{u8 last_box_num;u32 seq;}h2c;struct rtw_hal hal;struct rtw_efuse efuse;struct rtw_dm_info dm_info;};
static u8 bytes[0x5000],packet[32];static u32 events[70000][4],ec;
static u64 now_us;static u32 busy_reads,busy_seen,busy_target,busy_other,bt_idle_after,bt_reads,rfk_after,rfk_reads,iqk_after,iqk_reads;static bool rfk_pending,iqk_pending;
static void event(u32 k,u32 r,u32 w,u32 v){if(ec>=70000)abort();events[ec][0]=k;events[ec][1]=r;events[ec][2]=w;events[ec++][3]=v;}
static u8 rtw_read8(struct rtw_dev*d,u32 r){(void)d;u8 v=bytes[r];if(r==0x1cc)v=busy_other|(busy_seen++<busy_reads?(1<<busy_target):0);if(r==0x49c&&rfk_pending){if(rfk_reads++>=rfk_after)bytes[r]|=1;v=bytes[r];}if(r==0x2d9c&&iqk_pending){if(iqk_reads++>=iqk_after)bytes[r]=0xaa;v=bytes[r];}event(0,r,1,v);return v;}
static u32 rtw_read32(struct rtw_dev*d,u32 r){(void)d;u32 v;memcpy(&v,bytes+r,4);if(r==0xa8)v=bt_reads++<bt_idle_after?(1U<<21):0;event(0,r,4,v);return v;}
static void rtw_write8(struct rtw_dev*d,u32 r,u8 v){(void)d;bytes[r]=v;event(1,r,1,v);}
static void rtw_write32(struct rtw_dev*d,u32 r,u32 v){(void)d;memcpy(bytes+r,&v,4);event(1,r,4,v);if(r>=0x1d0&&r<0x1e0){rfk_pending=true;rfk_reads=0;}}
static void udelay(u64 us){now_us+=us;event(2,0,0,(u32)us);}
static void usleep_range(u64 min,u64 max){(void)min;udelay(max);}
static ktime_t ktime_get(void){return (ktime_t)(now_us*1000);}
static ktime_t ktime_add_us(ktime_t t,u64 us){return t+(ktime_t)(us*1000);}
static int ktime_compare(ktime_t a,ktime_t b){return (a>b)-(a<b);}
static bool rtw_chip_wcpu_8051(struct rtw_dev*d){(void)d;return false;}
static int rtw_hci_write_data_h2c(struct rtw_dev*d,u8*p,u32 len){(void)d;if(len!=32)abort();memcpy(packet,p,32);if((p[2]|(p[3]<<8))==0x0e)iqk_pending=true;return 0;}
static void put(FILE*f,const void*p,size_t n){if(fwrite(p,n,1,f)!=1)abort();}
static void reset(void){memset(bytes,0,sizeof(bytes));memset(packet,0,sizeof(packet));ec=0;now_us=0;busy_reads=busy_seen=busy_target=busy_other=bt_idle_after=bt_reads=rfk_after=rfk_reads=iqk_after=iqk_reads=0;rfk_pending=iqk_pending=false;}
'''.replace('/*DECLARATIONS*/',declarations)
main=r'''int main(int argc,char**argv){if(argc!=2)return 2;char path[4096];struct rtw_dev d={0};
snprintf(path,sizeof(path),"%s/packets.bin",argv[1]);FILE*f=fopen(path,"wb");if(!f)abort();
for(u32 c=0;c<65536;c++){reset();d.h2c.seq=c;d.hal.rf_type=RF_2T2R;d.hal.cut_version=(c/7)%7;d.hal.antenna_tx=d.hal.antenna_rx=3;d.efuse.rfe_option=c%7;rtw_fw_send_phydm_info(&d);put(f,packet,32);d.h2c.seq=c;struct rtw_iqk_para para={1,0};rtw_fw_do_iqk(&d,&para);put(f,packet,32);}
if(fclose(f))abort();snprintf(path,sizeof(path),"%s/mailbox.bin",argv[1]);f=fopen(path,"wb");if(!f)abort();
for(u32 box=0;box<4;box++)for(u32 start=0;start<2;start++)for(u32 wait=0;wait<33;wait++){reset();busy_target=box;busy_reads=wait;busy_other=(wait*17)&~(1U<<box)&255;d.h2c.last_box_num=box;rtw_fw_inform_rfk_status(&d,start);u32 h[7]={box,start,wait,busy_other,d.h2c.last_box_num,ec,wait<=30};put(f,h,sizeof(h));put(f,events,ec*sizeof(events[0]));}
if(fclose(f))abort();snprintf(path,sizeof(path),"%s/rfk.bin",argv[1]);f=fopen(path,"wb");if(!f)abort();
for(u32 bt=0;bt<4;bt++)for(u32 ready=0;ready<8;ready++){reset();d.h2c.last_box_num=0;d.dm_info.is_bt_iqk_timeout=false;bt_idle_after=bt;rfk_after=ready;rtw8822c_rfk_handshake(&d,true);u32 h[5]={bt,ready,ec,d.h2c.last_box_num,d.dm_info.is_bt_iqk_timeout};put(f,h,sizeof(h));put(f,events,ec*sizeof(events[0]));ec=0;rtw8822c_rfk_handshake(&d,false);u32 tail[2]={ec,d.h2c.last_box_num};put(f,tail,sizeof(tail));put(f,events,ec*sizeof(events[0]));}
if(fclose(f))abort();snprintf(path,sizeof(path),"%s/iqk.bin",argv[1]);f=fopen(path,"wb");if(!f)abort();
for(u32 ready=0;ready<19;ready++){reset();iqk_after=ready;d.h2c.seq=ready;rtw8822c_do_iqk(&d);u32 h[3]={ready,ec,d.h2c.seq};put(f,h,sizeof(h));put(f,packet,32);put(f,events,ec*sizeof(events[0]));}
if(fclose(f))abort();return 0;}
'''
source=out/'oracle.c';source.write_text(preamble+macros_text+'\n'+poll+'\n'+helpers+'\n'+functions+'\n'+main);exe=out/'oracle';subprocess.run(['clang','-std=gnu11','-fwrapv','-O1','-g','-Wno-macro-redefined','-fsanitize=address,undefined',str(source),'-o',str(exe)],check=True);subprocess.run([str(exe),str(out)],check=True)
for name in ['packets.bin','mailbox.bin','rfk.bin','iqk.bin']:
 b=(out/name).read_bytes();manifest.append(dict(artifact=name,bytes=len(b),sha256=hashlib.sha256(b).hexdigest()))
manifest.append(dict(packet_cases=65536,mailbox_cases=264,rfk_cases=32,iqk_cases=19,scope='native source firmware packet/rotating mailbox/source poll observations only; sticky RFK finish not fresh ACK or radio authority'))
(out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');print(json.dumps(manifest[-5:],indent=2))

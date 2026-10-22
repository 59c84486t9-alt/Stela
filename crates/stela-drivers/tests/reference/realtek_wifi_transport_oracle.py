#!/usr/bin/env python3
"""Extract unchanged pinned RTL8822C download functions and record HW-model I/O.

Usage: script reference-dir actual-8822c-image output-dir
MMIO, delay and lower beacon DMA submission are modeled, not hardware evidence.
The model records every read/write/delay and whole submitted payload. Linux HCI
setup is a no-op: Stela does not claim the unimplemented lower native TXBD ring
or actual OTP/calibration/radio initialization. No Linux runtime ABI is built.
"""
import hashlib
import json
import pathlib
import re
import subprocess
import sys

reference, image, out = map(pathlib.Path, sys.argv[1:])
out.mkdir(parents=True, exist_ok=True)
manifest = []


def extract(file, name, kind=None):
    text = (reference / 'rtw88' / file).read_text()
    if kind:
        match = re.search(r'\b' + kind + r' ' + name + r'\s*\{', text)
        start = match.start()
        brace = text.index('{', start)
    else:
        for match in re.finditer(r'\b' + name + r'\s*\(', text):
            end = text.index('(', match.start()) + 1
            depth = 1
            while depth:
                depth += (text[end] == '(') - (text[end] == ')')
                end += 1
            while text[end].isspace():
                end += 1
            if text[end] != '{':
                continue
            start = text.rfind('\n\n', 0, match.start()) + 2
            brace = end
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


preamble = r'''
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32;
typedef uint16_t __le16; typedef uint32_t __le32;
#define __packed __attribute__((packed))
#define BIT(n) (1U<<(n))
#define GENMASK(h,l) ((~0U>>(31-(h)))&(~0U<<(l)))
#define le16_to_cpu(x) (x)
#define le32_to_cpu(x) (x)
#define RTW_HCI_TYPE_PCIE 1
#define RTW_HCI_TYPE_USB 2
#define RTW_HCI_TYPE_SDIO 3
#define RTW_DMA_MAPPING_HIGH 3
#define REG_SDIO_FREE_TXPG 0xdead
#define RTW_FLAG_FW_RUNNING 0
#define FW_HDR_SIZE 64
#define FW_HDR_CHKSUM_SIZE 8
#define DLFW_RESTORE_REG_NUM 6
#define FW_KEY_MASK 0xffffff00
#define ILLEGAL_KEY_GROUP 0xFAAAAA00
#define OCPBASE_TXBUF_88XX 0x18780000
#define OCPBASE_DMEM_88XX 0x00200000
#define rtw_err(...) ((void)0)
#define WARN(...) ((void)0)
#define lockdep_assert_held(...) ((void)0)
#define EXPORT_SYMBOL(...)
struct rtw_ltecoex_addr {u32 ctrl,wdata,rdata;};
struct rtw_chip_info {u32 tx_pkt_desc_sz;const struct rtw_ltecoex_addr *ltecoex_addr;};
struct rtw_dev {const struct rtw_chip_info *chip;struct{u16 rsvd_boundary;}fifo;struct{u8 last_box_num,seq;}h2c;u32 flags[1];};
struct firmware {const u8 *data;u32 size;};
struct rtw_fw_state {const struct firmware *firmware;};
struct rtw_backup_info {u8 len;u32 reg,val;};
static FILE *output;
static u8 registers[0x170c];
static void word(u32 v){u8 b[]={v,v>>8,v>>16,v>>24};if(fwrite(b,1,4,output)!=4)abort();}
static void record(u32 tag,u32 r,u32 v){word(tag);word(r);word(v);}
static u32 get(u32 r,u32 n){if(r+n>sizeof(registers))abort();u32 v=0;for(u32 i=0;i<n;i++)v|=(u32)registers[r+i]<<(8*i);return v;}
static void set(u32 r,u32 n,u32 v){if(r+n>sizeof(registers))abort();for(u32 i=0;i<n;i++)registers[r+i]=v>>(8*i);}
static u32 read_reg(u32 r,u32 n){u32 v=get(r,n);record(n,r,v);return v;}
static void write_reg(u32 r,u32 n,u32 v){record(4+n,r,v);u32 stored=v;if(r==0x1208&&n==4)stored&=~BIT(31);if(r==0x204&&n==2)stored&=~BIT(15);if(r==0x1700&&n==4)stored=BIT(29);set(r,n,stored);if(r==3&&(v&4)&&(get(0x80,2)&0x4050)==0x4050)set(0x80,2,get(0x80,2)|0x8000);}
static u8 rtw_read8(struct rtw_dev*d,u32 r){(void)d;return read_reg(r,1);}
static u16 rtw_read16(struct rtw_dev*d,u32 r){(void)d;return read_reg(r,2);}
static u32 rtw_read32(struct rtw_dev*d,u32 r){(void)d;return read_reg(r,4);}
static void rtw_write8(struct rtw_dev*d,u32 r,u8 v){(void)d;write_reg(r,1,v);}
static void rtw_write16(struct rtw_dev*d,u32 r,u16 v){(void)d;write_reg(r,2,v);}
static void rtw_write32(struct rtw_dev*d,u32 r,u32 v){(void)d;write_reg(r,4,v);}
static void rtw_write8_set(struct rtw_dev*d,u32 r,u8 v){rtw_write8(d,r,rtw_read8(d,r)|v);}
static void rtw_write8_clr(struct rtw_dev*d,u32 r,u8 v){rtw_write8(d,r,rtw_read8(d,r)&~v);}
static void rtw_write32_set(struct rtw_dev*d,u32 r,u32 v){(void)d;(void)r;(void)v;abort();}
static u32 rtw_read32_mask(struct rtw_dev*d,u32 r,u32 mask){return (rtw_read32(d,r)&mask)>>__builtin_ctz(mask);}
static void udelay(u32 us){record(9,0,us);}
static int rtw_hci_type(struct rtw_dev*d){(void)d;return RTW_HCI_TYPE_PCIE;}
static bool rtw_chip_wcpu_8051(struct rtw_dev*d){(void)d;return false;}
static void rtw_hci_setup(struct rtw_dev*d){(void)d;}
static void set_bit(u32 n,u32 *p){*p|=BIT(n);}
static int rtw_hci_write_data_rsvd_page(struct rtw_dev*d,u8 *data,u32 size){(void)d;record(10,0,size);if(fwrite(data,1,size,output)!=size)abort();set(0x204,2,get(0x204,2)|BIT(15));return 0;}
'''
reg_header = (reference / 'rtw88/reg.h').read_text()
structs = extract('fw.h', 'rtw_fw_hdr', 'struct')
util = '\n'.join(extract('util.c', name) for name in [
    'check_hw_ready', 'ltecoex_read_reg', 'ltecoex_reg_write', 'rtw_restore_reg'])
reserved = extract('fw.c', 'rtw_fw_write_data_rsvd_page')
# The donor's kmemdup/HCI wrapper is modeled by the actual reserved-page path;
# no caller buffer is mutated by the underlying modeled TXBD submission.
packet = '''static int send_firmware_pkt(struct rtw_dev*d,u16 page,const u8 *data,u32 size){return rtw_fw_write_data_rsvd_page(d,page,(u8*)data,size);}\n'''
functions = '\n'.join(extract('mac.c', name) for name in [
    'check_firmware_size', 'wlan_cpu_enable', 'download_firmware_reg_backup',
    'download_firmware_reset_platform', 'download_firmware_reg_restore',
    'iddma_enable', 'iddma_download_firmware', 'check_fw_checksum',
    'download_firmware_to_mem', 'start_download_firmware',
    'download_firmware_validate', 'download_firmware_end_flow', '__rtw_download_firmware'])
main = r'''
int main(int argc,char **argv){if(argc!=3)return 2;FILE*f=fopen(argv[1],"rb");if(!f)abort();fseek(f,0,SEEK_END);long n=ftell(f);if(n<64||n>16*1024*1024)abort();rewind(f);u8 *data=malloc(n);if(!data||fread(data,1,n,f)!=(size_t)n)abort();fclose(f);output=fopen(argv[2],"wb");if(!output)abort();
for(u32 i=0;i<sizeof(registers);i++)registers[i]=i*37+11;set(0x80,2,0x35a5);set(0x1208,4,0);set(0x1700,4,BIT(29));set(0x1708,4,0x1234abcd);
struct rtw_ltecoex_addr lte={0x1700,0x1704,0x1708};struct rtw_chip_info chip={48,&lte};struct rtw_dev dev={.chip=&chip,.fifo={0x700}};struct firmware fw={data,n};struct rtw_fw_state state={&fw};if(__rtw_download_firmware(&dev,&state))abort();if((get(0x80,2)&0xcfff)!=0xc078)abort();if(fclose(output))abort();free(data);return 0;}
'''
source = out / 'oracle.c'
source.write_text(preamble + reg_header + structs + '\n' + util + '\n' + reserved + '\n' + packet + functions + '\n' + main)
exe = out / 'oracle'
subprocess.run(['clang', '-std=gnu11', '-O1', '-g', '-fsanitize=address,undefined', str(source), '-o', str(exe)], check=True)
trace = out / 'trace.bin'
subprocess.run([str(exe), str(image), str(trace)], check=True)
receipt = dict(linux_commit='a804c5742bff224d4cb4d25dd383554d598be32b', functions=manifest,
               image_sha256=hashlib.sha256(image.read_bytes()).hexdigest(),
               generated_source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
               trace_bytes=trace.stat().st_size, trace_sha256=hashlib.sha256(trace.read_bytes()).hexdigest(),
               oracle_limit=['MMIO, delay and lower beacon TXBD queue modeled; no hardware',
                             'source rtw_hci_setup no-op; native HCI reset/setup remains a dependency',
                             'source path evaluated on valid actual firmware only; adverse faults exercised by Rust model'])
(out / 'manifest.json').write_text(json.dumps(receipt, indent=2) + '\n')
print(json.dumps({k: receipt[k] for k in ['trace_bytes', 'trace_sha256']}))

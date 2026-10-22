#!/usr/bin/env python3
"""Unchanged pinned RTL8822C FIFO/H2C functions; modeled MMIO/LLT events.

Usage: script reference-dir output-dir
No DMA/radio or Linux runtime ABI is exercised by this register-only oracle.
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


def extract(file, name, kind=None, table=False):
    text = (reference / 'rtw88' / file).read_text()
    if table:
        m = re.search(r'static const struct \w+ ' + name + r'\[\] = \{.*?\n\};', text, re.S)
        body = m.group()
    else:
        if kind:
            m = re.search(r'\b' + kind + r' ' + name + r'\s*\{', text)
            start, brace = m.start(), text.index('{', m.start())
        else:
            for m in re.finditer(r'\b' + name + r'\s*\(', text):
                end, depth = text.index('(', m.start()) + 1, 1
                while depth:
                    depth += (text[end] == '(') - (text[end] == ')')
                    end += 1
                while text[end].isspace():
                    end += 1
                if text[end] != '{':
                    continue
                start, brace = text.rfind('\n\n', 0, m.start()) + 2, end
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


declarations = '\n'.join(extract('main.h', name, kind) for name, kind in [
    ('rtw_dma_mapping', 'enum'), ('rtw_rqpn', 'struct'),
    ('rtw_page_table', 'struct'), ('rtw_fifo_conf', 'struct')])
tables = '\n'.join(extract('rtw8822c.c', name, table=True) for name in ['page_table_8822c', 'rqpn_table_8822c'])
mac_header = (reference / 'rtw88/mac.h').read_text()
constants = '\n'.join(line for line in mac_header.splitlines() if line.startswith(('#define RSVD_PG_', '#define C2H_PKT_BUF')))
preamble = r'''
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
typedef uint8_t u8;typedef uint16_t u16;typedef uint32_t u32;
#define BIT(n) (1U<<(n))
#define GENMASK(h,l) ((~0U>>(31-(h)))&(~0U<<(l)))
#define RTW_HCI_TYPE_PCIE 1
#define RTW_HCI_TYPE_USB 2
#define RTW_HCI_TYPE_SDIO 3
#define TX_PAGE_SIZE_SHIFT 7
#define REG_SDIO_FREE_TXPG 0xdead
#define REG_SDIO_TX_CTRL 0xdead
#define EXPORT_SYMBOL(...)
#define rtw_err(...) ((void)0)
static FILE*output;static u8 registers[0x170c];
static void word(u32 v){u8 b[]={v,v>>8,v>>16,v>>24};if(fwrite(b,1,4,output)!=4)abort();}
static void record(u32 t,u32 r,u32 v){word(t);word(r);word(v);}
static u32 get(u32 r,u32 n){if(r+n>sizeof(registers))abort();u32 v=0;for(u32 i=0;i<n;i++)v|=(u32)registers[r+i]<<(i*8);return v;}
static void set(u32 r,u32 n,u32 v){if(r+n>sizeof(registers))abort();for(u32 i=0;i<n;i++)registers[r+i]=v>>(i*8);}
static u32 read_reg(u32 r,u32 n){u32 v=get(r,n);record(n,r,v);return v;}
static void write_reg(u32 r,u32 n,u32 v){record(4+n,r,v);set(r,n,(r==0x208&&n==1)?v&~1U:v);}
'''
models = r'''
struct rtw_chip_info {u16 txff_size_unused;u32 txff_size,rxff_size;u16 page_size;u8 rsvd_drv_pg_num,csi_buf_pg_num,usb_tx_agg_desc_num;const struct rtw_page_table*page_table;const struct rtw_rqpn*rqpn_table;};
struct rtw_dev {const struct rtw_chip_info*chip;struct rtw_fifo_conf fifo;struct{int type;u8 bulkout_num;}hci;};
static u8 rtw_read8(struct rtw_dev*d,u32 r){(void)d;return read_reg(r,1);}
static u16 rtw_read16(struct rtw_dev*d,u32 r){(void)d;return read_reg(r,2);}
static u32 rtw_read32(struct rtw_dev*d,u32 r){(void)d;return read_reg(r,4);}
static void rtw_write8(struct rtw_dev*d,u32 r,u8 v){(void)d;write_reg(r,1,v);}
static void rtw_write16(struct rtw_dev*d,u32 r,u16 v){(void)d;write_reg(r,2,v);}
static void rtw_write32(struct rtw_dev*d,u32 r,u32 v){(void)d;write_reg(r,4,v);}
static void rtw_write8_set(struct rtw_dev*d,u32 r,u8 v){rtw_write8(d,r,rtw_read8(d,r)|v);}
static void rtw_write32_set(struct rtw_dev*d,u32 r,u32 v){rtw_write32(d,r,rtw_read32(d,r)|v);}
static void rtw_write8_mask(struct rtw_dev*d,u32 r,u8 mask,u8 value){(void)d;(void)r;(void)mask;(void)value;abort();}
static u32 rtw_read32_mask(struct rtw_dev*d,u32 r,u32 mask){return (rtw_read32(d,r)&mask)>>__builtin_ctz(mask);}
static int rtw_hci_type(struct rtw_dev*d){(void)d;return RTW_HCI_TYPE_PCIE;}
static bool rtw_chip_wcpu_8051(struct rtw_dev*d){(void)d;return false;}
static bool rtw_chip_wcpu_3081(struct rtw_dev*d){(void)d;return true;}
static void udelay(u32 us){record(9,0,us);}
static int __priority_queue_cfg_legacy(struct rtw_dev*d,const struct rtw_page_table*p,u16 n){(void)d;(void)p;(void)n;abort();}
'''
functions = extract('util.c', 'check_hw_ready') + '\n' + '\n'.join(extract('mac.c', name) for name in [
    'txdma_queue_mapping', 'rtw_set_trx_fifo_info', '__priority_queue_cfg',
    'priority_queue_cfg', 'init_h2c', 'rtw_init_trx_cfg'])
main = r'''
int main(int argc,char**argv){if(argc!=2)return 2;FILE*all=fopen(argv[1],"wb");if(!all)abort();
struct rtw_chip_info chip={.txff_size=262144,.rxff_size=24576,.page_size=128,.rsvd_drv_pg_num=16,.csi_buf_pg_num=50,.usb_tx_agg_desc_num=3,.page_table=page_table_8822c,.rqpn_table=rqpn_table_8822c};
for(u32 seed=0;seed<16;seed++){FILE*test=tmpfile();if(!test)abort();output=test;for(u32 i=0;i<sizeof(registers);i++)registers[i]=i*37+seed;set(0xf0,4,0x1000);set(0x80,4,0xc078|((seed&3)<<12));set(0x10d0,4,0x3e100);set(0x10d4,4,0x3e100);
struct rtw_dev dev={.chip=&chip,.hci={RTW_HCI_TYPE_PCIE,0}};
/* Native identity and actual firmware-ready guards. */
if(rtw_read32(&dev,0xf0)!=0x1000||(rtw_read32(&dev,0x80)&0xcfff)!=0xc078)abort();if(rtw_init_trx_cfg(&dev))abort();
struct rtw_fifo_conf*g=&dev.fifo;word(g->rsvd_drv_pg_num);word(g->txff_pg_num);word(g->rsvd_pg_num);word(g->acq_pg_num);word(g->rsvd_boundary);word(g->rsvd_drv_addr);word(g->rsvd_csibuf_addr);word(g->rsvd_fw_txbuf_addr);word(g->rsvd_cpu_instr_addr);word(g->rsvd_h2cq_addr);word(g->rsvd_h2c_sta_info_addr);word(g->rsvd_h2c_info_addr);
long n=ftell(test);if(n<0)abort();rewind(test);output=all;word(n);for(long i=0;i<n;i++){int c=fgetc(test);if(c==EOF||fputc(c,all)==EOF)abort();}fclose(test);}if(fclose(all))abort();return 0;}
'''
source = out / 'oracle.c'
source.write_text(preamble + (reference / 'rtw88/reg.h').read_text() + '\n' + constants + '\n' + declarations + '\n' + tables + '\n' + models + functions + '\n' + main)
exe = out / 'oracle'
subprocess.run(['clang', '-std=gnu11', '-O1', '-g', '-fsanitize=address,undefined', str(source), '-o', str(exe)], check=True)
trace = out / 'trace.bin'
subprocess.run([str(exe), str(trace)], check=True)
receipt = dict(linux_commit='a804c5742bff224d4cb4d25dd383554d598be32b', symbols=manifest,
               cases=16, trace_bytes=trace.stat().st_size,
               trace_sha256=hashlib.sha256(trace.read_bytes()).hexdigest(),
               generated_source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
               oracle_limit=['register/LLT/H2C FIFO model only, no real HCI DMA rings/IRQ/RF or hardware',
                             'wrapper includes native identity/MCU-ready guards',
                             'all four SRAM priority pools and independent initial reserved bits, actual empty H2C pointers',
                             'USB/SDIO/8051 dispatch aborts if reached; actual PCIe RTL8822C only',
                             'adverse transport/identity/MCU/LLT/pointer/all-ones faults tested by checked native code'])
(out / 'manifest.json').write_text(json.dumps(receipt, indent=2) + '\n')
print(json.dumps({k: receipt[k] for k in ['cases', 'trace_bytes', 'trace_sha256']}))

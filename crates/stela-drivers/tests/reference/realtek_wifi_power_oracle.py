#!/usr/bin/env python3
"""Unchanged pinned RTL8822C MAC power functions/tables with bounded MMIO model.

Usage: script reference-dir output-dir
Linux polling macro, delay and MMIO are models; no kernel ABI or hardware.
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
        m = re.search(r'static const struct rtw_pwr_seq_cmd (?:\* const )?' + name + r'\[\] = \{.*?\n\};', text, re.S)
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


tables = '\n'.join(extract('rtw8822c.c', name, table=True) for name in [
    'trans_carddis_to_cardemu_8822c', 'trans_cardemu_to_act_8822c',
    'trans_act_to_cardemu_8822c', 'trans_cardemu_to_carddis_8822c',
    'card_enable_flow_8822c', 'card_disable_flow_8822c'])
declarations = extract('main.h', 'rtw_pwr_seq_cmd', 'struct')
main_header = (reference / 'rtw88/main.h').read_text()
power_defines = '\n'.join(line for line in main_header.splitlines() if line.startswith('#define RTW_PWR_'))
preamble = r'''
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
typedef uint8_t u8;typedef uint16_t u16;typedef uint32_t u32;
#define BIT(n) (1U<<(n))
#define GENMASK(h,l) ((~0U>>(31-(h)))&(~0U<<(l)))
#define RTW_HCI_TYPE_PCIE 1
#define RTW_HCI_TYPE_USB 2
#define RTW_HCI_TYPE_SDIO 3
#define RTW_CHIP_TYPE_8822C 1
#define RTW_CHIP_TYPE_8723D 2
#define RTW_CHIP_TYPE_8814A 3
#define RTW_CHIP_TYPE_8822B 4
#define RTW_CHIP_TYPE_8821C 5
#define RTW_FLAG_POWERON 0
#define RTW_PWR_DELAY_US 0
#define SDIO_LOCAL_OFFSET 0x10000
#define REG_SDIO_HSUS_CTRL 0xdead
#define BIT_HCI_SUS_REQ BIT(0)
#define BIT_HCI_RESUME_RDY BIT(1)
#define REG_SDIO_HIMR 0xdead
#define cut_version_to_mask(cut) (1U<<((cut)+1))
#define rtw_err(...) ((void)0)
#define EXPORT_SYMBOL(...)
#define read_poll_timeout_atomic(op,val,cond,delay,timeout,sleep,...) ({int result=-ETIMEDOUT;for(unsigned i=0;i<RTW_PWR_POLLING_CNT;i++){val=op(__VA_ARGS__);if(cond){result=0;break;}udelay(delay);}result;})
static FILE*output;
static u8 registers[0x170c];
static void word(u32 v){u8 b[]={v,v>>8,v>>16,v>>24};if(fwrite(b,1,4,output)!=4)abort();}
static void record(u32 tag,u32 r,u32 v){word(tag);word(r);word(v);}
static u32 get(u32 r,u32 n){if(r+n>sizeof(registers))abort();u32 v=0;for(u32 i=0;i<n;i++)v|=(u32)registers[r+i]<<(8*i);return v;}
static void set(u32 r,u32 n,u32 v){if(r+n>sizeof(registers))abort();for(u32 i=0;i<n;i++)registers[r+i]=v>>(8*i);}
static u32 read_reg(u32 r,u32 n){u32 v=get(r,n);record(n,r,v);return v;}
static void write_reg(u32 r,u32 n,u32 v){record(4+n,r,v);u32 stored=v;if(r==5&&n==1){if(v&1){set(0x100,1,0);stored&=~1U;}if(v&2){set(0x100,1,0xea);stored&=~2U;}}set(r,n,stored);}
'''
models = r'''
struct rtw_chip_info {u32 id;u8 sys_func_en;const struct rtw_pwr_seq_cmd *const*pwr_on_seq,*const*pwr_off_seq;};
struct rtw_dev {const struct rtw_chip_info*chip;struct{u8 cut_version;}hal;struct{u32 rpwm_addr;}hci;u32 flags[1];};
static u8 rtw_read8(struct rtw_dev*d,u32 r){(void)d;return read_reg(r,1);}
static u16 rtw_read16(struct rtw_dev*d,u32 r){(void)d;return read_reg(r,2);}
static u32 rtw_read32(struct rtw_dev*d,u32 r){(void)d;return read_reg(r,4);}
static void rtw_write8(struct rtw_dev*d,u32 r,u8 v){(void)d;write_reg(r,1,v);}
static void rtw_write16(struct rtw_dev*d,u32 r,u16 v){(void)d;write_reg(r,2,v);}
static void rtw_write32(struct rtw_dev*d,u32 r,u32 v){(void)d;write_reg(r,4,v);}
static void rtw_write8_set(struct rtw_dev*d,u32 r,u8 v){rtw_write8(d,r,rtw_read8(d,r)|v);}
static void rtw_write8_clr(struct rtw_dev*d,u32 r,u8 v){rtw_write8(d,r,rtw_read8(d,r)&~v);}
static void rtw_write32_set(struct rtw_dev*d,u32 r,u32 v){rtw_write32(d,r,rtw_read32(d,r)|v);}
static int rtw_hci_type(struct rtw_dev*d){(void)d;return RTW_HCI_TYPE_PCIE;}
static bool rtw_chip_wcpu_8051(struct rtw_dev*d){(void)d;return false;}
static bool rtw_chip_wcpu_3081(struct rtw_dev*d){(void)d;return true;}
static bool rtw_sdio_is_sdio30_supported(struct rtw_dev*d){(void)d;abort();}
static void udelay(u32 us){record(9,0,us);}
static void mdelay(u32 ms){udelay(ms*1000);}
static void usleep_range(u32 a,u32 b){(void)a;(void)b;abort();}
static void set_bit(u32 bit,u32*flags){*flags|=BIT(bit);}
static void clear_bit(u32 bit,u32*flags){*flags&=~BIT(bit);}
static int __rtw_mac_init_system_cfg_legacy(struct rtw_dev*d){(void)d;abort();}
'''
functions = '\n'.join(extract('mac.c', name) for name in [
    'rtw_mac_pre_system_cfg', 'do_pwr_poll_cmd', 'rtw_pwr_cmd_polling',
    'rtw_sub_pwr_seq_parser', 'rtw_pwr_seq_parser', 'rtw_mac_power_switch',
    '__rtw_mac_init_system_cfg', 'rtw_mac_init_system_cfg', 'rtw_mac_power_on'])
main = r'''
int main(int argc,char**argv){if(argc!=3)return 2;FILE*all=fopen(argv[1],"wb");if(!all)abort();
output=fopen(argv[2],"wb");if(!output)abort();
const struct rtw_pwr_seq_cmd *raw_tables[]={trans_carddis_to_cardemu_8822c,trans_cardemu_to_act_8822c,trans_act_to_cardemu_8822c,trans_cardemu_to_carddis_8822c};
for(u32 t=0;t<4;t++){const struct rtw_pwr_seq_cmd*c=raw_tables[t];do{word(c->offset);word(c->cut_mask);word(c->intf_mask);word(c->base);word(c->cmd);word(c->mask);word(c->value);}while((c++)->cmd!=RTW_PWR_CMD_END);}if(fclose(output))abort();
struct rtw_chip_info chip={RTW_CHIP_TYPE_8822C,0xd8,card_enable_flow_8822c,card_disable_flow_8822c};
for(u32 cut=0;cut<7;cut++)for(u32 powered=0;powered<2;powered++)for(u32 flash=0;flash<2;flash++){
FILE*test=tmpfile();if(!test)abort();output=test;for(u32 i=0;i<sizeof(registers);i++)registers[i]=i*37+11;set(0xf0,4,cut<<12);set(4,1,0);set(5,1,0);set(6,1,2);set(0x100,1,powered?0:0xea);set(0x80,4,(powered?0xc078:0)|(flash?BIT(20):0));
struct rtw_dev dev={.chip=&chip,.hal={cut},.hci={0x3d9}};
/* Native extra identity guard, before every mutation. */
if(rtw_read32(&dev,0xf0)!=(cut<<12))abort();if(rtw_mac_power_on(&dev))abort();
long n=ftell(test);if(n<0)abort();rewind(test);output=all;word(n);for(long i=0;i<n;i++){int c=fgetc(test);if(c==EOF||fputc(c,all)==EOF)abort();}fclose(test);}
if(fclose(all))abort();return 0;}
'''
source = out / 'oracle.c'
source.write_text(preamble + (reference / 'rtw88/reg.h').read_text() + '\n' + power_defines + '\n' + declarations + '\n' + tables + '\n' + models + functions + '\n' + main)
exe = out / 'oracle'
subprocess.run(['clang', '-std=gnu11', '-O1', '-g', '-fsanitize=address,undefined', str(source), '-o', str(exe)], check=True)
trace = out / 'trace.bin'
raw_tables = out / 'tables.bin'
subprocess.run([str(exe), str(trace), str(raw_tables)], check=True)
receipt = dict(linux_commit='a804c5742bff224d4cb4d25dd383554d598be32b', symbols=manifest,
               cases=28, trace_bytes=trace.stat().st_size,
               raw_table_bytes=raw_tables.stat().st_size,
               raw_table_sha256=hashlib.sha256(raw_tables.read_bytes()).hexdigest(),
               trace_sha256=hashlib.sha256(trace.read_bytes()).hexdigest(),
               generated_source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
               oracle_limit=['MMIO/delays and power-transition register events modeled; no physical evidence',
                             'polling macro models native bounded 20000 x 50us rather than Linux timekeeping internals',
                             'wrapper includes native immutable SYS_CFG1 identity guard before unchanged C functions',
                             'USB/SDIO and 8051 paths abort if reached; actual PCIe RTL8822C only',
                             'source cuts0..6 and powered/firmware-left-on plus boot-from-flash; adverse transport tested in Rust'])
(out / 'manifest.json').write_text(json.dumps(receipt, indent=2) + '\n')
print(json.dumps({k: receipt[k] for k in ['cases', 'trace_bytes', 'trace_sha256']}))

#!/usr/bin/env python3
"""Run unchanged pinned Linux mt76 helpers over redistributable images.

Usage: mt792x_firmware_oracle.py MT76_DIRECTORY FIRMWARE_DIRECTORY OUTPUT_DIRECTORY
Then STELA_MT792X_FIRMWARE=FIRMWARE_DIRECTORY STELA_MT792X_ORACLE=OUTPUT_DIRECTORY
cargo test -p stela-drivers actual_pinned -- --ignored

Only command/firmware/queue completion boundaries are stubbed. The extracted
helper bodies, structs, and mode constants are unchanged. ASan/UBSan runs prove
no real hardware effects, authentication, NIC capabilities, or radio readiness.
Generated C, binaries, firmware bytes and traces must remain ignored under .stela.
"""
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import sys

source, images, out = map(Path, sys.argv[1:])
out.mkdir(parents=True, exist_ok=False)
hashes = {
    'mcu.c': 'e0c3fc3323c0482afbd3a943676e5091e5832da4a1e2f711303183f886f4c79a',
    'mt76_connac_mcu.c': '52472fd20bc0a1d744f3eee7a28b7205609e160c479a9da1ec5afa4528e389ec',
    'mt76_connac_mcu.h': '2448b6c145f17397a717965eadf50c591934902f0b09684d37a8b0ae290b31ed',
}
texts = {}
for name, digest in hashes.items():
    raw = (source / name).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == digest, name
    texts[name] = raw.decode()


def function(file, name):
    text = texts[file]
    match = re.search(r'^(?:(?:static(?: inline)? )?(?:int|u32)\s+)'+name+r'\([^;{}]*?\)\n\{', text, re.M)
    assert match, name
    at, depth = match.end(), 1
    while depth:
        depth += (text[at] == '{') - (text[at] == '}')
        at += 1
    return text[match.start():at]


header = texts['mt76_connac_mcu.h']
constants = header[header.index('#define FW_FEATURE_SET_ENCRYPT'):header.index('#define MCU_PQ_ID')]
structures = header[header.index('struct mt76_connac2_patch_hdr {'):header.index('struct mt76_connac3_multi_header_v2_sec_raw_format {')]
prelude = r'''// SPDX-License-Identifier: BSD-3-Clause-Clear
// Copyright (C) 2020-2023 MediaTek Inc.
// Copyright (C) 2019 Lorenzo Bianconi <lorenzo.bianconi83@gmail.com>
// Extracted unchanged from Linux a804c5742bff224d4cb4d25dd383554d598be32b.
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32;
typedef uint16_t __be16; typedef uint32_t __be32; typedef uint32_t __le32;
#define __packed __attribute__((packed))
#define BIT(x) (1U << (x))
#define GENMASK(h,l) ((~0U << (l)) & (~0U >> (31-(h))))
#define FIELD_GET(m,v) (((v)&(m)) >> __builtin_ctz(m))
#define FIELD_PREP(m,v) (((u32)(v) << __builtin_ctz(m)) & (m))
#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error The modeled host transport is little endian.
#endif
#define cpu_to_le32(x) (x)
#define le32_to_cpu(x) (x)
#define be32_to_cpu(x) __builtin_bswap32(x)
#define min_t(t,a,b) ((t)(a)<(t)(b)?(t)(a):(t)(b))
#define dev_err(...) ((void)0)
#define dev_info(...) ((void)0)
#define MCU_PATCH_ADDRESS 0x200000
#define MCU_CMD(x) MCU_CMD_##x
#define MCU_CMD_TARGET_ADDRESS_LEN_REQ 0x01
#define MCU_CMD_FW_START_REQ 0x02
#define MCU_CMD_PATCH_START_REQ 0x05
#define MCU_CMD_PATCH_FINISH_REQ 0x07
#define MCU_CMD_PATCH_SEM_CONTROL 0x10
#define MCU_CMD_FW_SCATTER 0xee
#define PATCH_SEM_GET 1
#define PATCH_SEM_RELEASE 0
#define PATCH_IS_DL 1
#define PATCH_NOT_DL_SEM_SUCCESS 2
#define PATCH_REL_SEM_SUCCESS 3
#define MT_MCUQ_FWDL 0
struct mt76_dev;
struct queue_ops { void (*tx_cleanup)(struct mt76_dev *,void *,bool); };
struct mt76_dev { void *dev; struct queue_ops *queue_ops; void *q_mcu[1]; int chip; };
static bool is_connac_v1(struct mt76_dev *d) { (void)d; return false; }
static bool is_connac2(struct mt76_dev *d) { return d->chip==7921 || d->chip==7922; }
static bool is_connac3(struct mt76_dev *d) { return d->chip==7925; }
static bool is_mt7925(struct mt76_dev *d) { return d->chip==7925; }
static bool is_mt7927(struct mt76_dev *d) { (void)d; return false; }
static bool is_mt7928(struct mt76_dev *d) { (void)d; return false; }
static bool is_mt799x(struct mt76_dev *d) { (void)d; return false; }
static bool mt76_is_sdio(struct mt76_dev *d) { (void)d; return false; }
struct firmware { const u8 *data; size_t size; };
static struct firmware patch;
static int request_firmware(const struct firmware **fw,const char *name,void *dev) {
    (void)name; (void)dev; *fw=&patch; return 0;
}
static void release_firmware(const struct firmware *fw) { (void)fw; }
static int mt76_mcu_send_msg(struct mt76_dev *dev,int cmd,const void *data,int len,bool wait) {
    (void)dev;
    u8 h[6]={(u8)cmd,(u8)wait,(u8)len,(u8)(len>>8),(u8)(len>>16),(u8)(len>>24)};
    if(fwrite(h,1,6,stdout)!=6 || fwrite(data,1,len,stdout)!=(size_t)len) abort();
    if(cmd==MCU_CMD_PATCH_SEM_CONTROL)return *(const u8 *)data?2:3;
    return 0;
}
'''
names = [
    ('mcu.c', '__mt76_mcu_send_firmware'),
    ('mt76_connac_mcu.c', 'mt76_connac_mcu_start_firmware'),
    ('mt76_connac_mcu.c', 'mt76_connac_mcu_patch_sem_ctrl'),
    ('mt76_connac_mcu.c', 'mt76_connac_mcu_start_patch'),
    ('mt76_connac_mcu.c', 'mt76_connac_mcu_init_download'),
    ('mt76_connac_mcu.h', 'mt76_connac_mcu_gen_dl_mode'),
    ('mt76_connac_mcu.c', 'mt76_connac_mcu_send_ram_firmware'),
    ('mt76_connac_mcu.c', 'mt76_connac2_get_data_mode'),
    ('mt76_connac_mcu.c', 'mt76_connac2_load_patch'),
]
main = r'''
static u8 *load(const char *path,size_t *length) {
    FILE *f=fopen(path,"rb"); if(!f)abort();
    if(fseek(f,0,SEEK_END))abort(); long n=ftell(f); rewind(f); if(n<36)abort();
    u8 *p=malloc(n); if(!p || fread(p,1,n,f)!=(size_t)n)abort(); fclose(f); *length=n; return p;
}
int main(int argc,char **argv) {
    if(argc!=4)return 2;
    struct queue_ops ops={0}; struct mt76_dev dev={.queue_ops=&ops,.chip=atoi(argv[1])};
    size_t n=0; patch.data=load(argv[2],&patch.size); u8 *ram=load(argv[3],&n);
    int rc=mt76_connac2_load_patch(&dev,"fixture");
    if(!rc)rc=mt76_connac_mcu_send_ram_firmware(&dev,(const void *)(ram+n-sizeof(struct mt76_connac2_fw_trailer)),ram,false);
    free((void *)patch.data); free(ram); return rc?1:0;
}
'''
unit = out / 'linux-mt792x-download.c'
unit.write_text(prelude + constants + structures + '\n'.join(function(f, n) for f,n in names) + main)
exe = out / 'linux-mt792x-download'
subprocess.run(['cc', '-std=gnu11', '-O1', '-g', '-fsanitize=address,undefined', str(unit), '-o', str(exe)], check=True)
firmware = [
    (7921, 'mediatek/WIFI_MT7961_patch_mcu_1_2_hdr.bin', 'a276c06c2b772adb50b86639d33c82824ff4c21d617feb78caea74c040b873f6', 'mediatek/WIFI_RAM_CODE_MT7961_1.bin', 'b94217a951518a9c14095765f367bc5dd7698f2dc033941d6f18fc2ebd6a2ab9'),
    (7922, 'mediatek/WIFI_MT7922_patch_mcu_1_1_hdr.bin', '7fc9075d6d54b31e0539734614ca971fa52caf41b642a3000c8a4501591a4d98', 'mediatek/WIFI_RAM_CODE_MT7922_1.bin', 'd100e5e04c324fc8da6302112d1e0b4fac952286447d2419eabcd8fb0a1f5b93'),
    (7925, 'mediatek/mt7925/WIFI_MT7925_PATCH_MCU_1_1_hdr.bin', '67ff85f1a39d1a100a51abd8e2a26edd2f198d7052514b6b8981948b231e5016', 'mediatek/mt7925/WIFI_RAM_CODE_MT7925_1_1.bin', '329c0e27f780550789e4eba47452731b1723f69f9e67f525d0e50bf3cd2978ac'),
]
cases = []
for chip,pn,ph,rn,rh in firmware:
    for name,digest in [(pn,ph),(rn,rh)]:
        assert hashlib.sha256((images/name).read_bytes()).hexdigest()==digest, name
    trace=subprocess.run([str(exe.resolve()),str(chip),str((images/pn).resolve()),str((images/rn).resolve())],stdout=subprocess.PIPE,check=True).stdout
    (out/f'{chip}.trace').write_bytes(trace)
    count=0; at=0
    while at<len(trace):
        cmd,wait,n=struct.unpack_from('<BBI',trace,at); at+=6+n; count+=1
        assert wait == (cmd!=0xee)
    assert at==len(trace)
    cases.append({'chip':chip,'commands':count,'trace_bytes':len(trace),'trace_sha256':hashlib.sha256(trace).hexdigest(),'patch':{'name':pn,'sha256':ph},'ram':{'name':rn,'sha256':rh}})
report={'linux_commit':'a804c5742bff224d4cb4d25dd383554d598be32b','linux_firmware_commit':'59f9fc2ef8d1e312d2a613d4e1ffad2ff31a0a01','sources':hashes,'cases':cases}
(out/'manifest.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(cases,indent=2))

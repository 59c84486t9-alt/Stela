#!/usr/bin/env python3
"""Compile unchanged Linux firmware validators and compare bounded real cases.

Usage: rtl815x_firmware_oracle.py R8152_C FIXTURE_DIRECTORY OUTPUT_DIRECTORY
All real images must match the committed Rust fixture hashes. The generated C
retains donor license/copyright. The harness uses system SHA-256 and defines
only kernel logging/bit operations and container types; validator bodies are
not changed. Generated C, binaries and mutated firmware stay under .stela.
"""
import hashlib
from pathlib import Path
import re
import struct
import subprocess
import sys

source, fixtures, out = map(Path, sys.argv[1:])
assert hashlib.sha256(source.read_bytes()).hexdigest() == "9d766f203c7fdabe6449e8dd2b9e5dd4fccfa20a62aa5dbf00d64c0c475c5a9f"
text = source.read_text()
out.mkdir(parents=True, exist_ok=True)


def function(name):
    match = re.search(r"^static[^;{}]*?\b" + name + r"\([^;{}]*?\)\n\{", text, re.M)
    assert match, name
    at, depth = match.end(), 1
    while depth:
        depth += (text[at] == "{") - (text[at] == "}")
        at += 1
    return text[match.start():at]


prelude = r'''// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2014 Realtek Semiconductor Corp. All rights reserved.
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#ifdef __APPLE__
#include <CommonCrypto/CommonDigest.h>
static void sha256(const void *p,size_t n,void *out) { CC_SHA256(p,(CC_LONG)n,out); }
#else
#include <openssl/sha.h>
static void sha256(const void *p,size_t n,void *out) { SHA256(p,n,out); }
#endif
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32; typedef uint16_t __le16; typedef uint32_t __le32;
#define __packed __attribute__((packed))
#define __le16_to_cpu(x) (x)
#define __le32_to_cpu(x) (x)
#define BIT(x) (1UL << (x))
#define ALIGN(x,a) (((x)+(a)-1)&~((a)-1))
#define test_bit(n,p) (!!(*(p) & BIT(n)))
#define __set_bit(n,p) (*(p) |= BIT(n))
#define dev_err(...) ((void)0)
#define dev_warn(...) ((void)0)
#define BUILD_BUG_ON(x) _Static_assert(!(x),"build assertion")
#define SHA256_DIGEST_SIZE 32
#define RTL_VER_SIZE 32
#define SRAM_GPHY_FW_VER 0x801e
#define OCP_PHY_PATCH_CMD 0xb820
#define PLA_BP_BA 0xfc26
#define PLA_BP_0 0xfc28
#define PLA_BP_EN 0xfc38
#define USB_BP_BA PLA_BP_BA
#define USB_BP_0 PLA_BP_0
#define USB_BP_EN PLA_BP_EN
#define USB_BP2_EN 0xfc48
struct firmware { const u8 *data; size_t size; };
struct rtl_fw { const struct firmware *fw; };
struct r8152 { u8 version; };
'''
structures = text[text.index('struct fw_block {'):text.index('enum tx_csum_stat {')]
names = ['rtl8152_is_fw_phy_speed_up_ok', 'rtl8152_is_fw_phy_ver_ok', 'rtl8152_is_fw_phy_fixup_ok', 'rtl8152_is_fw_phy_union_ok', 'rtl8152_is_fw_phy_nc_ok', 'rtl8152_is_fw_mac_ok', 'rtl8152_fw_verify_checksum', 'rtl8152_check_firmware']
main = r'''
int main(int argc,char **argv) {
    if(argc!=3)return 2;
    FILE *f=fopen(argv[2],"rb"); if(!f)return 3;
    fseek(f,0,SEEK_END); long n=ftell(f); rewind(f); if(n<0)return 4;
    u8 *bytes=malloc(n); if(!bytes || fread(bytes,1,n,f)!=(size_t)n)return 5; fclose(f);
    struct firmware fw={.data=bytes,.size=n}; struct rtl_fw rtl={.fw=&fw}; struct r8152 tp={.version=atoi(argv[1])};
    int valid=rtl8152_check_firmware(&tp,&rtl)==0; free(bytes); puts(valid?"1":"0"); return 0;
}
'''
unit = out / 'linux-firmware-validator.c'
unit.write_text(prelude + structures + '\n'.join(function(n) for n in names) + main)
exe = out / 'linux-firmware-validator'
subprocess.run(['cc', '-std=gnu11', '-O1', '-fsanitize=address,undefined', '-Wno-deprecated-declarations', str(unit), '-o', str(exe)] + ([] if sys.platform == 'darwin' else ['-lcrypto']), check=True)
versions = [('rtl8153a-2.fw', 0x5c10, 4), ('rtl8153a-3.fw', 0x5c20, 5), ('rtl8153a-4.fw', 0x5c30, 6), ('rtl8153b-2.fw', 0x6010, 9), ('rtl8153c-1.fw', 0x6400, 15), ('rtl8156a-2.fw', 0x7030, 12), ('rtl8156b-2.fw', 0x7410, 14)]
# Hardware version -> enum index includes RTL_TEST_01 between VER_09/VER_10.
# Use the fixture SHA-256 strings also checked by the native real-image test.
rust = Path(__file__).resolve().parents[2] / 'src/usb/ethernet/firmware.rs'
entries = re.findall(r'"(rtl815\w+-\d\.fw)"\s*,\s*0x[0-9a-f]+\s*,\s*\d+\s*,\s*"([0-9a-f]{64})"', rust.read_text())
hashes = dict(entries)
assert len(hashes)==7
cases = []
for name, revision, enum in versions:
    original = (fixtures / name).read_bytes()
    assert hashlib.sha256(original).hexdigest()==hashes[name]
    mutations = [original]
    at=64
    while at+8<=len(original):
        kind,length=struct.unpack_from('<II',original,at)
        if kind==0:break
        fields = {1:[8,10,12,16,20,22],2:[8,10,12,16,20,22],5:[8,10,12,16,20,28,30],6:[8,10],7:[8],8:[8],9:[8],10:[8],11:[8],12:[8],13:[8,12],14:[8]}.get(kind,[])
        for field in fields:
            old=struct.unpack_from('<H',original,at+field)[0]
            for value in [0,0xffff,old^1]:
                if old==value:continue
                data=bytearray(original);struct.pack_into('<H',data,at+field,value);data[:32]=hashlib.sha256(data[32:]).digest();mutations.append(bytes(data))
        at+=(length+7)&~7
    for data in mutations:
        index=len(cases);path=out / f'case-{index}.fw';path.write_bytes(data)
        result=subprocess.run([str(exe.resolve()),str(enum),str(path.resolve())],stdout=subprocess.PIPE,check=True)
        expected=int(result.stdout)
        cases.append(f'{revision:04x} {expected} {path.resolve()}')
(out / 'cases.txt').write_text('\n'.join(cases)+'\n')
print(f'{len(cases)} unchanged-source cases: {out / "cases.txt"}')

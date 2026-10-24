#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""UNRUN unchanged Linux I801 hardware-PEC policy/error comparison.

Four complete original functions implement preflight, CRC/error handling and
outer access policy. Transaction engines, PCI/runtime PM, locking and registers
are services modeled here; this does not model CRC arithmetic or electrical
transmission. Native peers separately exercise those wire and ownership paths.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import signal

PIN = "a804c5742bff224d4cb4d25dd383554d598be32b"
SOURCE = "drivers/i2c/busses/i2c-i801.c"
SOURCE_SHA256 = "752d89228a166ec26ee11ccebe094896b8ded3600df9da3b998b825bf98b80d0"
HELPERS = {
    "amd_gpio_oracle.py": "ca7700acd35e9bf62ced277c25e30c44adb5ef9b7016c17a70ee033fa7ed2126",
    "child_wait.py": "5361474b3827648068e9341e9e2fa97089352429ab3c89822ece1a2f2f6c71fb",
}
MARKERS = [
    "static int i801_check_and_clear_pec_error(",
    "static int i801_check_pre(",
    "static int i801_check_post(",
    "static s32 i801_access(",
]


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def declaration(text, marker):
    start = text.index(marker)
    at = text.index("{", start) + 1
    depth = 1
    while depth and at < len(text):
        depth += (text[at] == "{") - (text[at] == "}")
        at += 1
    if depth:
        raise ValueError("unterminated pinned function")
    return text[start:at]


PREFIX = r'''
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef uint8_t u8;
typedef uint16_t u16;
typedef int32_t s32;
#define BIT(n) (1U << (n))
#define FEATURE_SMBUS_PEC BIT(0)
#define I2C_CLIENT_PEC 4
#define I2C_SMBUS_QUICK 0
#define I2C_SMBUS_BYTE 1
#define I2C_SMBUS_BYTE_DATA 2
#define I2C_SMBUS_WORD_DATA 3
#define I2C_SMBUS_BLOCK_DATA 5
#define I2C_SMBUS_BLOCK_PROC_CALL 7
#define I2C_SMBUS_I2C_BLOCK_DATA 8
#define SMBHSTSTS_HOST_BUSY BIT(0)
#define SMBHSTSTS_INTR BIT(1)
#define SMBHSTSTS_DEV_ERR BIT(2)
#define SMBHSTSTS_BUS_ERR BIT(3)
#define SMBHSTSTS_FAILED BIT(4)
#define SMBHSTSTS_INUSE_STS BIT(6)
#define STATUS_FLAGS (BIT(1)|BIT(2)|BIT(3)|BIT(4)|BIT(7))
#define SMBHSTCNT_KILL BIT(1)
#define SMBAUXSTS_CRCE BIT(0)
#define SMBAUXCTL_CRC BIT(0)
#define SMBHSTSTS(p) 0
#define SMBHSTCNT(p) 2
#define SMBAUXSTS(p) 12
#define SMBAUXCTL(p) 13
#define unlikely(x) (x)
#define pci_dbg(...) ((void)0)
#define pci_err(...) ((void)0)
#define mutex_lock(p) ((void)(p))
#define mutex_unlock(p) ((void)(p))
#define pm_runtime_get_sync(p) ((void)(p))
#define pm_runtime_put_autosuspend(p) ((void)(p))
struct pci_dev { int dev; };
struct i801_priv { unsigned features; int acpi_reserved, acpi_lock; struct pci_dev *pci_dev; };
struct i2c_adapter { struct i801_priv *priv; };
union i2c_smbus_data { u8 byte; u16 word; u8 block[34]; };
static u8 registers[16], original_status, original_crc, during_crc;
static struct i801_priv *i2c_get_adapdata(struct i2c_adapter *adapter) { return adapter->priv; }
static u8 ioread8(unsigned reg) { assert(reg<16); return registers[reg]; }
static void iowrite8(u8 value,unsigned reg) {
    assert(reg<16);
    if(reg==0 || reg==12) registers[reg]&=~value;
    else registers[reg]=value;
}
static int i801_wait_intr(struct i801_priv *priv) { (void)priv; return SMBHSTSTS_FAILED; }
static int transaction_service(struct i801_priv *priv) {
    (void)priv;
    during_crc = registers[13] & SMBAUXCTL_CRC;
    registers[12] |= original_crc;
    registers[0] |= original_status;
    return original_status;
}
static int i801_simple_transaction(struct i801_priv *p,union i2c_smbus_data *d,u8 a,u8 c,char r,int s) {
    (void)d;(void)a;(void)c;(void)r;(void)s;return transaction_service(p);
}
static int i801_smbus_block_transaction(struct i801_priv *p,union i2c_smbus_data *d,u8 a,u8 c,char r,int s) {
    (void)d;(void)a;(void)c;(void)r;(void)s;return transaction_service(p);
}
static int i801_i2c_block_transaction(struct i801_priv *p,union i2c_smbus_data *d,u8 a,u8 c,char r,int s) {
    (void)d;(void)a;(void)c;(void)r;(void)s;return transaction_service(p);
}
'''
SUFFIX = r'''
int main(void) {
    struct pci_dev pci = {0};
    struct i801_priv priv = {.features=FEATURE_SMBUS_PEC,.pci_dev=&pci};
    struct i2c_adapter adapter = {.priv=&priv};
    const unsigned statuses[] = {0,16,4,8,20,24,12,28};
    unsigned id=0;
    puts("I801_PEC a804c5742bff224d4cb4d25dd383554d598be32b 128");
    for(unsigned kind=0;kind<8;kind++) for(unsigned status=0;status<8;status++)
        for(unsigned crc=0;crc<2;crc++) {
            memset(registers,0,sizeof(registers));
            registers[13]=0x80;
            registers[0]=SMBHSTSTS_INUSE_STS;
            original_status=statuses[status] | (crc?SMBHSTSTS_DEV_ERR:0);
            original_crc=crc;
            during_crc=0;
            int size=kind<2?I2C_SMBUS_BYTE:kind<4?I2C_SMBUS_BYTE_DATA:
                kind<6?I2C_SMBUS_WORD_DATA:I2C_SMBUS_BLOCK_DATA;
            union i2c_smbus_data data={0};
            int result=i801_access(&adapter,0x2c,I2C_CLIENT_PEC,kind&1,0xa7,size,&data);
            unsigned cls=result==0?0:result==-EIO?1:result==-ENXIO?2:
                result==-EBADMSG?3:result==-EAGAIN?4:99;
            printf("%u %u %u %u %u %u %u %u %u %u\n", id++, kind, statuses[status],crc,
                original_status,cls,during_crc,registers[13],registers[0],registers[12]);
            assert(cls!=99);
        }
    assert(id==128);
    return 0;
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--linux-git-dir", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--cc", type=Path, required=True)
    args = parser.parse_args()
    # Source/hash checks precede importing the existing child ownership helper.
    for name, expected in HELPERS.items():
        if digest(Path(__file__).with_name(name).read_bytes()) != expected:
            raise ValueError("helper source integrity mismatch: " + name)
    helper_path = Path(__file__).with_name("amd_gpio_oracle.py")
    spec = importlib.util.spec_from_file_location("i801_pec_evidence", helper_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    evidence = module.Evidence(args.out)
    evidence.record.update(
        harness_sha256=digest(Path(__file__).read_bytes()), cases=128,
        limits="Unchanged Linux access/pre/post PEC policy and error classes only; modeled transaction/PM/locking/register services; no physical CRC/attachment/IRQ proof",
        compiler=str(args.cc.resolve()), compiler_sha256=digest(args.cc.resolve().read_bytes()),
    )
    def interrupted(signum, _frame):
        evidence.cancellation = signum
    previous = {sig: signal.signal(sig, interrupted) for sig in (signal.SIGINT, signal.SIGTERM)}
    try:
        raw = evidence.command("donor", ["git", "--git-dir=" + str(args.linux_git_dir), "show", PIN + ":" + SOURCE], 20)
        if digest(raw) != SOURCE_SHA256:
            raise ValueError("pinned donor integrity mismatch")
        bodies = [declaration(raw.decode(), marker) for marker in MARKERS]
        evidence.record["unchanged_function_sha256"] = {
            marker: digest(body.encode()) for marker, body in zip(MARKERS, bodies)
        }
        source = evidence.root / "i801-pec.c"
        source.write_text(PREFIX + "\n\n".join(bodies) + SUFFIX)
        evidence.record["generated_source_sha256"] = digest(source.read_bytes())
        binary = evidence.root / "i801-pec"
        evidence.command("compile", [str(args.cc), "-std=c11", "-O1", "-g", "-fsanitize=address,undefined", "-fno-omit-frame-pointer", str(source), "-o", str(binary)], 60)
        evidence.record["reference_binary_sha256"] = digest(binary.read_bytes())
        trace = evidence.command("reference", [str(binary)], 20)
        lines = trace.decode().splitlines()
        if len(lines) != 129 or lines[0] != "I801_PEC " + PIN + " 128":
            raise ValueError("reference trace shape mismatch")
        for index, line in enumerate(lines[1:]):
            fields = [int(value) for value in line.split()]
            if len(fields) != 10 or fields[0] != index:
                raise ValueError("reference trace identity mismatch")
        with args.out.open("xb") as output:
            output.write(trace)
        evidence.record.update(status="PASS", trace_sha256=digest(trace))
    except BaseException as error:
        evidence.record.update(status="FAIL", failure=type(error).__name__ + ": " + str(error))
        raise
    finally:
        try:
            evidence.save()
        finally:
            for sig, handler in previous.items():
                signal.signal(sig, handler)


if __name__ == "__main__":
    main()

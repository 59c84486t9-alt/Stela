#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Linux I801 source authors/notices are retained in bus/smbus/i801.rs.
"""Compile three unchanged pinned I801 fixed-block functions under sanitizers.

Only MMIO/configuration, wait and logging services are substituted. Complete
byte-handshake and outer configuration/address algorithms stay unchanged.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

PIN = "a804c5742bff224d4cb4d25dd383554d598be32b"
SOURCE = "drivers/i2c/busses/i2c-i801.c"
SHA256 = "752d89228a166ec26ee11ccebe094896b8ded3600df9da3b998b825bf98b80d0"


def declaration(source, marker):
    start = source.index(marker)
    opened = source.index("{", start)
    depth = 1
    end = opened + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--linux", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--cc", default="clang")
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    raw = subprocess.check_output(["git", "-C", str(args.linux.resolve()), "show", f"{PIN}:{SOURCE}"], timeout=30)
    if hashlib.sha256(raw).hexdigest() != SHA256:
        raise SystemExit("source integrity mismatch")
    (args.out / "i2c-i801.c").write_bytes(raw)
    source = raw.decode()
    markers = ["static int i801_block_transaction_byte_by_byte(", "static void i801_set_hstadd(", "static int i801_i2c_block_transaction("]
    bodies = [declaration(source, marker) for marker in markers]
    prefix = r'''
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
typedef uint8_t u8;
#define BIT(n) (1U<<(n))
#define I2C_SMBUS_WRITE 0
#define I2C_SMBUS_READ 1
#define I2C_SMBUS_BLOCK_PROC_CALL 7
#define I2C_SMBUS_I2C_BLOCK_DATA 8
#define I2C_SMBUS_BLOCK_MAX 32
#define SMBUS_LEN_SENTINEL 255
#define FEATURE_I2C_BLOCK_READ BIT(3)
#define FEATURE_IRQ BIT(4)
#define SMBHSTCFG 0x40
#define SMBHSTCFG_I2C_EN BIT(2)
#define SMBHSTCFG_SPD_WD BIT(4)
#define SMBHSTCNT_LAST_BYTE BIT(5)
#define SMBHSTCNT_START BIT(6)
#define SMBHSTCNT_INTREN BIT(0)
#define SMBHSTSTS_HOST_BUSY BIT(0)
#define SMBHSTSTS_INTR BIT(1)
#define SMBHSTSTS_BYTE_DONE BIT(7)
#define I801_BLOCK_DATA 0x14
#define I801_I2C_BLOCK_DATA 0x18
#define SMBHSTSTS(p) 0
#define SMBHSTCNT(p) 2
#define SMBHSTCMD(p) 3
#define SMBHSTADD(p) 4
#define SMBHSTDAT0(p) 5
#define SMBHSTDAT1(p) 6
#define SMBBLKDAT(p) 7
#define pci_err(...) ((void)0)
struct i2c_adapter { unsigned timeout; };
struct i801_priv {
    unsigned features;
    struct i2c_adapter adapter;
    bool is_read;
    unsigned cmd,len,count,status,done;
    u8 *data;
    u8 original_hstcfg;
    void *pci_dev;
};
union i2c_smbus_data {u8 byte;uint16_t word;u8 block[34];};
static u8 regs[16], config, outgoing[32];
static unsigned waits, outcount, start_control, last_after, config_writes;
static u8 ioread8(unsigned reg) {
    if(reg==7) return (u8)((waits-1)*7+0x31);
    return regs[reg];
}
static void iowrite8(u8 value,unsigned reg) {
    regs[reg]=value;
    if(reg==7) outgoing[outcount++]=value;
    if(reg==2) {
        if(value&SMBHSTCNT_START) start_control=value;
        if(value&SMBHSTCNT_LAST_BYTE) last_after=waits;
    }
}
static int pci_read_config_byte(void *p,unsigned reg,u8 *value) {
    (void)p;if(reg!=0x40) abort();*value=config;return 0;
}
static int pci_write_config_byte(void *p,unsigned reg,u8 value) {
    (void)p;if(reg!=0x40) abort();config=value;++config_writes;return 0;
}
static int i801_wait_byte_done(struct i801_priv *p) {(void)p;++waits;return 0;}
static int i801_wait_intr(struct i801_priv *p) {(void)p;return 0;}
static int i801_get_block_len(struct i801_priv *p) {(void)p;abort();}
#define reinit_completion(p) ((void)(p))
#define wait_for_completion_timeout(p,t) (0)
'''
    suffix = r'''
int main(void) {
    for(unsigned capable=0;capable<2;++capable) for(unsigned spd=0;spd<2;++spd)
    for(unsigned read=0;read<2;++read) for(unsigned length=0;length<=33;++length) {
        memset(regs,0,sizeof regs);memset(outgoing,0,sizeof outgoing);
        waits=outcount=start_control=config_writes=0;last_after=255;
        config=1|(spd?SMBHSTCFG_SPD_WD:0);
        struct i801_priv p={.features=capable?FEATURE_I2C_BLOCK_READ:0,.original_hstcfg=config};
        union i2c_smbus_data data;memset(&data,0xa5,sizeof data);data.block[0]=length;
        if(!read) for(unsigned n=0;n<32;++n)data.block[n+1]=(u8)(n*19+3);
        int result=i801_i2c_block_transaction(&p,&data,0x2c,0xa7,read,I2C_SMBUS_I2C_BLOCK_DATA);
        printf("%u,%u,%u,%u,%d,%u,%u,%u,%u,%u,%u,%u,",capable,spd,read,length,result,regs[4],regs[3],regs[6],start_control,last_after,config,config_writes);
        for(unsigned n=0;n<32;++n)printf("%02x",data.block[n+1]);
        putchar(',');for(unsigned n=0;n<outcount;++n)printf("%02x",outgoing[n]);putchar('\n');
    }
    return 0;
}
'''
    (args.out / "oracle.c").write_text(prefix + "\n".join(bodies) + suffix)
    command = [args.cc, "-std=gnu11", "-O1", "-g", "-fsanitize=address,undefined", "-fno-sanitize-recover=all", str(args.out / "oracle.c"), "-o", str(args.out / "oracle")]
    (args.out / "compiler-command.json").write_text(json.dumps(command) + "\n")
    compiled = subprocess.run(command, capture_output=True, timeout=120)
    (args.out / "compiler-stdout.txt").write_bytes(compiled.stdout)
    (args.out / "compiler-stderr.txt").write_bytes(compiled.stderr)
    compiled.check_returncode()
    run = subprocess.run([str((args.out / "oracle").resolve())], capture_output=True, timeout=60)
    (args.out / "trace.csv").write_bytes(run.stdout)
    (args.out / "stderr.txt").write_bytes(run.stderr)
    run.check_returncode()
    receipt = {"pin": PIN, "source": SOURCE, "source_sha256": SHA256,
               "extracted_functions": {marker: hashlib.sha256(body.encode()).hexdigest() for marker, body in zip(markers, bodies)},
               "cases": len(run.stdout.splitlines()), "trace_sha256": hashlib.sha256(run.stdout).hexdigest(),
               "oracle_limits": ["Kernel IRQ/scheduler/wait, MMIO/configuration and logging services substituted; polled source protocol only",
                                 "Donor config restore has no readback and runs even after unknown bus completion; native checks/restores only after real host quiescence",
                                 "Donor unsupported old-controller reads program target registers before refusing; native refusal precedes I/O",
                                 "No actual physical/firmware/arbitration or PCI attachment qualification"]}
    (args.out / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps(receipt, indent=2))


if __name__ == "__main__":
    main()

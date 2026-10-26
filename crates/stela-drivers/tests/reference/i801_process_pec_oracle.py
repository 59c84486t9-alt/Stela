#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Linux notices: Frodo Looijaard, Philip Edelbrock, Mark D. Studebaker;
# Jean Delvare; Intel Corporation, David Woodhouse (see bus/THIRD_PARTY.md).
"""Execute complete pinned I801 simple/access, polling and PEC/error functions.

Ordered registers, time, peripheral completion and runtime/locking are services;
the eight original algorithms stay unchanged. This qualifies process-call
request/response registers and PEC/error policy, not physical CRC or attachment.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

PIN = "cc9de5d4b5ab6459f5774946aa3195ad51236fa8"
SOURCE = "drivers/i2c/busses/i2c-i801.c"
SHA256 = "752d89228a166ec26ee11ccebe094896b8ded3600df9da3b998b825bf98b80d0"
MARKERS = [
    "static int i801_wait_intr(",
    "static int i801_check_and_clear_pec_error(",
    "static int i801_check_pre(",
    "static int i801_check_post(",
    "static int i801_transaction(",
    "static void i801_set_hstadd(",
    "static int i801_simple_transaction(",
    "static s32 i801_access(",
]


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def function(text, marker):
    start = text.index(marker)
    end = text.index("{", start) + 1
    depth = 1
    while depth:
        depth += (text[end] == "{") - (text[end] == "}")
        end += 1
    return text[start:end]


PREFIX = r'''
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef uint8_t u8; typedef uint16_t u16; typedef int32_t s32;
#define BIT(n) (1U<<(n))
#define FEATURE_SMBUS_PEC BIT(0)
#define FEATURE_IRQ BIT(4)
#define I2C_CLIENT_PEC 4
#define I2C_SMBUS_WRITE 0
#define I2C_SMBUS_READ 1
#define I2C_SMBUS_QUICK 0
#define I2C_SMBUS_BYTE 1
#define I2C_SMBUS_BYTE_DATA 2
#define I2C_SMBUS_WORD_DATA 3
#define I2C_SMBUS_PROC_CALL 4
#define I2C_SMBUS_BLOCK_DATA 5
#define I2C_SMBUS_BLOCK_PROC_CALL 7
#define I2C_SMBUS_I2C_BLOCK_DATA 8
#define I801_QUICK 0
#define I801_BYTE 4
#define I801_BYTE_DATA 8
#define I801_WORD_DATA 12
#define I801_PROC_CALL 16
#define SMBHSTSTS_HOST_BUSY BIT(0)
#define SMBHSTSTS_INTR BIT(1)
#define SMBHSTSTS_DEV_ERR BIT(2)
#define SMBHSTSTS_BUS_ERR BIT(3)
#define SMBHSTSTS_FAILED BIT(4)
#define SMBHSTSTS_INUSE_STS BIT(6)
#define STATUS_ERROR_FLAGS (BIT(2)|BIT(3)|BIT(4))
#define STATUS_FLAGS (STATUS_ERROR_FLAGS|BIT(1)|BIT(7))
#define SMBHSTCNT_KILL BIT(1)
#define SMBHSTCNT_INTREN BIT(0)
#define SMBHSTCNT_START BIT(6)
#define SMBAUXSTS_CRCE BIT(0)
#define SMBAUXCTL_CRC BIT(0)
#define SMBHSTSTS(p) 0
#define SMBHSTCNT(p) 2
#define SMBHSTCMD(p) 3
#define SMBHSTADD(p) ((void)(p),4)
#define SMBHSTDAT0(p) 5
#define SMBHSTDAT1(p) 6
#define SMBAUXSTS(p) 12
#define SMBAUXCTL(p) 13
#define unlikely(x) (x)
#define pci_dbg(...) ((void)0)
#define pci_err(...) ((void)0)
#define mutex_lock(p) ((void)(p))
#define mutex_unlock(p) ((void)(p))
#define pm_runtime_get_sync(p) ((void)(p))
#define pm_runtime_put_autosuspend(p) ((void)(p))
struct pci_dev {int dev;};
struct i801_priv;
struct i2c_adapter {unsigned long timeout; struct i801_priv *priv;};
struct i801_priv {unsigned features; int acpi_lock,acpi_reserved,done,status;
    struct pci_dev *pci_dev; struct i2c_adapter adapter;};
union i2c_smbus_data {u8 byte;u16 word;u8 block[34];};
static u8 registers[16], captured[7], response[2], completion_status, corrupt, active;
static unsigned long jiffies;
static struct i801_priv *i2c_get_adapdata(struct i2c_adapter *a){return a->priv;}
static u8 ioread8(unsigned reg){assert(reg<16);return registers[reg];}
static void iowrite8(u8 value,unsigned reg){
    assert(reg<16);
    if(reg==0||reg==12) registers[reg]&=~value;
    else registers[reg]=value;
    if(reg==2&&(value&SMBHSTCNT_START)){
        assert((value&0x1c)==I801_PROC_CALL);
        assert(!(registers[4]&1));
        memcpy(captured,registers,7);active=1;registers[0]|=SMBHSTSTS_HOST_BUSY;
    }
}
static void usleep_range(unsigned lo,unsigned hi){
    (void)lo;(void)hi;jiffies++;
    if(active){
        active=0; registers[0]=completion_status;
        if(corrupt&&(registers[13]&SMBAUXCTL_CRC)){
            registers[12]|=SMBAUXSTS_CRCE;registers[0]|=SMBHSTSTS_DEV_ERR;
        }
        if(!(registers[0]&STATUS_ERROR_FLAGS))registers[0]|=SMBHSTSTS_INTR;
        registers[5]=response[0];registers[6]=response[1];
    }
}
#define time_is_after_eq_jiffies(deadline) ((deadline)>=jiffies)
static void reinit_completion(int *p){(void)p;assert(0);}
static unsigned long wait_for_completion_timeout(int *p,unsigned long t){(void)p;(void)t;assert(0);return 0;}
static int i801_smbus_block_transaction(struct i801_priv*p,union i2c_smbus_data*d,u8 a,u8 c,char r,int s){
    (void)p;(void)d;(void)a;(void)c;(void)r;(void)s;assert(0);return -EOPNOTSUPP;
}
static int i801_i2c_block_transaction(struct i801_priv*p,union i2c_smbus_data*d,u8 a,u8 c,char r,int s){
    (void)p;(void)d;(void)a;(void)c;(void)r;(void)s;assert(0);return -EOPNOTSUPP;
}
'''
SUFFIX = r'''
int main(void){
    struct pci_dev pci={0};
    struct i801_priv p={.features=FEATURE_SMBUS_PEC,.pci_dev=&pci,.adapter={.timeout=10}};
    struct i2c_adapter a={.priv=&p};
    const unsigned addresses[]={8,44,119}, commands[]={0,255};
    const unsigned words[]={0,1,0x80ff,0xffff}, statuses[]={0,16,4,8,20,24,12,28};
    unsigned id=0;
    puts("I801_PROCESS_PEC cc9de5d4b5ab6459f5774946aa3195ad51236fa8 3072");
    for(unsigned ad=0;ad<3;ad++)for(unsigned cm=0;cm<2;cm++)
    for(unsigned req=0;req<4;req++)for(unsigned rep=0;rep<4;rep++)
    for(unsigned pec=0;pec<2;pec++)for(unsigned st=0;st<8;st++)for(unsigned cr=0;cr<2;cr++){
        memset(registers,0,sizeof(registers));memset(captured,0,sizeof(captured));
        registers[13]=0x80;registers[0]=SMBHSTSTS_INUSE_STS;
        jiffies=0;active=0;completion_status=statuses[st];corrupt=cr;
        response[0]=words[rep]&255;response[1]=words[rep]>>8;
        union i2c_smbus_data data={.word=words[req]};
        int result=i801_access(&a,addresses[ad],pec?I2C_CLIENT_PEC:0,
            I2C_SMBUS_WRITE,commands[cm],I2C_SMBUS_PROC_CALL,&data);
        unsigned cls=result==0?0:result==-EIO?1:result==-ENXIO?2:
            result==-EBADMSG?3:result==-EAGAIN?4:99;
        assert(cls!=99);
        printf("%u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u\n",
            id++,addresses[ad],commands[cm],words[req],words[rep],pec,statuses[st],cr,
            cls,captured[2],captured[4],captured[5],captured[6],data.word,
            registers[13],registers[0],registers[12]);
    }
    assert(id==3072);return 0;
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--cc", default="clang")
    args = parser.parse_args()
    raw = (args.reference / SOURCE).read_bytes()
    if digest(raw) != SHA256:
        raise ValueError("pinned original source hash mismatch")
    args.out.mkdir(parents=True, exist_ok=False)
    report = dict(pin=PIN, source=SOURCE, source_sha256=digest(raw),
                  script_sha256=digest(Path(__file__).read_bytes()), status="FAIL")
    def save():
        (args.out / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    save()
    try:
        compiler = shutil.which(args.cc)
        if compiler is None:
            raise ValueError("compiler not found")
        compiler = Path(compiler).resolve()
        report.update(compiler=str(compiler), compiler_sha256=digest(compiler.read_bytes()))
        bodies = [function(raw.decode(), marker) for marker in MARKERS]
        report["unchanged_functions"] = {m: digest(b.encode()) for m, b in zip(MARKERS, bodies)}
        source = args.out / "process.c"
        source.write_text(PREFIX + "\n\n".join(bodies) + SUFFIX)
        binary = args.out / "process"
        command = [str(compiler), "-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
                   "-fsanitize=address,undefined", "-fno-sanitize-recover=all",
                   "-fno-omit-frame-pointer", str(source), "-o", str(binary)]
        report["compile_command"] = command
        report["generated_source_sha256"] = digest(source.read_bytes())
        report["phase"] = "compiling"
        save()
        result = subprocess.run(command, capture_output=True, timeout=60)
        (args.out / "compile.log").write_bytes(result.stdout + result.stderr)
        result.check_returncode()
        report["binary_sha256"] = digest(binary.read_bytes())
        report["phase"] = "executing source binary"
        save()
        result = subprocess.run([str(binary)], capture_output=True, timeout=30)
        (args.out / "stderr.log").write_bytes(result.stderr)
        result.check_returncode()
        lines = result.stdout.decode().splitlines()
        assert len(lines) == 3073 and lines[0] == f"I801_PROCESS_PEC {PIN} 3072"
        for i, line in enumerate(lines[1:]):
            values = list(map(int, line.split()))
            assert len(values) == 17 and values[0] == i
        (args.out / "records.txt").write_bytes(result.stdout)
        report.update(status="PASS", records=3072, records_sha256=digest(result.stdout),
                      phase="complete",
                      limits=["Eight complete unchanged source functions; polling path only",
                              "Clock/register/peripheral completion and PCI/runtime/locking services modeled",
                              "C error policy does not calculate wire CRC; native independent CRC peers do",
                              "Native additionally stages output through cleanup/actual PCI guard/deadline"])
    except BaseException as error:
        report["failure"] = type(error).__name__ + ": " + str(error)
        raise
    finally:
        save()


if __name__ == "__main__":
    main()

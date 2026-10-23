#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Execute unchanged pinned UAS reset and SCSI block-zero read bodies.

Usage: usb_uas_recovery_oracle.py SOURCE_DIRECTORY NEW_OUTPUT_DIRECTORY
The source directory contains uas.c and sd.c from the pinned Linux commit.
USB locking, anchored-transfer kills and the physical reset are recorded
callbacks, not a Linux kernel, actual USB device, or DMA retirement oracle.
The native xHCI models independently check actual ring/event retirement.
"""
import hashlib
import json
from pathlib import Path
import subprocess
import sys


source, output = map(Path, sys.argv[1:])
pins = {
    "uas.c": "82d61ee8016f4d3a377f963df789f54dcf27aa1719f0f164bc01c7b873d07373",
    "sd.c": "c5b311837a5193158c81aee879e229527b575fb2b6faef8e92dadaa8b87b4fa2",
}
donors = {}
for name, digest in pins.items():
    data = (source / name).read_bytes()
    assert hashlib.sha256(data).hexdigest() == digest, name
    donors[name] = data.decode()


def function(text, declaration):
    start = text.index(declaration)
    opening = text.index("{", start)
    depth = 1
    cursor = opening + 1
    while depth:
        depth += (text[cursor] == "{") - (text[cursor] == "}")
        cursor += 1
    return text[start:cursor]


reset = function(donors["uas.c"], "static int uas_eh_host_reset_handler(")
block_zero = function(donors["sd.c"], "static void sd_read_block_zero(")
output.mkdir(parents=True, exist_ok=False)
harness = output / "oracle.c"
harness.write_text(r'''// Original Linux function bodies retain GPL-2.0-only terms.
// uas.c: Hans de Goede/Red Hat; Matthew Wilcox and Sarah Sharp/Intel.
// sd.c: Drew Eckhardt; Eric Youngdale. See source manifest.
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint8_t u8;
#define KERN_ERR ""
#define KERN_INFO ""
#define FAILED 1
#define SUCCESS 0
#define GFP_KERNEL 0
#define READ_10 0x28
#define READ_16 0x88
#define REQ_OP_DRV_IN 0
#define SD_TIMEOUT 30
#define shost_printk(...) ((void)0)
struct usb_device { int unused; };
struct uas_dev_info {
 struct usb_device *udev; void *intf;
 int lock, resetting, cmd_urbs, sense_urbs, data_urbs;
};
struct scsi_device {
 void *hostdata; void *host;
 unsigned int sector_size; int use_16_for_rw;
};
struct scsi_cmnd { struct scsi_device *device; };
struct scsi_disk { struct scsi_device *device; int max_retries; };
static struct uas_dev_info devinfo;
static int lock_failure, reset_failure;
static char events[16]; static unsigned event_count;
static FILE *trace;
static void record(char event) { assert(event_count < sizeof events); events[event_count++] = event; }
static int usb_lock_device_for_reset(struct usb_device *u, void *i) {
 assert(u == devinfo.udev && i == devinfo.intf); record('L'); return lock_failure;
}
static void usb_unlock_device(struct usb_device *u) {
 assert(u == devinfo.udev && !devinfo.resetting); record('U');
}
#define spin_lock_irqsave(lock, flags) do { (void)(lock); (flags)=0; } while(0)
#define spin_unlock_irqrestore(lock, flags) do { (void)(lock); (void)(flags); } while(0)
static void usb_kill_anchored_urbs(int *anchor) {
 assert(devinfo.resetting);
 record(anchor == &devinfo.cmd_urbs ? 'C' : anchor == &devinfo.sense_urbs ? 'S' : 'D');
}
static void uas_zap_pending(struct uas_dev_info *info, int result) {
 assert(info == &devinfo && result == 8 && info->resetting); record('Z');
}
#define DID_RESET 8
static int usb_reset_device(struct usb_device *u) {
 assert(u == devinfo.udev && devinfo.resetting); record('R'); return reset_failure;
}
static void *kmalloc(unsigned int bytes, int flags) { (void)flags; return malloc(bytes); }
static void kfree(void *bytes) { free(bytes); }
static void put_unaligned_be16(uint16_t v, u8 *p) { p[0]=v>>8; p[1]=v; }
static void put_unaligned_be32(uint32_t v, u8 *p) { for(int i=3;i>=0;--i){p[i]=v;v>>=8;} }
static void put_unaligned_be64(uint64_t v, u8 *p) { for(int i=7;i>=0;--i){p[i]=v;v>>=8;} }
static void le32(uint32_t v) { for(int i=0;i<4;++i){fputc(v&255,trace);v>>=8;} }
static int scsi_execute_cmd(struct scsi_device *s, u8 *cmd, int op, u8 *buffer,
 unsigned int bytes, int timeout, int retries, void *args) {
 assert(s && op == REQ_OP_DRV_IN && buffer && bytes == s->sector_size);
 assert(timeout == SD_TIMEOUT && retries == 0 && args == NULL);
 le32(bytes); fputc(s->use_16_for_rw,trace); fwrite(cmd,1,16,trace);
 return -1; // Original helper deliberately ignores a completed read error.
}
''' + reset + "\n" + block_zero + r'''
int main(int argc, char **argv) {
 assert(argc == 2); trace=fopen(argv[1],"wb");assert(trace);
 fwrite("UASRCV01",1,8,trace);
 struct usb_device usb={0}; struct scsi_device scsi={.hostdata=&devinfo};
 struct scsi_cmnd cmnd={.device=&scsi};
 devinfo.udev=&usb;
 for(int lock=0;lock<2;++lock) for(int reset=0;reset<2;++reset) {
  lock_failure=lock ? -1 : 0; reset_failure=reset ? -1 : 0; event_count=0;
  int result=uas_eh_host_reset_handler(&cmnd);
  assert(!devinfo.resetting);
  fputc(lock,trace); fputc(reset,trace); fputc(result,trace);
  fputc(event_count,trace); fwrite(events,1,event_count,trace);
 }
 struct scsi_disk disk={.device=&scsi};
 unsigned sizes[]={512,4096,65536};
 for(unsigned i=0;i<3;++i) for(int long_cdb=0;long_cdb<2;++long_cdb) {
  scsi.sector_size=sizes[i]; scsi.use_16_for_rw=long_cdb; sd_read_block_zero(&disk);
 }
 assert(fclose(trace)==0); return 0;
}
''')
binary = output / "oracle"
subprocess.run([
    "clang", "-std=c11", "-Wall", "-Wextra", "-Werror", "-O1",
    "-fsanitize=address,undefined", str(harness), "-o", str(binary),
], check=True)
trace = output / "trace.bin"
subprocess.run([str(binary), str(trace)], check=True)
(output / "manifest.json").write_text(json.dumps({
    "commit": "a804c5742bff224d4cb4d25dd383554d598be32b",
    "source_sha256": pins,
    "trace_sha256": hashlib.sha256(trace.read_bytes()).hexdigest(),
    "limitations": "USB/core callbacks recorded; no actual kernel/device/DMA",
}, indent=2) + "\n")

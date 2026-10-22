#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Run pinned UAS command-IU builders and the original unusual-device table.

Usage: usb_uas_oracle.py SOURCE_DIRECTORY NEW_OUTPUT_DIRECTORY
The directory contains uas.c, uas.h, scsi_common.c and unusual_uas.h from
Linux a804c5742bff224d4cb4d25dd383554d598be32b. No kernel/USB API is emulated:
unchanged field construction and int_to_scsilun run in a small native harness.
The complete unchanged unusual_uas.h is instantiated with a metadata macro.
"""
import hashlib
import json
from pathlib import Path
import subprocess
import sys

source, output = map(Path, sys.argv[1:])
pins = {
 'uas.c':'82d61ee8016f4d3a377f963df789f54dcf27aa1719f0f164bc01c7b873d07373',
 'uas.h':'49d4fc782b107874052143027fc487bc20e9eb5dc60d82b9dddbd8e99b9dd1d7',
 'scsi_common.c':'6312e1887e213e6eef7d786d2dcdf45776b33233d1ce2b721caa0a78a2d3b962',
 'unusual_uas.h':'82d294d79e5b87daddd4f771b736c46b0bfd629f1c545ac7886851b2f8a655aa',
}
for name, digest in pins.items():
 assert hashlib.sha256((source/name).read_bytes()).hexdigest()==digest,name
text=(source/'uas.c').read_text()
start=text.index('\tlen = cmnd->cmd_len - 16;',text.index('static struct urb *uas_alloc_cmd_urb'))
length=text[start:text.index('\n\tiu = kzalloc(',start)]
start=text.index('\tiu->iu_id = IU_ID_COMMAND;',start)
fields=text[start:text.index('\n\tusb_fill_bulk_urb(',start)]
common=(source/'scsi_common.c').read_text()
start=common.index('void int_to_scsilun(')
convert=common[start:common.index('\n}',start)+2]
header=(source/'uas.h').read_text().replace('#include <scsi/scsi.h>','').replace('#include <scsi/scsi_cmnd.h>','')
output.mkdir(parents=True,exist_ok=False)
(output/'unusual_uas.h').write_bytes((source/'unusual_uas.h').read_bytes())
c=output/'oracle.c'
c.write_text('''// Generated harness. Extracted UAS GPL-2.0-only and SCSI source notices
// remain recorded in the source manifest; unusual table GPL-2.0-or-later.
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error This harness requires a little-endian host
#endif
typedef uint8_t __u8;typedef uint16_t __be16;typedef uint64_t u64;
#define SCSI_SENSE_BUFFERSIZE 96
struct scsi_lun { unsigned char scsi_lun[8]; };
''' + header + '\n' + convert + '''
#define ALIGN(x,a) (((x)+(a)-1)&~((a)-1))
#define cpu_to_be16(x) __builtin_bswap16((uint16_t)(x))
struct scsi_cmnd { int cmd_len;unsigned char cmnd[260]; };
struct scsi_device { uint64_t lun; };
struct uas_cmd_info { uint16_t uas_tag; };
static struct command_iu *make(struct scsi_cmnd *cmnd,struct scsi_device *sdev,struct uas_cmd_info *cmdinfo) {
 struct command_iu *iu;int len;
''' + length + '''
 iu=calloc(1,sizeof(*iu)+len);assert(iu);
''' + fields + '''
 return iu;
}
#define US_FL_NO_REPORT_OPCODES 1
#define US_FL_NO_SAME 2
#define US_FL_IGNORE_UAS 4
#define US_FL_NO_REPORT_LUNS 8
#define US_FL_NO_ATA_1X 16
#define US_FL_BROKEN_FUA 32
#define US_FL_ALWAYS_SYNC 64
// UAS has no BOT CSW residue; this retained table flag has no wire effect here.
#define US_FL_IGNORE_RESIDUE 0
#define UNUSUAL_DEV(v,p,lo,hi,vs,ps,sc,pr,init,flags) {v,p,lo,hi,flags}
static const struct entry {uint16_t v,p,lo,hi;uint8_t flags;} entries[]={
#include "unusual_uas.h"
};
static void le16(FILE*f,uint16_t n){fputc(n&255,f);fputc(n>>8,f);}
int main(int argc,char **argv) {
 assert(argc==2);FILE*f=fopen(argv[1],"wb");assert(f);fwrite("UASRAW01",1,8,f);
 const uint16_t tags[]={1,0x100,0x7fff,0xffff};const uint64_t luns[]={0,1,15,255,0x4000,0xffff,0x00010002,0xffff000000000003ULL};const unsigned sizes[]={1,6,10,16,17,31,32,255,260};
 unsigned cases=0;
 for(unsigned t=0;t<4;t++) for(unsigned l=0;l<8;l++) for(unsigned n=0;n<9;n++) {
  struct scsi_cmnd cmnd={.cmd_len=sizes[n]};for(unsigned i=0;i<sizes[n];i++)cmnd.cmnd[i]=(unsigned char)(i*13+n*17+l);
  struct scsi_device sdev={.lun=luns[l]};struct uas_cmd_info info={.uas_tag=tags[t]};struct command_iu *iu=make(&cmnd,&sdev,&info);
  unsigned length=sizeof(*iu)+iu->len;assert(sizeof(*iu)==32);le16(f,tags[t]);le16(f,sizes[n]);fwrite(iu->lun.scsi_lun,1,8,f);le16(f,length);fwrite(cmnd.cmnd,1,sizes[n],f);fwrite(iu,1,length,f);free(iu);cases++;
 }
 assert(cases==288);fwrite("POLICY24",1,8,f);assert(sizeof(entries)/sizeof(entries[0])==24);
 for(unsigned i=0;i<24;i++){const struct entry*e=&entries[i];le16(f,e->v);le16(f,e->p);le16(f,e->lo);le16(f,e->hi);fputc(e->flags,f);}
 assert(!fclose(f));return 0;
}
''')
exe=output/'oracle';trace=output/'trace.bin'
subprocess.run(['clang','-std=c11','-O1','-g','-Wall','-Wextra','-Werror','-Wno-sign-compare','-fsanitize=address,undefined','-fno-omit-frame-pointer',str(c),'-o',str(exe)],check=True)
subprocess.run([str(exe),str(trace)],check=True)
paths=[source/name for name in pins]+[c,exe,trace,output/'unusual_uas.h']
items=[dict(path=str(p.resolve()),bytes=p.stat().st_size,sha256=hashlib.sha256(p.read_bytes()).hexdigest()) for p in paths]
(output/'receipt.json').write_text(json.dumps(dict(command_cases=288,policy_rows=24,artifacts=items),indent=2)+'\n')
print(trace)

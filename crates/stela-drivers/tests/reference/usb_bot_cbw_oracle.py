#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Execute unchanged pinned Linux CBW construction, retaining complete wrappers.

Usage: usb_bot_cbw_oracle.py TRANSPORT_C USB_STORAGE_H OUTPUT_DIRECTORY
The inputs are from Linux a804c5742bff224d4cb4d25dd383554d598be32b.
Only the surrounding SCSI structures, endian macro and trace I/O are harnesses.
The actual wrapper field assignments/memcpy block and USB wrapper struct/macros
are extracted unchanged. This checks bytes, not real USB hardware or recovery.
"""
import hashlib
import json
from pathlib import Path
import subprocess
import sys

transport, header, output = map(Path, sys.argv[1:])
expected = {
    transport: 'd0f3e12e12db2b9912252c54eea9673183aa3a1095a18b3e96e2bdd2680210e9',
    header: 'b0a64313842229a8a7ba67e3fa7d4e3fb560fea1dc402f6b5c85af8a87de3b22',
}
for path, digest in expected.items():
    assert hashlib.sha256(path.read_bytes()).hexdigest() == digest, path
source = transport.read_text()
start = source.index('\t/* set up the command wrapper */', source.index('int usb_stor_Bulk_transport('))
end = source.index('\n\t/* send it to out endpoint */', start)
block = source[start:end]
h = header.read_text()
struct_start = h.index('struct bulk_cb_wrap {')
struct_end = h.index('\n/* command status wrapper */', struct_start)
wrapper = h[struct_start:struct_end]
output.mkdir(parents=True, exist_ok=False)
c = output / 'oracle.c'
c.write_text('''// Generated harness; extracted donor blocks retain upstream notices.
// transport.c GPL-2.0-or-later, Matthew Dharm and contributors;
// include/linux/usb/storage.h GPL-2.0-only, Matthew Wilcox/Intel Corp 2010.
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error This trace harness requires a little-endian machine
#endif
typedef uint32_t __le32; typedef uint32_t __u32; typedef uint8_t __u8;
#define cpu_to_le32(x) ((uint32_t)(x))
#define unlikely(x) (x)
#define DMA_FROM_DEVICE 1
#define US_FL_SCM_MULT_TARG 1
''' + wrapper + '''
struct device { unsigned char lun, id; };
struct scsi_cmnd { struct device *device; int sc_data_direction; unsigned char cmd_len; unsigned char cmnd[16]; };
struct us_data { unsigned int tag, fflags; };
static void run(struct bulk_cb_wrap *bcb, struct scsi_cmnd *srb, struct us_data *us, unsigned int transfer_length) {
''' + block + '''
}
static void le32(FILE *f, uint32_t v) { for (int i=0;i<4;i++) fputc((v>>(8*i))&255,f); }
int main(int argc, char **argv) {
 assert(argc==2);FILE *f=fopen(argv[1],"wb");assert(f);fwrite("BOTCBW01",1,8,f);
 unsigned int lengths[]={0,1,8,13,36,512,32768,65536};
 unsigned int tags[]={0,1,0x7fffffff,0xffffffff};
 unsigned char sizes[]={1,6,10,12,15,16};
 unsigned int cases=0;
 for (unsigned lun=0;lun<16;lun++) for(unsigned n=0;n<8;n++) for(unsigned input=0;input<2;input++) for(unsigned t=0;t<4;t++) for(unsigned k=0;k<6;k++) {
  struct bulk_cb_wrap cbw;memset(&cbw,0xa5,sizeof(cbw));
  struct device dev={.lun=lun,.id=0};struct us_data us={.tag=tags[t]-1,.fflags=0};
  struct scsi_cmnd srb={.device=&dev,.sc_data_direction=input?DMA_FROM_DEVICE:0,.cmd_len=sizes[k]};
  for(unsigned b=0;b<16;b++) srb.cmnd[b]=(unsigned char)(lun*17+b*13+n);
  run(&cbw,&srb,&us,lengths[n]);
  le32(f,tags[t]);fputc(lun,f);fputc(sizes[k],f);fputc(input,f);le32(f,lengths[n]);fwrite(srb.cmnd,1,16,f);fwrite(&cbw,1,US_BULK_CB_WRAP_LEN,f);cases++;
 }
 assert(cases==6144);assert(!fclose(f));return 0;
}
''')
exe = output / 'oracle'
subprocess.run(['clang','-std=c11','-O1','-g','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-fno-omit-frame-pointer',str(c),'-o',str(exe)],check=True)
trace = output / 'trace.bin'
subprocess.run([str(exe),str(trace)],check=True)
items=[]
for path in [transport,header,c,exe,trace]:
    items.append(dict(path=str(path.resolve()),bytes=path.stat().st_size,sha256=hashlib.sha256(path.read_bytes()).hexdigest()))
(output/'receipt.json').write_text(json.dumps(dict(cases=6144,artifacts=items),indent=2)+'\n')
print(trace)

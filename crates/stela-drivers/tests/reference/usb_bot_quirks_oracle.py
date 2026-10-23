#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only AND GPL-2.0-or-later
"""Expand the unchanged pinned Linux unusual-device tables and flag definitions.

Usage: usb_bot_quirks_oracle.py LINUX_SOURCE_ROOT NEW_OUTPUT_DIRECTORY
This executes original table/flag preprocessing, not physical USB operations.
The surrounding trace serializer and supported-profile predicate are harnesses.
"""
import hashlib
import json
from pathlib import Path
import subprocess
import sys

root, output = map(Path, sys.argv[1:])
expected = {
    'drivers/usb/storage/unusual_devs.h': 'e68fd51762f3eb42fccd930d254b0b233f2e3ae7a99add7fdf58d9a1a29470e0',
    'drivers/usb/storage/unusual_uas.h': '82d294d79e5b87daddd4f771b736c46b0bfd629f1c545ac7886851b2f8a655aa',
    'include/linux/usb_usual.h': '6318f0c0e03479d6987114c48f65eb803461e871f78ad2462cba3a83c323f8c6',
    'include/linux/usb/storage.h': 'b0a64313842229a8a7ba67e3fa7d4e3fb560fea1dc402f6b5c85af8a87de3b22',
}
for name, digest in expected.items():
    assert hashlib.sha256((root / name).read_bytes()).hexdigest() == digest, name
usual = (root / 'include/linux/usb_usual.h').read_text()
# Retain original US_DO_ALL_FLAGS and enum expansion, omit only its include and
# kernel-only forward declarations. The original USB header supplies constants.
flags = usual[:usual.index('#include <linux/usb/storage.h>')] + '\n#endif\n'
output.mkdir(parents=True, exist_ok=False)
source = output / 'oracle.c'
source.write_text('''// Linux notices and SPDX identities remain in included donor files.
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
typedef uint32_t __le32; typedef uint32_t __u32; typedef uint8_t __u8;
''' + flags + '\n#include "' + str((root / 'include/linux/usb/storage.h').resolve()) + '''"
#define IS_ENABLED(x) 1
#define UNUSUAL_DEV(v,p,lo,hi,vn,pn,sc,pr,init,flags) {v,p,lo,hi,flags,sc,pr,#init}
#define COMPLIANT_DEV UNUSUAL_DEV
#define USUAL_DEV(sc,pr) {0,0,0,0,0,sc,pr,"NULL"}
struct entry { uint16_t v,p,lo,hi; uint32_t flags; uint8_t sc,pr; const char *init; };
static const struct entry entries[] = {
#include "''' + str((root / 'drivers/usb/storage/unusual_devs.h').resolve()) + '''"
};
static void le(FILE *f,uint32_t v,unsigned count) { while(count--) { fputc(v&255,f); v>>=8; } }
int main(int argc,char **argv) {
 assert(argc==2); FILE *f=fopen(argv[1],"wb");assert(f);fwrite("BOTQUI01",1,8,f);
 unsigned rows=0;
 for(unsigned n=0;n<sizeof(entries)/sizeof(entries[0]);n++) {
  const struct entry *e=&entries[n];if(!e->v && !e->p) continue;rows++;le(f,e->v,2);le(f,e->p,2);le(f,e->lo,2);le(f,e->hi,2);le(f,e->flags,4);
  fputc((e->sc!=USB_SC_DEVICE && e->sc!=USB_SC_SCSI) || (e->pr!=USB_PR_DEVICE && e->pr!=USB_PR_BULK) || strcmp(e->init,"NULL")!=0,f);
 }
 assert(rows==347);assert(!fclose(f));return 0;
}
''')
exe = output / 'oracle'
subprocess.run(['clang', '-std=c11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                '-fsanitize=address,undefined', '-fno-omit-frame-pointer', str(source), '-o', str(exe)], check=True)
trace = output / 'trace.bin'
subprocess.run([str(exe), str(trace)], check=True)
items = [root / name for name in expected] + [source, exe, trace]
(output / 'manifest.json').write_text(json.dumps([
    dict(path=str(p.resolve()), bytes=p.stat().st_size, sha256=hashlib.sha256(p.read_bytes()).hexdigest())
    for p in items], indent=2) + '\n')
print(trace)

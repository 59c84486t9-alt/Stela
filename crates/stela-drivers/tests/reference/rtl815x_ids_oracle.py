#!/usr/bin/env python3
"""Compile the unchanged pinned r8152 USB ID table; keep output ignored."""
import hashlib
from pathlib import Path
import re
import subprocess
import sys

source, header, out = map(Path, sys.argv[1:])
assert hashlib.sha256(source.read_bytes()).hexdigest() == "9d766f203c7fdabe6449e8dd2b9e5dd4fccfa20a62aa5dbf00d64c0c475c5a9f"
assert hashlib.sha256(header.read_bytes()).hexdigest() == "2d171ccd1779082dfcb4e2663e0127844acd1d67b0358ef1ed2eadb6510f06e0"
out.mkdir(parents=True, exist_ok=True)
table = re.search(r"static const struct usb_device_id rtl8152_table\[\] = \{.*?\n\};", source.read_text(), re.S).group()
# A driver_info or additional match flag must never be discarded by a table
# conversion. Refuse source entries other than these exact USB_DEVICE pairs.
entries = re.sub(r"/\*.*?\*/", "", table[table.index("{") + 1:table.rindex("}")], flags=re.S)
assert len(re.findall(r"\{ USB_DEVICE\(VENDOR_ID_\w+,\s*0x[0-9a-f]+\) \},", entries)) == 34
assert not re.sub(r"\{ USB_DEVICE\(VENDOR_ID_\w+,\s*0x[0-9a-f]+\) \},|\{\}|\s", "", entries)
defines = "\n".join(re.findall(r"^#define\s+VENDOR_ID_\w+\s+0x[0-9a-f]+", header.read_text(), re.M))
prelude = '''// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2014 Realtek Semiconductor Corp. All rights reserved.
// Copyright (c) 2020 Realtek Semiconductor Corp. All rights reserved.
#include <stdint.h>
#include <stdio.h>
struct usb_device_id { uint16_t vendor, product; };
#define USB_DEVICE(v,p) .vendor=(v),.product=(p)
'''
main = '''
int main(void) {
 for(unsigned i=0;rtl8152_table[i].vendor;i++)
  printf("%04x %04x\\n",rtl8152_table[i].vendor,rtl8152_table[i].product);
 return 0;
}
'''
unit = out / "linux-rtl815x-ids.c"
unit.write_text(prelude + defines + "\n" + table + main)
exe = out / "linux-rtl815x-ids"
subprocess.run(["cc", "-std=gnu11", "-O1", "-g", "-fsanitize=address,undefined", str(unit), "-o", str(exe)], check=True)
with (out / "ids.txt").open("wb") as trace:
    subprocess.run([str(exe.resolve())], stdout=trace, check=True)
print(out / "ids.txt")

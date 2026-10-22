#!/usr/bin/env python3
"""Compile complete unchanged legacy ASIX ID table and local driver_info bodies.

Callback tokens are metadata, not executed substitutes. The separately defined
AX88172A info is deliberately opaque/unimplemented; no such ID is admitted.
"""
import hashlib
from pathlib import Path
import re
import subprocess
import sys
source,header,asix_header,out=map(Path,sys.argv[1:])
for p,d in [(source,"b908ea9c09c7981c215c6ed2647b8facb83fa4b676e1cefda2b135968cfbb00a"),(header,"42fefd71077979bac698b5491037ebe8be5971223a6ad2cfaadcc193e806a6c2"),(asix_header,"4d04e4b63d0884bce00d5d8a8bf01504e4114b844d875d2bc79dc24f6d29b278")]:assert hashlib.sha256(p.read_bytes()).hexdigest()==d
out.mkdir(parents=True,exist_ok=True);text=source.read_text()
infos=re.findall(r"static const struct driver_info \w+ = \{.*?\n\};",text,re.S);assert len(infos)==10
products=re.search(r"static const struct usb_device_id\s+products\s*\[\] = \{.*?\n\};",text,re.S).group()
flags="\n".join(re.findall(r"^#define FLAG_(?:ETHER|FRAMING_AX|LINK_INTR|MULTI_PACKET)\b[^\n]*",header.read_text(),re.M))
flags+="\n"+re.search(r"^#define FLAG_EEPROM_MAC\b[^\n]*",asix_header.read_text(),re.M).group()
callbacks=["ax88172_bind","asix_status","ax88172_link_reset","ax88772_bind","ax88772_unbind","ax88772_reset","ax88772_stop","asix_rx_fixup_common","asix_tx_fixup","ax88178_bind","ax88178_unbind","ax88178_link_reset","ax88178_reset"]
prelude='''// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2003-2006 David Hollis; 2005 Phil Chang;
// 2006 James Painter; 2002-2003 TiVo Inc.
// usbnet.h flag definitions: Copyright (C) 2000-2005 David Brownell;
// Copyright (C) 2003-2005 David Hollis.
#include <stdio.h>
struct driver_info{const char*description;unsigned long bind,unbind,status,link_reset,reset,stop,flags,rx_fixup,tx_fixup,data;};
struct usb_device_id{unsigned vendor,product;unsigned long driver_info;};
#define USB_DEVICE(v,p) .vendor=v,.product=p
// External AX88172A initializer is not source-copied or claimed implemented.
static const struct driver_info ax88172a_info={0};
'''+"\n".join(f"#define {name} {i+1}"for i,name in enumerate(callbacks))+"\n"
main=r'''
int main(void){for(unsigned i=0;products[i].vendor;i++){
 const struct usb_device_id*p=&products[i];const struct driver_info*d=(void*)p->driver_info;
 printf("%04x %04x %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu\n",p->vendor,p->product,d->bind,d->unbind,d->status,d->link_reset,d->reset,d->stop,d->flags,d->rx_fixup,d->tx_fixup,d->data);
}}
'''
unit=out/"linux-asix-legacy-ids.c";unit.write_text(prelude+flags+"\n"+"\n".join(infos)+"\n"+products+main)
exe=out/"linux-asix-legacy-ids"
subprocess.run(["cc","-std=gnu11","-O1","-g","-fsanitize=address,undefined",str(unit),"-o",str(exe)],check=True)
with(out/"ids.txt").open("wb")as f:subprocess.run([str(exe.resolve())],stdout=f,check=True)
print(out/"ids.txt")

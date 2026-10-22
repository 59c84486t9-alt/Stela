#!/usr/bin/env python3
"""Compile unchanged ASIX USB/interface and driver_info initializers.

Callback names are explicit numeric fixture identities, not executed substitutes.
Unknown callbacks/fields/flags fail compilation instead of being discarded.
"""
import hashlib
from pathlib import Path
import re
import subprocess
import sys
source,header,out=map(Path,sys.argv[1:])
assert hashlib.sha256(source.read_bytes()).hexdigest()=="fa49b818e1051cf13e765792a8a386aa828e4ac9bd516f16c2b134c6edf6a6c8"
assert hashlib.sha256(header.read_bytes()).hexdigest()=="42fefd71077979bac698b5491037ebe8be5971223a6ad2cfaadcc193e806a6c2"
flag_defines="\n".join(re.findall(r"^#define FLAG_(?:ETHER|FRAMING_AX)\b[^\n]*",header.read_text(),re.M))
assert len(flag_defines.splitlines())==2
text=source.read_text();out.mkdir(parents=True,exist_ok=True)
infos=re.findall(r"static const struct driver_info \w+ = \{.*?\n\};",text,re.S)
assert len(infos)==13
products=re.search(r"static const struct usb_device_id products\[\] = \{.*?\n\};",text,re.S).group()
prelude=r'''// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2011-2013 ASIX
// Copyright (C) 2000-2005 David Brownell
// Copyright (C) 2003-2005 David Hollis
#include <stdio.h>
#include <stdint.h>
#define ax88179_bind 1
#define ax88179_unbind 2
#define ax88179_status 3
#define ax88179_link_reset 4
#define ax88179_net_reset 5
#define ax88179_stop 6
#define ax88179_rx_fixup 7
#define ax88179_tx_fixup 8
struct driver_info{const char*description;unsigned long bind,unbind,status,link_reset,reset,stop,flags,rx_fixup,tx_fixup;};
struct usb_device_id{unsigned vendor,product,cls,sub,proto;unsigned long driver_info;};
#define USB_DEVICE_AND_INTERFACE_INFO(v,p,c,s,r) .vendor=v,.product=p,.cls=c,.sub=s,.proto=r
'''
main=r'''
int main(void){
 for(unsigned i=0;products[i].vendor;i++){
  const struct usb_device_id*p=&products[i];const struct driver_info*d=(void*)p->driver_info;
  printf("%04x %04x %u %u %u %lu %lu %lu %lu %lu %lu %lu %lu %lu\n",p->vendor,p->product,p->cls,p->sub,p->proto,d->flags,d->bind,d->unbind,d->status,d->link_reset,d->reset,d->stop,d->rx_fixup,d->tx_fixup);
 }
 return 0;
}
'''
unit=out/"linux-asix-ids.c";unit.write_text(prelude+"\n"+flag_defines+"\n"+"\n".join(infos)+"\n"+products+main)
exe=out/"linux-asix-ids"
subprocess.run(["cc","-std=gnu11","-O1","-g","-fsanitize=address,undefined",str(unit),"-o",str(exe)],check=True)
with(out/"ids.txt").open("wb")as f:subprocess.run([str(exe.resolve())],stdout=f,check=True)
print(out/"ids.txt")

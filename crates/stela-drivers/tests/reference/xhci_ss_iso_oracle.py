#!/usr/bin/env python3
"""Compile unchanged pinned Linux SS isoch burst/Mult helpers; no hardware claim.
Usage: xhci_ss_iso_oracle.py FLAT_REFERENCE_DIRECTORY NEW_OUTPUT_DIRECTORY
The fixture supplies USB object layouts and predicates; it does not replace the
three algorithms under comparison. USB2 double-bandwidth ECN remains outside scope.
"""
import ast
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

source, out = map(Path, sys.argv[1:])
expected = {
    'xhci-mem.c': 'abfe6f6f70bdeaf7a279a734bdab034ef014f329785ccb8c5f5cf3e763320198',
    'xhci-ring.c': '8c15822f3e118fc5ee9e647b5fc82f75d72f51519f1d9f6dee96d222fe6c9882',
}
texts = {}
for name, digest in expected.items():
    raw = (source / name).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == digest, name
    texts[name] = raw.decode()
out.mkdir(parents=True, exist_ok=False)
fragments = []


def function(file, name):
    text = texts[file]
    match = re.search(r'^static\s+(?:unsigned int|u32)\s+' + name + r'\([^;{}]*?\)\n\{', text, re.M)
    assert match, name
    at, depth = match.end(), 1
    while depth:
        depth += (text[at] == '{') - (text[at] == '}')
        at += 1
    value = text[match.start():at]
    fragments.append(dict(file=file, name=name, sha256=hashlib.sha256(value.encode()).hexdigest()))
    return value


tree = ast.parse(Path(__file__).with_name('xhci_endpoint_oracle.py').read_text())
prelude = next(ast.literal_eval(n.value) for n in tree.body if isinstance(n, ast.Assign)
               and any(isinstance(t, ast.Name) and t.id == 'prelude' for t in n.targets))
prelude = prelude.replace('unsigned char bMaxBurst;', 'unsigned char bMaxBurst, bmAttributes;')
prelude += r'''
#define HCC2_LEC (1u << 4)
#define XHCI_INTEL_HOST 1u
#define DIV_ROUND_UP(x,y) (((x)+(y)-1)/(y))
struct xhci_hcd { unsigned hci_version, hcc_params2, quirks; };
struct urb { struct usb_device *dev; struct usb_host_endpoint *ep; };
'''
body = function('xhci-mem.c', 'xhci_get_endpoint_mult') + '\n' + '\n'.join(
    function('xhci-ring.c', name) for name in
    ['xhci_get_burst_count', 'xhci_get_last_burst_packet_count'])
main = r'''
int main(void) {
 for(unsigned speed=USB_SPEED_SUPER;speed<=USB_SPEED_SUPER_PLUS;speed++)
 for(unsigned lec=0;lec<2;lec++)for(unsigned burst=0;burst<16;burst++)
 for(unsigned mult=0;mult<3;mult++) {
  struct xhci_hcd x={.hci_version=0x110,.hcc_params2=lec?HCC2_LEC:0};
  struct usb_device u={.speed=speed};
  struct usb_host_endpoint e={.desc={.bmAttributes=1},
      .ss_ep_comp={.bMaxBurst=burst,.bmAttributes=mult}};
  struct urb urb={.dev=&u,.ep=&e};
  for(unsigned packets=1;packets<=(burst+1)*(mult+1);packets++)
   printf("B %u %u %u %u %u %u %u %u\n",speed,lec,burst,mult,packets,
       xhci_get_endpoint_mult(&x,&u,&e),xhci_get_burst_count(&x,&urb,packets),
       xhci_get_last_burst_packet_count(&x,&urb,packets));
 }
 return 0;
}
'''
unit = out / 'linux-xhci-ss-iso.c'
unit.write_text(prelude + '\n' + body + '\n' + main)
exe = out / 'linux-xhci-ss-iso'
subprocess.run(['cc', '-std=gnu11', '-O1', '-g', '-fsanitize=address,undefined',
                str(unit), '-o', str(exe)], check=True)
with (out / 'trace.txt').open('wb') as trace:
    subprocess.run([str(exe.resolve())], stdout=trace, check=True)
trace = (out / 'trace.txt').read_bytes()
(out / 'receipt.json').write_text(json.dumps(dict(
    revision='a804c5742bff224d4cb4d25dd383554d598be32b', donors=expected,
    functions=fragments, trace_sha256=hashlib.sha256(trace).hexdigest(),
    rows=len(trace.splitlines())), indent=2) + '\n')
print(hashlib.sha256(trace).hexdigest(), len(trace.splitlines()))

#!/usr/bin/env python3
"""Reproduce six unchanged Linux stream helpers and their pinned wire macros.

Usage: python3 xhci_streams_oracle.py FLAT_DONOR_DIRECTORY NEW_OUTPUT_DIRECTORY
The C fixture supplies only prevalidated endpoint objects; it does not implement
Linux USB admission, hardware access, DMA completion or stop/reset. Those paths
have native adverse DMA/controller models. Generated files stay ignored.
"""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

source, out = map(Path, sys.argv[1:])
expected = {
    "xhci.c": "dbc9e7c61efdf32566145eadc70ad3a255f3be08e811dad053b321ea11df8062",
    "xhci-mem.c": "abfe6f6f70bdeaf7a279a734bdab034ef014f329785ccb8c5f5cf3e763320198",
    "xhci-ring.c": "8c15822f3e118fc5ee9e647b5fc82f75d72f51519f1d9f6dee96d222fe6c9882",
    "xhci.h": "44ca06ce699192d60302896df23ef3ee243abe979ac5f3c759de9830ec311cc0",
    "xhci-caps.h": "096eb25ef1cceefe6a54f0e661b585ac19fa102db9b9807c4073c660cd452b43",
    "ch9.h": "56ac789006af0e76a0cdfc671540aabc8da3f1edcab0c034518e2314c3e72ff8",
}
text = {}
for name, sha in expected.items():
    raw = (source / name).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == sha, name
    text[name] = raw.decode()
out.mkdir(parents=True, exist_ok=False)
fragments = []


def function(file, name):
    match = re.search(r"^(?:static\s+)?(?:inline\s+)?(?:unsigned\s+int|void|int)\s+" + name + r"\([^;{}]*?\)\n\{", text[file], re.M)
    assert match, (file, name)
    at, depth = match.end(), 1
    while depth:
        depth += (text[file][at] == "{") - (text[file][at] == "}")
        at += 1
    body = text[file][match.start():at]
    fragments.append(dict(file=file, name=name, start=match.start(), end=at,
                          sha256=hashlib.sha256(body.encode()).hexdigest()))
    return body


def structure(file, name):
    start = text[file].index("struct " + name + " {")
    end = text[file].index(";", text[file].index("}", start)) + 1
    return text[file][start:end]


def macro(file, name):
    match = re.search(r"^#define\s+" + name + r"\b[^\n]*(?:\\\n[^\n]*)*", text[file], re.M)
    assert match, (file, name)
    return match[0]


prelude = r'''
#include <stdint.h>
#include <stdio.h>
#include <assert.h>
typedef uint32_t u32;
typedef uint64_t u64;
typedef uint8_t __u8;
typedef uint16_t __le16;
typedef uint32_t __le32;
typedef uint64_t __le64;
#define BIT(n) (1u << (n))
#define GENMASK(h,l) ((~0u << (l)) & (~0u >> (31-(h))))
#define FIELD_GET(mask,value) (((value)&(mask)) >> __builtin_ctz(mask))
#define cpu_to_le32(n) (n)
#define cpu_to_le64(n) (n)
#define roundup_pow_of_two(n) (1u << (32 - __builtin_clz((n)-1)))
#define fls(n) ((n) ? 32 - __builtin_clz(n) : 0)
#define xhci_dbg(x,...) ((void)(x))
#define xhci_dbg_trace(x,...) ((void)(x))
#define EINVAL 22
struct xhci_hcd { u32 hcc_params; };
struct usb_device { unsigned slot_id; };
struct xhci_stream_info { unsigned num_stream_ctxs; u64 ctx_array_dma; };
'''
structs = "\n".join([structure("ch9.h", "usb_endpoint_descriptor"),
                     structure("ch9.h", "usb_ss_ep_comp_descriptor"),
                     structure("xhci.h", "xhci_ep_ctx")])
compat = r'''
struct usb_host_endpoint { struct usb_endpoint_descriptor desc; struct usb_ss_ep_comp_descriptor ss_ep_comp; };
#define usb_endpoint_xfer_control(d) (((d)->bmAttributes & 3) == 0)
#define usb_endpoint_num(d) ((d)->bEndpointAddress & 15)
#define usb_endpoint_dir_in(d) ((d)->bEndpointAddress & 128)
/* Fixture admission only: every compared endpoint is valid, configured,
 * exclusively owned and empty. Native tests cover rejection/failure paths. */
static int xhci_check_streams_endpoint(struct xhci_hcd *x, struct usb_device *u,
        struct usb_host_endpoint *ep, unsigned slot) { return 0; }
'''
macros = "\n".join(macro(file, name) for file, name in [
    ("xhci-caps.h", "HCC_MAX_PSA"), ("xhci-caps.h", "GET_MAX_PSA_SIZE"),
    ("xhci.h", "EP_MAXPSTREAMS_MASK"), ("xhci.h", "EP_MAXPSTREAMS"),
    ("xhci.h", "EP_HAS_LSA"), ("xhci.h", "DB_VALUE"),
    ("xhci.h", "STREAM_ID_FOR_TRB"), ("xhci.h", "SCT_FOR_TRB"),
    ("xhci.h", "SCT_PRI_TR"),
])
functions = "\n\n".join(function(file, name) for file, name in [
    ("ch9.h", "usb_ss_max_streams"),
    ("xhci.c", "xhci_get_endpoint_index"),
    ("xhci.c", "xhci_get_endpoint_flag"),
    ("xhci.c", "xhci_calculate_streams_and_bitmask"),
    ("xhci.c", "xhci_calculate_streams_entries"),
    ("xhci-mem.c", "xhci_setup_streams_ep_input_ctx"),
])
main = r'''
int main(void) {
    unsigned requests[] = {1,2,3,4,7,8,15,16,31,32,63,64,127,128,1023,1024,65534,65535};
    for (unsigned h=0; h<16; h++) for (unsigned e=1; e<=16; e++)
    for (unsigned r=0; r<sizeof(requests)/sizeof(requests[0]); r++) {
        struct xhci_hcd x = { .hcc_params = h << 12 };
        if (GET_MAX_PSA_SIZE(x.hcc_params) < 4) continue;
        struct usb_device dev = { .slot_id = 1 };
        struct usb_host_endpoint first = { .desc = { .bEndpointAddress = 0x81, .bmAttributes = 2 }, .ss_ep_comp = { .bmAttributes = e } };
        struct usb_host_endpoint second = { .desc = { .bEndpointAddress = 2, .bmAttributes = 2 }, .ss_ep_comp = { .bmAttributes = (e+4 > 16 ? 16 : e+4) } };
        struct usb_host_endpoint *eps[] = { &first, &second };
        unsigned streams = requests[r] + 1, contexts = 0; u32 mask = 0;
        assert(xhci_calculate_streams_and_bitmask(&x, &dev, eps, 2, &streams, &mask) == 0);
        xhci_calculate_streams_entries(&x, &streams, &contexts);
        struct xhci_ep_ctx ctx = { .ep_info = 0x12800000, .deq = 0xffff };
        struct xhci_stream_info info = { .num_stream_ctxs = contexts, .ctx_array_dma = 0x123456780 };
        xhci_setup_streams_ep_input_ctx(&x, &ctx, &info);
        printf("S %u %u %u %u %u %u %llu %u\n", h,e,requests[r],streams-1,contexts,
            ctx.ep_info,(unsigned long long)ctx.deq,mask);
    }
    unsigned ids[] = {1,2,3,31,32,255,256,65535};
    for (unsigned d=2; d<32; d++) for (unsigned i=0; i<sizeof(ids)/sizeof(ids[0]); i++)
        printf("E %u %u %u %u %u\n",d,ids[i],DB_VALUE(d-1,ids[i]),STREAM_ID_FOR_TRB(ids[i]),SCT_FOR_TRB(SCT_PRI_TR));
    return 0;
}
'''
c = out / "oracle.c"
c.write_text("\n\n".join([prelude, structs, compat, macros, functions, main]))
compiler = ["clang", "-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
            "-Wno-unused-parameter", "-Wno-sign-compare", "-fsanitize=address,undefined", "-fno-sanitize-recover=all",
            str(c), "-o", str(out / "oracle")]
subprocess.run(compiler, check=True)
with (out / "trace.txt").open("wb") as output:
    subprocess.run([str(out / "oracle")], stdout=output, check=True)
(out / "extracted-functions.json").write_text(json.dumps(fragments, indent=2) + "\n")
raw = (out / "trace.txt").read_bytes()
print(json.dumps(dict(bytes=len(raw), rows=raw.count(b"\n"), sha256=hashlib.sha256(raw).hexdigest(), compiler=compiler)))

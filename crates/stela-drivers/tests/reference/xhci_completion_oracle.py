#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Execute unchanged pinned Linux one-TRB bulk/interrupt length accounting.

Usage: xhci_completion_oracle.py FLAT_DONOR_DIRECTORY NEW_OUTPUT_DIRECTORY
Only callbacks/context lookup are fixture boundaries. Soft retry is disabled as
in the source quirk; the original function handles success/short/stopped codes.
This is not a DMA retirement oracle: native controller models test that boundary.
Authored for the source-only driver assignment; execution remains UNRUN.
"""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

source, out = map(Path, sys.argv[1:])
expected = {
    "xhci-ring.c": "8c15822f3e118fc5ee9e647b5fc82f75d72f51519f1d9f6dee96d222fe6c9882",
    "xhci.h": "44ca06ce699192d60302896df23ef3ee243abe979ac5f3c759de9830ec311cc0",
}
text = {}
for name, digest in expected.items():
    raw = (source / name).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == digest, name
    text[name] = raw.decode()

name = "process_bulk_intr_td"
match = re.search(r"^static void " + name + r"\([^;{}]*?\)\n\{", text["xhci-ring.c"], re.M)
assert match
at, depth = match.end(), 1
while depth:
    depth += (text["xhci-ring.c"][at] == "{") - (text["xhci-ring.c"][at] == "}")
    at += 1
body = text["xhci-ring.c"][match.start():at]


def macro(name):
    for file in text.values():
        found = re.search(r"^#define\s+" + name + r"\b[^\n]*(?:\\\n[^\n]*)*", file, re.M)
        if found:
            return found[0]
    raise AssertionError(name)


prelude = r'''
#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
typedef uint32_t u32;
#define BIT_ULL(n) (1ull << (n))
#define le32_to_cpu(x) (x)
#define xhci_warn(x,...) ((void)(x))
#define xhci_dbg(x,...) ((void)(x))
struct urb { unsigned transfer_buffer_length, actual_length; };
union xhci_trb { struct { u32 field[4]; } generic; };
struct xhci_transfer_event { u32 transfer_len; };
struct xhci_td { struct urb *urb; union xhci_trb *end_trb; int status; };
struct xhci_slot_ctx { u32 tt_info; };
struct xhci_hcd { unsigned long long quirks; };
struct xhci_virt_ep { void *vdev; unsigned err_count; };
struct xhci_ring { unsigned unused; };
static struct xhci_slot_ctx context;
static struct xhci_slot_ctx *xhci_get_slot_ctx(struct xhci_hcd *x, void *v) { return &context; }
/* Exactly one TRB, so there are no preceding lengths to sum. */
static unsigned sum_trb_lengths(struct xhci_td *t, union xhci_trb *p) { return 0; }
static void xhci_handle_halted_endpoint(struct xhci_hcd *x, struct xhci_virt_ep *e,
        struct xhci_td *t, unsigned flags) { abort(); }
/* Observe original length/status accounting without claiming Linux hardware
 * dequeue, URB giveback, or a native cancellation ACK. */
static void finish_td(struct xhci_hcd *x, struct xhci_virt_ep *e,
        struct xhci_ring *r, struct xhci_td *t, u32 code) { }
'''
macros = "\n".join(macro(name) for name in [
    "COMP_CODE_MASK", "GET_COMP_CODE", "EVENT_TRB_LEN", "TRB_LEN", "COMP_SUCCESS",
    "COMP_SHORT_PACKET", "COMP_STOPPED", "COMP_STOPPED_SHORT_PACKET", "COMP_STOPPED_LENGTH_INVALID",
    "COMP_USB_TRANSACTION_ERROR", "XHCI_NO_SOFT_RETRY", "MAX_SOFT_RETRY",
    "TT_SLOT",
])
reset_type = re.search(r"enum xhci_ep_reset_type \{[^}]+\};", text["xhci.h"])
assert reset_type
main = r'''
int main(void) {
    unsigned sizes[] = {0, 1, 16, 64, 512, 4096, 65536};
    unsigned codes[] = {COMP_SUCCESS, COMP_SHORT_PACKET, COMP_STOPPED, COMP_STOPPED_SHORT_PACKET};
    for (unsigned c=0; c<4; c++) for (unsigned s=0; s<7; s++) {
        unsigned length=sizes[s];
        for (unsigned residual=0; residual<=length; residual++) {
            struct xhci_hcd x = { .quirks=XHCI_NO_SOFT_RETRY };
            struct xhci_virt_ep ep = {0}; struct xhci_ring ring = {0};
            union xhci_trb trb = { .generic.field={0,0,length,0} };
            struct urb urb = { .transfer_buffer_length=length, .actual_length=123 };
            struct xhci_td td = { .urb=&urb, .end_trb=&trb, .status=-123 };
            struct xhci_transfer_event event = { .transfer_len=codes[c]<<24 | residual };
            process_bulk_intr_td(&x,&ep,&ring,&td,&trb,&event);
            assert(urb.actual_length == (c==3 ? residual : length-residual));
            assert(td.status == (c<2 ? 0 : -123));
            printf("%c %u %u %u %u\n",c<2 ? 'B' : 'C',codes[c],length,residual,urb.actual_length);
        }
    }
}
'''
out.mkdir(parents=True, exist_ok=False)
c = out / "oracle.c"
c.write_text("\n\n".join([prelude, macros, reset_type[0], body, main]))
compiler = ["clang", "-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
            "-Wno-unused-parameter", "-Wno-sign-compare", "-fsanitize=address,undefined",
            "-fno-sanitize-recover=all", str(c), "-o", str(out / "oracle")]
subprocess.run(compiler, check=True)
with (out / "trace.txt").open("w") as stream:
    subprocess.run([str(out / "oracle")], stdout=stream, check=True)
(out / "manifest.json").write_text(json.dumps({
    "revision": "a804c5742bff224d4cb4d25dd383554d598be32b", "donors": expected,
    "function": name, "sha256": hashlib.sha256(body.encode()).hexdigest(),
    "compiler": compiler, "scope": "one-TRB success/short/stopped byte accounting only",
}, indent=2) + "\n")

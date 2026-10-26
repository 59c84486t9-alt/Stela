#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Run the unchanged Linux USB mixer IRQ function against recorded callbacks.

Only callback classification and requeue policy are donor evidence. The native
xHCI/DMA ownership, graph validation and stronger atomic packet refusals have
separate Rust models. No URB stand-in establishes actual endpoint retirement.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

PIN = "cc9de5d4b5ab6459f5774946aa3195ad51236fa8"
DONORS = {
    "sound/usb/mixer.c": "eee06c847e152d9aba9b7efe4dcf56d17e7c933a7b67d4a6fe2f38ea365ed292",
    "include/uapi/linux/usb/audio.h": "d00a53ba5f0e75e485d7642bfc9a6a3d355429878804d6818aff217fe9508a2e",
    "include/linux/usb/audio-v2.h": "9e5608aa0d1117ce48c0ad573f080a81a57fef767ada6b72606beed30c1612ba",
}


def function(source, name):
    match = re.search(r"^static void " + name + r"\([^;]*?\n\{", source, re.M)
    if match is None:
        raise RuntimeError(f"missing donor function {name}")
    position = source.index("{", match.start())
    depth = 1
    end = position + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[match.start():end]


def structure(source, name):
    match = re.search(r"^struct " + name + r" \{.*?\} __attribute__\s*\(\(packed\)\);", source, re.M | re.S)
    if match is None:
        raise RuntimeError(f"missing donor structure {name}")
    return match[0]


def definitions(source, names):
    selected = []
    for name in names:
        match = re.search(r"^#define\s+" + name + r"\s+[^\n]+", source, re.M)
        if match is None:
            raise RuntimeError(f"missing donor definition {name}")
        selected.append(match[0])
    return "\n".join(selected)


PRELUDE = r'''
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef uint8_t __u8;
typedef uint16_t __le16;
#define le16_to_cpu(x) (x)
#define GFP_ATOMIC 0
#define dev_dbg(device, ...) ((void)(device))
struct usb_device { struct { unsigned unused; } dev; };
struct snd_usb_audio { struct usb_device *dev; };
struct usb_mixer_interface { int protocol; struct snd_usb_audio *chip; };
struct urb {
    void *context;
    int actual_length, status;
    void *transfer_buffer;
    struct usb_device *dev;
};
static unsigned controls, memories, queued, unit;
static void snd_usb_mixer_rc_memory_change(struct usb_mixer_interface *m, unsigned id) {
    (void)m; ++memories; unit = id;
}
static void snd_usb_mixer_notify_id(struct usb_mixer_interface *m, unsigned id) {
    (void)m; ++controls; unit = id;
}
static void snd_usb_mixer_interrupt_v2(struct usb_mixer_interface *m, int a, int v, int i) {
    (void)m; (void)a; (void)v; (void)i; assert(!"UAC2 outside oracle scope");
}
static void usb_submit_urb(struct urb *urb, int flags) {
    (void)urb; (void)flags; ++queued;
}
'''

RUNNER = r'''
int main(void) {
    struct usb_device dev = {0};
    struct snd_usb_audio chip = { .dev = &dev };
    struct usb_mixer_interface mixer = { .protocol = UAC_VERSION_1, .chip = &chip };
    unsigned char packet[8] = {0};
    struct urb urb = { .context = &mixer, .actual_length = 2, .status = 0,
        .transfer_buffer = packet, .dev = &dev };
    const unsigned origins[] = {0, 1, 2, 3, 4, 5, 99, 255};
    for (unsigned status = 0; status != 256; ++status) {
        for (unsigned i = 0; i != sizeof(origins)/sizeof(origins[0]); ++i) {
            packet[0] = status; packet[1] = origins[i];
            controls = memories = queued = unit = 0;
            snd_usb_mixer_interrupt(&urb);
            printf("word %u %u %u %u %u %u\n", status, origins[i], controls, memories, queued, unit);
        }
    }
    const int errors[] = {0, -ENOENT, -ECONNRESET, -ESHUTDOWN, -EPIPE, -EPROTO, -ETIMEDOUT};
    packet[0] = UAC1_STATUS_TYPE_IRQ_PENDING; packet[1] = 2;
    for (unsigned i = 0; i != sizeof(errors)/sizeof(errors[0]); ++i) {
        controls = memories = queued = unit = 0;
        urb.status = errors[i];
        snd_usb_mixer_interrupt(&urb);
        printf("error %d %u %u %u\n", errors[i], controls, memories, queued);
    }
    urb.status = 0;
    for (unsigned n = 0; n != 4; ++n) { packet[n*2] = 0x80; packet[n*2+1] = 2; }
    for (unsigned n = 0; n <= sizeof(packet); ++n) {
        controls = memories = queued = unit = 0;
        urb.actual_length = n;
        snd_usb_mixer_interrupt(&urb);
        printf("length %u %u %u %u\n", n, controls, memories, queued);
    }
    return 0;
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("reference", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--cc", default="clang")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    sources = {}
    for name, expected in DONORS.items():
        data = (args.reference / name).read_bytes()
        actual = hashlib.sha256(data).hexdigest()
        if actual != expected:
            raise RuntimeError(f"donor SHA-256 mismatch: {name}: {actual}")
        sources[name] = data.decode()
    # Keep the untouched function's UAC2 branch compilable, although the model
    # refuses to execute it. The exact layout/constants are extracted as well.
    v2 = sources["include/linux/usb/audio-v2.h"]
    body = function(sources["sound/usb/mixer.c"], "snd_usb_mixer_interrupt")
    v1 = sources["include/uapi/linux/usb/audio.h"]
    code = PRELUDE + definitions(v1, ["UAC_VERSION_1", "UAC1_STATUS_TYPE_ORIG_MASK",
        "UAC1_STATUS_TYPE_ORIG_AUDIO_CONTROL_IF", "UAC1_STATUS_TYPE_MEM_CHANGED",
        "UAC1_STATUS_TYPE_IRQ_PENDING"]) + "\n"
    code += structure(v1, "uac1_status_word") + "\n"
    code += definitions(v2, ["UAC2_INTERRUPT_DATA_MSG_VENDOR", "UAC2_INTERRUPT_DATA_MSG_EP"]) + "\n"
    code += structure(v2, "uac2_interrupt_data_msg") + "\n" + body + "\n" + RUNNER
    source_path = args.output / "oracle.c"
    source_path.write_text(code)
    # The original Linux function compares signed actual_length with sizeof;
    # preserve those bytes and narrowly match the kernel warning policy.
    command = [args.cc, "-std=gnu11", "-O1", "-g", "-Wall", "-Wextra", "-Werror", "-Wno-sign-compare",
        "-fsanitize=address,undefined", "-fno-omit-frame-pointer", str(source_path), "-o", str(args.output / "oracle")]
    with (args.output / "compile.log").open("w") as log:
        subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=30, check=True)
    with (args.output / "run.log").open("w") as log:
        result = subprocess.run([str(args.output / "oracle")], stdout=subprocess.PIPE,
            stderr=log, timeout=10, check=True)
    trace = f"linux {PIN}\n".encode() + result.stdout
    (args.output / "trace.txt").write_bytes(trace)
    receipt = {"pin": PIN, "donors": DONORS,
        "function_sha256": hashlib.sha256(body.encode()).hexdigest(),
        "source_sha256": hashlib.sha256(code.encode()).hexdigest(),
        "trace_sha256": hashlib.sha256(trace).hexdigest(),
        "records": len(result.stdout.splitlines()), "compile_command": command,
        "scope": "unchanged UAC1 callback classification and URB requeue; no native DMA ownership"}
    (args.output / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps(receipt, indent=2))


if __name__ == "__main__":
    main()

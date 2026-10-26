#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Execute original Linux get_connector_value on recorded control callbacks.

Only original request/boolean/error behavior is source evidence. Native code
requires an exact complete response and propagates errors, including speakers.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

from hda_unsolicited_oracle import function
from usb_audio_status_oracle import PIN, definitions, structure

DONORS = {
    "sound/usb/mixer.c": "eee06c847e152d9aba9b7efe4dcf56d17e7c933a7b67d4a6fe2f38ea365ed292",
    "include/uapi/linux/usb/audio.h": "d00a53ba5f0e75e485d7642bfc9a6a3d355429878804d6818aff217fe9508a2e",
    "include/linux/usb/audio-v2.h": "9e5608aa0d1117ce48c0ad573f080a81a57fef767ada6b72606beed30c1612ba",
    "include/linux/usb/audio-v3.h": "ca4967a7d8ad7494fbe9d5237c445018dba1194ac057ad451585799bbb521b95",
}
PRELUDE = r'''
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef uint8_t __u8; typedef uint32_t __le32;
#define USB_RECIP_INTERFACE 1
#define USB_TYPE_CLASS 0x20
#define USB_DIR_IN 0x80
struct snd_usb_audio { void *dev; };
struct usb_mixer_interface { struct snd_usb_audio *chip; unsigned protocol, interface; };
struct usb_mixer_elem_info { struct { struct usb_mixer_interface *mixer; unsigned id; } head; unsigned control, val_type; };
struct lock { int err; };
static struct lock new_lock(struct snd_usb_audio *c) { (void)c; return (struct lock){0}; }
#define CLASS(t,n) struct lock n = new_lock
#define usb_rcvctrlpipe(d,e) ((void)(d),(e))
#define usb_audio_err(c,...) ((void)(c))
static int mixer_ctrl_intf(struct usb_mixer_interface *m) { return m->interface; }
static int filter_error(struct usb_mixer_elem_info *c, int e) { (void)c; return e; }
static unsigned channel, request, value, request_index, bytes, request_type, calls;
static int reply_result;
static int snd_usb_ctl_msg(void *d, unsigned pipe, unsigned r, unsigned type,
    unsigned v, unsigned i, void *p, unsigned n) {
    (void)d; (void)pipe; ++calls; request=r; request_type=type; value=v; request_index=i; bytes=n;
    // A defined callback fills the whole object even for short/error records:
    // original code inspects it before checking ret. This does not establish
    // initialized bytes for a real failed/short Linux USB transfer.
    assert(n==6); memset(p,0,n); ((unsigned char *)p)[0]=channel;
    return reply_result;
}
'''
RUNNER = r'''
int main(void) {
    struct snd_usb_audio chip={0};
    struct usb_mixer_interface mixer={.chip=&chip,.protocol=UAC_VERSION_2};
    struct usb_mixer_elem_info c={.head={.mixer=&mixer},.control=UAC2_TE_CONNECTOR};
    for(unsigned interface=0;interface<2;interface++) for(unsigned entity=3;entity<5;entity++)
    for(channel=0;channel<256;channel++) for(unsigned failure=0;failure<3;failure++)
    for(unsigned speaker=0;speaker<2;speaker++) {
        mixer.interface=interface?7:0; c.head.id=entity;
        reply_result=failure==0?6:failure==1?5:-32; calls=0;
        int connected=-1;
        int result=get_connector_value(&c,speaker?"Speaker Jack":"Microphone Jack",&connected);
        assert(calls==1);
        printf("C %u %u %u %d %u %d %d %u %u %u %u %u\n",
            mixer.interface,entity,channel,reply_result,speaker,result,connected,
            request,request_type,value,request_index,bytes);
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
    for path, expected in DONORS.items():
        data = (args.reference / path).read_bytes()
        actual = hashlib.sha256(data).hexdigest()
        if actual != expected:
            raise RuntimeError(f"donor SHA-256 mismatch: {path}: {actual}")
        sources[path] = data.decode()
    body = function(sources["sound/usb/mixer.c"], "static int get_connector_value(")
    constants = definitions(sources["include/uapi/linux/usb/audio.h"], ["UAC_VERSION_2", "UAC_GET_", "UAC__CUR", "UAC_GET_CUR"])
    constants += "\n" + definitions(sources["include/linux/usb/audio-v2.h"], ["UAC2_CS_CUR", "UAC2_TE_CONNECTOR"])
    structures = structure(sources["include/linux/usb/audio-v2.h"], "uac2_connectors_ctl_blk")
    structures += "\n" + structure(sources["include/linux/usb/audio-v3.h"], "uac3_insertion_ctl_blk")
    code = constants + "\n" + PRELUDE + "\n" + structures + "\n" + body + "\n" + RUNNER
    source = args.output / "oracle.c"
    source.write_text(code)
    command = [args.cc, "-std=gnu11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
        "-fsanitize=address,undefined", "-fno-omit-frame-pointer", str(source), "-o", str(args.output / "oracle")]
    with (args.output / "compile.log").open("w") as log:
        subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, check=True, timeout=30)
    with (args.output / "run.log").open("w") as log:
        result = subprocess.run([str(args.output / "oracle")], stdout=subprocess.PIPE, stderr=log, check=True, timeout=10)
    trace = f"linux {PIN}\n".encode() + result.stdout
    (args.output / "trace.txt").write_bytes(trace)
    receipt = {"pin": PIN, "donors": DONORS, "source_sha256": hashlib.sha256(code.encode()).hexdigest(),
        "function_sha256": hashlib.sha256(body.encode()).hexdigest(), "trace_sha256": hashlib.sha256(trace).hexdigest(),
        "records": len(result.stdout.splitlines()), "compile_command": command,
        "oracle_limit": ["callback supplies PM lock and full defined reply bytes even for short/error, not physical PM/USB behavior",
            "native requires complete6bytes and propagates failure rather than source name-based Speaker connected fallback",
            "only UAC2 branch executed; UAC3 struct retained to compile unchanged complete function",
            "native EP0 DMA, retained PCM, stale admission and notification requery have independent Rust models"]}
    (args.output / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps(receipt, indent=2))


if __name__ == "__main__":
    main()

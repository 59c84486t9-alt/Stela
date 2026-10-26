#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Unchanged Linux jack admission and unsolicited queue/dispatch functions.

Logical serialized work and codec callbacks only. Native RIRB/MMIO/PCM,
acknowledgements and stronger explicit overflow reporting have separate models.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

from usb_audio_status_oracle import PIN, definitions

DONORS = {
    "sound/hda/core/bus.c": "13ab8ca4fede06fccb9b7e9b4ef5b8360b211c46b181d56e29953ab4e9a82a08",
    "sound/hda/common/jack.c": "3220e341fcb569b0cde1368f8803a87836cac3283ede8ff5424020b906b9efde",
    "include/sound/hda_verbs.h": "4371ee96e755f8d007e7607cf7a58a9ae232fb0a294d63a26acf09f09e75287e",
    "include/sound/hdaudio.h": "37db8b71a18130acbe129bc2f4c1fbad03475fa614f78f2ba5dbd84642ab8f87",
}


def function(source, signature):
    start = source.index(signature)
    opening = source.index("{", start)
    depth, end = 1, opening + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end]


PRELUDE = r'''
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
typedef uint32_t u32;
typedef unsigned hda_nid_t;
struct work_struct { int unused; };
struct hdac_device;
struct hdac_driver { void (*unsol_event)(struct hdac_device *, unsigned); };
struct hdac_device { bool registered; struct { void *driver; } dev; };
struct hdac_bus {
    unsigned unsol_wp, unsol_rp;
    u32 unsol_queue[HDA_UNSOL_QUEUE_SIZE * 2];
    struct work_struct unsol_work;
    int reg_lock;
    struct hdac_device *caddr_tbl[16];
};
struct hda_codec { bool no_jack_detect; unsigned jackpoll_interval, pin_caps, widget_caps, config; };
static unsigned snd_hda_query_pin_caps(struct hda_codec *c, unsigned n) { (void)n; return c->pin_caps; }
static unsigned snd_hda_codec_get_pincfg(struct hda_codec *c, unsigned n) { (void)n; return c->config; }
static unsigned get_wcaps(struct hda_codec *c, unsigned n) { (void)n; return c->widget_caps; }
#define get_defcfg_misc(v) (((v)>>8)&15)
#define trace_hda_unsol_event(b,r,e) ((void)(b),(void)(r),(void)(e))
#define schedule_work(w) ((void)(w))
#define container_of(p,t,m) ((t *)((char *)(p)-offsetof(t,m)))
#define drv_to_hdac_driver(p) ((struct hdac_driver *)(p))
#define spin_lock_irq(p) ((void)(p))
#define spin_unlock_irq(p) ((void)(p))
static unsigned callbacks, last;
static void observed(struct hdac_device *c, unsigned response) { (void)c; ++callbacks; last = response; }
'''

RUNNER = r'''
int main(void) {
    struct hda_codec c = {0};
    for (unsigned no = 0; no != 2; ++no) for (unsigned poll = 0; poll != 2; ++poll)
    for (unsigned pin = 0; pin != 2; ++pin) for (unsigned widget = 0; widget != 2; ++widget)
    for (unsigned disabled = 0; disabled != 2; ++disabled) {
        c.no_jack_detect = no; c.jackpoll_interval = poll ? 10 : 0;
        c.pin_caps = pin ? AC_PINCAP_PRES_DETECT : 0;
        c.widget_caps = widget ? AC_WCAP_UNSOL_CAP : 0;
        c.config = disabled ? 0x100 : 0;
        printf("D %u %u %u %u %u %u\n", no, poll, pin, widget, disabled, is_jack_detectable(&c, 4));
    }
    struct hdac_bus bus = {0};
    struct hdac_driver driver = { .unsol_event = observed };
    struct hdac_device devices[16];
    snd_hdac_bus_queue_event(NULL, 1, 0x10);
    for (unsigned sequence = 0; sequence != 600; ++sequence) {
        unsigned codec = sequence % 16;
        devices[codec].registered = sequence % 3 != 0;
        devices[codec].dev.driver = &driver;
        bus.caddr_tbl[codec] = sequence % 7 == 0 ? NULL : &devices[codec];
        u32 response = (sequence % 64 << 26) | sequence;
        u32 extra = codec | (sequence % 5 == 0 ? 0 : 0x10);
        callbacks = last = 0;
        snd_hdac_bus_queue_event(&bus, response, extra);
        snd_hdac_bus_process_unsol_events(&bus.unsol_work);
        assert(bus.unsol_wp == bus.unsol_rp);
        printf("Q %u %u %u %u\n", response, extra, callbacks, last);
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
    bodies = [function(sources["sound/hda/common/jack.c"], "bool is_jack_detectable("),
        function(sources["sound/hda/core/bus.c"], "void snd_hdac_bus_queue_event("),
        function(sources["sound/hda/core/bus.c"], "static void snd_hdac_bus_process_unsol_events(struct work_struct *work)\n{")]
    constants = definitions(sources["include/sound/hdaudio.h"], ["HDA_UNSOL_QUEUE_SIZE"]) + "\n"
    constants += definitions(sources["include/sound/hda_verbs.h"], ["AC_PINCAP_PRES_DETECT", "AC_WCAP_UNSOL_CAP", "AC_DEFCFG_MISC_NO_PRESENCE"]) + "\n"
    code = constants + PRELUDE + "\n".join(bodies) + "\n" + RUNNER
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
        "functions_sha256": [hashlib.sha256(body.encode()).hexdigest() for body in bodies],
        "trace_sha256": hashlib.sha256(trace).hexdigest(), "records": len(result.stdout.splitlines()),
        "compile_command": command, "oracle_limit": ["logical serialized work/codec callbacks only; no native DMA/GCTL/verb acknowledgements",
            "original queue tested below overrun; explicit bounded native overflow is independently modeled",
            "native unsolicited subscriptions require capability and do not use Linux polling fallback or OEM no_jack_detect inference"]}
    (args.output / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps(receipt, indent=2))


if __name__ == "__main__":
    main()

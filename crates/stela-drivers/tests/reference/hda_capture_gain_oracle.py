#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Run original Linux capture-index/channel selection and stereo amplifier verbs.

The callbacks supply an explicit graph and record actual requested verbs. This
does not establish native DMA, codec acknowledgement, OEM or acoustic behavior.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

from hda_unsolicited_oracle import function
from usb_audio_status_oracle import PIN, definitions

DONORS = {
    "sound/hda/core/regmap.c": "bb2f8837866fefef6cb7f817b7fad3edc7cf339f739a2531bbe8f25caff64a06",
    "sound/hda/codecs/generic.c": "958a8f600267f078c4ce44a8188fd7c042045bf32ffb5e8c08547c6bdaa61196",
    "sound/hda/codecs/realtek/realtek.c": "3d4b9dc7ca482931169093667a4b961f50fd13c315ce9a952c7af72008e1c493",
    "sound/hda/common/hda_local.h": "21b31260451c5fd4868f030cad31b86012acd3e5091caaa39a902d648073d2a9",
    "include/sound/hda_regmap.h": "331b5d896664e97ad65fb0de38d1e57b8c6eff57ac1fae1f073d0341da894075",
    "include/sound/hda_verbs.h": "4371ee96e755f8d007e7607cf7a58a9ae232fb0a294d63a26acf09f09e75287e",
}


def macro(source, name):
    match = re.search(r"^#define\s+" + name + r"(?=[(\s])(?:[^\n]*\\\n)*[^\n]*", source, re.M)
    if not match:
        raise RuntimeError("missing macro " + name)
    return match[0]


PRELUDE = r'''
#include <assert.h>
#include <stdbool.h>
#include <errno.h>
#include <stdio.h>
typedef unsigned hda_nid_t;
enum { HDA_INPUT, HDA_OUTPUT };
enum { NID_PATH_VOL_CTL, NID_PATH_MUTE_CTL };
struct nid_path { int depth; unsigned path[3], idx[3], ctls[2]; };
struct hda_codec { bool single_adc_amp; unsigned chosen, wcaps[128], count[128], source[128]; };
struct hdac_device { unsigned commands[2], count, value; };
static unsigned get_wcaps(struct hda_codec *c, unsigned n) { return c->wcaps[n]; }
static unsigned get_wcaps_type(unsigned w) { return w >> 20 & 15; }
static unsigned snd_hda_get_num_conns(struct hda_codec *c, unsigned n) { return c->count[n]; }
static int snd_hda_get_connections(struct hda_codec *c, unsigned n, unsigned *v, unsigned count) {
    assert(count == 1); *v = c->source[n]; return 1;
}
static bool nid_has_volume(struct hda_codec *c, unsigned n, unsigned d) { return n == c->chosen && d == HDA_INPUT; }
static bool nid_has_mute(struct hda_codec *c, unsigned n, unsigned d) { return nid_has_volume(c,n,d); }
static int snd_hdac_exec_verb(struct hdac_device *c, unsigned v, unsigned flags, unsigned *result) {
    assert(flags == 0 && c->count < 2); c->commands[c->count++] = v;
    if (result) *result = c->value;
    return 0;
}
'''

RUNNER = r'''
int main(void) {
    struct hda_codec c = {0};
    for (unsigned single = 0; single != 2; ++single)
    for (unsigned mixer = 0; mixer != 2; ++mixer)
    for (unsigned index = 0; index != 16; ++index) {
        c.single_adc_amp = single; c.chosen = mixer ? 6 : 3;
        struct nid_path p = {.depth=3, .path={5,6,3}, .idx={index,index,index}};
        int result = parse_capvol_in_path(&c, &p);
        printf("P %u %u %u %d %u %u\n", single,mixer,index,result,p.ctls[0],p.ctls[1]);
    }
    for (unsigned mix = 0; mix != 2; ++mix)
    for (unsigned stereo = 0; stereo != 2; ++stereo)
    for (unsigned source = 0; source != 2; ++source)
    for (unsigned count = 0; count != 3; ++count) {
        c.wcaps[6] = (mix ? AC_WID_AUD_MIX : AC_WID_AUD_IN) << 20;
        c.wcaps[6] |= stereo ? AC_WCAP_STEREO : 0;
        c.wcaps[5] = source ? AC_WCAP_STEREO : 0; c.source[6]=5; c.count[6]=count;
        printf("S %u %u %u %u %u\n",mix,stereo,source,count,is_stereo_amps(&c,6,HDA_INPUT));
    }
    for (unsigned index = 0; index != 16; ++index)
    for (unsigned value = 0; value != 256; ++value) {
        struct hdac_device dev = {.value=value};
        unsigned reg = snd_hdac_regmap_encode_amp_stereo(6,HDA_INPUT,index);
        assert(hda_reg_write_stereo_amp(&dev,reg,value | value<<8) == 0);
        assert(dev.count == 1);
        unsigned write = dev.commands[0], read;
        dev.count=0;
        assert(hda_reg_read_stereo_amp(&dev,reg,&read) == 0);
        assert(dev.count == 2 && read == (value | value<<8));
        assert(dev.commands[0] == snd_hdac_regmap_encode_amp(6,0,HDA_INPUT,index));
        assert(dev.commands[1] == snd_hdac_regmap_encode_amp(6,1,HDA_INPUT,index));
        printf("W %u %u %u %u %u\n", index,value,write,dev.commands[0],dev.commands[1]);
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
    allocation = function(sources["sound/hda/codecs/realtek/realtek.c"], "int alc_alloc_spec(")
    assert "codec->single_adc_amp = 1;" in allocation
    bodies = [
        function(sources["sound/hda/codecs/generic.c"], "static int parse_capvol_in_path("),
        function(sources["sound/hda/codecs/generic.c"], "static bool is_stereo_amps("),
        function(sources["sound/hda/core/regmap.c"], "static int hda_reg_write_stereo_amp("),
        function(sources["sound/hda/core/regmap.c"], "static int hda_reg_read_stereo_amp("),
    ]
    constants = definitions(sources["include/sound/hda_verbs.h"], [
        "AC_VERB_GET_AMP_GAIN_MUTE", "AC_VERB_SET_AMP_GAIN_MUTE", "AC_WCAP_STEREO",
        "AC_AMP_GET_LEFT", "AC_AMP_GET_RIGHT",
        "AC_AMP_GET_INPUT", "AC_AMP_GET_OUTPUT", "AC_AMP_SET_LEFT", "AC_AMP_SET_RIGHT",
        "AC_AMP_SET_INPUT", "AC_AMP_SET_OUTPUT"])
    constants += "\n" + re.search(r"enum \{\n\s*AC_WID_AUD_OUT,.*?\n\};",
        sources["include/sound/hda_verbs.h"], re.S)[0]
    for name in ["snd_hdac_regmap_encode_verb", "snd_hdac_regmap_encode_amp", "snd_hdac_regmap_encode_amp_stereo"]:
        constants += "\n" + macro(sources["include/sound/hda_regmap.h"], name)
    for name in ["HDA_COMPOSE_AMP_VAL_OFS", "HDA_COMPOSE_AMP_VAL"]:
        constants += "\n" + macro(sources["sound/hda/common/hda_local.h"], name)
    code = constants + "\n" + PRELUDE + "\n".join(bodies) + "\n" + RUNNER
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
        "realtek_allocation_sha256": hashlib.sha256(allocation.encode()).hexdigest(),
        "trace_sha256": hashlib.sha256(trace).hexdigest(), "records": len(result.stdout.splitlines()),
        "compile_command": command, "oracle_limit": [
            "graph/capability callbacks supplied; full Realtek allocator is source-audited, not executed",
            "explicit selected input amplifier API; Linux automatic choice among gain/mute widgets is not implemented by this API",
            "equal-channel stereo physical gain/mute only; Linux fake/minimum mute, regmap caching and unequal channel updates outside scope",
            "native ownership, PCM, acknowledgements, failures and strict live authority have independent models; no physical result"]}
    (args.output / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps(receipt, indent=2))


if __name__ == "__main__":
    main()

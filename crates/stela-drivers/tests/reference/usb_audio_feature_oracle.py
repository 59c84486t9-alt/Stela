#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Execute unchanged Linux scalar feature type and conversion helpers.

The actual feature table, enum and three complete helpers are extracted without
rewriting their bytes. U32 delay's missing upstream encode case is recorded as
a limitation, not accepted as permission to zero a requested device value.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

from usb_audio_status_oracle import PIN, DONORS as STATUS_DONORS, definitions

DONORS = STATUS_DONORS | {
    "sound/usb/mixer.h": "dfbfac7f2b7494fe51204692f0accaa54bc5efd485216d31f80d9f6762fe2b4e",
}


def function(source, name):
    match = re.search(r"^static int " + name + r"\([^;]*?\n\{", source, re.M)
    if match is None:
        raise RuntimeError(f"missing original helper {name}")
    position = source.index("{", match.start())
    depth, end = 1, position + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[match.start():end]


RUNNER = r'''
int main(void) {
    const unsigned protocols[] = {0, 32, 48};
    const unsigned samples16[] = {0, 1, 127, 128, 255, 256, 32767, 32768, 65535};
    const uint32_t samples32[] = {0, 1, 0x7fffffffU, 0x80000000U, 0xffffffffU};
    for (unsigned p = 0; p != 3; ++p) {
        unsigned protocol = protocols[p];
        for (unsigned i = 0; i != sizeof(audio_feature_info)/sizeof(audio_feature_info[0]); ++i) {
            const struct usb_feature_control_info *info = &audio_feature_info[i];
            unsigned selector = info->control;
            if (selector < 3 || selector == 6 || (!protocol && selector > 10)) continue;
            int type = protocol && info->type_uac2 >= 0 ? info->type_uac2 : info->type;
            struct usb_mixer_elem_info cval = { .val_type = type };
            unsigned width = protocol ? uac2_ctl_value_size(type) : (type >= USB_MIXER_S16 ? 2 : 1);
            printf("layout %u %u %d %u\n", protocol, selector, type, width);
            unsigned count = width == 1 ? 256 : width == 2 ? 9 : 5;
            for (unsigned sample = 0; sample != count; ++sample) {
                uint32_t raw = width == 1 ? sample : width == 2 ? samples16[sample] : samples32[sample];
                int decoded = convert_signed_value(&cval, (int)raw);
                int encoded = convert_bytes_value(&cval, decoded);
                printf("value %u %u %d %u %u %d %u\n", protocol, selector, type, width, raw, decoded, (uint32_t)encoded);
            }
        }
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
    mixer = sources["sound/usb/mixer.c"]
    table = re.search(r"^struct usb_feature_control_info \{.*?^\};\s*\nstatic const struct usb_feature_control_info audio_feature_info\[\] = \{.*?^\};", mixer, re.M | re.S)
    enum = re.search(r"^enum \{\s*USB_MIXER_BOOLEAN,.*?^\};", sources["sound/usb/mixer.h"], re.M | re.S)
    if table is None or enum is None:
        raise RuntimeError("missing exact feature table or value-type enum")
    names = re.findall(r"\{\s*(UAC\w+),", table[0])
    header = sources["include/uapi/linux/usb/audio.h"] + "\n" + sources["include/linux/usb/audio-v2.h"]
    bodies = [function(mixer, name) for name in ["convert_signed_value", "convert_bytes_value", "uac2_ctl_value_size"]]
    code = "#include <stdint.h>\n#include <stdio.h>\n" + enum[0] + "\n"
    code += "struct usb_mixer_elem_info { int val_type; };\n" + definitions(header, names) + "\n"
    code += table[0] + "\n" + "\n".join(bodies) + "\n" + RUNNER
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
        "helpers_sha256": [hashlib.sha256(body.encode()).hexdigest() for body in bodies],
        "table_sha256": hashlib.sha256(table[0].encode()).hexdigest(),
        "trace_sha256": hashlib.sha256(trace).hexdigest(), "records": len(result.stdout.splitlines()),
        "compile_command": command, "oracle_limit": ["logical cval type only; no native EP0 or range transactions",
            "original U32 conversion encode falls through to zero; native explicit unsigned encoding qualified by separate wire model"]}
    (args.output / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps(receipt, indent=2))


if __name__ == "__main__":
    main()

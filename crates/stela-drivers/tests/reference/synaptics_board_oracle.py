#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Unchanged complete Synaptics PnP coordinate table and application policy."""
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys

helper = Path(__file__).with_name("synaptics_child_oracle.py")
spec = importlib.util.spec_from_file_location("child", helper)
child = importlib.util.module_from_spec(spec)
spec.loader.exec_module(child)
pt = child.pt
PREFIX = r'''
// SPDX-License-Identifier: GPL-2.0-only
// Original Synaptics/psmouse notices remain in source manifests.
#define _GNU_SOURCE
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
typedef uint8_t u8;typedef int8_t s8;typedef uint32_t u32;
struct psmouse;struct serio;
#include "SYNAPTICS_HEADER"
/* The complete source matching helper sees bounded, modeled firmware strings;
   this array is fixture storage, not a claim about Linux serio's native ABI. */
struct serio {char firmware_id[128];};
struct ps2dev {struct serio*serio;};
struct psmouse {struct ps2dev ps2dev;};
#define GFP_KERNEL 0
static char*kstrndup(const char*p,size_t n,int flags){(void)flags;char*copy=strndup(p,n);assert(copy);return copy;}
#define kfree(p) free(p)
#define psmouse_info(...) ((void)0)
'''
MAIN = r'''
int main(void){
    static const char*ids[]={"PNP: LEN0033","PNP: LEN0042","PNP: LEN0034","PNP: LEN0036","PNP: LEN0037","PNP: LEN0039","PNP: LEN2002","PNP: LEN2004",
        "PNP: LEN2000","PNP: LEN2001","PNP: LEN2006","PNP: other","PNP: len0033","PNP: other len2006 other","PNP: LEN0033x","PNP: ALEN0033",
        "PNP: LEN2006 LEN0033","PNP: LEN2006 LEN0034","PNP: LEN0042 LEN0033","PNP: LEN2001 LEN2000","PNP: SYN300D LEN0033","PNP: LEN2006 LEN0042","PNP: ","PNP:  LEN0033  ",
        "PNP: LEN0034 LEN2006","PNP: LEN2000 LEN0042","PNP: LEN0036 other","PNP: len2004","PNP: LEN0034x","PNP: SYN3014","PNP: LEN2006 LEN2001","PNP: LEN2002 LEN2000"};
    assert(sizeof(ids)/sizeof(*ids)==32);
    static const unsigned boundary[]={0,1,2690,2691,2692,2960,2961,2962,16383};
    for(unsigned i=0;i<32;++i)for(unsigned n=0;n<256;++n){
        bool queried=n!=0;unsigned board=n<10?boundary[n? n-1:0]:(n*67)&16383;
        struct serio serio={0};assert(strlen(ids[i])<sizeof(serio.firmware_id));strcpy(serio.firmware_id,ids[i]);
        struct psmouse mouse={{&serio}};
        struct synaptics_device_info info={0};info.board_id=queried?board:0;
        info.x_min=1000;info.y_min=800;info.x_max=6000;info.y_max=5000;
        synaptics_apply_quirks(&mouse,&info);
        if(queried)printf("%u ",board);else printf("N ");
        for(const char*p=ids[i];*p;++p)printf("%02x",(unsigned char)*p);
        printf(" %u %u %u %u\n",info.x_min,info.y_min,info.x_max,info.y_max);
    }
    return 0;
}
'''


def main():
    root, output = map(Path, sys.argv[1:])
    output.mkdir(parents=True, exist_ok=False)
    mouse = root/"drivers/input/mouse"
    for name, expected in pt.absolute.HASHES.items():
        assert hashlib.sha256((mouse/name).read_bytes()).hexdigest() == expected
    base = (mouse/"psmouse-base.c").read_bytes()
    assert hashlib.sha256(base).hexdigest() == child.BASE_SHA
    source = (mouse/"synaptics.c").read_text()
    declarations = re.search(r"#define ANY_BOARD_ID 0\nstruct min_max_quirk \{.*?\n\};\n\nstatic const struct min_max_quirk min_max_pnpid_table\[\] = \{.*?\n\};", source, re.S).group()
    bodies = {"psmouse_check_pnp_id":pt.absolute.function(base.decode(),"psmouse_check_pnp_id"),
              "psmouse_matches_pnp_id":pt.exported(base.decode(),"bool psmouse_matches_pnp_id("),
              "synaptics_apply_quirks":pt.absolute.function(source,"synaptics_apply_quirks")}
    c = output/"oracle.c"
    c.write_text(PREFIX.replace("SYNAPTICS_HEADER",str((mouse/"synaptics.h").resolve()))+declarations+"\n"+"\n".join(bodies.values())+MAIN)
    binary=output/"oracle"
    subprocess.run(["clang","-std=gnu11","-O1","-g","-fsanitize=address,undefined","-fno-sanitize-recover=all",str(c),"-o",str(binary)],check=True,timeout=60)
    result=subprocess.run([str(binary.resolve())],capture_output=True,text=True,check=True,timeout=60)
    (output/"records.txt").write_text(result.stdout)
    (output/"manifest.json").write_text(json.dumps({
        "pin":pt.absolute.PIN,"sources":{**pt.absolute.HASHES,"psmouse-base.c":child.BASE_SHA},
        "helper_sha256":hashlib.sha256(helper.read_bytes()).hexdigest(),
        "unchanged_table_sha256":hashlib.sha256(declarations.encode()).hexdigest(),
        "unchanged_functions":{name:hashlib.sha256(body.encode()).hexdigest()for name,body in bodies.items()},
        "records":len(result.stdout.splitlines()),"oracle_limit":[
            "Complete original coordinate table, apply policy and both PnP matchers execute; allocation/string storage are modeled bounded successful services.",
            "Firmware strings are fixture context,not actual native PnP authority; board absence retains native None while source policy uses its zero-initialized field.",
            "Native comparison separately performs real i8042 firmware/board queries and accepted mode setup. No DMI/physical/guest qualification.",
        ]},indent=2)+"\n")
    print(len(result.stdout.splitlines()),"original PnP/board coordinate records")


if __name__=="__main__":main()

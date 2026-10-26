#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Complete pinned integrated TrackPoint report/check functions, no native claim."""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

helper = Path(__file__).with_name('elantech_reports_oracle.py')
spec = importlib.util.spec_from_file_location('reports', helper)
reports = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reports)
pt = reports.pt

PREFIX = r'''
// SPDX-License-Identifier: GPL-2.0-only
// Elantech Copyright2007-2009 Arjan Opmeer; psmouse notices retained by manifest.
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef uint8_t u8;typedef uint32_t u32;
#define BIT(n) (1U<<(n))
struct psmouse;struct input_dev;
#include "ELANTECH_HEADER"
#define BTN_LEFT 0
#define BTN_RIGHT 1
#define BTN_MIDDLE 2
#define REL_X 0
#define REL_Y 1
#define elantech_debug(...) ((void)0)
struct input_dev {unsigned buttons,sync;int x,y;};
struct psmouse {struct input_dev*dev;void*private;u8 packet[8];};
static u32 get_unaligned_le32(const u8*p){return (u32)p[0]|((u32)p[1]<<8)|((u32)p[2]<<16)|((u32)p[3]<<24);}
static void input_report_key(struct input_dev*d,unsigned key,int value){assert(key<=2);if(value)d->buttons|=1U<<key;else d->buttons&=~(1U<<key);}
static void input_report_rel(struct input_dev*d,unsigned axis,int value){assert(axis<=1);if(axis==REL_X)d->x=value;else d->y=value;}
static void input_sync(struct input_dev*d){++d->sync;}
static void elantech_packet_dump(struct psmouse*p){(void)p;}
'''

MAIN = r'''
int main(void){
    static const u32 patterns[]={0x06000030U,0x16008020U,0x26800010U,0x36808000U};
    for(unsigned profile=0;profile<4;++profile){
        struct elantech_data data={0};struct input_dev dev={0};struct psmouse mouse={0};mouse.private=&data;data.tp_dev=&dev;
        data.info.hw_version=profile==0||profile==3?3:4;data.info.fw_version=data.info.hw_version==3?0x050001:0x060001;
        data.info.crc_enabled=profile>=2;
        for(unsigned n=0;n<2048;++n){
            u32 prefix=patterns[n&3]|((n>>2)&7);u8*p=mouse.packet;
            for(unsigned i=0;i<4;++i)p[i]=prefix>>(i*8);
            p[4]=(n>>2)&255;p[5]=(n*37+(n>>10)*17)&255;
            if(n%17==0)p[1]^=4; /* classifier-valid, report function ignores it */
            if(n%19==0)p[4]=0x80;
            if(n%23==0)p[5]=0x80;
            unsigned before=dev.sync;dev.x=dev.y=0;
            int type=data.info.hw_version==3?elantech_packet_check_v3(&mouse):elantech_packet_check_v4(&mouse);
            if(type==PACKET_TRACKPOINT)elantech_report_trackpoint(&mouse,type);
            printf("%u %u %u ",profile,data.info.hw_version,data.info.crc_enabled);
            for(unsigned i=0;i<6;++i)printf("%02x",p[i]);
            printf(" %u %u %u %d %d\n",type==PACKET_TRACKPOINT,dev.sync-before,dev.buttons,dev.x,dev.y);
        }
    }
    return 0;
}
'''


def main():
    root, output = map(Path, sys.argv[1:])
    output.mkdir(parents=True, exist_ok=False)
    mouse = root/'drivers/input/mouse'
    for name, expected in reports.HASHES.items():
        assert hashlib.sha256((mouse/name).read_bytes()).hexdigest() == expected
    source = (mouse/'elantech.c').read_text()
    base = (mouse/'psmouse-base.c').read_text()
    bodies = {'psmouse_report_standard_buttons': pt.exported(base, 'void psmouse_report_standard_buttons(')}
    for name in ['elantech_report_trackpoint', 'elantech_packet_check_v3', 'elantech_packet_check_v4']:
        bodies[name] = pt.absolute.function(source, name)
    c = output/'oracle.c'
    c.write_text(PREFIX.replace('ELANTECH_HEADER', str((mouse/'elantech.h').resolve()))+'\n'.join(bodies.values())+MAIN)
    binary = output/'oracle'
    subprocess.run(['clang', '-std=gnu11', '-O1', '-g', '-fsanitize=address,undefined', '-fno-sanitize-recover=all', str(c), '-o', str(binary)], check=True, timeout=60)
    result = subprocess.run([str(binary.resolve())], capture_output=True, text=True, check=True, timeout=60)
    (output/'records.txt').write_text(result.stdout)
    (output/'manifest.json').write_text(json.dumps({
        'pin': pt.absolute.PIN, 'sources': reports.HASHES,
        'helper_sha256': {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in [Path(__file__), helper, Path(pt.__file__), Path(pt.absolute.__file__)]},
        'unchanged_functions': {name: hashlib.sha256(body.encode()).hexdigest() for name, body in bodies.items()},
        'records': len(result.stdout.splitlines()),
        'columns': ['profile', 'hardware', 'crc', 'raw', 'classified_trackpoint', 'input_sync', 'held_buttons', 'dx', 'dy'],
        'oracle_limit': ['Complete original packet checks, integrated trackpoint report and standard-button function execute logical input services. This alone proves no native integrated trackpoint operation.',
                        'Actual source v3 CRC profile does not classify these packets as trackpoint; source v4 recognizes the child marker before CRC/ordinary checks. Caller admission/initialization remains separate.',
                        'Four original prefix formats, ignored invalid prefixes, sign/magnitude rejection, held buttons and individual relative event values execute. Numeric Linux event ABI, kernel input buffering and physical motion remain unqualified.',
                        'No firmware report-ID mutation/SMBus handoff, native child binding or guest/frontend capability is established.'],
    }, indent=2)+'\n')
    print(len(result.stdout.splitlines()), 'original integrated trackpoint report/check records')


if __name__ == '__main__':
    main()

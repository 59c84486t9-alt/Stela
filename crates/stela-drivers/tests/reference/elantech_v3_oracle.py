#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Complete pinned Elantech v3 configuration and sequential head/tail reports."""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

helper = Path(__file__).with_name('elantech_controls_oracle.py')
spec = importlib.util.spec_from_file_location('controls', helper)
controls = importlib.util.module_from_spec(spec)
spec.loader.exec_module(controls)
reports = controls.reports
pt = reports.pt

REPORT_MAIN = r'''
int main(void){
    for(unsigned group=0;group<256;++group){
        unsigned firmware=0x050001|((group&1)?0x4000:0)|((group&2)?0x1000:0);
        struct elantech_data data={0};data.info.fw_version=firmware;assert(elantech_set_properties(&data.info)==0);assert(data.info.hw_version==3);
        data.y_max=900;
        struct input_dev dev={0};dev.allowed=elantech_is_buttonpad(&data.info)?1:3;dev.pressure=dev.width=-1;
        struct psmouse mouse={&dev,&data,{0}};
        for(unsigned n=0;n<32;++n){
            static const unsigned counts[]={2,2,2,1,2,0,2,3};
            unsigned fingers=counts[n%8],x=(group*31+n*67)&4095,y=(group*47+n*89)&4095;
            unsigned z=(group*13+n*29)&255,w=(group+n)&15;bool tail=(n%4)==0||(n%4)==2;
            u8*p=mouse.packet;memset(p,0,8);
            p[0]=(fingers<<6)|((w&12)<<2)|((group+n)&3)|(tail?12:4);
            p[1]=(z&0xf0)|((x>>8)&15);p[2]=x;
            p[3]=((w&3)<<4)|(data.info.crc_enabled?(tail?9:8):(tail?12:2));
            p[4]=((z&15)<<4)|((y>>8)&15);p[5]=y;
            if(n==23){const u8 debounce[]={0xc4,0xff,0xff,2,0xff,0xff};memcpy(p,debounce,6);}
            int type=elantech_packet_check_v3(&mouse);assert(type!=PACKET_UNKNOWN&&type!=PACKET_TRACKPOINT);
            unsigned before=dev.sync;if(type!=PACKET_DEBOUNCE)elantech_report_absolute_v3(&mouse,type);
            char kind=type==PACKET_DEBOUNCE?'B':before==dev.sync?'H':'F';
            printf("%u %u ",group,firmware);for(unsigned i=0;i<6;++i)printf("%02x",p[i]);
            printf(" %c %u %u %u %d %d %u %d %d %d %d %d %d\n",kind,dev.touch,dev.tools,dev.buttons,dev.x,dev.y,dev.slots,dev.sx[0],dev.sy[0],dev.sx[1],dev.sy[1],dev.pressure,dev.width);
        }
    }
    return 0;
}
'''

CONTROL_MAIN = controls.MAIN.replace(
    '0x010000,0x020022,0x020600,0x020030,0x020800,0x020b00,0x020801,0x0208ff,0x020900,0x040215,0x040216,0x040219,0x140900,0x140900',
    '0x050001,0x051001,0x054001,0x055001'
).replace('firmware_id[0]=0;firmware_id[1]=index==13?0x10:0;firmware_id[2]=0;',
          'firmware_id[0]=0x35;firmware_id[1]=0x78;firmware_id[2]=0x84;'
).replace('assert(info.hw_version<=2)', 'assert(info.hw_version==3)')


def main():
    root, output = map(Path, sys.argv[1:3])
    assert sys.argv[3:] in [[], ['--controls']]
    control = bool(sys.argv[3:])
    output.mkdir(parents=True, exist_ok=False)
    mouse = root/'drivers/input/mouse'
    for name, expected in reports.HASHES.items():
        assert hashlib.sha256((mouse/name).read_bytes()).hexdigest() == expected
    source = (mouse/'elantech.c').read_text()
    base = (mouse/'psmouse-base.c').read_text()
    if control:
        lib = (root/'drivers/input/serio/libps2.c').read_text()
        assert hashlib.sha256(lib.encode()).hexdigest() == pt.LIB_SHA
        header = (mouse/'psmouse.h').read_text()
        assert hashlib.sha256(header.encode()).hexdigest() == '9ee4f530d7c954d80828bd51cd6194494581e05764c1604d5c0bbb5b704aa5a1'
        constants = '\n'.join(line for text in [header, lib] for line in text.splitlines()
                              if line.startswith(('#define PSMOUSE_CMD_', '#define PS2_CMD_'))) + '\n'
        constants += '\n'.join(controls.re.search(r'enum '+name+r' \{.*?\n\};', header, controls.re.S).group()
                               for name in ['psmouse_scale', 'psmouse_type'])+'\n'
        prefix = constants + controls.PREFIX.replace('assert(custom_values[0]==0x11)', 'assert(custom_values[0]==0)')
        prefix = prefix.replace('custom_values[0]==0x10', 'custom_values[0]==0')
        prefix = prefix.replace('else if(slice_count==1){switch(slice_values[0]){',
                                'else if(slice_count==1||custom_count==1){switch(slice_count? slice_values[0]:custom_values[0]){')
        bodies = {'ps2_sliced_command': pt.exported(lib, 'int ps2_sliced_command(')}
        for name in ['synaptics_send_cmd', 'elantech_send_cmd', 'elantech_ps2_command', 'elantech_read_reg', 'elantech_write_reg',
                     'elantech_is_buttonpad', 'elantech_is_signature_valid', 'elantech_set_properties', 'elantech_query_info', 'elantech_set_absolute_mode']:
            bodies[name] = pt.absolute.function(source, name)
        bodies['elantech_detect'] = pt.exported(source, 'int elantech_detect(')
        bodies['psmouse_set_resolution'] = pt.exported(base, 'void psmouse_set_resolution(')
        for name in ['psmouse_set_rate', 'psmouse_set_scale', 'psmouse_initialize']:
            bodies[name] = pt.absolute.function(base, name)
        main = CONTROL_MAIN
    else:
        prefix = reports.PREFIX
        bodies = {'psmouse_report_standard_buttons': pt.exported(base, 'void psmouse_report_standard_buttons(')}
        for name in ['elantech_is_buttonpad', 'elantech_set_properties', 'elantech_set_slot', 'elantech_report_semi_mt_data',
                     'elantech_report_absolute_v3', 'elantech_packet_check_v3']:
            bodies[name] = pt.absolute.function(source, name)
        main = REPORT_MAIN
    c = output/'oracle.c'
    c.write_text(prefix.replace('ELANTECH_HEADER', str((mouse/'elantech.h').resolve()))+'\n'.join(bodies.values())+main)
    binary = output/'oracle'
    subprocess.run(['clang', '-std=gnu11', '-O1', '-g', '-fsanitize=address,undefined', '-fno-sanitize-recover=all', str(c), '-o', str(binary)], check=True, timeout=60)
    result = subprocess.run([str(binary.resolve())], capture_output=True, text=True, check=True, timeout=60)
    (output/'records.txt').write_text(result.stdout)
    (output/'manifest.json').write_text(json.dumps({
        'pin': pt.absolute.PIN, 'sources': reports.HASHES,
        'helper_sha256': {str(p.name): hashlib.sha256(p.read_bytes()).hexdigest() for p in [Path(__file__), helper, Path(reports.__file__), Path(pt.__file__), Path(pt.absolute.__file__)]},
        'command_sources': {'libps2_sha256': pt.LIB_SHA, 'psmouse_header_sha256': hashlib.sha256(header.encode()).hexdigest()} if control else {},
        'unchanged_functions': {name: hashlib.sha256(body.encode()).hexdigest() for name, body in bodies.items()},
        'controls': control, 'records': len(result.stdout.splitlines()),
        'oracle_limit': ['Complete unchanged pinned source functions execute with modeled successful PS2 or logical input services.',
                         'Ordinary no-DMI v3 profiles cover firmware CRC and clickpad flags; no integrated trackpoint, physical, guest or native MT frontend qualification.',
                         'Source cached head/default zero and semi-MT projections are software effects, separate from actual native observed-head provenance.',
                         'Uncertain command and complete failed-read source retries remain unselected; native lifecycle/failures require separate controls.']
    }, indent=2)+'\n')
    print(len(result.stdout.splitlines()), 'original Elantech v3', 'controls' if control else 'reports')


if __name__ == '__main__':
    main()

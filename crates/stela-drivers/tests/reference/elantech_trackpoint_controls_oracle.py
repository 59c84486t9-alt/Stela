#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Complete original integrated TrackPoint report-ID/query/init transactions."""
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys

helper = Path(__file__).with_name('elantech_v4_controls_oracle.py')
spec = importlib.util.spec_from_file_location('v4', helper)
v4 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(v4)
controls = v4.controls
reports = controls.reports
pt = reports.pt

MAIN = v4.MAIN.replace(v4.VERSIONS, '0x0f0001,0x0f0002,0x0f2001,0x0f2002')
MAIN = MAIN.replace('capabilities[0]=n&1?0:4;', 'capabilities[0]=0x80;')
MAIN = re.sub(r'samples\[0\]=.*?;samples\[1\]=.*?;samples\[2\]=.*?;',
              'samples[0]=0;samples[1]=(u8[]){8,9,0x0d,0x0e,10,0x74,0xab,0x2a}[n&7];samples[2]=20+((n>>1)&7);', MAIN)
MAIN = MAIN.replace('memset(regs,0,sizeof(regs));', 'memset(regs,0,sizeof(regs));memset(reg_hi,0,sizeof(reg_hi));report_id_writes=0;memset(report_id_read,0,3);')
MAIN = MAIN.replace('for(unsigned i=0;i<wire_count;++i)printf("%02x",wire[i]);',
                    'printf("%u %u %02x%02x%02x ",info.has_trackpoint,report_id_writes,report_id_read[0],report_id_read[1],report_id_read[2]);for(unsigned i=0;i<wire_count;++i)printf("%02x",wire[i]);')


def main():
    root, output = map(Path, sys.argv[1:])
    output.mkdir(parents=True, exist_ok=False)
    mouse = root/'drivers/input/mouse'
    for name, expected in reports.HASHES.items():
        assert hashlib.sha256((mouse/name).read_bytes()).hexdigest() == expected
    lib = (root/'drivers/input/serio/libps2.c').read_text()
    assert hashlib.sha256(lib.encode()).hexdigest() == pt.LIB_SHA
    header = (mouse/'psmouse.h').read_text()
    assert hashlib.sha256(header.encode()).hexdigest() == '9ee4f530d7c954d80828bd51cd6194494581e05764c1604d5c0bbb5b704aa5a1'
    constants = '\n'.join(line for text in [header, lib] for line in text.splitlines()
                          if line.startswith(('#define PSMOUSE_CMD_', '#define PS2_CMD_'))) + '\n'
    constants += '\n'.join(re.search(r'enum '+name+r' \{.*?\n\};', header, re.S).group()
                           for name in ['psmouse_scale', 'psmouse_type'])+'\n'
    prefix = controls.PREFIX
    for name in ['elantech_change_report_id', 'elantech_get_resolution_v4']:
        prefix = re.sub(r'static int '+name+r'\([^\n]+\n', '', prefix)
    prefix = prefix.replace('static unsigned firmware,', 'static u8 resolution[3],icbody[3],reg_hi[256],report_id_read[3];static unsigned report_id_writes;\nstatic unsigned firmware,')
    prefix = prefix.replace('if(custom_count==3){assert(custom_values[0]==0x11);regs[custom_values[1]]=custom_values[2];custom_count=0;}',
        'if(custom_count==4){assert(custom_values[0]==0);reg_hi[custom_values[1]]=custom_values[2];regs[custom_values[1]]=custom_values[3];if(custom_values[1]==7&&custom_values[2]==0x10&&custom_values[3]==3)++report_id_writes;custom_count=0;}')
    prefix = prefix.replace('custom_values[0]==0x10', 'custom_values[0]==0')
    prefix = prefix.replace('param[0]=readback_value;param[1]=0xfa;param[2]=0xfe;',
        'param[0]=0xfa;param[1]=readback_value;param[2]=0xfe;if(custom_count==2&&reg_hi[custom_values[1]]){param[0]=reg_hi[custom_values[1]];param[1]=regs[custom_values[1]];memcpy(report_id_read,param,3);}')
    prefix = prefix.replace('else if(slice_count==1){switch(slice_values[0]){',
                            'else if(slice_count==1||custom_count==1){switch(slice_count?slice_values[0]:custom_values[0]){')
    prefix = prefix.replace('case 3:++sample_queries;memcpy(param,samples,3);break;',
        'case 3:++sample_queries;memcpy(param,samples,3);break;case 4:memcpy(param,resolution,3);break;case 5:memcpy(param,icbody,3);break;')
    prefix = prefix.replace('if((command&255)==0xe9)', 'if(command==PSMOUSE_CMD_GETINFO)')
    source = (mouse/'elantech.c').read_text()
    base = (mouse/'psmouse-base.c').read_text()
    bodies = {'ps2_sliced_command': pt.exported(lib, 'int ps2_sliced_command(')}
    for name in ['synaptics_send_cmd', 'elantech_send_cmd', 'elantech_ps2_command',
                 'elantech_read_reg_params', 'elantech_write_reg_params', 'elantech_read_reg', 'elantech_write_reg',
                 'elantech_is_buttonpad', 'elantech_is_signature_valid', 'elantech_convert_res',
                 'elantech_get_resolution_v4', 'elantech_set_properties', 'elantech_change_report_id',
                 'elantech_query_info', 'elantech_set_absolute_mode', 'elantech_set_rate_restore_reg_07']:
        bodies[name] = pt.absolute.function(source, name)
    bodies['elantech_detect'] = pt.exported(source, 'int elantech_detect(')
    bodies['psmouse_set_resolution'] = pt.exported(base, 'void psmouse_set_resolution(')
    for name in ['psmouse_set_rate', 'psmouse_set_scale', 'psmouse_initialize']:
        bodies[name] = pt.absolute.function(base, name)
    c = output/'oracle.c'
    c.write_text(constants+prefix.replace('ELANTECH_HEADER', str((mouse/'elantech.h').resolve()))+'\n'.join(bodies.values())+MAIN)
    binary = output/'oracle'
    subprocess.run(['clang', '-std=gnu11', '-O1', '-g', '-fsanitize=address,undefined', '-fno-sanitize-recover=all', str(c), '-o', str(binary)], check=True, timeout=60)
    result = subprocess.run([str(binary.resolve())], capture_output=True, text=True, check=True, timeout=60)
    (output/'records.txt').write_text(result.stdout)
    (output/'manifest.json').write_text(json.dumps({
        'pin': pt.absolute.PIN, 'sources': reports.HASHES, 'libps2_sha256': pt.LIB_SHA,
        'psmouse_header_sha256': hashlib.sha256(header.encode()).hexdigest(),
        'helper_sha256': {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in [Path(__file__), helper, Path(controls.__file__), Path(reports.__file__), Path(pt.__file__), Path(pt.absolute.__file__)]},
        'unchanged_functions': {name: hashlib.sha256(body.encode()).hexdigest() for name, body in bodies.items()},
        'records': len(result.stdout.splitlines()),
        'columns': ['firmware','capabilities','samples','firmware_id','knock_tail','raw_register_byte','mode_result','hardware','xmin','ymin','xmax','ymax','pressure','jumpy','runtime_register_value','pattern','ic_version','width','x_traces','y_traces','x_resolution','y_resolution','bus','middle','crc','trackpoint','report_id_writes','report_id_readback','wire'],
        'oracle_limit': ['Complete original detection/query/report-ID write/read/check/mode/default-init/register bodies execute against successful modeled command services; this alone establishes no native integrated attachment.',
                        'Four IC17 pattern1/2 firmwares with all four source affected products and four unaffected products select actual full query-info report-ID branches; exact parameter writes/readback precede mode and enable.',
                        'No uncertain replay/error-mask equivalence, DMI/SMBus handoff, source kernel input frontend, native authority grant or physical hardware qualification is implied.'],
    }, indent=2)+'\n')
    print(len(result.stdout.splitlines()), 'original integrated TrackPoint configuration/report-ID records')


if __name__ == '__main__':
    main()

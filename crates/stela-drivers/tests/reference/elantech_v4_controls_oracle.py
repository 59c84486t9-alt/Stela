#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Complete pinned v4 query/mode/default-rate/register functions; no native claim."""
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys

helper = Path(__file__).with_name('elantech_controls_oracle.py')
spec = importlib.util.spec_from_file_location('controls', helper)
controls = importlib.util.module_from_spec(spec)
spec.loader.exec_module(controls)
reports = controls.reports
pt = reports.pt

VERSIONS = '0x060001,0x064001,0x070001,0x074001,0x080001,0x0a1001,0x0c0001,0x0f0000,0x0f0001,0x0f2002,0x381f17'
OLD_VERSIONS = '0x010000,0x020022,0x020600,0x020030,0x020800,0x020b00,0x020801,0x0208ff,0x020900,0x040215,0x040216,0x040219,0x140900,0x140900'
MAIN = controls.MAIN.replace(OLD_VERSIONS,VERSIONS).replace('assert(info.hw_version<=2)','assert(info.hw_version==4)')
MAIN = MAIN.replace('firmware_id[0]=0;firmware_id[1]=index==13?0x10:0;firmware_id[2]=0;',
    'firmware_id[0]=0x35;firmware_id[1]=0x78;firmware_id[2]=0x84;resolution[0]=0x55;resolution[1]=n*17;resolution[2]=n%5;icbody[0]=0;icbody[1]=0x11;icbody[2]=0x17;')
MAIN = MAIN.replace('samples[0]=0;samples[1]=10+(n&7);samples[2]=20+((n>>1)&7);',
    'samples[0]=(n&1)?0xab:0;samples[1]=(index==2&&(n&1))?0x2a:10+(n&7);samples[2]=20+((n>>1)&7);if(n<2)capabilities[2]=n;')
MAIN = MAIN.replace('int result=elantech_set_absolute_mode(&mouse);',
    'if(firmware==0x381f17){data.original_set_rate=mouse.set_rate;mouse.set_rate=elantech_set_rate_restore_reg_07;}int result=elantech_set_absolute_mode(&mouse);')
MAIN = MAIN.replace('for(unsigned i=0;i<wire_count;++i)printf("%02x",wire[i]);',
    'printf("%u %u %u %u %u %u %u %u %u %u ",info.pattern,info.ic_version,info.width,info.x_traces,info.y_traces,info.x_res,info.y_res,info.bus,info.has_middle_button,info.crc_enabled);for(unsigned i=0;i<wire_count;++i)printf("%02x",wire[i]);')


def main():
    root, output = map(Path,sys.argv[1:])
    output.mkdir(parents=True,exist_ok=False)
    mouse = root/'drivers/input/mouse'
    for name,expected in reports.HASHES.items():
        assert hashlib.sha256((mouse/name).read_bytes()).hexdigest()==expected
    lib = (root/'drivers/input/serio/libps2.c').read_text()
    assert hashlib.sha256(lib.encode()).hexdigest()==pt.LIB_SHA
    header = (mouse/'psmouse.h').read_text()
    assert hashlib.sha256(header.encode()).hexdigest()=='9ee4f530d7c954d80828bd51cd6194494581e05764c1604d5c0bbb5b704aa5a1'
    constants = '\n'.join(line for text in [header,lib] for line in text.splitlines()
                          if line.startswith(('#define PSMOUSE_CMD_','#define PS2_CMD_'))) + '\n'
    constants += '\n'.join(re.search(r'enum '+name+r' \{.*?\n\};',header,re.S).group()
                           for name in ['psmouse_scale','psmouse_type'])+'\n'
    prefix = controls.PREFIX
    prefix = re.sub(r'static int elantech_get_resolution_v4\([^\n]+\n','',prefix)
    prefix = prefix.replace('static unsigned firmware,','static u8 resolution[3],icbody[3];\nstatic unsigned firmware,')
    prefix = prefix.replace('if(custom_count==3){assert(custom_values[0]==0x11);regs[custom_values[1]]=custom_values[2];custom_count=0;}',
        'if(custom_count==4){assert(custom_values[0]==0&&custom_values[2]==0);regs[custom_values[1]]=custom_values[3];custom_count=0;}')
    prefix = prefix.replace('custom_values[0]==0x10','custom_values[0]==0')
    prefix = prefix.replace('param[0]=readback_value;param[1]=0xfa;param[2]=0xfe;',
                            'param[0]=0xfa;param[1]=readback_value;param[2]=0xfe;')
    prefix = prefix.replace('else if(slice_count==1){switch(slice_values[0]){',
                            'else if(slice_count==1||custom_count==1){switch(slice_count?slice_values[0]:custom_values[0]){')
    prefix = prefix.replace('case 3:++sample_queries;memcpy(param,samples,3);break;',
        'case 3:++sample_queries;memcpy(param,samples,3);break;case 4:memcpy(param,resolution,3);break;case 5:memcpy(param,icbody,3);break;')
    source = (mouse/'elantech.c').read_text()
    base = (mouse/'psmouse-base.c').read_text()
    bodies = {'ps2_sliced_command':pt.exported(lib,'int ps2_sliced_command(')}
    for name in ['synaptics_send_cmd','elantech_send_cmd','elantech_ps2_command','elantech_read_reg','elantech_write_reg',
                 'elantech_is_buttonpad','elantech_is_signature_valid','elantech_convert_res','elantech_get_resolution_v4',
                 'elantech_set_properties','elantech_query_info','elantech_set_absolute_mode','elantech_set_rate_restore_reg_07']:
        bodies[name] = pt.absolute.function(source,name)
    bodies['elantech_detect'] = pt.exported(source,'int elantech_detect(')
    bodies['psmouse_set_resolution'] = pt.exported(base,'void psmouse_set_resolution(')
    for name in ['psmouse_set_rate','psmouse_set_scale','psmouse_initialize']:
        bodies[name] = pt.absolute.function(base,name)
    c = output/'oracle.c'
    c.write_text(constants+prefix.replace('ELANTECH_HEADER',str((mouse/'elantech.h').resolve()))+'\n'.join(bodies.values())+MAIN)
    binary = output/'oracle'
    subprocess.run(['clang','-std=gnu11','-O1','-g','-fsanitize=address,undefined','-fno-sanitize-recover=all',str(c),'-o',str(binary)],check=True,timeout=60)
    result = subprocess.run([str(binary.resolve())],capture_output=True,text=True,check=True,timeout=60)
    (output/'records.txt').write_text(result.stdout)
    (output/'manifest.json').write_text(json.dumps({
        'pin':pt.absolute.PIN,'sources':reports.HASHES,'libps2_sha256':pt.LIB_SHA,
        'psmouse_header_sha256':hashlib.sha256(header.encode()).hexdigest(),
        'helper_sha256':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in [Path(__file__),helper,Path(reports.__file__),Path(pt.__file__),Path(pt.absolute.__file__)]},
        'unchanged_functions':{name:hashlib.sha256(body.encode()).hexdigest() for name,body in bodies.items()},
        'records':len(result.stdout.splitlines()),
        'columns':['firmware','capabilities','samples','firmware_id','knock_tail','raw_register_byte','mode_result','hardware','xmin','ymin','xmax','ymax','pressure','jumpy','runtime_register_value','pattern','ic_version','width','x_traces','y_traces','x_resolution','y_resolution','bus','middle','crc','wire'],
        'oracle_limit':['Complete original success-path query/mode/read/default-rate bodies execute against modeled PS2 services; this alone proves no native v4 implementation.',
                       'Covers11 v4 firmware profiles, pattern/IC-body query, resolution/bus/geometry, source reg07 ACK-only mode and381f17 rate restore. DMI and integrated trackpoints remain unselected.',
                       'Full Linux probe/SMBus handoff, failed optional queries/retries, input/MT frontend and physical hardware remain outside these configuration transcripts.']},indent=2)+'\n')
    print(len(result.stdout.splitlines()),'original v4 configuration records')


if __name__=='__main__':
    main()

#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Complete original Elantech register setter/read primitives, successful services."""
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

MAIN = r'''
int main(void){
    static const u8 addresses[]={7,0x10,0x11,0x20,0x21,0x22,0x23,0x24,0x25,0x26};
    static const size_t offsets[]={offsetof(struct elantech_data,reg_07),offsetof(struct elantech_data,reg_10),offsetof(struct elantech_data,reg_11),offsetof(struct elantech_data,reg_20),offsetof(struct elantech_data,reg_21),offsetof(struct elantech_data,reg_22),offsetof(struct elantech_data,reg_23),offsetof(struct elantech_data,reg_24),offsetof(struct elantech_data,reg_25),offsetof(struct elantech_data,reg_26)};
    for(source_hw=1;source_hw<=4;++source_hw)for(unsigned r=0;r<ARRAY_SIZE(addresses);++r)for(unsigned value=0;value<256;++value){
        struct elantech_data data={0};struct psmouse mouse={0};mouse.private=&data;data.info.hw_version=source_hw;
        scale_count=sliced=quarters=slice_count=custom_count=wire_count=source_sleep_ms=0;
        rejected_services=service_calls=0;resolution_arg=custom_literal=locked=false;memset(regs,0,sizeof(regs));
        struct elantech_attr_data attr={offsets[r],addresses[r]};u8*cache=(u8*)&data+offsets[r];*cache=0x55;
        char text[3];snprintf(text,sizeof(text),"%02x",value);
        /* The native protected caller is separately qualified. These source
         * command services bracket the unchanged attribute setter/read leaf. */
        assert(ps2_command(&mouse.ps2dev,NULL,PSMOUSE_CMD_DISABLE)==0);
        ssize_t result=elantech_set_int_attr(&mouse,&attr,text,2);
        assert(result==2);assert(*cache==regs[addresses[r]]);
        assert(ps2_command(&mouse.ps2dev,NULL,PSMOUSE_CMD_ENABLE)==0);
        assert(ps2_command(&mouse.ps2dev,NULL,PSMOUSE_CMD_DISABLE)==0);
        readback_value=value^0xa5;u8 observed=0;
        assert(elantech_read_reg(&mouse,addresses[r],&observed)==0);
        assert(ps2_command(&mouse.ps2dev,NULL,PSMOUSE_CMD_ENABLE)==0);
        assert(!locked);assert(source_sleep_ms==0);
        printf("%u %u %u %u %u ",source_hw,addresses[r],value,*cache,observed);
        for(unsigned i=0;i<wire_count;++i)printf("%02x",wire[i]);printf("\n");
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
    lib = (root/'drivers/input/serio/libps2.c').read_text()
    assert hashlib.sha256(lib.encode()).hexdigest() == pt.LIB_SHA
    header = (mouse/'psmouse.h').read_text()
    assert hashlib.sha256(header.encode()).hexdigest() == '9ee4f530d7c954d80828bd51cd6194494581e05764c1604d5c0bbb5b704aa5a1'
    constants = '\n'.join(line for text in [header, lib] for line in text.splitlines()
                          if line.startswith(('#define PSMOUSE_CMD_', '#define PS2_CMD_'))) + '\n'
    constants += '\n'.join(re.search(r'enum '+name+r' \{.*?\n\};', header, re.S).group()
                           for name in ['psmouse_scale', 'psmouse_type'])+'\n'
    prefix = controls.PREFIX.replace('#include <errno.h>', '#include <errno.h>\n#include <stddef.h>\n#include <sys/types.h>')
    prefix = prefix.replace('static unsigned firmware,', 'static unsigned source_hw;\nstatic unsigned firmware,')
    prefix = prefix.replace('if(custom_count==3){assert(custom_values[0]==0x11);regs[custom_values[1]]=custom_values[2];custom_count=0;}',
        'if(custom_count==3){assert(custom_values[0]==0x11||custom_values[0]==0);regs[custom_values[1]]=custom_values[2];custom_count=0;}else if(custom_count==4){assert(custom_values[0]==0&&custom_values[2]==0);regs[custom_values[1]]=custom_values[3];custom_count=0;}')
    prefix = prefix.replace('custom_values[0]==0x10', '(custom_values[0]==0x10||custom_values[0]==0)')
    # A literal register value may itself equal E9. Only the encoded three-byte
    # GETINFO service requests a reply; the plain byte remains custom payload.
    prefix = prefix.replace('if((command&255)==0xe9)', 'if(command==PSMOUSE_CMD_GETINFO)')
    prefix = prefix.replace('param[0]=readback_value;param[1]=0xfa;param[2]=0xfe;',
        'param[0]=source_hw==4?0xfa:readback_value;param[1]=source_hw==4?readback_value:0xfa;param[2]=0xfe;')
    # Parsing is a callback boundary: this oracle supplies only valid two-digit
    # hex strings. It does not claim to implement or qualify Linux kstrtox.
    prefix += '\nstatic int kstrtou8(const char*text,unsigned base,u8*out){unsigned v=0;assert(base==16&&strlen(text)==2&&sscanf(text,"%2x",&v)==1&&v<=255);*out=v;return 0;}\n'
    source = (mouse/'elantech.c').read_text()
    attr = re.search(r'struct elantech_attr_data \{.*?\n\};', source, re.S).group()
    bodies = {'ps2_sliced_command': pt.exported(lib, 'int ps2_sliced_command(')}
    for name in ['elantech_ps2_command', 'elantech_read_reg', 'elantech_write_reg', 'elantech_set_int_attr']:
        bodies[name] = pt.absolute.function(source, name)
    c = output/'oracle.c'
    c.write_text(constants+prefix.replace('ELANTECH_HEADER', str((mouse/'elantech.h').resolve()))+attr+'\n'+'\n'.join(bodies.values())+MAIN)
    binary = output/'oracle'
    subprocess.run(['clang', '-std=gnu11', '-O1', '-g', '-fsanitize=address,undefined', '-fno-sanitize-recover=all', str(c), '-o', str(binary)], check=True, timeout=60)
    result = subprocess.run([str(binary.resolve())], capture_output=True, text=True, check=True, timeout=60)
    (output/'records.txt').write_text(result.stdout)
    (output/'manifest.json').write_text(json.dumps({
        'pin': pt.absolute.PIN, 'sources': reports.HASHES, 'libps2_sha256': pt.LIB_SHA,
        'psmouse_header_sha256': hashlib.sha256(header.encode()).hexdigest(),
        'helper_sha256': {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in [Path(__file__), helper, Path(reports.__file__), Path(pt.__file__), Path(pt.absolute.__file__)]},
        'unchanged_functions': {name: hashlib.sha256(body.encode()).hexdigest() for name, body in bodies.items()},
        'records': len(result.stdout.splitlines()),
        'columns': ['hardware', 'address', 'requested', 'source_effective_and_cached', 'observed_value', 'wire'],
        'oracle_limit': ['Five complete original register setter/read/write/retry/sliced bodies execute successful command services. This does not establish a native mutable control.',
                        'All256 values of ten advertised hardware register attributes on v1-v4 exercise actual V1 forced mode bits, family dialect and independent readback values.',
                        'Only valid two-digit hex strings are passed through a modeled kstrtou8 service; parser behavior and full protected sysfs/kernel service wrapper are not qualified.',
                        'Source setter masks write errors in its byte-count result. Native uncertainty/retry/effect retention, firmware reporting, frontend and physical devices require separate proof.'],
    }, indent=2)+'\n')
    print(len(result.stdout.splitlines()), 'original mutable register control records')


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Linux I801 authors/notices are retained in bus/THIRD_PARTY.md.
"""Execute complete original I801 Quick/PEC-exclusion/error algorithms.

Eight unchanged source functions; ordered register, completion, time and
runtime/locking services are modeled. Quick never carries command/data/PEC.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess

HELPER_SHA="1c0e3c18af288ade9161e3c1a6342655b3dbd52440073494af1c6f6f941564cf"


def digest(raw):return hashlib.sha256(raw).hexdigest()


SERVICES=r'''
static u8 registers[16],captured[7],completion_status,active,start_crc;
static unsigned data_reads,command_stores,data_stores;
static unsigned long jiffies;
static struct i801_priv*i2c_get_adapdata(struct i2c_adapter*a){return a->priv;}
static u8 ioread8(unsigned r){assert(r<16);if(r==5||r==6)data_reads++;return registers[r];}
static void iowrite8(u8 v,unsigned r){
    assert(r<16);if(r==3)command_stores++;if(r==5||r==6)data_stores++;
    if(r==0||r==12)registers[r]&=~v;else registers[r]=v;
    if(r==2&&(v&SMBHSTCNT_START)){
        assert((v&0x1c)==I801_QUICK);memcpy(captured,registers,7);
        start_crc=registers[13]&SMBAUXCTL_CRC;assert(!start_crc);
        active=1;registers[0]|=SMBHSTSTS_HOST_BUSY;
    }
}
static void usleep_range(unsigned lo,unsigned hi){
    (void)lo;(void)hi;jiffies++;if(!active)return;
    active=0;registers[0]=completion_status;
    if(!(registers[0]&STATUS_ERROR_FLAGS))registers[0]|=SMBHSTSTS_INTR;
}
#define time_is_after_eq_jiffies(deadline) ((deadline)>=jiffies)
static void reinit_completion(int*p){(void)p;assert(0);}
static unsigned long wait_for_completion_timeout(int*p,unsigned long t){(void)p;(void)t;assert(0);return 0;}
static int i801_smbus_block_transaction(struct i801_priv*p,union i2c_smbus_data*d,u8 a,u8 c,char r,int s){(void)p;(void)d;(void)a;(void)c;(void)r;(void)s;assert(0);return -EOPNOTSUPP;}
static int i801_i2c_block_transaction(struct i801_priv*p,union i2c_smbus_data*d,u8 a,u8 c,char r,int s){(void)p;(void)d;(void)a;(void)c;(void)r;(void)s;assert(0);return -EOPNOTSUPP;}
'''
SUFFIX=r'''
int main(void){
    struct pci_dev pci={0};struct i801_priv p={.features=FEATURE_SMBUS_PEC,.pci_dev=&pci,.adapter={.timeout=10}};
    struct i2c_adapter a={.priv=&p};const unsigned addresses[]={8,44,119},statuses[]={0,16,4,8,20,24,12,28};unsigned id=0;
    puts("I801_QUICK cc9de5d4b5ab6459f5774946aa3195ad51236fa8 96");
    for(unsigned ad=0;ad<3;ad++)for(unsigned read=0;read<2;read++)for(unsigned pec=0;pec<2;pec++)for(unsigned st=0;st<8;st++){
        memset(registers,0,sizeof(registers));registers[0]=SMBHSTSTS_INUSE_STS;registers[13]=0x81;
        registers[3]=0xf0;registers[5]=0x5a;registers[6]=0xa5;
        active=0;jiffies=0;data_reads=0;command_stores=0;data_stores=0;completion_status=statuses[st];
        union i2c_smbus_data data={0};
        int result=i801_access(&a,addresses[ad],pec?I2C_CLIENT_PEC:0,read,0xa7,I2C_SMBUS_QUICK,&data);
        unsigned cls=result==0?0:result==-EIO?1:result==-ENXIO?2:result==-EAGAIN?4:99;assert(cls!=99);
        assert(!data_reads&&!command_stores&&!data_stores);
        printf("%u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u\n",
            id++,addresses[ad],read,pec,statuses[st],cls,captured[2],captured[4],start_crc,
            data_reads,command_stores,data_stores,registers[3],registers[5],registers[6],registers[13],registers[0],registers[12]);
    }assert(id==96);return 0;
}
'''


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--reference',type=Path,required=True)
    parser.add_argument('--out',type=Path,required=True)
    parser.add_argument('--cc',default='clang')
    args=parser.parse_args()
    helper=Path(__file__).with_name('i801_process_pec_oracle.py')
    if digest(helper.read_bytes())!=HELPER_SHA:raise ValueError('declaration helper changed')
    spec=importlib.util.spec_from_file_location('process_declarations',helper)
    base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base)
    raw=(args.reference/base.SOURCE).read_bytes()
    if digest(raw)!=base.SHA256:raise ValueError('donor hash mismatch')
    compiler=shutil.which(args.cc)
    if compiler is None:raise ValueError('compiler unavailable')
    compiler=Path(compiler).resolve();args.out.mkdir(parents=True,exist_ok=False)
    report=dict(status='FAIL',pin=base.PIN,source_sha256=digest(raw),script_sha256=digest(Path(__file__).read_bytes()),helper_sha256=HELPER_SHA,
                compiler=str(compiler),compiler_sha256=digest(compiler.read_bytes()))
    def save():(args.out/'report.json').write_text(json.dumps(report,indent=2)+'\n')
    save()
    try:
        prefix=base.PREFIX[:base.PREFIX.index('static u8 registers[')]
        bodies=[base.function(raw.decode(),m) for m in base.MARKERS]
        report['unchanged_functions']={m:digest(b.encode()) for m,b in zip(base.MARKERS,bodies)}
        source=args.out/'quick.c';source.write_text(prefix+SERVICES+'\n\n'.join(bodies)+SUFFIX);binary=args.out/'quick'
        command=[str(compiler),'-std=c11','-O1','-g','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-fno-sanitize-recover=all','-fno-omit-frame-pointer',str(source),'-o',str(binary)]
        report.update(phase='compiling',compile_command=command,generated_source_sha256=digest(source.read_bytes()));save()
        result=subprocess.run(command,capture_output=True,timeout=60);(args.out/'compile.log').write_bytes(result.stdout+result.stderr);result.check_returncode()
        report.update(phase='executing',binary_sha256=digest(binary.read_bytes()));save()
        result=subprocess.run([str(binary)],capture_output=True,timeout=30);(args.out/'stderr.log').write_bytes(result.stderr);result.check_returncode()
        lines=result.stdout.decode().splitlines();assert len(lines)==97 and lines[0]==f'I801_QUICK {base.PIN} 96'
        for i,line in enumerate(lines[1:]):
            v=list(map(int,line.split()));assert len(v)==18 and v[0]==i
        (args.out/'records.txt').write_bytes(result.stdout)
        report.update(status='PASS',phase='complete',records=96,records_sha256=digest(result.stdout),limits=[
            'Eight complete unchanged functions, Quick polled path only; both client PEC flags explicitly leave hardware CRC disabled',
            'Ordered register/time/peripheral final completion and runtime/locking services modeled; no physical bus/IRQ/attachment proof',
            'Native actual configuration/deadline guard is additional containment; all ordinary unicast addresses tested separately'])
    except BaseException as error:report['failure']=type(error).__name__+': '+str(error);raise
    finally:save()


if __name__=='__main__':main()

#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Linux I801 authors/notices are retained in bus/THIRD_PARTY.md.
"""Execute eleven unchanged Linux I801 E32B block-process/PEC algorithms.

Hash-bound declaration services are shared with the process-call fixture;
FIFO, peripheral completion/error and time services below are independent.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess

HELPER_SHA="1c0e3c18af288ade9161e3c1a6342655b3dbd52440073494af1c6f6f941564cf"
MARKERS=["static int i801_wait_intr(","static int i801_check_and_clear_pec_error(",
         "static int i801_check_pre(","static int i801_check_post(",
         "static int i801_transaction(","static int i801_get_block_len(",
         "static void i801_set_hstadd(","static int i801_simple_transaction(",
         "static int i801_block_transaction_by_block(",
         "static int i801_smbus_block_transaction(","static s32 i801_access("]


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


SERVICES=r'''
#define FEATURE_BLOCK_BUFFER BIT(1)
#define FEATURE_BLOCK_PROC BIT(2)
#define I2C_SMBUS_BLOCK_MAX 32
#define SMBUS_LEN_SENTINEL 255
#define I801_BLOCK_DATA 20
#define I801_BLOCK_PROC_CALL 28
#define SMBAUXCTL_E32B BIT(1)
#define SMBBLKDAT(p) ((void)(p),7)
static u8 registers[16],fifo[32],reply[32],transmitted[32],captured[7];
static unsigned long jiffies;
static unsigned index_fifo,active,tx_count,rx_count,resets;
static u8 completion_status,corrupt,start_aux;
static struct i801_priv*i2c_get_adapdata(struct i2c_adapter*a){return a->priv;}
static u8 ioread8(unsigned r){assert(r<16);if(r==2){index_fifo=0;resets++;}if(r==7){assert(index_fifo<32);return fifo[index_fifo++];}return registers[r];}
static void iowrite8(u8 v,unsigned r){
    assert(r<16);
    if(r==0||r==12)registers[r]&=~v;
    else if(r==7){assert(index_fifo<32);fifo[index_fifo++]=v;}
    else registers[r]=v;
    if(r==2&&(v&SMBHSTCNT_START)){
        assert((v&0x1c)==I801_BLOCK_PROC_CALL);assert(!(registers[4]&1));
        memcpy(captured,registers,7);start_aux=registers[13];
        assert(start_aux&SMBAUXCTL_E32B);assert(registers[5]==tx_count);
        memcpy(transmitted,fifo,tx_count);active=1;registers[0]|=SMBHSTSTS_HOST_BUSY;
    }
}
static void iowrite8_rep(unsigned r,const void*p,unsigned n){const u8*b=p;for(unsigned i=0;i<n;i++)iowrite8(b[i],r);}
static void ioread8_rep(unsigned r,void*p,unsigned n){u8*b=p;for(unsigned i=0;i<n;i++)b[i]=ioread8(r);}
static void usleep_range(unsigned lo,unsigned hi){
    (void)lo;(void)hi;jiffies++;if(!active)return;
    active=0;memcpy(fifo,reply,rx_count);registers[5]=rx_count;
    registers[0]=completion_status;
    if(corrupt&&(registers[13]&SMBAUXCTL_CRC)){registers[12]|=SMBAUXSTS_CRCE;registers[0]|=SMBHSTSTS_DEV_ERR;}
    if(!(registers[0]&STATUS_ERROR_FLAGS))registers[0]|=SMBHSTSTS_INTR;
}
#define time_is_after_eq_jiffies(deadline) ((deadline)>=jiffies)
static void reinit_completion(int*p){(void)p;assert(0);}
static unsigned long wait_for_completion_timeout(int*p,unsigned long t){(void)p;(void)t;assert(0);return 0;}
static int i801_block_transaction_byte_by_byte(struct i801_priv*p,union i2c_smbus_data*d,char r,int c){(void)p;(void)d;(void)r;(void)c;assert(0);return -EOPNOTSUPP;}
static int i801_i2c_block_transaction(struct i801_priv*p,union i2c_smbus_data*d,u8 a,u8 c,char r,int s){(void)p;(void)d;(void)a;(void)c;(void)r;(void)s;assert(0);return -EOPNOTSUPP;}
'''
SUFFIX=r'''
static uint32_t hash(const u8*b,unsigned n){uint32_t h=2166136261U;for(unsigned i=0;i<n;i++)h=(h^b[i])*16777619U;return h;}
int main(void){
    struct pci_dev pci={0};struct i801_priv p={.features=FEATURE_SMBUS_PEC|FEATURE_BLOCK_BUFFER|FEATURE_BLOCK_PROC,.pci_dev=&pci,.adapter={.timeout=10}};
    struct i2c_adapter a={.priv=&p};
    const unsigned sizes[]={1,2,31,32},statuses[]={0,16,4,8,20,24,12,28};unsigned id=0;
    puts("I801_BLOCK_PROCESS cc9de5d4b5ab6459f5774946aa3195ad51236fa8 512");
    for(unsigned tx=0;tx<4;tx++)for(unsigned rx=0;rx<4;rx++)for(unsigned pec=0;pec<2;pec++)
    for(unsigned st=0;st<8;st++)for(unsigned cr=0;cr<2;cr++){
        memset(registers,0,sizeof(registers));registers[0]=SMBHSTSTS_INUSE_STS;registers[13]=0x80;
        tx_count=sizes[tx];rx_count=sizes[rx];index_fifo=0;active=0;resets=0;jiffies=0;completion_status=statuses[st];corrupt=cr;
        union i2c_smbus_data data={.block={0}};data.block[0]=tx_count;
        for(unsigned i=0;i<tx_count;i++)data.block[i+1]=(u8)(i*19+tx_count);
        for(unsigned i=0;i<rx_count;i++)reply[i]=(u8)(i*31+rx_count);
        int result=i801_access(&a,0x2c,pec?I2C_CLIENT_PEC:0,I2C_SMBUS_WRITE,0xa7,I2C_SMBUS_BLOCK_PROC_CALL,&data);
        unsigned cls=result==0?0:result==-EIO?1:result==-ENXIO?2:result==-EBADMSG?3:result==-EAGAIN?4:99;
        assert(cls!=99);
        printf("%u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u\n",id++,tx_count,rx_count,pec,statuses[st],cr,cls,
            captured[2],start_aux,captured[4],hash(transmitted,tx_count),hash(data.block+1,data.block[0]),data.block[0],
            registers[13],registers[0],registers[12],resets);
    }
    assert(id==512);return 0;
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
    compiler=Path(compiler).resolve()
    args.out.mkdir(parents=True,exist_ok=False)
    report=dict(status='FAIL',pin=base.PIN,source_sha256=digest(raw),script_sha256=digest(Path(__file__).read_bytes()),helper_sha256=HELPER_SHA,
                compiler=str(compiler),compiler_sha256=digest(compiler.read_bytes()))
    def save():(args.out/'report.json').write_text(json.dumps(report,indent=2)+'\n')
    save()
    try:
        prefix=base.PREFIX[:base.PREFIX.index('static u8 registers[')]
        prefix=prefix.replace('#define SMBHSTDAT0(p) 5','#define SMBHSTDAT0(p) ((void)(p),5)')
        bodies=[base.function(raw.decode(),m) for m in MARKERS]
        report['unchanged_functions']={m:digest(b.encode()) for m,b in zip(MARKERS,bodies)}
        source=args.out/'block-process.c';source.write_text(prefix+SERVICES+'\n\n'.join(bodies)+SUFFIX)
        binary=args.out/'block-process'
        command=[str(compiler),'-std=c11','-O1','-g','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-fno-sanitize-recover=all','-fno-omit-frame-pointer',str(source),'-o',str(binary)]
        report.update(phase='compiling',compile_command=command,generated_source_sha256=digest(source.read_bytes()));save()
        result=subprocess.run(command,capture_output=True,timeout=60);(args.out/'compile.log').write_bytes(result.stdout+result.stderr);result.check_returncode()
        report.update(phase='executing',binary_sha256=digest(binary.read_bytes()));save()
        result=subprocess.run([str(binary)],capture_output=True,timeout=30);(args.out/'stderr.log').write_bytes(result.stderr);result.check_returncode()
        lines=result.stdout.decode().splitlines();assert len(lines)==513 and lines[0]==f'I801_BLOCK_PROCESS {base.PIN} 512'
        for i,line in enumerate(lines[1:]):
            v=list(map(int,line.split()));assert len(v)==17 and v[0]==i
        (args.out/'records.txt').write_bytes(result.stdout)
        report.update(status='PASS',phase='complete',records=512,records_sha256=digest(result.stdout),limits=[
            'Eleven complete unchanged functions, E32B/polled block-process path; capability feature supplied at source frontend, native exact-profile refusal tested separately',
            'Ordered FIFO/time/peripheral final completion/CRC/error/runtime/locking services modeled; no physical CRC, IRQ or actual firmware attachment proof',
            'Native stages response through cleanup/actual PCI guard/deadline rather than exposing Linux mutable union before post-check'])
    except BaseException as error:report['failure']=type(error).__name__+': '+str(error);raise
    finally:save()


if __name__=='__main__':main()

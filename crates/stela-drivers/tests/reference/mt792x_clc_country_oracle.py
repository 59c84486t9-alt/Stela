#!/usr/bin/env python3
"""Run complete unchanged CLC loaders and country request helpers on actual images.
Usage: mt792x_clc_country_oracle.py MT76_DIRECTORY FRESH_OUTPUT_DIRECTORY FIRMWARE_DIRECTORY
ACPI/power-node observations and MCU allocation/handoff are modeled. Captured
commands are wire evidence, never applied regulatory or location authority.
"""
import hashlib,json,re,struct,subprocess,sys
from pathlib import Path
source,out,images=map(Path,sys.argv[1:]);out.mkdir(parents=True,exist_ok=False)
subprocess.run([sys.executable,str(Path(__file__).with_name('mt792x_clc_oracle.py')),str(source),str(out/'selection'),str(images)],stdout=subprocess.PIPE,check=True)
manifest=json.loads((out/'selection/manifest.json').read_text());hashes=manifest['sources']
hashes.update({'mt7921/mcu.h':'b5ce3ab4d77fb541b1c52f478bf0d7ed4c289daa41e72b0bc3c9105d3a9e39ca','kernel-regulatory.h':'f79e798657c7c688d851fa96d1fb65d8970ee6f866692f411c317f1d6b2ec179'})
texts={}
for name,digest in hashes.items():
 raw=(source/name).read_bytes();assert hashlib.sha256(raw).hexdigest()==digest,name;texts[name]=raw.decode()
def function(file,name):
 text=texts[file];m=re.search(r'\b'+name+r'\([^;{}]*?\)\n\{',text);assert m,name
 start=text.rfind('\n\n',0,m.start())+2;at,depth=m.end(),1
 while depth:depth+=(text[at]=='{')-(text[at]=='}');at+=1
 return text[start:at]+'\n'
def record(file,name):
 text=texts[file];start=text.index('struct '+name+' {');return text[start:text.index('} __packed;',start)+len('} __packed;')]+'\n'
unit=(out/'selection/linux-mt792x-clc.c').read_text().split('int main(',1)[0]
old='struct mt792x_phy {u8 clc_chan_conf;void *clc[MT792x_CLC_MAX_NUM];};'
assert old in unit;unit=unit.replace(old,'struct mt792x_phy {u8 clc_chan_conf,power_type;uint64_t chip_cap;void *clc[MT792x_CLC_MAX_NUM];};')
extra='typedef uint16_t u16;typedef uint16_t __le16;\n#define cpu_to_le16(x) (x)\n#define le16_to_cpu(x) (x)\n#define ENOENT 2\n#define ESRCH 3\n'
for file,name in [('mt7921/mt7921.h','mt7921_clc_rule'),('mt7921/mcu.h','mt7921_clc_info_tlv'),('mt7925/mt7925.h','mt7925_clc_rule'),('mt7925/mt7925.h','mt7925_clc_segment')]:extra+=record(file,name)
reg=texts['kernel-regulatory.h'];start=reg.index('enum environment_cap {');extra+=reg[start:reg.index('};',start)+2]+'\n'
# Include the complete permissive notice attached to the environment ABI.
start=reg.index('/*');extra+=reg[start:reg.index('*/',start)+2]+'\n'
for name in ['MCU_CE_CMD_SET_CLC','MCU_UNI_CMD_SET_POWER_LIMIT']:
 val=re.search(r'\b'+name+r'\s*=\s*(0x[0-9a-f]+)',texts['mt76_connac_mcu.h']);assert val;extra+='#define '+name+' '+val[1]+'\n'
extra+='#define MCU_CE_CMD(x) ((1<<18)|MCU_CE_CMD_##x)\n#define MCU_UNI_CMD(x) ((1<<17)|MCU_UNI_CMD_##x)\n#define MT792x_CHIP_CAP_CLC_EVT_EN BIT(0)\n'
scaffold=r'''
struct sk_buff {u8 *data;size_t len,capacity;};
static u8 flags;static u32 mtcl_requested,mtcl_world;static bool power_node,c3;
static u8 captured[1024*4096];static size_t captured_len;static u16 captured_count;
static u8 mt792x_acpi_get_flags(struct mt792x_phy *p){(void)p;return flags;}
static u32 mt792x_acpi_get_mtcl_conf(struct mt792x_phy *p,const u8 *country){(void)p;return !memcmp(country,"00",2)?mtcl_world:mtcl_requested;}
static bool mt76_find_power_limits_node(struct mt76_dev *p){(void)p;return power_node;}
static struct sk_buff *__mt76_mcu_msg_alloc(struct mt76_dev *d,const void *p,size_t cap,size_t n,int f){
 (void)d;if(f||n>cap)abort();struct sk_buff *s=calloc(1,sizeof(*s));if(!s)abort();s->data=malloc(cap);if(!s->data)abort();memcpy(s->data,p,n);s->len=n;s->capacity=cap;return s;
}
static void skb_put_data(struct sk_buff *s,const void *p,size_t n){if(n>s->capacity-s->len)abort();memcpy(s->data+s->len,p,n);s->len+=n;}
static void dev_kfree_skb(struct sk_buff *s){free(s->data);free(s);}
static void capture(struct mt76_dev *d,struct sk_buff *s,int cmd,bool wait){
 struct mt792x_dev *owner=(void *)d;u16 n=s->len;if(n!=s->len||captured_len+8+n>sizeof(captured)||captured_count==1024)abort();
 memcpy(captured+captured_len,&cmd,4);captured[captured_len+4]=wait;captured[captured_len+5]=c3?owner->phy.clc_chan_conf:0;memcpy(captured+captured_len+6,&n,2);
 memcpy(captured+captured_len+8,s->data,n);captured_len+=8+n;captured_count++;dev_kfree_skb(s);
}
static int mt76_mcu_skb_send_and_get_msg(struct mt76_dev *d,struct sk_buff *s,int cmd,bool wait,struct sk_buff **ret){
 capture(d,s,cmd,wait);*ret=NULL;if(wait){struct sk_buff *r=calloc(1,sizeof(*r));if(!r)abort();r->len=r->capacity=4+sizeof(struct mt7921_clc_info_tlv);r->data=calloc(1,r->len);if(!r->data)abort();r->data[8]=0x5a;*ret=r;}return 0;
}
static int mt76_mcu_skb_send_msg(struct mt76_dev *d,struct sk_buff *s,int cmd,bool wait){capture(d,s,cmd,wait);return 0;}
'''
helpers=''.join(function(f'mt{chip}/mcu.c',name) for chip in [7921,7925] for name in [f'__mt{chip}_mcu_set_clc',f'mt{chip}_mcu_set_clc'])
main=r'''
int main(int argc,char **argv){
 if(argc!=2)return 1;int chip=atoi(argv[1]);c3=chip==7925;
 for(;;){
  u8 meta[23];size_t got=fread(meta,1,23,stdin);if(!got)break;if(got!=23)abort();u32 size;if(fread(&size,1,4,stdin)!=4||!size||size>16*1024*1024)abort();
  input.size=size;input.data=malloc(size);if(!input.data)abort();if(fread(input.data,1,size,stdin)!=size)abort();
  struct mt792x_dev d={0};eeprom=meta[0];flags=meta[4];d.phy.power_type=meta[5];power_node=meta[6];memcpy(&d.phy.chip_cap,meta+7,8);memcpy(&mtcl_requested,meta+15,4);memcpy(&mtcl_world,meta+19,4);
  int rc=c3?mt7925_load_clc(&d,"exact-input"):mt7921_load_clc(&d,"exact-input");if(rc)abort();
  u32 combined=0;for(int i=0;i<3;i++){if(d.phy.clc[i]){u32 n;memcpy(&n,d.phy.clc[i],4);combined+=n;}}
  if(fwrite(meta,1,23,stdout)!=23||fwrite(&combined,1,4,stdout)!=4)abort();
  for(int i=0;i<3;i++){if(d.phy.clc[i]){u32 n;memcpy(&n,d.phy.clc[i],4);if(fwrite(d.phy.clc[i],1,n,stdout)!=n)abort();}}
  captured_len=captured_count=0;rc=c3?mt7925_mcu_set_clc(&d,meta+1,(enum environment_cap)meta[3]):mt7921_mcu_set_clc(&d,meta+1,(enum environment_cap)meta[3]);if(rc)abort();
  if(fwrite(&captured_count,1,2,stdout)!=2||fwrite(captured,1,captured_len,stdout)!=captured_len)abort();
  for(int i=0;i<4;i++)free(d.phy.clc[i]);free(input.data);
 }
 return 0;
}
'''
unit_path=out/'linux-mt792x-clc-country.c';unit_path.write_text(unit+extra+scaffold+helpers+main)
exe=out/'linux-mt792x-clc-country';subprocess.run(['cc','-std=gnu11','-O1','-g','-fsanitize=address,undefined','-fno-sanitize-recover=all','-Wno-pointer-sign',str(unit_path),'-o',str(exe)],check=True)
def synthetic(chip,i):
 records=[]
 for slot in range(2):
  if chip!=7925:
   data=b''
   for country in [b'US',b'00',b'US',b'CA']:
    payload=bytes((i+slot+j)&255 for j in range(24+(i+slot)%30));data+=country+bytes([i&255,slot])+struct.pack('<H',len(payload))+payload
   header=struct.pack('<I',16+len(data))+bytes([slot,1,4,0])+bytes(8)
  else:
   payload1=bytes((i+j)&255 for j in range(24+i%30));payload2=bytes((i*3+j)&255 for j in range(48+i%30))
   rules=b''.join(country+bytes([i&255,slot,index,flag,0,0]) for country,index,flag in [(b'US',1,i&255),(b'00',2,(i+7)&255),(b'US',2,(i+9)&255),(b'CA',1,(i+11)&255)])
   start=32+len(rules);seg=lambda index,off,n:bytes([index,0,0,0])+struct.pack('<II',off,n)+bytes(4)
   data=seg(1,start,len(payload1))+seg(2,start+len(payload1),len(payload2))+rules+payload1+payload2
   header=struct.pack('<I',16+len(data))+bytes([slot,1+i%2,4,0,2])+bytes(7)
  records.append(header+data)
 data=b''.join(records);desc=bytearray(40);struct.pack_into('<I',desc,20,len(data));desc[24:26]=bytes([64,2]);trailer=bytearray(36);trailer[:4]=bytes([0x79,1,1,2]);return data+desc+trailer
firmware={case['chip']:(case['ram_name'],case['ram_sha256']) for case in manifest['cases']}
cases=[]
for chip in [7921,7922,7925]:
 inputs=[]
 def append(data,i,country):
  world=0x98760000|(i^0xff);requested=world if country==b'00' else 0x12340000|i
  meta=bytes([i&0xfc])+country+bytes([i%3,(i*3)&255,(i*5)&255,(i//2)%2])+struct.pack('<QII',(i//3)&1,requested,world)
  assert len(meta)==23;inputs.append(meta+struct.pack('<I',len(data))+data)
 for i in range(96):append(synthetic(chip,i),i,[b'US',b'CA',b'ZZ',b'00'][i%4])
 name,digest=firmware[chip];actual=(images/name).read_bytes();assert hashlib.sha256(actual).hexdigest()==digest
 for i in range(12):append(actual,i,[b'US',b'CN',b'ZZ',b'00'][i%4])
 trace=subprocess.run([str(exe.resolve()),str(chip)],input=b''.join(inputs),stdout=subprocess.PIPE,check=True).stdout
 (out/f'{chip}.trace').write_bytes(trace);cases.append({'chip':chip,'plans':len(inputs),'bytes':len(trace),'sha256':hashlib.sha256(trace).hexdigest()})
(out/'manifest.json').write_text(json.dumps({'linux_commit':manifest['linux_commit'],'sources':hashes,'cases':cases},indent=2)+'\n');print(json.dumps(cases,indent=2))

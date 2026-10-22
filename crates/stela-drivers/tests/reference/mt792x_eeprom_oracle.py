#!/usr/bin/env python3
"""Compare full unchanged EEPROM request/read helpers and full MCU fill writers.
Usage: mt792x_eeprom_oracle.py MT76_DIRECTORY FRESH_OUTPUT_DIRECTORY
Response bytes, firmware handoff and skb ownership are modeled, not EEPROM or
physical firmware validity. Sanitizer errors terminate the oracle.
"""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
source,out=map(Path,sys.argv[1:]);out.mkdir(parents=True,exist_ok=False)
hashes={
 'mt7921/mcu.c':'3b356eeef80727c27ad5f179e277a9d434297d14ac6df8297c98f4ce445e91b6',
 'mt7921/mcu.h':'b5ce3ab4d77fb541b1c52f478bf0d7ed4c289daa41e72b0bc3c9105d3a9e39ca',
 'mt7925/mcu.c':'cca76caa6429584b0b37f2772f5132e754a9e26b71660fb0e362ead4ee01dde6',
 'mt7921/mt7921.h':'370d21968a2fd423f4b745be820e83d06f336b17913616da487551a52797baab',
 'mt7925/mt7925.h':'b6fec2103954269927b44b095944120dd22a5a0503fa8930e49a8ecc044844dc',
 'mt76_connac_mcu.h':'2448b6c145f17397a717965eadf50c591934902f0b09684d37a8b0ae290b31ed',
}
texts={}
for name,digest in hashes.items():
 raw=(source/name).read_bytes();assert hashlib.sha256(raw).hexdigest()==digest,name;texts[name]=raw.decode()
def function(file,name):
 text=texts[file];m=re.search(r'\b'+name+r'\([^;{}]*?\)\n\{',text);assert m,name
 start=text.rfind('\n\n',0,m.start())+2;at,depth=m.end(),1
 while depth:depth+=(text[at]=='{')-(text[at]=='}');at+=1
 return text[start:at]+'\n'
def macro(file,name):return re.search(r'^#define\s+'+name+r'\b[^\n]*',texts[file],re.M).group()+'\n'
subprocess.run([sys.executable,str(Path(__file__).with_name('mt792x_mcu_oracle.py')),str(source),str(out/'fill')],stdout=subprocess.PIPE,check=True)
manifest=json.loads((out/'fill/manifest.json').read_text());hashes.update(manifest['sources'])
unit=(out/'fill/linux-mt792x-mcu.c').read_text().split('int main(',1)[0]
constants=''
for name in ['MCU_CMD_EXT_CID','MCU_EXT_CMD_EFUSE_ACCESS']:
 val=re.search(r'\b'+name+r'\s*=\s*(0x[0-9a-f]+)',texts['mt76_connac_mcu.h']);assert val,name;constants+='#define '+name+' '+val[1]+'\n'
constants+=macro('mt7921/mt7921.h','MT7921_EEPROM_BLOCK_SIZE')+macro('mt7925/mt7925.h','MT7925_EEPROM_BLOCK_SIZE')
h=texts['mt7921/mcu.h'];start=h.index('struct mt7921_mcu_eeprom_info {');constants+=h[start:h.index('} __packed;',start)+len('} __packed;')]+'\n'
scaffold=r'''
#define __MCU_CMD_FIELD_WM BIT(20)
#define MCU_EXT_QUERY(x) (MCU_CMD_EXT_CID|(MCU_EXT_CMD_##x<<8)|__MCU_CMD_FIELD_QUERY)
#define MCU_WM_UNI_CMD_QUERY(x) (MCU_UNI_CMD(x)|__MCU_CMD_FIELD_QUERY|__MCU_CMD_FIELD_WM)
#define round_down(x,y) ((x)&~((typeof(x))(y)-1))
struct mt792x_dev {struct mt76_dev mt76;};
static int chip;
static u8 response[80],wire[128];static int response_length,wire_length;
static void dev_kfree_skb(struct sk_buff *s){free(s->data);free(s);}
static int mt76_mcu_send_and_get_msg(struct mt76_dev *d,int cmd,const void *body,int n,bool wait,struct sk_buff **out) {
 if(!wait)abort();u8 *allocation=calloc(1,n+128);if(!allocation)abort();struct sk_buff s={.data=allocation+128,.len=n};memcpy(s.data,body,n);int seq;
 int rc=chip==7925?mt7925_mcu_fill_message(d,&s,cmd,&seq):mt76_connac2_mcu_fill_message(d,&s,cmd,&seq);if(rc||s.len>sizeof(wire))abort();
 wire_length=s.len;memcpy(wire,s.data,s.len);free(allocation);
 struct sk_buff *r=calloc(1,sizeof(*r));if(!r)abort();r->data=malloc(response_length);if(!r->data)abort();memcpy(r->data,response,response_length);r->len=response_length;*out=r;return 0;
}
'''
helpers=function('mt7921/mcu.c','mt7921_mcu_read_eeprom')+function('mt7925/mcu.c','mt7925_mcu_read_eeprom')
main=r'''
int main(int argc,char **argv){
 if(argc!=2)return 1;chip=atoi(argv[1]);bool c3=chip==7925;struct mt792x_dev d={0};
 for(int i=0;i<512;i++){
  response_length=c3?80:24;for(int j=0;j<response_length;j++)response[j]=(u8)(i*17+j*7);
  u32 addr=c3?0xa70:0x550;memcpy(response+(c3?12:0),&addr,4);
  if(i%3==0)memset(response+(c3?16:4),0,4);
  u8 result=0;int rc=c3?mt7925_mcu_read_eeprom(&d,0xa71,&result):mt7921_mcu_read_eeprom(&d,0x55b,&result);if(rc)abort();
  u16 wn=wire_length,rn=response_length;
  if(fwrite(&wn,1,2,stdout)!=2||fwrite(wire,1,wn,stdout)!=wn||fwrite(&rn,1,2,stdout)!=2||fwrite(response,1,rn,stdout)!=rn||fwrite(&result,1,1,stdout)!=1)abort();
 }
 return 0;
}
'''
unit_path=out/'linux-mt792x-eeprom.c';unit_path.write_text(unit+constants+scaffold+helpers+main)
exe=out/'linux-mt792x-eeprom';subprocess.run(['cc','-std=gnu11','-O1','-g','-fsanitize=address,undefined','-fno-sanitize-recover=all',str(unit_path),'-o',str(exe)],check=True)
cases=[]
for chip in [7921,7922,7925]:
 trace=subprocess.run([str(exe.resolve()),str(chip)],stdout=subprocess.PIPE,check=True).stdout
 (out/f'{chip}.trace').write_bytes(trace);cases.append({'chip':chip,'queries':512,'bytes':len(trace),'sha256':hashlib.sha256(trace).hexdigest()})
(out/'manifest.json').write_text(json.dumps({'linux_commit':'a804c5742bff224d4cb4d25dd383554d598be32b','sources':hashes,'cases':cases,'unchanged_fill_cases':manifest['cases']},indent=2)+'\n')
print(json.dumps(cases,indent=2))

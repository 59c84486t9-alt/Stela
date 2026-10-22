#!/usr/bin/env python3
"""Pass actual unchanged CLC country-helper bodies through full MCU writers.
Usage: mt792x_clc_wire_oracle.py MT76_DIRECTORY FRESH_OUTPUT_DIRECTORY FIRMWARE_DIRECTORY
Generates fresh prerequisite oracles and preserves all their immutable traces.
No native completion, policy application or radio qualification is inferred.
"""
import hashlib,json,struct,subprocess,sys
from pathlib import Path
source,out,images=map(Path,sys.argv[1:]);out.mkdir(parents=True,exist_ok=False)
parent=Path(__file__).parent
subprocess.run([sys.executable,str(parent/'mt792x_clc_country_oracle.py'),str(source),str(out/'country'),str(images)],stdout=subprocess.PIPE,check=True)
subprocess.run([sys.executable,str(parent/'mt792x_mcu_oracle.py'),str(source),str(out/'fill')],stdout=subprocess.PIPE,check=True)
country=json.loads((out/'country/manifest.json').read_text());fill=json.loads((out/'fill/manifest.json').read_text());hashes=country['sources'];hashes.update(fill['sources'])
unit=(out/'fill/linux-mt792x-mcu.c').read_text().split('int main(',1)[0]
main=r'''
int main(int argc,char **argv){
 if(argc!=2)return 1;int chip=atoi(argv[1]);struct mt76_dev d={0};
 for(;;){u32 cmd;size_t got=fread(&cmd,1,4,stdin);if(!got)break;if(got!=4)abort();u16 n;if(fread(&n,1,2,stdin)!=2||n>4096)abort();
  u8 *allocation=calloc(1,n+128);if(!allocation)abort();struct sk_buff s={.data=allocation+128,.len=n};if(fread(s.data,1,n,stdin)!=n)abort();
  int seq;int rc=chip==7925?mt7925_mcu_fill_message(&d,&s,cmd,&seq):mt76_connac2_mcu_fill_message(&d,&s,cmd,&seq);if(rc)abort();
  u16 length=s.len;if(length!=s.len)abort();if(fwrite(&length,1,2,stdout)!=2||fwrite(s.data,1,length,stdout)!=length)abort();free(allocation);
 }
 return 0;
}
'''
path=out/'linux-mt792x-clc-wire.c';path.write_text(unit+main);exe=out/'linux-mt792x-clc-wire'
subprocess.run(['cc','-std=gnu11','-O1','-g','-fsanitize=address,undefined','-fno-sanitize-recover=all',str(path),'-o',str(exe)],check=True)
cases=[]
for case in country['cases']:
 chip=case['chip'];raw=(out/f'country/{chip}.trace').read_bytes();at=0;inputs=[]
 for _ in range(case['plans']):
  at+=23;n=struct.unpack_from('<I',raw,at)[0];at+=4+n;count=struct.unpack_from('<H',raw,at)[0];at+=2
  for _ in range(count):
   cmd=struct.unpack_from('<I',raw,at)[0];n=struct.unpack_from('<H',raw,at+6)[0];at+=8
   inputs.append(struct.pack('<IH',cmd,n)+raw[at:at+n]);at+=n
 assert at==len(raw)
 trace=subprocess.run([str(exe.resolve()),str(chip)],input=b''.join(inputs),stdout=subprocess.PIPE,check=True).stdout
 (out/f'{chip}.trace').write_bytes(trace);cases.append({'chip':chip,'commands':len(inputs),'bytes':len(trace),'sha256':hashlib.sha256(trace).hexdigest()})
(out/'manifest.json').write_text(json.dumps({'linux_commit':country['linux_commit'],'sources':hashes,'cases':cases,'unchanged_fill_cases':fill['cases']},indent=2)+'\n');print(json.dumps(cases,indent=2))

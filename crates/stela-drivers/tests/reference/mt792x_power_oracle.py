#!/usr/bin/env python3
"""Run complete unchanged source SKU/band/SAR helpers and MCU writers.
Usage: mt792x_power_oracle.py MT76_DIRECTORY FRESH_OUTPUT_DIRECTORY
Platform/DTS resolution is an explicit per-rate fixture callback, not authority.
"""
import hashlib,json,re,subprocess,sys
from pathlib import Path
source,out=map(Path,sys.argv[1:]);out.mkdir(parents=True,exist_ok=False)
hashes={
'mt76_connac_mcu.c':'52472fd20bc0a1d744f3eee7a28b7205609e160c479a9da1ec5afa4528e389ec',
'mt76_connac_mcu.h':'2448b6c145f17397a717965eadf50c591934902f0b09684d37a8b0ae290b31ed',
'mt7925/mcu.c':'cca76caa6429584b0b37f2772f5132e754a9e26b71660fb0e362ead4ee01dde6',
'mt7925/mcu.h':'35855f4cdc673a7562241afd618fdd73fc181d210127e3ca2f762f3199cbc772',
'mt76.h':'b7e52e9559ff1bd5d256ccdbaa2b4c277d418955acd141708059af3161470bea',
'mac80211.c':'4a88a2105def248340f237377f698300478e1352dfc81a955e8a5e61f91d07df',
'mt792x_regs.h':'6c3d946ff97e6952d8ff702cc0f74c6cc77f64c2e04129d1fdd2ed0024869557',
}
texts={}
for name,digest in hashes.items():
 raw=(source/name).read_bytes();assert hashlib.sha256(raw).hexdigest()==digest,name;texts[name]=raw.decode()
def function(file,name):
 text=texts[file];m=re.search(r'\b'+name+r'\([^;{}]*?\)\n\{',text);assert m,name
 start=text.rfind('\n\n',0,m.start())+2;at,depth=m.end(),1
 while depth:depth+=(text[at]=='{')-(text[at]=='}');at+=1
 return text[start:at]+'\n'
def block(file,needle):
 text=texts[file];start=text.index(needle);at=text.index('{',start)+1;depth=1
 while depth:depth+=(text[at]=='{')-(text[at]=='}');at+=1
 return text[start:text.index(';',at)+1]+'\n'
subprocess.run([sys.executable,str(Path(__file__).with_name('mt792x_domain_oracle.py')),str(source),str(out/'domain')],stdout=subprocess.PIPE,check=True)
domain=json.loads((out/'domain/manifest.json').read_text());hashes.update(domain['sources'])
unit=(out/'domain/linux-mt792x-domain.c').read_text().split('struct ieee80211_channel {',1)[0]
unit=unit.replace('mcu; u8 alpha2[2];','mcu; u8 alpha2[2]; void *dev; struct ieee80211_hw *hw;')
# The full source helpers below remain byte-for-byte unchanged. These are
# their bounded host allocations, device/cfg80211 containers and resolved DTS
# callbacks. Canary allocation makes source-unwritten C3 header bytes visible.
model=r"""
typedef int8_t s8;typedef int32_t s32;
#define MCU_CE_QUERY(x) (__MCU_CMD_FIELD_CE|__MCU_CMD_FIELD_QUERY|MCU_CE_CMD_##x)
#define GFP_KERNEL 0
#define ARRAY_SIZE(x) (sizeof(x)/sizeof((x)[0]))
#define DIV_ROUND_UP(n,d) (((n)+(d)-1)/(d))
#define min_t(t,a,b) ((t)(a)<(t)(b)?(t)(a):(t)(b))
#define NL80211_SAR_TYPE_POWER 1
enum nl80211_band {NL80211_BAND_2GHZ,NL80211_BAND_5GHZ,NL80211_BAND_60GHZ,NL80211_BAND_6GHZ};
struct ieee80211_channel{u16 hw_value;enum nl80211_band band;u32 flags;int max_reg_power;};
struct ieee80211_supported_band{int n_channels;struct ieee80211_channel *channels;};
struct cfg80211_sar_freq_ranges{u32 start_freq,end_freq;};
struct cfg80211_sar_capa{int num_freq_ranges;struct cfg80211_sar_freq_ranges *freq_ranges;};
struct cfg80211_sar_specs{int type,num_sub_specs;struct {u32 freq_range_index;s32 power;} sub_specs[3];};
struct wiphy{struct cfg80211_sar_capa *sar_capa;};
struct ieee80211_hw{void *priv;struct wiphy *wiphy;struct{int power_level;}conf;};
struct frp{struct cfg80211_sar_freq_ranges *range;int power;};
struct mt76_phy{struct mt76_dev *dev;struct ieee80211_hw *hw;struct frp *frp;struct {struct ieee80211_supported_band sband;}sband_2g,sband_5g,sband_6g;struct{bool has_2ghz,has_5ghz,has_6ghz;}cap;struct{struct ieee80211_channel *chan;}chandef;};
struct mt792x_dev{struct{u8 clc_chan_conf;}phy;};
static struct mt792x_dev device;
static int chip,seed,forced_frequency;
static FILE *resolved;
static struct mt792x_dev *mt792x_hw_dev(struct ieee80211_hw *hw){(void)hw;return &device;}
static bool is_connac2(struct mt76_dev *dev){(void)dev;return chip!=7925;}
static bool is_mt7663(struct mt76_dev *dev){(void)dev;return false;}
static int ieee80211_channel_to_frequency(int channel,int band){if(forced_frequency)return forced_frequency;return band==NL80211_BAND_2GHZ?(channel==14?2484:2407+channel*5):(band==NL80211_BAND_6GHZ?5950:5000)+channel*5;}
static void *devm_kmalloc(void *dev,size_t n,int flags){(void)dev;(void)flags;void *p=malloc(n);if(!p)abort();memset(p,0x5a,n);return p;}
static void devm_kfree(void *dev,void *p){(void)dev;free(p);}
static void mt76_connac_set_txpower_cur(struct mt76_phy *phy,int power){(void)phy;(void)power;}
static void output(void *p,size_t n){if(fwrite(p,1,n,stdout)!=n)abort();}
static void emit(FILE *f,void *p,size_t n){if(fwrite(p,1,n,f)!=n)abort();}
static struct sk_buff *mt76_mcu_msg_alloc(struct mt76_dev *dev,void *data,int length){(void)dev;if(length<0||length>8192)abort();struct sk_buff *s=calloc(1,sizeof(*s));if(!s)abort();s->allocation=malloc(length+128);if(!s->allocation)abort();memset(s->allocation,0,128);memset(s->allocation+128,0x5a,length);s->capacity=length+128;s->data=s->allocation+128;if(data){memcpy(s->data,data,length);s->len=length;}return s;}
static void skb_reserve(struct sk_buff *s,int n){if(s->len||n<0||s->data+n>s->allocation+s->capacity)abort();s->data+=n;}
static void *skb_put(struct sk_buff *s,int n){if(n<0||s->data+s->len+n>s->allocation+s->capacity)abort();void *p=s->data+s->len;s->len+=n;return p;}
static void skb_put_data(struct sk_buff *s,void *p,int n){memcpy(skb_put(s,n),p,n);}
static void *__skb_push(struct sk_buff *s,int n){if(n<0||s->data-n<s->allocation)abort();return skb_push(s,n);}
static int mt76_mcu_skb_send_msg(struct mt76_dev *dev,struct sk_buff *s,int cmd,bool wait){u32 c=cmd;u8 w=wait;u16 n=s->len;if(n!=s->len)abort();output(&c,4);output(&w,1);output(&n,2);output(s->data,n);int seq;int rc=chip==7925?mt7925_mcu_fill_message(dev,s,cmd,&seq):mt76_connac2_mcu_fill_message(dev,s,cmd,&seq);if(rc)abort();n=s->len;output(&n,2);output(s->data,n);free(s->allocation);free(s);return 0;}
static int mt76_mcu_send_msg(struct mt76_dev *dev,int cmd,void *p,int n,bool wait){struct sk_buff *s=mt76_mcu_msg_alloc(dev,p,n);return mt76_mcu_skb_send_msg(dev,s,cmd,wait);}
u32 mt76_connac_mcu_reg_rr(struct mt76_dev *,u32);
"""
# Source structs include nested path arrays; they are intentionally retained,
# while the resolved per-rate fixture below records only the source SKU inputs.
parts=block('mt76.h','struct mt76_power_limits {')
for file,name in [('mt76_connac_mcu.h','MT_SKU_POWER_LIMIT'),('mt7925/mcu.h','MT_CONNAC3_SKU_POWER_LIMIT'),('mt792x_regs.h','MT_PSE_BASE')]:
 m=re.search(r'^#define '+name+r'\s+[^\n]+',texts[file],re.M);assert m;parts+=m.group()+'\n'
for file,name in [('mt76_connac_mcu.h','struct mt76_connac_sku_tlv {'),('mt76_connac_mcu.h','struct mt76_connac_tx_power_limit_tlv {'),('mt7925/mcu.h','struct mt7925_sku_tlv {'),('mt7925/mcu.h','struct mt7925_tx_power_limit_tlv {')]:parts+=block(file,name)
resolver=r"""
static s8 mt76_get_rate_power_limits(struct mt76_phy *phy,struct ieee80211_channel *chan,struct mt76_power_limits *limits,s8 target){
 (void)phy;s8 *data=(s8 *)limits;for(size_t j=0;j<sizeof(*limits);j++){s8 requested=(s8)((seed*17+chan->hw_value*3+j*5)%151-80);data[j]=min_t(s8,target,requested);}
 u8 meta[2]={chan->hw_value,chan->band};emit(resolved,meta,2);emit(resolved,limits,392);return target;
}
"""
main=r"""
int main(int argc,char **argv){
 if(argc!=3)return 1;chip=atoi(argv[1]);resolved=fopen(argv[2],"wb");if(!resolved)abort();
 struct mt76_dev dev={0};struct ieee80211_hw hw={0};struct wiphy wiphy={0};struct frp frp[3]={0};
 struct cfg80211_sar_freq_ranges ranges[3]={{2400,2500},{5000,5925},{5925,7200}};struct cfg80211_sar_capa capa={3,ranges};wiphy.sar_capa=&capa;hw.wiphy=&wiphy;dev.hw=&hw;
 struct mt76_phy phy={.dev=&dev,.hw=&hw,.frp=frp};hw.priv=&phy;
 if(chip==0){
  const int frequencies[]={2399,2400,2499,2500,4999,5000,5924,5925,7199,7200};
  for(int i=0;i<1024;i++){
   memset(frp,0,sizeof(frp));struct cfg80211_sar_specs specs={.type=NL80211_SAR_TYPE_POWER,.num_sub_specs=1+i%3};
   s32 quarter[3]={0};for(int b=0;b<specs.num_sub_specs;b++){int index=(i+b)%3;specs.sub_specs[b].freq_range_index=index;quarter[index]=specs.sub_specs[b].power=(i*31+b*17)%510-254;}
   if(mt76_init_sar_power(&hw,&specs))abort();s8 target=(i*19)%255-127;int16_t power=target;forced_frequency=frequencies[i%10];u32 freq=forced_frequency;
   output(&power,2);output(&freq,4);for(int b=0;b<3;b++){u8 present=frp[b].range!=NULL;output(&present,1);output(&ranges[b].start_freq,4);output(&ranges[b].end_freq,4);output(&quarter[b],4);}
   struct ieee80211_channel channel={0};s8 result=mt76_get_sar_power(&phy,&channel,target);output(&result,1);
  }
  if(fclose(resolved))abort();return 0;
 }
 struct ieee80211_channel band[3][256];for(int b=0;b<3;b++)for(int c=0;c<256;c++)band[b][c]=(struct ieee80211_channel){.hw_value=c,.max_reg_power=15};
 phy.sband_2g.sband=(struct ieee80211_supported_band){256,band[0]};phy.sband_5g.sband=(struct ieee80211_supported_band){256,band[1]};phy.sband_6g.sband=(struct ieee80211_supported_band){256,band[2]};
 for(seed=0;seed<24;seed++){
  unsigned mask=1+seed%7;phy.cap.has_2ghz=mask&1;phy.cap.has_5ghz=mask&2;phy.cap.has_6ghz=mask&4;device.phy.clc_chan_conf=(seed%4)?0xff:0;
  hw.conf.power_level=1+seed%29;dev.alpha2[0]=seed%3?'U':'0';dev.alpha2[1]=seed%3?'S':'0';
  struct cfg80211_sar_specs specs={.type=NL80211_SAR_TYPE_POWER,.num_sub_specs=3};for(int b=0;b<3;b++){specs.sub_specs[b].freq_range_index=b;specs.sub_specs[b].power=60-seed*3-b*7;}if(mt76_init_sar_power(&hw,&specs))abort();
  u16 counts[3]={phy.cap.has_2ghz?14:0,phy.cap.has_5ghz?(chip==7925?46:48):0,phy.cap.has_6ghz&&(chip!=7925||device.phy.clc_chan_conf)?109:0};
  emit(resolved,counts,6);emit(resolved,dev.alpha2,2);u16 messages=0;for(int b=0;b<3;b++)messages+=chip==7925?DIV_ROUND_UP(counts[b],3):2*DIV_ROUND_UP(counts[b],8);output(&messages,2);
  int rc=chip==7925?mt7925_mcu_set_rate_txpower(&phy):mt76_connac_mcu_set_rate_txpower(&phy);if(rc)abort();
 }
 if(fclose(resolved))abort();return 0;
}
"""
functions=function('mac80211.c','mt76_init_sar_power')+function('mac80211.c','mt76_get_sar_power')+function('mt76_connac_mcu.c','mt76_connac_get_ch_power')+resolver+function('mt76_connac_mcu.c','mt76_connac_get_rate_power_limit')
for file,name in [('mt76_connac_mcu.c','mt76_connac_mcu_build_sku'),('mt76_connac_mcu.c','mt76_connac_mcu_rate_txpower_band'),('mt76_connac_mcu.c','mt76_connac_mcu_set_rate_txpower'),('mt76_connac_mcu.c','mt76_connac_mcu_reg_rr'),('mt7925/mcu.c','mt7925_mcu_build_sku'),('mt7925/mcu.c','mt7925_mcu_rate_txpower_band'),('mt7925/mcu.c','mt7925_mcu_set_rate_txpower')]:functions+=function(file,name)
path=out/'linux-mt792x-power.c';path.write_text(unit+model+parts+functions+main);exe=out/'linux-mt792x-power'
subprocess.run(['cc','-std=gnu11','-O1','-g','-fsanitize=address,undefined','-fno-sanitize-recover=all',str(path),'-o',str(exe)],check=True)
cases=[]
sar=subprocess.run([str(exe.resolve()),'0',str((out/'sar-resolver-unused').resolve())],stdout=subprocess.PIPE,check=True).stdout
(out/'sar.trace').write_bytes(sar)
for chip in [7921,7922,7925]:
 trace=subprocess.run([str(exe.resolve()),str(chip),str((out/f'{chip}.limits').resolve())],stdout=subprocess.PIPE,check=True).stdout
 (out/f'{chip}.trace').write_bytes(trace);limits=(out/f'{chip}.limits').read_bytes();cases.append({'chip':chip,'plans':24,'bytes':len(trace),'sha256':hashlib.sha256(trace).hexdigest(),'limits_bytes':len(limits),'limits_sha256':hashlib.sha256(limits).hexdigest()})
(out/'manifest.json').write_text(json.dumps({'linux_commit':domain['linux_commit'],'sources':hashes,'cases':cases,'sar_cases':1024,'sar_bytes':len(sar),'sar_sha256':hashlib.sha256(sar).hexdigest(),'source_unwritten_connac3_header':'canary5a; native deliberately zeroes reserved/version/limit_type/alpha2 padding'},indent=2)+'\n');print(json.dumps(cases,indent=2))

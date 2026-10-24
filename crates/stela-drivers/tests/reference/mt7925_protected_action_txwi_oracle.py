#!/usr/bin/env python3
"""Independent pinned Linux TXD trace for five protected unicast Action bodies.

Usage: mt7925_protected_action_txwi_oracle.py PINNED_MT76 FRESH_OUTPUT
The historical 768-case oracle is unchanged and never executed or imported.
Only its hash-bound literal C metadata fixture is reused. This compares TXD
arithmetic, not frame acceptance, key installation, encryption or radio delivery.
"""
if not __debug__:
    raise RuntimeError('optimized Python disabled required source guards')
import ast
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

HISTORICAL_SHA256 = '06798ab08723ff9fdbe74c26e59878f17e730e87f334468fe50cce5cfd83a809'
FUNCTION_SHA256 = {
    'mt76_connac_lmac_mapping': '4b41bef618fd5db635f70047a9e29271741fe8406a44cc56319fee3453640d86',
    'mt7925_mac_write_txwi_80211': 'fe5a3acd3236464ebd70c0bdd76902ee3a4fd69a63f901ab3d21e95dac9f250d',
    'mt7925_mac_write_txwi': 'a66ce43b187a90f6e9133991194bab1e10a170721ec11ab3a47a309ebe071095',
}
CASES = 480
RECORD_BYTES = 132

MAIN = r'''
static void put16(u8 *p, u16 n) {p[0]=n;p[1]=n>>8;}
int main(void) {
 const u32 wcids[]={7,0,19},omacs[]={0,2,63},wmms[]={0,3};
 const u32 bands[]={0,1,2,3,255},pids[]={0,2,3,255},tids[]={0,7,15};
 const u32 rates[]={18,14,31,63};
 for(u32 action=0;action<5;action++) for(u32 c=0;c<96;c++) {
  u32 wcid=wcids[c%3],omac=omacs[(c/3)%3],wmm=wmms[(c/9)%2];
  u32 band=bands[c%5],pid=pids[c%4],priority=tids[(c/4)%3];
  u32 explicit_seq=(c/12)%2,seq=(c/24)%2?4095:0;
  u32 noack=(c/2)%2,amsdu=(c/6)%2,minrate=!(c%2),rate=rates[c%4];
  u32 len=action<2?33:action==2?30:28,tid=tids[(c/8)%3];
  u32 input[]={action*96+c,action,wcid,omac,wmm,band,pid,priority,
               explicit_seq,seq,noack,amsdu,minrate,rate,len,tid};
  // All fixture MPDUs have a normal 24-byte unicast management header. The
  // plaintext Action body precedes hardware CCMP insertion/encryption; there
  // is no fabricated CCMP header, MIC, PN or MMIE in this TXD-only input.
  u32 storage[9]={0},txd[8]={0};u8 *frame=(void*)storage;
  put16(frame,0x40d0);frame[4]=2;frame[10]=4;frame[16]=6;
  put16(frame+22,seq<<4);
  if(action<3) {
   frame[24]=WLAN_CATEGORY_BACK;frame[25]=action;
   if(action==0) {
    frame[26]=1;put16(frame+27,2|(tid<<2)|(16<<6));
    put16(frame+29,0);put16(frame+31,0x1230);
   } else if(action==1) {
    frame[26]=1;put16(frame+27,0);put16(frame+29,2|(tid<<2)|(16<<6));
    put16(frame+31,0);
   } else {put16(frame+26,(tid<<12)|(1<<11));put16(frame+28,37);}
  } else {frame[24]=8;frame[25]=action-3;frame[26]=0xa5;frame[27]=0x5a;}
  struct mt792x_bss_conf bss={.mt76={omac,wmm,band,rate,rate,rate}};
  struct ieee80211_vif vif={.drv_priv=&bss,.mld=false};
  struct sk_buff skb={.data=frame,.len=len,.priority=priority,.queue_mapping=0,.hdrlen=24};
  skb.info.control.vif=&vif;
  skb.info.flags=(noack?IEEE80211_TX_CTL_NO_ACK:0)|
                 (explicit_seq?IEEE80211_TX_CTL_INJECTED:0)|
                 (minrate?IEEE80211_TX_CTL_USE_MINRATE:0);
  struct mt76_dev dev={.phy={.antenna_mask=1}};
  struct mt76_wcid w={.idx=wcid,.amsdu=amsdu};
  struct ieee80211_key_conf key={.cipher=0x000fac04};
  mt7925_mac_write_txwi(&dev,txd,&skb,&w,&key,pid,MT_TXQ_PSD,0);
  if(fwrite(input,sizeof(input),1,stdout)!=1 ||
     fwrite(frame,36,1,stdout)!=1 || fwrite(txd,32,1,stdout)!=1)abort();
 }
 return 0;
}
'''


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def function(text, name):
    match = re.search(r'^(?:static )?(?:inline )?(?:void|u8)\s*\n?' + name +
                      r'\([^;{}]*?\)\n\{', text, re.M)
    assert match, name
    end, depth = match.end(), 1
    while depth:
        depth += (text[end] == '{') - (text[end] == '}')
        end += 1
    result = text[match.start():end]
    assert digest(result.encode()) == FUNCTION_SHA256[name], name
    return result


def prepare(source):
    old = Path(__file__).with_name('mt792x_txwi_oracle.py').read_bytes()
    assert digest(old) == HISTORICAL_SHA256, 'historical oracle changed'
    assignments = {}
    for node in ast.parse(old).body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target = node.targets[0]
            if isinstance(target, ast.Name) and target.id in ('hashes', 'prelude'):
                assignments[target.id] = ast.literal_eval(node.value)
    hashes, prelude = assignments['hashes'], assignments['prelude']
    texts = {}
    for name, expected in hashes.items():
        raw = (source / name).read_bytes()
        assert digest(raw) == expected, name
        texts[name] = raw.decode()
    # Robust/BIP callbacks cannot run for these exact unicast CCMP fixtures.
    # Abort rather than let the historical false stub hide a new call path.
    old_callback = 'static bool ieee80211_is_robust_mgmt_frame(struct sk_buff*s){(void)s;return false;}'
    assert prelude.count(old_callback) == 1
    prelude = prelude.replace(old_callback,
                             'static bool ieee80211_is_robust_mgmt_frame(struct sk_buff*s){(void)s;abort();}')
    header = texts['mt76_connac3_mac.h']
    constants = '\n'.join(re.findall(r'^#define MT_TXD[^\n]+', header, re.M)) + '\n'
    for file, name in [('mt76.h', 'MT_PACKET_ID_FIRST'),
                       ('mt76.h', 'MT_TX_HW_QUEUE_PHY'),
                       ('mt76_connac.h', 'MT76_CONNAC_MAX_WMM_SETS'),
                       ('mt792x.h', 'MT792x_BASIC_RATES_TBL')]:
        match = re.search(r'^#define ' + name + r'\s+[^\n]+', texts[file], re.M)
        assert match, name
        constants += match.group() + '\n'
    enums = ''
    for enum in re.findall(r'^enum[^;{]*\{.*?^\};', header, re.M | re.S):
        if any(name in enum for name in ('MT_HDR_FORMAT_802_11', 'MT_TX_TYPE_CT',
                                        'MT_LMAC_ALTX0', 'MT_TX_FRAG_NONE', 'MT_TX_NORMAL')):
            enums += enum + '\n'
    enums += re.search(r'^enum mt76_txq_id \{.*?^\};', texts['mt76.h'], re.M | re.S).group() + '\n'
    helpers = [function(texts['mt76_connac.h'], 'mt76_connac_lmac_mapping'),
               function(texts['mt7925/mac.c'], 'mt7925_mac_write_txwi_80211'),
               function(texts['mt7925/mac.c'], 'mt7925_mac_write_txwi')]
    code = prelude + constants + enums + '\n'.join(helpers) + MAIN
    return code, {
        'linux_commit': 'a804c5742bff224d4cb4d25dd383554d598be32b',
        'linux_relative_root': 'drivers/net/wireless/mediatek/mt76',
        'source_sha256': hashes, 'function_sha256': FUNCTION_SHA256,
        'historical_fixture_sha256': HISTORICAL_SHA256,
        'generated_c_sha256': digest(code.encode()),
        'records': CASES, 'record_bytes': RECORD_BYTES,
        'case_inventory': {'protected_addba_request': 96, 'protected_addba_response': 96,
                           'protected_delba': 96, 'protected_sa_query_request': 96,
                           'protected_sa_query_response': 96},
        'fixture_preconditions': [
            'Little endian host; actual unchanged writers and original descriptor constants/enums.',
            'Modeled mac80211 metadata; 24-byte unicast Protected Action header; vif present, single link.',
            'Actual CCMP128 cipher selector supplied; no multicast AES-CMAC/BIP or robust callback permitted.',
            'Valid plaintext pre-encryption Action body; hardware inserts CCMP overhead; no host PN.',
            'Case0 native-shaped profile: sample WCID7/OMAC0/WMM0/band0/PID0/hardware sequence/rate18.',
            'Remaining profiles exercise descriptor-admitted bounds, not live firmware negotiated contexts.',
            'No key install/handshake/cipher/PN/DMA/publication/radio/firmware proof.'
        ],
    }


def main():
    source, out = map(Path, sys.argv[1:])
    code, manifest = prepare(source)
    out.mkdir(parents=True, exist_ok=False)
    cpath, binary = out / 'mt7925-protected-actions.c', out / 'mt7925-protected-actions'
    cpath.write_text(code)
    subprocess.run(['clang', '-std=c11', '-O1', '-g', '-fsanitize=address,undefined',
                    '-fno-omit-frame-pointer', '-fno-sanitize-recover=all', str(cpath), '-o', str(binary)], check=True)
    trace = subprocess.run([str(binary)], check=True, capture_output=True).stdout
    assert len(trace) == CASES * RECORD_BYTES
    (out / 'mt7925-protected-actions.bin').write_bytes(trace)
    manifest['trace_sha256'] = digest(trace)
    manifest['status'] = 'ACTUAL_C_TRACE_GENERATED_RUST_COMPARISON_REQUIRED'
    (out / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(json.dumps({'records': CASES, 'trace_sha256': digest(trace)}))


if __name__ == '__main__':
    main()

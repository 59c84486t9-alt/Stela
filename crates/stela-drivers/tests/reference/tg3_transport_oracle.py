#!/usr/bin/env python3
"""UNRUN harness: unchanged pinned Linux tg3 APE/MDIO/SRAM transport.

Arguments: directory containing unchanged tg3.c and tg3.h, ignored output dir.
Only register callbacks are modeled. This is not hardware or full-driver proof.
"""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

PIN = "a804c5742bff224d4cb4d25dd383554d598be32b"
DONORS = {
    "tg3.c": "a794b7d4616c9e919ff8577d3975532c7661fe7a304e8d4d888ec2eb2089a38e",
    "tg3.h": "898d1c54fe7b63c197a95f7b830ac92e315b41f15f1b8955e7c7e29710aaa460",
}


def body(source, name):
    match = re.search(r"^static (?:int|void) " + re.escape(name) + r"\([^;]+?\n\{", source, re.M)
    if not match:
        raise ValueError(name)
    end, level = match.end(), 1
    while level:
        level += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[match.start():end]


def main():
    source, output = map(Path, sys.argv[1:])
    texts = {}
    for name, digest in DONORS.items():
        data = (source / name).read_bytes()
        if hashlib.sha256(data).hexdigest() != digest:
            raise ValueError("pinned donor mismatch: " + name)
        texts[name] = data.decode()
    names = ["tg3_ape_lock", "tg3_ape_unlock", "__tg3_readphy", "__tg3_writephy", "tg3_read_mem", "tg3_write_mem"]
    bodies = {name: body(texts["tg3.c"], name) for name in names}
    # Preserve the unchanged header prefix, which contains the real constants.
    # The remaining kernel structs are irrelevant to these selected helpers.
    header = texts["tg3.h"].split("struct tg3_tx_buffer_desc {", 1)[0] + "\n#endif\n"
    output.mkdir(parents=True, exist_ok=True)
    (output / "donor_constants.h").write_text(header)
    wrapper = r'''
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
typedef uint32_t u32;
#include "donor_constants.h"
#define PHY_BUSY_LOOPS 5000
#define TG3_PHYFLG_IS_FET 1
#define MII_CTRL1000 9
#define tg3_asic_rev(tp) ((tp)->pci_chip_rev_id >> 12)
#define flag_ENABLE_APE 1
#define flag_SRAM_USE_CONFIG 0
#define tg3_flag(tp, flag) flag_##flag
#define spin_lock_irqsave(lock, flags) ((void)(lock), (void)(&(flags)))
#define spin_unlock_irqrestore(lock, flags) ((void)(lock), (void)(&(flags)))
struct tg3 {
 unsigned pci_fn, pci_chip_rev_id, phy_ape_lock, mi_mode, phy_flags;
 int pdev, indirect_lock;
};
static unsigned trace, window, command, busy_reads;
static u32 mac_mode, sram_data, phy[32], grant_reg, grant_value;
static void event(char kind,u32 at,u32 value) {
 if(trace) printf("%c %08x %08x\n",kind,at,value);
}
static u32 read_mac(u32 at) {
 u32 value=0;
 if(at==MAC_MI_MODE) value=mac_mode;
 else if(at==TG3PCI_MEM_WIN_BASE_ADDR) value=window;
 else if(at==TG3PCI_MEM_WIN_DATA) value=sram_data;
 else if(at==MAC_MI_COM) {
  if(busy_reads) {busy_reads--;value=command;}
  else {
   unsigned reg=(command >> 16)&31;
   if(command & MI_COM_CMD_WRITE) phy[reg]=command&0xffff;
   value=(command & ~(MI_COM_START|0xffff))|phy[reg];
  }
 }
 event('R',at,value);return value;
}
static void write_mac(u32 at,u32 value) {
 event('W',at,value);
 if(at==MAC_MI_MODE) mac_mode=value;
 else if(at==TG3PCI_MEM_WIN_BASE_ADDR) window=value;
 else if(at==TG3PCI_MEM_WIN_DATA) sram_data=value;
 else if(at==MAC_MI_COM) {command=value;busy_reads=1;}
}
#define tr32(at) read_mac(at)
#define tw32_f(at,value) do {write_mac(at,value);(void)read_mac(at);}while(0)
static u32 tg3_ape_read32(struct tg3 *tp,u32 at) {
 (void)tp;u32 v=at==grant_reg ? grant_value : 0;event('A',at,v);return v;
}
static void tg3_ape_write32(struct tg3 *tp,u32 at,u32 value) {
 u32 req=tg3_asic_rev(tp)==ASIC_REV_5761?TG3_APE_LOCK_REQ:TG3_APE_PER_LOCK_REQ;
 u32 gnt=tg3_asic_rev(tp)==ASIC_REV_5761?TG3_APE_LOCK_GRANT:TG3_APE_PER_LOCK_GRANT;
 event('G',at,value);
 if(at>=req && at<req+32) {grant_reg=gnt+(at-req);grant_value=value;}
 else grant_value=0;
}
static void udelay(unsigned us){event('D',us,0);}
static int pci_channel_offline(int pdev){(void)pdev;return 0;}
static void pci_write_config_dword(int pdev,u32 at,u32 value){(void)pdev;(void)at;(void)value;abort();}
static void pci_read_config_dword(int pdev,u32 at,u32 *value){(void)pdev;(void)at;(void)value;abort();}
'''
    wrapper += "\n".join(bodies.values())
    wrapper += r'''
int main(void) {
 const unsigned asics[]={ASIC_REV_5761,ASIC_REV_5720,ASIC_REV_5762};
 const unsigned locks[]={TG3_APE_LOCK_PHY0,TG3_APE_LOCK_PHY1,TG3_APE_LOCK_PHY2,TG3_APE_LOCK_PHY3};
 for(unsigned a=0;a<3;a++) for(unsigned f=0;f<4;f++) for(unsigned ap=0;ap<2;ap++) for(unsigned wr=0;wr<2;wr++) {
  struct tg3 tp={.pci_fn=f,.pci_chip_rev_id=asics[a]<<12,.phy_ape_lock=locks[f],.mi_mode=ap?MAC_MI_MODE_AUTO_POLL:0};
  mac_mode=tp.mi_mode;command=0;busy_reads=0;phy[7]=0xa55a;
  printf("CASE %u %u %u %u\n",a,f,ap,wr);trace=1;
  /* Rust observes MI_MODE, rather than accepting caller-supplied cached state. */
  (void)read_mac(MAC_MI_MODE);
  unsigned addr=a==1?f+1:1;u32 value=0;
  int ret=wr?__tg3_writephy(&tp,addr,7,0x1234):__tg3_readphy(&tp,addr,7,&value);
  trace=0;printf("END %d %04x\n",ret,wr?0:value);
 }
 for(unsigned wr=0;wr<2;wr++) {
  struct tg3 tp={.pci_chip_rev_id=ASIC_REV_5761<<12};
  window=0;sram_data=0xffffffff;printf("SRAM %u\n",wr);trace=1;u32 value=0;
  if(wr)tg3_write_mem(&tp,0x1000,0xffffffff);else tg3_read_mem(&tp,0x1000,&value);
  trace=0;printf("END 0 %08x\n",wr?0:value);
 }
 return 0;
}
'''
    c = output / "oracle.c"
    c.write_text(wrapper)
    binary = output / "oracle"
    subprocess.run(["clang", "-std=c11", "-Wall", "-Wextra", "-Werror", "-O1", "-g", "-fsanitize=address,undefined", "-I", str(output.resolve()), str(c.resolve()), "-o", str(binary.resolve())], check=True)
    trace = subprocess.check_output([str(binary.resolve())])
    (output / "trace.txt").write_bytes(trace)
    (output / "manifest.json").write_text(json.dumps({
        "linux_commit": PIN,
        "sources": DONORS,
        "functions": {name: hashlib.sha256(text.encode()).hexdigest() for name, text in bodies.items()},
        "wrapper_sha256": hashlib.sha256(c.read_bytes()).hexdigest(),
        "trace_sha256": hashlib.sha256(trace).hexdigest(),
        "cases": 50,
        "scope": "unchanged APE/MDIO/SRAM helpers; model callbacks; successful paths only; no reset/PHY calibration/traffic or hardware evidence",
    }, indent=2) + "\n")
    print("STELA_TG3_TRANSPORT_ORACLE=" + str((output / "trace.txt").resolve()))


if __name__ == "__main__":
    main()

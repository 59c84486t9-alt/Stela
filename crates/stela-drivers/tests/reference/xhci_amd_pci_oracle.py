#!/usr/bin/env python3
"""Execute unchanged pinned PCI quirks + AMD chipset/PLL discovery on saved IDs.
Usage: xhci_amd_pci_oracle.py FLAT_REFERENCE_DIRECTORY NEW_OUTPUT_DIRECTORY
All PCI reads are immutable logical fixtures. No actual host access or Linux ABI.
"""
import hashlib,json,re,subprocess,sys
from pathlib import Path
source,out=map(Path,sys.argv[1:])
expected={'xhci-pci.c':'56659d07018ff7ae99334e910065c7bf46f80deb65c4445443ee52313422d6e8','xhci.h':'44ca06ce699192d60302896df23ef3ee243abe979ac5f3c759de9830ec311cc0','pci-quirks.c':'490a44a2447031469c30f734380580fe45facf03d19a7c03e075434338c8de64','pci_ids.h':'020fac001871c0f8441c1294f787231fb6cfbf2c55915ca8f918262e2db4487c'}
texts={}
for name,digest in expected.items():
 raw=(source/name).read_bytes();assert hashlib.sha256(raw).hexdigest()==digest,name;texts[name]=raw.decode()
out.mkdir(parents=True,exist_ok=False)
fragments=[]
def function(file,name):
 text=texts[file];m=re.search(r'^(?:static\s+)?(?:int|bool|void)\s+'+name+r'\([^;{}]*?\)\n\{',text,re.M);assert m,name
 at,depth=m.end(),1
 while depth:depth+=(text[at]=='{')-(text[at]=='}');at+=1
 value=text[m.start():at];fragments.append(dict(source=file,function=name,sha256=hashlib.sha256(value.encode()).hexdigest()));return value
# Definitions used by the entire original PCI quirk function are retained.
defines='\n'.join(line for line in texts['xhci-pci.c'].splitlines() if line.startswith('#define PCI_'))
defines+='\n'+'\n'.join(line for line in texts['xhci.h'].splitlines() if re.match(r'#define\s+XHCI_\w+\s+BIT_ULL\(',line))
prelude=r'''
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
typedef uint8_t u8;
#define BIT_ULL(n) (1ull<<(n))
#define xhci_dbg_trace(...) ((void)0)
#define KERN_DEBUG ""
#define printk(...) ((void)0)
#define spin_lock_irqsave(lock,flags) ((void)0)
#define spin_unlock_irqrestore(lock,flags) ((void)0)
struct device {unsigned vendor,device,revision;};
struct pci_dev {unsigned vendor,device,revision;};
#define to_pci_dev(d) ((struct pci_dev *)(d))
struct xhci_hcd {unsigned hci_version,limit_active_eps,dma_mask_bits;uint64_t quirks;};
static struct pci_dev inventory;
static struct pci_dev *pci_get_device(unsigned vendor,unsigned device,void *from) {(void)from;return inventory.vendor==vendor&&inventory.device==device?&inventory:NULL;}
static void pci_dev_put(struct pci_dev *p) {(void)p;}
'''
# Original generation/type declarations (no lock implementation is copied).
a=texts['pci-quirks.c'].index('enum amd_chipset_gen {');b=texts['pci-quirks.c'].index('static DEFINE_SPINLOCK',a)
body=texts['pci-quirks.c'][a:b]+'\n'
body+='\n'.join(function('pci-quirks.c',n) for n in ['amd_chipset_sb_type_init','usb_amd_find_chipset_info','usb_amd_quirk_pll_check'])
body+='\n'+function('xhci-pci.c','xhci_pci_quirks')
main=r'''
int main(void) {
 unsigned ids[]={0x15b6,0x15b7,0x15b8,0x43fc};unsigned versions[]={0x100,0x110,0x120};
 inventory=(struct pci_dev){.vendor=0x1022,.device=0x790b,.revision=0x71};
 for(unsigned i=0;i<4;i++)for(unsigned rev=0;rev<256;rev++)for(unsigned v=0;v<3;v++){
  amd_chipset=(struct amd_chipset_info){0};struct device dev={.vendor=0x1022,.device=ids[i],.revision=rev};struct xhci_hcd x={.hci_version=versions[v]};xhci_pci_quirks(&dev,&x);printf("P %u %u %u %llu %d\n",ids[i],rev,versions[v],(unsigned long long)x.quirks,amd_chipset.need_pll_quirk);
 }
 unsigned vendors[]={0x1002,0x1022,0x1022,0x1022};unsigned devices[]={0x4385,0x780b,0x145c,0x790b};
 for(unsigned i=0;i<4;i++)for(unsigned rev=0;rev<256;rev++){
  inventory=(struct pci_dev){.vendor=vendors[i],.device=devices[i],.revision=rev};amd_chipset=(struct amd_chipset_info){0};bool pll=usb_amd_quirk_pll_check();printf("L %u %u %u %u %d\n",vendors[i],devices[i],rev,pll,amd_chipset.sb_type.gen);
 }
 return 0;
}
'''
unit=out/'linux-amd-xhci.c';unit.write_text(prelude+'\n'+texts['pci_ids.h']+'\n'+defines+'\n'+body+'\n'+main)
exe=out/'linux-amd-xhci';subprocess.run(['cc','-std=gnu11','-O1','-g','-fno-strict-aliasing','-fsanitize=address,undefined',str(unit),'-o',str(exe)],check=True)
with (out/'trace.txt').open('wb') as f:subprocess.run([str(exe.resolve())],stdout=f,check=True)
trace=(out/'trace.txt').read_bytes();(out/'receipt.json').write_text(json.dumps(dict(donors=expected,functions=fragments,trace_sha256=hashlib.sha256(trace).hexdigest(),rows=len(trace.splitlines())),indent=2)+'\n');print(hashlib.sha256(trace).hexdigest(),len(trace.splitlines()))

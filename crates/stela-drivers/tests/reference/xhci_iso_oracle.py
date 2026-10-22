#!/usr/bin/env python3
"""Execute pinned unchanged USB2 isoch context/scheduling/completion helpers.
Usage: xhci_iso_oracle.py FLAT_REFERENCE_DIRECTORY NEW_OUTPUT_DIRECTORY
Fixture boundaries: logical USB objects, one retained TD/TRB per service,
zero quirks for the exact audited AMD profiles, no Linux DMA/workqueue runtime.
"""
import ast
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

source, out = map(Path, sys.argv[1:])
expected = {
    'xhci-mem.c': 'abfe6f6f70bdeaf7a279a734bdab034ef014f329785ccb8c5f5cf3e763320198',
    'xhci-ring.c': '8c15822f3e118fc5ee9e647b5fc82f75d72f51519f1d9f6dee96d222fe6c9882',
    'xhci.h': '44ca06ce699192d60302896df23ef3ee243abe979ac5f3c759de9830ec311cc0',
    'xhci-caps.h': '096eb25ef1cceefe6a54f0e661b585ac19fa102db9b9807c4073c660cd452b43',
    'xhci-pci.c': '56659d07018ff7ae99334e910065c7bf46f80deb65c4445443ee52313422d6e8',
}
texts = {}
for name, digest in expected.items():
    raw = (source/name).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == digest, name
    texts[name] = raw.decode()
out.mkdir(parents=True, exist_ok=False)
fragments = []
def function(file, name):
    text = texts[file]
    match = re.search(r'^(?:static\s+)?(?:unsigned int|u32|int|bool|void)\s+' + name + r'\([^;{}]*?\)\n\{', text, re.M)
    assert match, name
    at, depth = match.end(), 1
    while depth:
        depth += (text[at]=='{') - (text[at]=='}')
        at += 1
    value = text[match.start():at]
    fragments.append(dict(file=file, name=name, sha256=hashlib.sha256(value.encode()).hexdigest()))
    return value
# Existing fixture helper declarations are reused without executing its script.
tree = ast.parse(Path(__file__).with_name('xhci_endpoint_oracle.py').read_text())
prelude = next(ast.literal_eval(n.value) for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='prelude' for t in n.targets))
prelude = prelude.replace('unsigned char bMaxBurst;', 'unsigned char bMaxBurst, bmAttributes;')
prelude += r'''
#define EINVAL 22
#define ENOMEM 12
#define ECOMM 70
#define EOVERFLOW 75
#define EXDEV 18
#define EPROTO 71
typedef uint64_t u64;
typedef int gfp_t;
#define cpu_to_le32(x) (x)
#define cpu_to_le64(x) (x)
#define le32_to_cpu(x) (x)
#define BIT(n) (1u<<(n))
#define FIELD_GET(mask,x) (((x)&(mask))>>__builtin_ctz(mask))
#define DIV_ROUND_UP(x,y) (((x)+(y)-1)/(y))
#define DIV_ROUND_UP_POW2(x,y) DIV_ROUND_UP(x,y)
#define roundup(x,y) (DIV_ROUND_UP(x,y)*(y))
#define HCS_IST_VALUE 7
#define HCS_IST_UNIT BIT(3)
#define HCC_CFC BIT(11)
#define HCC2_LEC BIT(4)
#define HCC2_EUSB2_DIC BIT(11)
#define XHCI_CFC_DELAY 10
#define MFINDEX_TO_FRAME(p) (((p)>>3)&0x7ff)
#define MAX_FRAMES 2048
#define MAX_UFRAMES (8*MAX_FRAMES)
#define URB_ISO_ASAP 1
#define XHCI_INTEL_HOST BIT(0)
#define XHCI_LIMIT_ENDPOINT_INTERVAL_9 BIT(1)
#define XHCI_LIMIT_ENDPOINT_INTERVAL_7 BIT(2)
#define EP_MAX_ESIT_PAYLOAD_HI(p) ((((p)>>16)&255)<<24)
#define EP_MAX_ESIT_PAYLOAD_LO(p) (((p)&65535)<<16)
#define EP_INTERVAL(p) (((p)&255)<<16)
#define EP_MULT(p) (((p)&3)<<8)
#define EP_TYPE(p) ((p)<<3)
#define ERROR_COUNT(p) (((p)&3)<<1)
#define MAX_PACKET(p) (((p)&65535)<<16)
#define MAX_BURST(p) (((p)&255)<<8)
#define EP_AVG_TRB_LENGTH(p) ((p)&65535)
#define CTRL_EP 4
#define BULK_IN_EP 6
#define BULK_OUT_EP 2
#define ISOC_IN_EP 5
#define ISOC_OUT_EP 1
#define INT_IN_EP 7
#define INT_OUT_EP 3
#define USB_ENDPOINT_XFER_CONTROL 0
#define USB_ENDPOINT_XFER_ISOC 1
#define USB_ENDPOINT_XFER_BULK 2
#define USB_ENDPOINT_XFER_INT 3
#define xhci_dbg(...) ((void)0)
#define xhci_usb_endpoint_maxp(u,e) ((e)->desc.wMaxPacketSize&2047)
#define xhci_ring_init(x,r) ((void)0)
#define readl(p) (*(p))
#define rounddown_pow_of_two(p) (1u<<(31-__builtin_clz(p)))
struct xhci_run_regs { u32 microframe_index; };
struct xhci_hcd { unsigned hci_version,hcs_params2,hcc_params,hcc_params2,quirks; struct xhci_run_regs *run_regs; };
struct xhci_ep_ctx { u32 ep_info,ep_info2; u64 deq; u32 tx_info; };
struct segment {u64 dma;};
struct xhci_ring { struct segment *first_seg; unsigned cycle_state; };
enum xhci_ring_type { TYPE_CTRL,TYPE_ISOC,TYPE_BULK,TYPE_INT };
struct xhci_virt_ep { struct xhci_ring *new_ring; bool skip; int next_uframe; };
struct xhci_virt_device { struct xhci_ep_ctx *in_ctx; struct xhci_virt_ep eps[32]; };
static unsigned usb_endpoint_type(const struct usb_endpoint_descriptor *d) {return d->bmAttributes&3;}
static bool usb_endpoint_dir_in(const struct usb_endpoint_descriptor *d) {return d->bEndpointAddress&128;}
static unsigned xhci_get_endpoint_index(const struct usb_endpoint_descriptor *d) {return (d->bEndpointAddress&15)*2+!!(d->bEndpointAddress&128)-1;}
static struct xhci_ep_ctx *xhci_get_ep_ctx(struct xhci_hcd *x,struct xhci_ep_ctx *c,unsigned i) {(void)x;return c+i;}
static struct xhci_ring *xhci_ring_alloc(struct xhci_hcd *x,int n,enum xhci_ring_type t,unsigned m,gfp_t f) {(void)x;(void)n;(void)t;(void)m;(void)f;static struct segment s={65536};static struct xhci_ring r={&s,1};return &r;}
static unsigned usb_endpoint_max_periodic_payload(struct usb_device *u,struct usb_host_endpoint *e) {return (e->desc.wMaxPacketSize&2047)*(u->speed==USB_SPEED_HIGH?usb_endpoint_maxp_mult(&e->desc):1);}
struct usb_iso_packet_descriptor {unsigned length,actual_length;int status;};
struct urb {struct usb_device *dev;struct usb_host_endpoint *ep;unsigned transfer_flags;int interval,number_of_packets,start_frame;void *hcpriv;struct usb_iso_packet_descriptor iso_frame_desc[1];unsigned actual_length;};
struct urb_priv {int num_tds_done;};
union xhci_trb {struct {u32 field[4];}generic;};
struct xhci_td {struct urb *urb;union xhci_trb *end_trb;bool error_mid_td,urb_length_set;};
struct xhci_transfer_event {u32 transfer_len;};
#define GET_COMP_CODE(p) ((p)>>24)
#define EVENT_TRB_LEN(p) ((p)&0xffffff)
#define TRB_LEN(p) ((p)&0x1ffff)
#define CTX_TO_EP_TYPE(p) (((p)>>3)&7)
#define GET_EP_CTX_STATE(p) ((p)->ep_info&7)
#define EP_STATE_HALTED 2
#define COMP_SUCCESS 1
#define COMP_BABBLE_DETECTED_ERROR 3
#define COMP_USB_TRANSACTION_ERROR 4
#define COMP_SPLIT_TRANSACTION_ERROR 36
#define COMP_STALL_ERROR 6
#define COMP_SHORT_PACKET 13
#define COMP_BANDWIDTH_OVERRUN_ERROR 18
#define COMP_INCOMPATIBLE_DEVICE_ERROR 22
#define COMP_MISSED_SERVICE_ERROR 23
#define COMP_STOPPED 26
#define COMP_STOPPED_LENGTH_INVALID 27
#define COMP_STOPPED_SHORT_PACKET 28
#define COMP_ISOCH_BUFFER_OVERRUN 31
static unsigned sum_trb_lengths(struct xhci_td *t,union xhci_trb *b) {(void)t;(void)b;return 0;}
static unsigned finished;
static void finish_td(struct xhci_hcd *x,struct xhci_virt_ep *e,struct xhci_ring *r,struct xhci_td *t,u32 c) {(void)x;(void)e;(void)r;(void)t;(void)c;finished++;}
'''
mem_names = ['xhci_parse_exponent_interval','xhci_microframes_to_exponent','xhci_parse_microframe_interval','xhci_parse_frame_interval','xhci_get_endpoint_interval','xhci_get_endpoint_mult','xhci_get_endpoint_max_burst','xhci_get_endpoint_type','xhci_endpoint_init']
ring_names = ['xhci_get_burst_count','xhci_get_last_burst_packet_count','xhci_ist_microframes','xhci_isoc_td_uses_frame_id','xhci_frame_in_range','xhci_get_isoc_start_frame','process_isoc_td','xhci_halted_host_endpoint']
body = '\n'.join(function('xhci-mem.c',n) for n in mem_names)+'\n'+'\n'.join(function('xhci-ring.c',n) for n in ring_names)
main = r'''
int main(void) {
 struct xhci_run_regs regs={0};struct xhci_hcd x={.hci_version=0x110,.run_regs=&regs};
 /* Execute non-isoc interval dependencies as bounded logical fixture probes. */
 struct usb_device probe_u={.speed=USB_SPEED_HIGH};struct usb_host_endpoint probe_e={.desc={.bmAttributes=2,.bInterval=4}};
 if(xhci_parse_microframe_interval(&probe_u,&probe_e)!=2)abort();
 probe_u.speed=USB_SPEED_FULL;probe_e.desc.bmAttributes=3;probe_e.desc.bInterval=8;
 if(xhci_parse_frame_interval(&probe_u,&probe_e)!=6)abort();
 for(int speed=2;speed<=3;speed++)for(unsigned interval=1;interval<=16;interval++)for(unsigned burst=0;burst<=(speed==3?2:0);burst++)for(unsigned dir=0;dir<2;dir++) {
  unsigned packet=speed==2?192:1024;struct usb_device u={.speed=speed};struct usb_host_endpoint e={.desc={.bEndpointAddress=dir?0x81:1,.bmAttributes=1,.bInterval=interval,.wMaxPacketSize=packet|(burst<<11)}};struct xhci_ep_ctx ctx[32]={0};struct xhci_virt_device v={.in_ctx=ctx};
  if(xhci_endpoint_init(&x,&v,&u,&e,0))abort();unsigned n=xhci_get_endpoint_index(&e.desc);printf("E %d %u %u %u %u %u %u %u\n",speed,interval,burst,dir,packet,ctx[n].ep_info,ctx[n].ep_info2,ctx[n].tx_info);
 }
 unsigned values[]={0,1,7,8,8190,16370,16383};unsigned intervals[]={1,2,8,32,4096};
 for(unsigned i=0;i<7;i++)for(unsigned hcs=0;hcs<16;hcs++)for(unsigned cfc=0;cfc<2;cfc++)for(unsigned j=0;j<5;j++)for(int next=-1;next<3;next++) {
  struct usb_device u={.speed=USB_SPEED_HIGH};struct usb_host_endpoint e={0};struct urb urb={.dev=&u,.ep=&e,.interval=intervals[j],.number_of_packets=1};struct xhci_virt_ep ep={.next_uframe=next<0?-1:(int)((values[i]+next*8)%MAX_UFRAMES)};regs.microframe_index=values[i];x.hcs_params2=hcs;x.hcc_params=cfc?HCC_CFC:0;unsigned start=xhci_get_isoc_start_frame(&x,&urb,&ep);unsigned low=(values[i]/8+DIV_ROUND_UP(xhci_ist_microframes(&x),8)+1)%MAX_FRAMES;unsigned high=(values[i]/8+895)%MAX_FRAMES;
  printf("S %u %u %u %u %d %u %u %u\n",values[i],hcs,cfc,intervals[j],ep.next_uframe,start,xhci_isoc_td_uses_frame_id(&x,&urb,&ep,0),xhci_frame_in_range(start/8,low,high));
 }
 unsigned codes[]={1,13,23,4,3,18,31,6,22};
 for(unsigned i=0;i<9;i++)for(unsigned residual=0;residual<=128;residual+=32) {
  struct usb_device u={0};struct urb_priv priv={0};struct urb urb={.dev=&u,.hcpriv=&priv,.iso_frame_desc={{.length=128}}};union xhci_trb trb={.generic={{0,0,128,0}}};struct xhci_td td={.urb=&urb,.end_trb=&trb};struct xhci_virt_ep ep={0};struct xhci_transfer_event event={.transfer_len=(codes[i]<<24)|residual};finished=0;process_isoc_td(&x,&ep,0,&td,&trb,&event);struct xhci_ep_ctx context={.ep_info2=ISOC_IN_EP<<3};printf("C %u %u %u %d %u %u\n",codes[i],residual,urb.iso_frame_desc[0].actual_length,urb.iso_frame_desc[0].status,finished,xhci_halted_host_endpoint(&x,&context,codes[i]));
 }
 for(unsigned packets=1;packets<=3;packets++){struct usb_device u={.speed=USB_SPEED_HIGH};struct usb_host_endpoint e={0};struct urb urb={.dev=&u,.ep=&e};printf("B %u %u %u\n",packets,xhci_get_burst_count(&x,&urb,packets),xhci_get_last_burst_packet_count(&x,&urb,packets));}
 return 0;
}
'''
unit=out/'linux-xhci-iso.c';unit.write_text(prelude+'\n'+body+'\n'+main)
exe=out/'linux-xhci-iso'
subprocess.run(['cc','-std=gnu11','-O1','-g','-fsanitize=address,undefined',str(unit),'-o',str(exe)],check=True)
with (out/'trace.txt').open('wb') as trace:subprocess.run([str(exe.resolve())],stdout=trace,check=True)
trace=(out/'trace.txt').read_bytes()
(out/'receipt.json').write_text(json.dumps(dict(donors=expected,functions=fragments,trace_sha256=hashlib.sha256(trace).hexdigest(),rows=len(trace.splitlines())),indent=2)+'\n')
print(hashlib.sha256(trace).hexdigest(),len(trace.splitlines()))

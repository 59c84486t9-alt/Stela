#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Generate (never compile/run) a source-bound Intel ISH C comparison fixture.

Only whole original function/type bodies are selected. Linux lists, waits,
logging and device allocations are bounded single-thread research fixtures;
this establishes no kernel scheduling, native IRQ/DMA or firmware behavior.
The caller owns any future compiler/test processes and their cancellation,
whole deadline, reaping and terminal receipt. This generator starts no child.
"""
import argparse
import hashlib
import json
import pathlib
import re

PINS = {
    'drivers/hid/intel-ish-hid/ishtp-hid-client.c':'db7525f6e7e4cac0a30d72eeefe7d7396966d10880cc87517fd1355d2fc7ae8b',
    'drivers/hid/intel-ish-hid/ishtp-hid.h':'beb4dc0d7630202996bec5f0c8d4ebd0ac57d9a339ba270c10fcb1c8d95388ad',
    'drivers/hid/intel-ish-hid/ishtp/hbm.c':'5ebf98ec996f76da2b07ee5fded779acb5e77e27f19ddae76b6fd4acf66e4e93',
    'drivers/hid/intel-ish-hid/ishtp/hbm.h':'6f13f57f814d98aa05c96ae642217e0e8ce6c71e23f780f2bb996621c0544796',
    'drivers/hid/intel-ish-hid/ishtp/client.c':'a42b51df5f5156e808f031919673133afff88549bce1db7e1692115cfcf9c314',
    'drivers/hid/intel-ish-hid/ishtp/client.h':'a56102334196b9c54e5d30e19da6ddda0f425974b4a69a3556cd20ad31726522',
    'drivers/hid/intel-ish-hid/ishtp/ishtp-dev.h':'0a089fcf2b16a36f3ea715a593e78bcd5928f495529f76f5821c20f65aed367e',
    'include/linux/intel-ish-client-if.h':'2718cb15ebc8eecb9bfd9dfdf7e8cd1c05dd366cc45a0b25a34be86db04617ee',
}

def extract(text, name, declaration=False):
    """Select an entire original definition, without rewriting its body."""
    pattern=(r'(?m)^(?:struct|enum)\s+'+re.escape(name)+r'\s*\{' if declaration else
             r'(?m)^(?:static\s+)?(?:inline\s+)?[A-Za-z_][A-Za-z_0-9 \t*]*\b'+re.escape(name)+r'\s*\([^;{}]*\)\s*\{')
    matches=list(re.finditer(pattern,text)); assert len(matches)==1,(name,len(matches))
    start=matches[0].start(); brace=text.index('{',start)
    masked=re.sub(r'/\*[\s\S]*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'',lambda m:' '*len(m[0]),text)
    depth=0
    for index in range(brace,len(text)):
        depth += (masked[index]=='{')-(masked[index]=='}')
        if depth==0:
            end=text.index(';',index)+1 if declaration else index+1
            if text[end:end+1]=='\n':end+=1
            return text[start:end]
    raise AssertionError(name)

PREFIX=r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint8_t u8;
typedef uint16_t u16;
#define __packed __attribute__((packed))
#define __aligned(n) __attribute__((aligned(n)))
#define DECLARE_BITMAP(name,bits) unsigned long name[((bits)+63)/64]
typedef int spinlock_t;
typedef int wait_queue_head_t;
typedef int64_t ktime_t;
struct work_struct {int fixture;};
struct device {int fixture;};
struct hid_device {void *driver_data;};
struct ishtp_device; struct ishtp_cl; struct ishtp_cl_device;
struct ishtp_hw_ops;
typedef void (*ishtp_print_log)(struct ishtp_device *,const char *,...);
struct list_head {struct list_head *next,*prev;};
static void init_list(struct list_head *p){p->next=p;p->prev=p;}
static bool list_empty(const struct list_head *p){return p->next==p;}
static void list_add_tail(struct list_head *p,struct list_head *head){p->prev=head->prev;p->next=head;head->prev->next=p;head->prev=p;}
static void list_del_init(struct list_head *p){p->prev->next=p->next;p->next->prev=p->prev;init_list(p);}
#define list_entry(p,type,member) ((type *)((char *)(p)-offsetof(type,member)))
#define spin_lock_irqsave(lock,flags) do{(void)(lock);(flags)=0;}while(0)
#define spin_unlock_irqrestore(lock,flags) do{(void)(lock);(void)(flags);}while(0)
#define hid_ishtp_trace(...) ((void)0)
#define dev_err(...) ((void)0)
#define dev_info(...) ((void)0)
#define cl_data_to_dev(p) ((void *)(p))
#define GFP_KERNEL 0
#define ENOMEM 12
#define ETIMEDOUT 110
#define EIO 5
#define HZ 1000
#define HID_FEATURE_REPORT 2
#define HID_INPUT_REPORT 0
#define wait_event_interruptible_timeout(q,c,t) ((void)(q),(void)(t),1L)
#define devm_kcalloc(dev,n,size,flags) calloc((n),(size))
#define IPC_PAYLOAD_SIZE 128
#define ISHTP_CLIENTS_MAX 256
#define RD_INT_FIFO_SIZE 64
#define CL_TX_PATH_IPC 1
#define HOSTIF_GET_HID_DESCRIPTOR 0
#define HOSTIF_GET_REPORT_DESCRIPTOR 1
#define HOSTIF_GET_FEATURE_REPORT 2
#define HOSTIF_SET_FEATURE_REPORT 3
#define HOSTIF_GET_INPUT_REPORT 4
#define HOSTIF_DM_ENUM_DEVICES 33
#define MAX_HID_DEVICES 32
'''
STUBS=r'''
_Static_assert(sizeof(struct ishtp_msg_hdr)==4,"actual packed ISHTP header");
_Static_assert(sizeof(struct hostif_msg_hdr)==6,"actual packed HostIF header");
_Static_assert(sizeof(struct hostif_msg_to_sensor)==7,"actual GET request");
_Static_assert(sizeof(struct device_info)==9,"actual device enumeration record");
static unsigned char captured[16384];static size_t captured_len;
struct captured_frame {unsigned char bytes[128];size_t length;};
static struct captured_frame fragments[256];static size_t fragment_count;
static int ishtp_hid_link_ready_wait(struct ishtp_cl_data *p){(void)p;return 0;}
static void *ishtp_get_client_data(struct ishtp_cl *p){return p->client_data;}
static int ishtp_cl_send(struct ishtp_cl *p,const unsigned char *b,size_t n){assert(n<=sizeof(captured));memcpy(captured,b,n);captured_len=n;struct ishtp_cl_data *d=p->client_data;d->enum_devices_done=true;d->hid_descr_done=true;d->report_descr_done=true;return 0;}
static int ishtp_write_message(struct ishtp_device *d,struct ishtp_msg_hdr *h,void *b){(void)d;assert(fragment_count<256);assert(h->length<=124);struct captured_frame *f=&fragments[fragment_count++];memcpy(f->bytes,h,4);memcpy(f->bytes+4,b,h->length);f->length=4+h->length;return 0;}
static void hex(const unsigned char *p,size_t n){for(size_t i=0;i<n;i++)printf("%02x",p[i]);}
static unsigned wire_index;
static void wire_line(void){printf("W %u %zu ",wire_index++,captured_len);hex(captured,captured_len);putchar('\n');}
'''
SUFFIX=r'''
int main(void){
 puts("STELA_ISH_ORACLE_60_V1");
 struct ishtp_cl cl={0};struct ishtp_cl_data data={0};struct ishtp_hid_data hd={.index=0,.client_data=&data};struct hid_device hid={.driver_data=&hd};struct device_info info={.dev_id=7};
 unsigned char dummy=0;cl.client_data=&data;data.hid_ishtp_cl=&cl;data.hid_devices=&info;data.hid_sensor_hubs[0]=&hid;data.num_hid_devices=1;data.hid_descr[0]=&dummy;data.report_descr[0]=&dummy;
 for(unsigned dev=0;dev<2;dev++){info.dev_id=dev?19:7;for(unsigned rid=1;rid<=2;rid++)for(unsigned kind=0;kind<2;kind++){hid_ishtp_get_report(&hid,rid,kind?HID_FEATURE_REPORT:HID_INPUT_REPORT);wire_line();}}
 const size_t sizes[]={1,4,125,249};
 for(unsigned dev=0;dev<2;dev++){info.dev_id=dev?19:7;for(unsigned n=0;n<4;n++){unsigned char b[256];memset(b,0xcc,sizeof(b));for(size_t j=0;j<sizes[n];j++)b[6+j]=(unsigned char)(j*17+3);hid_ishtp_set_feature(&hid,(char *)b,sizes[n]+6,123);wire_line();}}
 info.dev_id=7;assert(ishtp_enum_enum_devices(&cl)==0);wire_line();
 for(unsigned dev=0;dev<2;dev++){info.dev_id=dev?19:7;assert(ishtp_get_hid_descriptor(&cl,0)==0);wire_line();assert(ishtp_get_report_descriptor(&cl,0)==0);wire_line();}
 cl.fw_client_id=5;cl.host_client_id=1;
 for(unsigned cmd=6;cmd<=8;cmd++){size_t n=cmd==8?8:4;unsigned char b[8];struct ishtp_msg_hdr h;ishtp_hbm_hdr(&h,n);ishtp_hbm_cl_hdr(&cl,cmd,b,n);memcpy(captured,&h,4);memcpy(captured+4,b,n);captured_len=n+4;wire_line();}
 assert(wire_index==24);
 const size_t lengths[]={1,6,7,123,124,125,248,249,1024};unsigned index=0;
 for(unsigned li=0;li<9;li++)for(unsigned mode=0;mode<4;mode++){
   struct ishtp_device dev={0};struct ishtp_cl c={0};struct ishtp_cl_tx_ring entry={0};unsigned char b[1024];for(size_t j=0;j<lengths[li];j++)b[j]=(unsigned char)(j*29+11);
   dev.dev_state=mode==3?ISHTP_DEV_DISABLED:ISHTP_DEV_ENABLED;dev.mtu=124;c.dev=&dev;c.state=mode==2?ISHTP_CL_DISCONNECTED:ISHTP_CL_CONNECTED;c.host_client_id=1;c.fw_client_id=5;c.ishtp_flow_ctrl_creds=mode==1?0:1;c.last_ipc_acked=1;
   init_list(&c.tx_list.list);init_list(&c.tx_free_list.list);init_list(&entry.list);entry.send_buf.data=b;entry.send_buf.size=lengths[li];list_add_tail(&entry.list,&c.tx_list.list);fragment_count=0;unsigned before=c.ishtp_flow_ctrl_creds;
   ipc_tx_send(&c);
   printf("I %u %zu %u %u %u %d %zu %d %u %d %d %zu\n",index++,lengths[li],mode,before,c.ishtp_flow_ctrl_creds,c.sending,c.tx_offs,c.tx_ring_free_size,(unsigned)list_empty(&c.tx_list.list),c.last_ipc_acked,c.last_tx_path,fragment_count);
   for(size_t j=0;j<fragment_count;j++){printf("F %zu %zu ",j,fragments[j].length);hex(fragments[j].bytes,fragments[j].length);putchar('\n');}
 }
 assert(index==36);puts("END 60");return 0;
}
'''

def generate(source_root):
    texts={}
    for path,digest in PINS.items():
        b=(source_root/path).read_bytes();assert hashlib.sha256(b).hexdigest()==digest,path;texts[path]=b.decode()
    base='drivers/hid/intel-ish-hid/'; selections=[]
    def pick(path,name,decl=False):
        value=extract(texts[path],name,decl);selections.append({'path':path,'name':name,'declaration':decl,'bytes':len(value.encode()),'sha256':hashlib.sha256(value.encode()).hexdigest()});return value
    definitions=[]
    for path,name in [
        ('include/linux/intel-ish-client-if.h','cl_state'),
        (base+'ishtp/ishtp-dev.h','ishtp_dev_state'),(base+'ishtp/hbm.h','ishtp_hbm_state'),
        (base+'ishtp/hbm.h','ishtp_msg_hdr'),(base+'ishtp/hbm.h','hbm_version'),
        (base+'ishtp/ishtp-dev.h','ish_version'),('include/linux/intel-ish-client-if.h','ishtp_msg_data'),
        ('include/linux/intel-ish-client-if.h','ishtp_cl_rb'),(base+'ishtp/client.h','ishtp_cl_tx_ring'),
        (base+'ishtp/client.h','ishtp_cl'),(base+'ishtp/ishtp-dev.h','ishtp_device'),
        (base+'ishtp-hid.h','hostif_msg_hdr'),(base+'ishtp-hid.h','hostif_msg'),
        (base+'ishtp-hid.h','hostif_msg_to_sensor'),(base+'ishtp-hid.h','device_info'),
        (base+'ishtp-hid.h','ishtp_cl_data'),(base+'ishtp-hid.h','ishtp_hid_data'),
        (base+'ishtp/hbm.h','ishtp_hbm_cl_cmd'),
    ]:definitions.append(pick(path,name,True))
    functions=[]
    for name in ['hid_ishtp_get_report','hid_ishtp_set_feature','ishtp_enum_enum_devices','ishtp_get_hid_descriptor','ishtp_get_report_descriptor']:
        functions.append(pick(base+'ishtp-hid-client.c',name))
    functions.extend([pick(base+'ishtp/hbm.h','ishtp_hbm_hdr'),pick(base+'ishtp/hbm.c','ishtp_hbm_cl_hdr'),pick(base+'ishtp/client.c','ipc_tx_send')])
    return PREFIX+'\n'.join(definitions)+STUBS+'\n'.join(functions)+SUFFIX,selections

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--source-root',type=pathlib.Path,required=True);parser.add_argument('--output',type=pathlib.Path,required=True);args=parser.parse_args()
    c,selections=generate(args.source_root);args.output.mkdir(parents=True,exist_ok=False);(args.output/'oracle.c').write_text(c)
    manifest={'linux_commit':'a804c5742bff224d4cb4d25dd383554d598be32b','status':'GENERATED_SOURCE_ONLY_UNRUN','source_pins':PINS,'selections':selections,'oracle_sha256':hashlib.sha256(c.encode()).hexdigest(),'cases':60,'wire_cases':24,'ipc_cases':36,'child_processes':0,'limits':['Single-thread list/lock/wait fixture; not kernel scheduling or native IRQ/DMA.','Firmware completions are fixture metadata for serializer selection only.','Internal Linux struct layouts have fixture-only opaque lock/work fields; wire structs are whole original packed definitions with actual static size checks.','Original aggregated-parser scaled pointer arithmetic excluded; no malformed or multireport C parser equivalence claimed.','No compiler/executable/trace/Rust binary/qualification receipt/execution lease facts are supplied.']}
    (args.output/'source-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')

if __name__=='__main__':main()

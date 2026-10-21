#!/usr/bin/env python3
"""Compile unchanged pinned rtw88/rtw89 firmware helpers against bounded fixtures.

Usage: script REFERENCE_DIRECTORY RTL8822C_IMAGE RTL8852B_IMAGE OUTPUT_DIRECTORY
No Linux services or firmware bytes are part of the Stela binary. The C harness
models register access, records legacy download calls, and disables secure boot.
Formatted-MSSC handling is an explicit unsupported stub; tested images use zero
legacy-MSSC entries. Actual ROM upload/authentication are outside this oracle.
"""
import hashlib,json,pathlib,re,subprocess,sys
reference,image88,image89,out=map(pathlib.Path,sys.argv[1:]);out.mkdir(parents=True,exist_ok=True)
manifest=[]
def function(family,file,name):
    path=reference/family/file; text=path.read_text()
    for m in re.finditer(r'\b'+re.escape(name)+r'\s*\(',text):
        pos=text.index('(',m.start());depth=1;end=pos+1
        while depth:
            depth+=(text[end]=='(')-(text[end]==')');end+=1
        while text[end].isspace():end+=1
        if text[end]!='{':continue
        start=text.rfind('\n\n',0,m.start())+2;pos=end;depth=1;end+=1
        while depth:
            depth+=(text[end]=='{')-(text[end]=='}');end+=1
        body=text[start:end];manifest.append(dict(path=f'{family}/{file}',function=name,sha256=hashlib.sha256(body.encode()).hexdigest()));return body
    raise ValueError(name)
def declaration(family,file,kind,name):
    text=(reference/family/file).read_text();m=re.search(r'\b'+kind+r' '+name+r'\s*\{',text);start=m.start();pos=text.index('{',start);depth=1;end=pos+1
    while depth:depth+=(text[end]=='{')-(text[end]=='}');end+=1
    end=text.index(';',end)+1;return text[start:end]
preamble=r'''
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error little endian oracle required
#endif
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32;
typedef uint16_t __le16; typedef uint32_t __le32;
#define __packed __attribute__((packed))
#define BIT(n) (1U<<(n))
#define GENMASK(h,l) ((~0U>>(31-(h)))&(~0U<<(l)))
#define le16_to_cpu(x) (x)
#define le32_to_cpu(x) (x)
#define le32_get_bits(x,mask) (((x)&(mask))>>__builtin_ctz(mask))
#define struct_size(p,member,n) (sizeof(*(p))+sizeof((p)->member[0])*(n))
#define rtw89_err(...) ((void)0)
#define rtw89_warn(...) ((void)0)
#define rtw89_debug(...) ((void)0)
#define WARN_ONCE(...) ((void)0)
#define FW_HDR_SIZE 64
#define FW_HDR_CHKSUM_SIZE 8
#define REG_MCUFW_CTRL 0x0080
#define BIT_MCUFWDL_EN BIT(0)
#define FWDL_SECTION_MAX_NUM 10
#define FWDL_SECTION_CHKSUM_LEN 8
#define FWDL_SECTION_PER_PKT_LEN 2020
#define FWDL_SECURITY_SECTION_TYPE 9
#define FWDL_SECURITY_SIGLEN 512
#define FWDL_SECURITY_CHKSUM_LEN 8
#define FORMATTED_MSSC 0xff
#define FORMATTED_MSSC_MASK 0xff
#define RTW89_CHIP_AX 0
#define RTL8852B 2
#define RTW89_FW_NORMAL 1
#define RTW89_FW_LOGFMT 255
#define RTW89_MFW_SIG 255
static FILE *output; static const u8 *legacy_base; static const u8 *ax_base;
static void word(u32 v){if(fwrite(&v,4,1,output)!=1)abort();}
static void raw(const u8 *p,size_t n){if(fwrite(p,1,n,output)!=n)abort();}
struct rtw_dev { int unused; };
static u16 rtw_read16(struct rtw_dev *d,u32 reg){(void)d;if(reg!=REG_MCUFW_CTRL)abort();return 0x35a5;}
static void rtw_write16(struct rtw_dev *d,u32 reg,u16 value){(void)d;if(reg!=REG_MCUFW_CTRL||value!=0x3001)abort();}
static int download_firmware_to_mem(struct rtw_dev *d,const u8 *p,u32 source,u32 address,u32 len){(void)d;if(source)abort();word(address);word(len);word(p-legacy_base);raw(p,len);return 0;}
struct firmware { const u8 *data; size_t size; };
struct rtw89_fw_secure { bool secure_boot; u32 mss_idx; };
struct rtw89_fw_suit { const u8 *data;u32 size; };
struct rtw89_fw_info { struct {const struct firmware *firmware;} req; struct rtw89_fw_secure sec; };
enum rtw89_fw_type { dummy_fw_type=0 };
struct rtw89_fw_blacklist {u8 ver;u8 list[32];};
struct rtw89_chip_info { int chip_gen;int chip_id;const struct rtw89_fw_blacklist *fw_blacklist;};
struct rtw89_dev {const struct rtw89_chip_info *chip;struct rtw89_fw_info fw;struct {u8 cv;}hal;};
'''
structs='\n'.join([declaration('rtw88','fw.h','struct','rtw_fw_hdr')]+[declaration('rtw89','fw.h','struct',s) for s in ['rtw89_fw_hdr_section_info','rtw89_fw_bin_info','rtw89_fw_hdr_section','rtw89_fw_hdr','rtw89_fw_dynhdr_hdr','rtw89_mfw_info','rtw89_mfw_hdr']]+[declaration('rtw89','fw.h','union','rtw89_fw_section_mssc_content')])
header=(reference/'rtw89/fw.h').read_text();macros='\n'.join(line for line in header.splitlines() if line.startswith(('#define FW_HDR_W','#define FWSECTION_HDR_')))
stub='''static int __parse_formatted_mssc(struct rtw89_dev*d,struct rtw89_fw_bin_info*i,struct rtw89_fw_hdr_section_info*s,const void*c,u32*l){(void)d;(void)i;(void)s;(void)c;(void)l;return -EINVAL;}\n'''
funcs='\n'.join([function('rtw88','mac.c',s) for s in ['check_firmware_size','start_download_firmware']]+[function('rtw89','fw.c',s) for s in ['__check_secure_blacklist','__parse_security_section','rtw89_fw_hdr_parser_v0','rtw89_mfw_get_hdr_ptr','rtw89_mfw_validate_hdr','rtw89_mfw_recognize']])
main=r'''
static u8 *load(const char *path,size_t *size){FILE*f=fopen(path,"rb");if(!f)abort();fseek(f,0,SEEK_END);long n=ftell(f);if(n<64||n>16*1024*1024)abort();rewind(f);u8*b=malloc(n);if(!b||fread(b,1,n,f)!=(size_t)n)abort();fclose(f);*size=n;return b;}
int main(int argc,char **argv){if(argc!=4)return 2;size_t n88,n89;u8*b88=load(argv[1],&n88),*b89=load(argv[2],&n89);output=fopen(argv[3],"wb");if(!output)abort();legacy_base=b88;word(0x38385752);if(!check_firmware_size(b88,n88))abort();struct rtw_dev old={0};if(start_download_firmware(&old,b88,n88))abort();
word(0x39385752);struct firmware fw={b89,n89};struct rtw89_chip_info chip={RTW89_CHIP_AX,RTL8852B,NULL};struct rtw89_dev dev={.chip=&chip,.fw={.req={&fw},.sec={false,0}}};
for(u32 cut=0;cut<16;cut++){dev.hal.cv=cut;struct rtw89_fw_suit suit={0};int ret=rtw89_mfw_recognize(&dev,(enum rtw89_fw_type)5,&suit,true);u32 type=5;if(ret){type=1;ret=rtw89_mfw_recognize(&dev,(enum rtw89_fw_type)1,&suit,true);}word(cut);word(ret);if(ret)continue;ax_base=suit.data;struct rtw89_fw_bin_info info={0};if(rtw89_fw_hdr_parser_v0(&dev,suit.data,suit.size,&info))abort();word(type);word(suit.data-b89);word(suit.size);word(info.hdr_len);word(info.dynamic_hdr_len);word(info.part_size);word(info.section_num);for(u32 i=0;i<info.section_num;i++){struct rtw89_fw_hdr_section_info*s=&info.section_info[i];word(s->type);word(s->dladdr);word(s->len);word(s->redl);word(s->mssc);word(s->addr-ax_base);raw(s->addr,s->len+s->mssc*512);}}
if(fclose(output))abort();free(b88);free(b89);return 0;}
'''
c=out/'oracle.c';c.write_text(preamble+structs+'\n'+macros+'\n'+stub+funcs+'\n'+main)
exe=out/'oracle';subprocess.run(['clang','-std=gnu11','-O1','-g','-fsanitize=address,undefined',str(c),'-o',str(exe)],check=True)
trace=out/'trace.bin';subprocess.run([str(exe),str(image88),str(image89),str(trace)],check=True)
rows=[]
for p in [c,exe,trace,image88,image89]:
 b=p.read_bytes();rows.append(dict(path=str(p.resolve()),bytes=len(b),sha256=hashlib.sha256(b).hexdigest()))
(out/'manifest.json').write_text(json.dumps(dict(linux_commit='a804c5742bff224d4cb4d25dd383554d598be32b',functions=manifest,artifacts=rows,limits=['Actual images and selected cuts only; malformed firmware is tested by Rust rather than unsafe donor parser','MMIO and lower download engine are modeled; no ROM/device I/O','Secure boot off; formatted MSSC unsupported stub not reached by these fixtures','Provider integrity/provenance and actual security/blacklist/OTP policy are separate']),indent=2)+'\n')
print('8 unchanged functions; trace',trace.stat().st_size,hashlib.sha256(trace.read_bytes()).hexdigest())

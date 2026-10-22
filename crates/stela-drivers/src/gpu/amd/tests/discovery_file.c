/* SPDX-License-Identifier: MIT */
/* Actual whole Linux file wrapper vs frozen guarded original. CPU only. */
#include "../stela/discovery_file.h"
#include "../amdgpu/amdgpu_discovery_file_core.h"
#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint8_t u8;
struct firmware { size_t size; const uint8_t *data; };
struct amdgpu_device { void *dev; unsigned ddev; struct { uint32_t size; } discovery; };
static struct firmware image;
static int request_status, amdgpu_discovery;
static char trace[8192];static size_t used;
static unsigned comparisons;
static void event(const char *format,...)
{
 va_list a;va_start(a,format);int n=vsnprintf(trace+used,sizeof(trace)-used,format,a);va_end(a);
 assert(n>=0&&(size_t)n<sizeof(trace)-used);used+=(size_t)n;
}
static void log_error(void *device,const char *format,...)
{
 (void)device;event("E:");va_list a;va_start(a,format);int n=vsnprintf(trace+used,sizeof(trace)-used,format,a);va_end(a);
 assert(n>=0&&(size_t)n<sizeof(trace)-used);used+=(size_t)n;
}
static void log_info(void *device,const char *format,...)
{
 (void)device;event("I:");va_list a;va_start(a,format);int n=vsnprintf(trace+used,sizeof(trace)-used,format,a);va_end(a);
 assert(n>=0&&(size_t)n<sizeof(trace)-used);used+=(size_t)n;
}
#define dev_err(...) log_error(__VA_ARGS__)
#define drm_info(...) log_info(__VA_ARGS__)
static int firmware_request_nowarn(const struct firmware **out,const char *name,void *device)
{
 (void)device;event("request:%s;",name);if(request_status)return request_status;*out=&image;return 0;
}
static void release_firmware(const struct firmware *firmware)
{assert(firmware==&image);event("release;");}
static void *copy_bytes(void *destination,const void *source,size_t bytes)
{event("copy:%zu;",bytes);return memcpy(destination,source,bytes);}
#undef memcpy
#define memcpy copy_bytes
#include "discovery_file_reference.h"
#include "discovery-file-linux.inc"
#undef memcpy
size_t stela_amd_ip_fixture(uint8_t *,size_t,unsigned,unsigned,unsigned);
static void compare(const uint8_t *data,size_t bytes,uint32_t capacity,int status,int option)
{
 size_t allocation=capacity?capacity:1;uint8_t *a=malloc(allocation),*b=malloc(allocation);assert(a&&b);
 memset(a,0,allocation);memset(b,0,allocation);image=(struct firmware){bytes,data};
 request_status=status;amdgpu_discovery=option;
 struct amdgpu_device adev={.discovery={capacity}};
 used=0;trace[0]=0;int expected=original_read_file(&adev,a,"amdgpu/ip_discovery.bin");
 char saved[sizeof(trace)];memcpy(saved,trace,used+1);size_t saved_used=used;
 used=0;trace[0]=0;int actual=amdgpu_discovery_read_binary_from_file(&adev,b,"amdgpu/ip_discovery.bin");
 assert(expected==actual&&used==saved_used&&!memcmp(saved,trace,used+1));
 assert(!memcmp(a,b,allocation));
 if(expected)for(size_t i=0;i<allocation;i++)assert(a[i]==0);
 else {assert(bytes<=capacity&&!memcmp(a,data,bytes));for(size_t i=bytes;i<allocation;i++)assert(a[i]==0);}
 free(a);free(b);comparisons++;
}
static void exercise(const uint8_t *data,size_t bytes)
{
 const uint32_t minimum=offsetof(struct binary_header,binary_size)+sizeof(((struct binary_header*)0)->binary_size);
 const uint32_t capacities[]={0,1,minimum-1,minimum,minimum+1,(uint32_t)bytes-1,(uint32_t)bytes,(uint32_t)bytes+1,65536};
 for(unsigned i=0;i<sizeof(capacities)/sizeof(*capacities);i++)
  for(int option=-1;option<=3;option++)for(int request=0;request<3;request++)
   compare(data,bytes,capacities[i],request==0?0:request==1?-ENOENT:-EIO,option);
 for(size_t cut=0;cut<bytes;cut++)compare(data,cut,(uint32_t)bytes,0,2);
 uint8_t *copy=malloc(bytes);assert(copy);memcpy(copy,data,bytes);
 for(size_t i=0;i<bytes;i+=17){copy[i]^=0xa5;compare(copy,bytes,(uint32_t)bytes,0,2);copy[i]^=0xa5;}
 free(copy);
}
int main(int argc,char **argv)
{
 uint8_t data[65536];
 for(unsigned version=0;version<=2;version++)for(unsigned wide=0;wide<2;wide++){
  size_t bytes=stela_amd_ip_fixture(data,sizeof(data),version,4,wide);exercise(data,bytes);
 }
 for(int n=1;n<argc;n++){
  FILE *f=fopen(argv[n],"rb");assert(f);size_t bytes=fread(data,1,sizeof(data),f);assert(bytes&&bytes<sizeof(data)&&feof(f));fclose(f);
  exercise(data,bytes);
 }
 assert(stela_amd_discovery_file_minimum()==offsetof(struct binary_header,binary_size)+sizeof(((struct binary_header*)0)->binary_size));
 assert(stela_amd_discovery_file_validate(NULL,0,0)==AMDGPU_DISCOVERY_FILE_TOO_SMALL);
 assert(stela_amd_discovery_file_validate(NULL,20,0)==AMDGPU_DISCOVERY_FILE_TOO_LARGE);
 assert(stela_amd_discovery_file_validate(NULL,20,20)==AMDGPU_DISCOVERY_FILE_INVALID);
 printf("AMD selected-file: %u whole original/current request/log/copy/release comparisons; actual extent/zero-tail/error atomicity; CPU only\n",comparisons);
 return 0;
}

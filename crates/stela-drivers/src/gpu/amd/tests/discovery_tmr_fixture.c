/* SPDX-License-Identifier: MIT */
/* Reuse existing original-format CPU fixture generation; no firmware payload. */
#define main stela_amd_discovery_existing_fixture_main
#include "discovery_binary_test.c"
#undef main
const uint8_t *stela_amd_tmr_fixture(size_t *size)
{
 static uint8_t bytes[10240];
 struct fixture f=make_fixture(2,4,1,1,3,0);
 assert(amdgpu_discovery_binary_validate(f.binary,f.size)==AMDGPU_DISCOVERY_BINARY_OK);
 memset(bytes,0,sizeof(bytes));memcpy(bytes,f.binary,f.size);*size=sizeof(bytes);return bytes;
}

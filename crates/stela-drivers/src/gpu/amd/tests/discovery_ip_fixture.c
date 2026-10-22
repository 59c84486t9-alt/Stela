/* SPDX-License-Identifier: MIT */
/* Original existing CPU fixture generation, never a production firmware source. */
#define main stela_amd_ip_existing_fixture_main
#include "discovery_binary_test.c"
#undef main
size_t stela_amd_ip_fixture(uint8_t *out, size_t capacity, unsigned version,
                           unsigned ip_version, unsigned wide)
{
   struct fixture f = make_fixture(version, ip_version, wide, 1, 3, 0);
   assert(capacity >= f.size);
   memcpy(out, f.binary, f.size);
   return f.size;
}

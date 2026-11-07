/* SPDX-License-Identifier: MIT */
/* ASTC LDR blocks decoded as Apple's GPUs do, for the decoder tests: Mesa's
 * reference decoder, kept at 16 bits for linear formats, with the one rule
 * Apple adds, a void extent's reserved bits. Apple reads a linear texel's
 * top 12 bits and an sRGB texel's 8. */
#include "util/half_float.h"
#undef FP16_ONE
#define FP16_ONE 0xffff
/* The linear decode's UNORM16 color, which Mesa would convert to half. */
#define _mesa_uint16_div_64k_to_half(x) (x)
/* Mesa's own copy of the entry point stays the library's. */
#define _mesa_unpack_astc_2d_ldr stela_unused_unpack_astc_2d_ldr
#include "util/texcompress_astc.cpp"

extern "C" void stela_astc_reference(const uint8_t block[16], unsigned width, unsigned height,
                                     bool srgb, uint32_t (*texels)[2]);

void stela_astc_reference(const uint8_t block[16], unsigned width, unsigned height, bool srgb,
                          uint32_t (*texels)[2])
{
   uint16_t out[12 * 12 * 4];
   Decoder decoder(width, height, 1, srgb, srgb);
   decoder.decode(block, out);
   uint32_t first;
   memcpy(&first, block, sizeof(first));
   bool void_extent = (first & 0x1ff) == 0x1fc;
   for (unsigned i = 0; i < width * height; i++) {
      uint16_t *c = out + 4 * i;
      if (void_extent && (first >> 10 & 3) != 3) {
         uint16_t one = srgb ? 0xff : 0xffff;
         c[0] = c[2] = c[3] = one;
         c[1] = 0;
      }
      if (srgb) {
         texels[i][0] = c[0] | c[1] << 8 | c[2] << 16 | (uint32_t)c[3] << 24;
         texels[i][1] = 0;
      } else {
         uint32_t wide[4];
         for (unsigned k = 0; k < 4; k++) {
            uint32_t twelve = c[k] >> 4;
            wide[k] = twelve << 4 | twelve >> 8;
         }
         texels[i][0] = wide[0] | wide[1] << 16;
         texels[i][1] = wide[2] | wide[3] << 16;
      }
   }
}

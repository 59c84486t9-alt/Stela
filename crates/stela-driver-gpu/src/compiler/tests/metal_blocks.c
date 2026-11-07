/* SPDX-License-Identifier: MIT */
/* The block decoders against reference decoders that follow the formats'
 * specifications bit for bit, over random blocks. The decoders run through
 * the NIR effect oracle; the kernels that load and store around them need a
 * device. */
#include "../metal_abi.h"
#include "air_effect_oracle.h"
#include "util/ralloc.h"
#include <assert.h>
#include <math.h>
#include <stdio.h>
#ifdef NDEBUG
#error "These tests require active assertions"
#endif

#define BASE 0x10000ull

/* A decoder over inputs in memory: the block's four words at BASE, then
 * x, y and the codec; its raw texel is stored after them. */
struct decoder {
   nir_shader *shader;
   uint8_t memory[64];
};

static void put32(uint8_t *bytes, uint32_t value)
{
   memcpy(bytes, &value, sizeof(value));
}

static uint32_t get32(const uint8_t *bytes)
{
   uint32_t value;
   memcpy(&value, bytes, sizeof(value));
   return value;
}

static struct decoder decoder(nir_def *(*decode)(nir_builder *, nir_def *, nir_def *, nir_def *,
                                                 nir_def *))
{
   nir_builder b = nir_builder_init_simple_shader(MESA_SHADER_COMPUTE, NULL, "decode");
   nir_def *base = nir_imm_int64(&b, BASE);
   nir_def *words = nir_load_global(&b, 4, 32, base, .align_mul = 16);
   nir_def *inputs = nir_load_global(&b, 3, 32, nir_iadd_imm(&b, base, 16), .align_mul = 4);
   nir_def *raw = decode(&b, words, nir_channel(&b, inputs, 0), nir_channel(&b, inputs, 1),
                         nir_channel(&b, inputs, 2));
   nir_store_global(&b, raw, nir_iadd_imm(&b, base, 32), .align_mul = 4);
   nir_validate_shader(b.shader, "decoder");
   nir_index_ssa_defs(nir_shader_get_entrypoint(b.shader));
   return (struct decoder){.shader = b.shader};
}

static uint32_t run(struct decoder *d, const uint8_t block[16], unsigned x, unsigned y,
                    unsigned codec)
{
   memcpy(d->memory, block, 16);
   put32(d->memory + 16, x);
   put32(d->memory + 20, y);
   put32(d->memory + 24, codec);
   const struct air_effect_environment environment = {
      .base = BASE, .bytes = d->memory, .size = sizeof(d->memory),
   };
   struct air_effect_store trace[4];
   struct air_effect_run result =
      air_effect_execute_in(d->shader, 100000, trace, ARRAY_SIZE(trace), &environment);
   if (result.status != AIR_EFFECT_COMPLETE)
      fprintf(stderr, "decode: %s\n", result.detail);
   assert(result.status == AIR_EFFECT_COMPLETE && result.stores == 1);
   return get32(d->memory + 32);
}

static uint64_t random_state = 0x853c49e6748fea9bull;

static uint32_t random32(void)
{
   random_state = random_state * 6364136223846793005ull + 1442695040888963407ull;
   return (uint32_t)(random_state >> 32);
}

static void random_block(uint8_t block[16])
{
   for (unsigned i = 0; i < 16; i += 4)
      put32(block + i, random32());
}

/* ETC2 and EAC, after the Khronos Data Format Specification's sections on
 * them: a block is a big-endian 64-bit word. */
static uint64_t big_endian(const uint8_t *bytes)
{
   uint64_t value = 0;
   for (unsigned i = 0; i < 8; i++)
      value = value << 8 | bytes[i];
   return value;
}

static unsigned bits64(uint64_t v, unsigned high, unsigned low)
{
   return (unsigned)(v >> low) & ((1u << (high - low + 1)) - 1);
}

static int signed3(unsigned v)
{
   return v & 4 ? (int)v - 8 : (int)v;
}

static int clamp(int v, int low, int high)
{
   return v < low ? low : v > high ? high : v;
}

static unsigned extend4(unsigned v) { return v << 4 | v; }
static unsigned extend5(unsigned v) { return v << 3 | v >> 2; }
static unsigned extend6(unsigned v) { return v << 2 | v >> 4; }
static unsigned extend7(unsigned v) { return v << 1 | v >> 6; }

enum etc_mode { INDIVIDUAL, DIFFERENTIAL, T_MODE, H_MODE, PLANAR, MODES };
static unsigned etc_modes[MODES];

/* RGBA of an ETC2 RGB8 or RGB8A1 block at x and y. */
static void reference_etc(const uint8_t *bytes, unsigned x, unsigned y, bool punch_through,
                          int rgba[4])
{
   static const int distances[8] = {3, 6, 11, 16, 23, 32, 41, 64};
   static const int modifiers[8][4] = {
      {2, 8, -2, -8}, {5, 17, -5, -17}, {9, 29, -9, -29}, {13, 42, -13, -42},
      {18, 60, -18, -60}, {24, 80, -24, -80}, {33, 106, -33, -106}, {47, 183, -47, -183},
   };
   uint64_t v = big_endian(bytes);
   unsigned p = x * 4 + y;
   unsigned index = bits64(v, p + 16, p + 16) << 1 | bits64(v, p, p);
   bool diff = bits64(v, 33, 33), flip = bits64(v, 32, 32);
   bool opaque = !punch_through || diff;
   int color[3];
   rgba[3] = 255;
   int r = bits64(v, 63, 59), g = bits64(v, 55, 51), b = bits64(v, 47, 43);
   int dr = signed3(bits64(v, 58, 56)), dg = signed3(bits64(v, 50, 48)),
       db = signed3(bits64(v, 42, 40));
   unsigned sub = flip ? y >= 2 : x >= 2;
   enum etc_mode mode;
   if (!punch_through && !diff)
      mode = INDIVIDUAL;
   else if (r + dr < 0 || r + dr > 31)
      mode = T_MODE;
   else if (g + dg < 0 || g + dg > 31)
      mode = H_MODE;
   else if (b + db < 0 || b + db > 31)
      mode = PLANAR;
   else
      mode = DIFFERENTIAL;
   etc_modes[mode]++;
   if (mode == INDIVIDUAL || mode == DIFFERENTIAL) {
      int base[3];
      if (mode == INDIVIDUAL) {
         for (unsigned c = 0; c < 3; c++)
            base[c] = extend4(bits64(v, 63 - 8 * c - 4 * sub, 60 - 8 * c - 4 * sub));
      } else {
         base[0] = extend5(sub ? r + dr : r);
         base[1] = extend5(sub ? g + dg : g);
         base[2] = extend5(sub ? b + db : b);
      }
      unsigned table = sub ? bits64(v, 36, 34) : bits64(v, 39, 37);
      /* The pixel index orders msb then lsb: 0, 1 are +a, +b; 2, 3 -a, -b. */
      int modifier = modifiers[table][index];
      if (!opaque && (index == 0 || index == 2))
         modifier = 0;
      for (unsigned c = 0; c < 3; c++)
         color[c] = base[c] + modifier;
   } else if (mode == T_MODE) {
      int c0[3] = {(int)extend4(bits64(v, 60, 59) << 2 | bits64(v, 57, 56)),
                   (int)extend4(bits64(v, 55, 52)), (int)extend4(bits64(v, 51, 48))};
      int c1[3] = {(int)extend4(bits64(v, 47, 44)), (int)extend4(bits64(v, 43, 40)),
                   (int)extend4(bits64(v, 39, 36))};
      int d = distances[bits64(v, 35, 34) << 1 | bits64(v, 32, 32)];
      for (unsigned c = 0; c < 3; c++) {
         int paint[4] = {c0[c], c1[c] + d, c1[c], c1[c] - d};
         color[c] = paint[index];
      }
   } else if (mode == H_MODE) {
      unsigned r0 = bits64(v, 62, 59), g0 = bits64(v, 58, 56) << 1 | bits64(v, 52, 52),
               b0 = bits64(v, 51, 51) << 3 | bits64(v, 49, 47);
      unsigned r1 = bits64(v, 46, 43), g1 = bits64(v, 42, 39), b1 = bits64(v, 38, 35);
      unsigned ordered = (r0 << 8 | g0 << 4 | b0) >= (r1 << 8 | g1 << 4 | b1);
      int d = distances[bits64(v, 34, 34) << 2 | bits64(v, 32, 32) << 1 | ordered];
      int c0[3] = {(int)extend4(r0), (int)extend4(g0), (int)extend4(b0)};
      int c1[3] = {(int)extend4(r1), (int)extend4(g1), (int)extend4(b1)};
      for (unsigned c = 0; c < 3; c++) {
         int paint[4] = {c0[c] + d, c0[c] - d, c1[c] + d, c1[c] - d};
         color[c] = paint[index];
      }
   } else {
      int o[3] = {(int)extend6(bits64(v, 62, 57)),
                  (int)extend7(bits64(v, 56, 56) << 6 | bits64(v, 54, 49)),
                  (int)extend6(bits64(v, 48, 48) << 5 | bits64(v, 44, 43) << 3 |
                               bits64(v, 41, 39))};
      int h[3] = {(int)extend6(bits64(v, 38, 34) << 1 | bits64(v, 32, 32)),
                  (int)extend7(bits64(v, 31, 25)), (int)extend6(bits64(v, 24, 19))};
      int w[3] = {(int)extend6(bits64(v, 18, 13)), (int)extend7(bits64(v, 12, 6)),
                  (int)extend6(bits64(v, 5, 0))};
      for (unsigned c = 0; c < 3; c++)
         color[c] = ((int)x * (h[c] - o[c]) + (int)y * (w[c] - o[c]) + 4 * o[c] + 2) >> 2;
   }
   for (unsigned c = 0; c < 3; c++)
      rgba[c] = clamp(color[c], 0, 255);
   if (!opaque && mode != PLANAR && index == 2)
      rgba[0] = rgba[1] = rgba[2] = rgba[3] = 0;
}

static const int alpha_modifiers[16][8] = {
   {-3, -6, -9, -15, 2, 5, 8, 14}, {-3, -7, -10, -13, 2, 6, 9, 12},
   {-2, -5, -8, -13, 1, 4, 7, 12}, {-2, -4, -6, -13, 1, 3, 5, 12},
   {-3, -6, -8, -12, 2, 5, 7, 11}, {-3, -7, -9, -11, 2, 6, 8, 10},
   {-4, -7, -8, -11, 3, 6, 7, 10}, {-3, -5, -8, -11, 2, 4, 7, 10},
   {-2, -6, -8, -10, 1, 5, 7, 9}, {-2, -5, -8, -10, 1, 4, 7, 9},
   {-2, -4, -8, -10, 1, 3, 7, 9}, {-2, -5, -7, -10, 1, 4, 6, 9},
   {-3, -4, -7, -10, 2, 3, 6, 9}, {-1, -2, -3, -10, 0, 1, 2, 9},
   {-4, -6, -8, -9, 3, 5, 7, 8}, {-3, -5, -7, -9, 2, 4, 6, 8},
};

/* An ETC2 alpha block's value at x and y. */
static int reference_alpha(const uint8_t *bytes, unsigned x, unsigned y)
{
   uint64_t v = big_endian(bytes);
   unsigned p = x * 4 + y;
   int modifier = alpha_modifiers[bits64(v, 51, 48)][bits64(v, 47 - 3 * p, 45 - 3 * p)];
   return clamp((int)bits64(v, 63, 56) + modifier * (int)bits64(v, 55, 52), 0, 255);
}

/* An EAC R11 block's 16-bit code at x and y: the 11-bit value over 2047,
 * or the signed one over 1023, at 16 bits. */
static uint32_t reference_eac(const uint8_t *bytes, unsigned x, unsigned y, bool is_signed)
{
   uint64_t v = big_endian(bytes);
   unsigned p = x * 4 + y;
   int modifier = alpha_modifiers[bits64(v, 51, 48)][bits64(v, 47 - 3 * p, 45 - 3 * p)];
   int multiplier = (int)bits64(v, 55, 52);
   multiplier = multiplier ? multiplier * 8 : 1;
   if (is_signed) {
      int base = (int8_t)bits64(v, 63, 56);
      base = base == -128 ? -127 : base;
      int value = clamp(base * 8 + modifier * multiplier, -1023, 1023);
      return (uint32_t)lround(value * 32767.0 / 1023.0) & 0xffff;
   }
   int value = clamp((int)bits64(v, 63, 56) * 8 + 4 + modifier * multiplier, 0, 2047);
   return (uint32_t)lround(value * 65535.0 / 2047.0);
}

static uint32_t reference_etc_texel(const uint8_t *block, unsigned x, unsigned y, unsigned codec)
{
   int rgba[4];
   switch (codec) {
   case STELA_METAL_BLOCKS_ETC2_RGB8:
   case STELA_METAL_BLOCKS_ETC2_RGB8A1:
      reference_etc(block, x, y, codec == STELA_METAL_BLOCKS_ETC2_RGB8A1, rgba);
      break;
   case STELA_METAL_BLOCKS_EAC_RGBA8:
      reference_etc(block + 8, x, y, false, rgba);
      rgba[3] = reference_alpha(block, x, y);
      break;
   case STELA_METAL_BLOCKS_EAC_R11:
   case STELA_METAL_BLOCKS_EAC_R11_SNORM:
      return reference_eac(block, x, y, codec == STELA_METAL_BLOCKS_EAC_R11_SNORM);
   default: {
      bool is_signed = codec == STELA_METAL_BLOCKS_EAC_RG11_SNORM;
      return reference_eac(block, x, y, is_signed) | reference_eac(block + 8, x, y, is_signed) << 16;
   }
   }
   return (uint32_t)rgba[0] | (uint32_t)rgba[1] << 8 | (uint32_t)rgba[2] << 16 |
          (uint32_t)rgba[3] << 24;
}

static void etc_blocks_decode_as_specified(void)
{
   struct decoder d = decoder(stela_metal_decode_etc);
   for (unsigned codec = STELA_METAL_BLOCKS_ETC2_RGB8; codec <= STELA_METAL_BLOCKS_EAC_RG11_SNORM;
        codec++) {
      for (unsigned n = 0; n < 160; n++) {
         uint8_t block[16];
         random_block(block);
         /* Signed EAC's -128 base, which reads as -127. */
         if (n == 0)
            block[0] = block[8] = 0x80;
         for (unsigned y = 0; y < 4; y++) {
            for (unsigned x = 0; x < 4; x++) {
               uint32_t expected = reference_etc_texel(block, x, y, codec);
               uint32_t decoded = run(&d, block, x, y, codec);
               if (decoded != expected)
                  fprintf(stderr, "codec %u block %u (%u, %u): %08x, expected %08x\n", codec, n,
                          x, y, decoded, expected);
               assert(decoded == expected);
            }
         }
      }
   }
   /* Random blocks reach every mode. */
   for (unsigned mode = 0; mode < MODES; mode++)
      assert(etc_modes[mode] > 100);
   ralloc_free(d.shader);
}

int main(void)
{
   glsl_type_singleton_init_or_ref();
   etc_blocks_decode_as_specified();
   glsl_type_singleton_decref();
   puts("metal blocks: ok");
   return 0;
}

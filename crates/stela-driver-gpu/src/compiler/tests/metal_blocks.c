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
#include <string.h>
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

/* PVRTC1, after Imagination's decompressor, which Apple's GPUs match bit
 * for bit: a level's blocks in Morton order, each texel blending the four
 * nearest blocks' colors and weighed by its modulation. */
static unsigned twiddle(unsigned columns, unsigned rows, unsigned x, unsigned y)
{
   unsigned smaller = columns < rows ? columns : rows, out = 0, shift = 0;
   for (unsigned bit = 1; bit < smaller; bit <<= 1, shift++)
      out |= (y & bit ? 1u : 0u) << (2 * shift) | (x & bit ? 1u : 0u) << (2 * shift + 1);
   return out | ((columns > rows ? x : y) >> shift) << (2 * shift);
}

static void pvrtc_colors(uint64_t block, int a[4], int b[4])
{
   uint32_t c = (uint32_t)(block >> 32), lo = c & 0xffff, hi = c >> 16;
#define W4(v) ((v) << 1 | (v) >> 3)
   if (lo & 0x8000) {
      unsigned blue = lo >> 1 & 15;
      a[0] = lo >> 10 & 31, a[1] = lo >> 5 & 31, a[2] = W4(blue), a[3] = 15;
   } else {
      unsigned blue = lo >> 1 & 7;
      a[0] = W4(lo >> 8 & 15), a[1] = W4(lo >> 4 & 15), a[2] = blue << 2 | blue >> 1;
      a[3] = (lo >> 12 & 7) << 1;
   }
   if (hi & 0x8000) {
      b[0] = hi >> 10 & 31, b[1] = hi >> 5 & 31, b[2] = hi & 31, b[3] = 15;
   } else {
      b[0] = W4(hi >> 8 & 15), b[1] = W4(hi >> 4 & 15), b[2] = W4(hi & 15);
      b[3] = (hi >> 12 & 7) << 1;
   }
#undef W4
}

static const int pvrtc_weights[4] = {0, 3, 5, 8};

/* A 2-bpp block's value at x, y and its interpolation mode. */
static int pvrtc2_value(uint64_t block, unsigned x, unsigned y, int *mode)
{
   uint32_t bits = (uint32_t)block;
   if (!(block >> 32 & 1)) {
      *mode = 0;
      return bits >> (y * 8 + x) & 1 ? 8 : 0;
   }
   *mode = 1;
   if (bits & 1) {
      *mode = bits & 1u << 20 ? 3 : 2;
      bits = bits & 1u << 21 ? bits | 1u << 20 : bits & ~(1u << 20);
   }
   bits = bits & 2 ? bits | 1 : bits & ~1u;
   return pvrtc_weights[bits >> (2 * (y * 4 + x / 2)) & 3];
}

static uint32_t reference_pvrtc(const uint8_t *level, unsigned columns, unsigned rows, unsigned x,
                                unsigned y, bool two_bpp)
{
   unsigned w = two_bpp ? 8 : 4;
   int px = (int)((x + columns * w - w / 2) / w % columns);
   int py = (int)((y + rows * 4 - 2) / 4 % rows);
   unsigned lx = (x + columns * w - w / 2) % w, ly = (y + rows * 4 - 2) % 4;
   uint64_t quad[4];
   unsigned at[4][2] = {{px, py}, {(px + 1) % columns, py}, {px, (py + 1) % rows},
                        {(px + 1) % columns, (py + 1) % rows}};
   for (unsigned i = 0; i < 4; i++)
      memcpy(&quad[i], level + 8 * twiddle(columns, rows, at[i][0], at[i][1]), 8);
   int weights[4] = {(int)((w - lx) * (4 - ly)), (int)(lx * (4 - ly)), (int)((w - lx) * ly),
                     (int)(lx * ly)};
   int sum_a[4] = {0}, sum_b[4] = {0};
   for (unsigned i = 0; i < 4; i++) {
      int a[4], b[4];
      pvrtc_colors(quad[i], a, b);
      for (unsigned c = 0; c < 4; c++)
         sum_a[c] += weights[i] * a[c], sum_b[c] += weights[i] * b[c];
   }
   unsigned qx = lx + w / 2, qy = ly + 2;
   int weight;
   bool punch = false;
   if (!two_bpp) {
      uint64_t own = quad[(qy >= 4) * 2 + (qx >= 4)];
      unsigned value = (uint32_t)own >> (2 * ((qy % 4) * 4 + qx % 4)) & 3;
      if (own >> 32 & 1) {
         static const int punched[4] = {0, 4, 4, 8};
         weight = punched[value];
         punch = value == 2;
      } else {
         weight = pvrtc_weights[value];
      }
   } else {
#define AT(X, Y, MODE) \
      pvrtc2_value(quad[((Y) >= 4) * 2 + ((X) >= 8)], (X) % 8, (Y) % 4, MODE)
      int mode, unused;
      weight = AT(qx, qy, &mode);
      if (mode && (qx ^ qy) & 1) {
         int l = AT(qx - 1, qy, &unused), r = AT(qx + 1, qy, &unused);
         int u = AT(qx, qy - 1, &unused), d = AT(qx, qy + 1, &unused);
         weight = mode == 1 ? (l + r + u + d + 2) / 4 : mode == 2 ? (l + r + 1) / 2 : (u + d + 1) / 2;
      }
#undef AT
   }
   uint32_t texel = 0;
   for (unsigned c = 0; c < 4; c++) {
      int ua, ub;
      if (c < 3 && !two_bpp)
         ua = (sum_a[c] >> 1) + (sum_a[c] >> 6), ub = (sum_b[c] >> 1) + (sum_b[c] >> 6);
      else if (c < 3)
         ua = (sum_a[c] >> 2) + (sum_a[c] >> 7), ub = (sum_b[c] >> 2) + (sum_b[c] >> 7);
      else if (!two_bpp)
         ua = sum_a[c] + (sum_a[c] >> 4), ub = sum_b[c] + (sum_b[c] >> 4);
      else
         ua = (sum_a[c] >> 1) + (sum_a[c] >> 5), ub = (sum_b[c] >> 1) + (sum_b[c] >> 5);
      int value = (ua * (8 - weight) + ub * weight) / 8;
      if (c == 3 && punch)
         value = 0;
      texel |= (uint32_t)value << (8 * c);
   }
   return texel;
}

/* A decoder of a level in memory: its blocks at BASE + 64, then columns,
 * rows, x, y and the codec at BASE; its raw texel is stored at BASE + 32. */
static nir_def *pvrtc_inputs(nir_builder *b, nir_def *words, nir_def *x, nir_def *y,
                             nir_def *codec)
{
   return stela_metal_decode_pvrtc(b, nir_imm_int64(b, BASE + 64), nir_channel(b, words, 0),
                                   nir_channel(b, words, 1), x, y, codec);
}

static void pvrtc_blocks_decode_as_apple_does(void)
{
   static uint8_t memory[64 + 8 * 64];
   nir_builder b = nir_builder_init_simple_shader(MESA_SHADER_COMPUTE, NULL, "pvrtc");
   nir_def *base = nir_imm_int64(&b, BASE);
   nir_def *words = nir_load_global(&b, 4, 32, base, .align_mul = 16);
   nir_def *inputs = nir_load_global(&b, 3, 32, nir_iadd_imm(&b, base, 16), .align_mul = 4);
   nir_def *raw = pvrtc_inputs(&b, words, nir_channel(&b, inputs, 0), nir_channel(&b, inputs, 1),
                               nir_channel(&b, inputs, 2));
   nir_store_global(&b, raw, nir_iadd_imm(&b, base, 32), .align_mul = 4);
   nir_index_ssa_defs(nir_shader_get_entrypoint(b.shader));
   /* Levels of one block to eight by eight, and 2-bpp levels twice as tall
    * as wide in blocks. */
   static const unsigned shapes[][3] = {{1, 1, 0}, {2, 2, 0}, {4, 4, 0}, {8, 8, 0},
                                        {1, 1, 1}, {1, 2, 1}, {2, 4, 1}, {4, 8, 1}};
   for (unsigned s = 0; s < ARRAY_SIZE(shapes); s++) {
      unsigned columns = shapes[s][0], rows = shapes[s][1];
      bool two_bpp = shapes[s][2];
      unsigned codec = two_bpp ? STELA_METAL_BLOCKS_PVRTC_2BPP : STELA_METAL_BLOCKS_PVRTC_4BPP;
      for (unsigned rep = 0; rep < 3; rep++) {
         for (unsigned i = 0; i < 8 * columns * rows; i += 4)
            put32(memory + 64 + i, random32());
         unsigned width = columns * (two_bpp ? 8 : 4), height = rows * 4;
         for (unsigned y = 0; y < height; y++) {
            for (unsigned x = 0; x < width; x++) {
               uint32_t inputs[8] = {columns, rows, 0, 0, x, y, codec, 0};
               memcpy(memory, inputs, sizeof(inputs));
               const struct air_effect_environment environment = {
                  .base = BASE, .bytes = memory, .size = 64 + 8 * columns * rows,
               };
               struct air_effect_store trace[4];
               struct air_effect_run result =
                  air_effect_execute_in(b.shader, 100000, trace, ARRAY_SIZE(trace), &environment);
               if (result.status != AIR_EFFECT_COMPLETE)
                  fprintf(stderr, "pvrtc: %s\n", result.detail);
               assert(result.status == AIR_EFFECT_COMPLETE);
               uint32_t decoded = get32(memory + 32);
               uint32_t expected = reference_pvrtc(memory + 64, columns, rows, x, y, two_bpp);
               if (decoded != expected)
                  fprintf(stderr, "pvrtc %ux%u%s (%u, %u): %08x, expected %08x\n", columns, rows,
                          two_bpp ? " 2bpp" : "", x, y, decoded, expected);
               assert(decoded == expected);
            }
         }
      }
   }
   ralloc_free(b.shader);
}

/* The reorder kernel moves a region's rows of blocks to and from a level's
 * Morton order. */
static void reorder_kernel_twiddles_regions(void)
{
   nir_shader *shader = stela_metal_reorder_blocks_kernel(NULL);
   nir_index_ssa_defs(nir_shader_get_entrypoint(shader));
   /* A level of 4x8 blocks at 0, a buffer of rows 40 bytes apart at 1024,
    * and the arguments at 2048: a 3x2 region from block (1, 5). */
   static uint8_t memory[4096];
   const uint64_t level = BASE, rows = BASE + 1024, arguments = BASE + 2048;
   for (unsigned to_rows = 0; to_rows < 2; to_rows++) {
      memset(memory, 0, sizeof(memory));
      for (unsigned i = 0; i < 1024; i += 4)
         put32(memory + i + (to_rows ? 0 : 1024), random32());
      uint8_t before[2048];
      memcpy(before, memory, sizeof(before));
      uint8_t *a = memory + 2048;
      memcpy(a + STELA_METAL_REORDER_ROWS, &rows, 8);
      memcpy(a + STELA_METAL_REORDER_LEVEL, &level, 8);
      const uint32_t words[] = {6, to_rows, 4, 8, 1, 5, 3, 40};
      memcpy(a + STELA_METAL_REORDER_COUNT, words, sizeof(words));
      uint8_t push[STELA_METAL_PUSH_BYTES] = {0};
      memcpy(push + STELA_METAL_PUSH_ARGUMENTS, &arguments, 8);
      for (unsigned thread = 0; thread < 7; thread++) {
         const struct air_effect_environment environment = {
            .base = BASE, .bytes = memory, .size = sizeof(memory), .push = push,
            .push_size = sizeof(push), .local_index = thread,
         };
         struct air_effect_store trace[2];
         struct air_effect_run run =
            air_effect_execute_in(shader, 10000, trace, ARRAY_SIZE(trace), &environment);
         if (run.status != AIR_EFFECT_COMPLETE)
            fprintf(stderr, "reorder: %s\n", run.detail);
         assert(run.status == AIR_EFFECT_COMPLETE && run.stores == (thread < 6));
      }
      for (unsigned y = 0; y < 2; y++) {
         for (unsigned x = 0; x < 3; x++) {
            unsigned in_level = 8 * twiddle(4, 8, 1 + x, 5 + y), in_rows = 1024 + 40 * y + 8 * x;
            const uint8_t *moved = to_rows ? memory + in_rows : memory + in_level;
            const uint8_t *source = to_rows ? before + in_level : before + in_rows;
            assert(memcmp(moved, source, 8) == 0);
         }
      }
   }
   ralloc_free(shader);
}

void stela_astc_reference(const uint8_t block[16], unsigned width, unsigned height, bool srgb,
                          uint32_t (*texels)[2]);

/* ASTC blocks of every size, random, void extents and blocks of the block
 * modes common encoders pick, decode as Apple's do: as Mesa's reference
 * decoder with Apple's void-extent rule, which matches Apple's texels. */
static void astc_blocks_decode_as_apple_does(void)
{
   nir_builder b = nir_builder_init_simple_shader(MESA_SHADER_COMPUTE, NULL, "astc");
   nir_def *base = nir_imm_int64(&b, BASE);
   nir_def *words = nir_load_global(&b, 4, 32, base, .align_mul = 16);
   nir_def *inputs = nir_load_global(&b, 4, 32, nir_iadd_imm(&b, base, 16), .align_mul = 16);
   nir_def *srgb = nir_ine_imm(&b, nir_load_global(&b, 1, 32, nir_iadd_imm(&b, base, 40), .align_mul = 4), 0);
   nir_def *raw = stela_metal_decode_astc(&b, words, nir_channel(&b, inputs, 0), nir_channel(&b, inputs, 1),
                                          nir_channel(&b, inputs, 2), nir_channel(&b, inputs, 3), srgb);
   nir_store_global(&b, raw, nir_iadd_imm(&b, base, 32), .align_mul = 8);
   nir_validate_shader(b.shader, "astc");
   nir_index_ssa_defs(nir_shader_get_entrypoint(b.shader));
   static const unsigned sizes[][2] = {{4, 4}, {5, 4}, {5, 5}, {6, 5}, {6, 6}, {8, 5}, {8, 6},
                                       {8, 8}, {10, 5}, {10, 6}, {10, 8}, {10, 10}, {12, 10}, {12, 12}};
   static const uint32_t modes[] = {0x0042, 0x0053, 0x0063, 0x0102, 0x0142, 0x0182,
                                    0x0242, 0x0442, 0x0542, 0x0843, 0x0101, 0x0151};
   unsigned blocks = 0;
   for (unsigned s = 0; s < ARRAY_SIZE(sizes); s++) {
      unsigned width = sizes[s][0], height = sizes[s][1];
      for (unsigned rep = 0; rep < 24; rep++) {
         bool srgb = rep & 1;
         uint8_t block[16];
         uint32_t expected[12 * 12][2];
         uint32_t magenta[2] = {srgb ? 0xffff00ffu : 0x0000ffffu, srgb ? 0 : 0xffffffffu};
         /* Six random blocks, mostly illegal; three void extents; and
          * fifteen legal blocks of the common modes, of 1 to 4 partitions. */
         for (bool legal = false; !legal;) {
            random_block(block);
            uint32_t first = get32(block);
            if (rep >= 6 && rep < 9) {
               /* Unbounded, LDR or HDR, its reserved bits right in two. */
               uint32_t reserved = rep == 8 ? first & 0xc00u : 0xc00u;
               first = (first & 0x200u) | reserved | 0x1fc | 0xfffff000u;
               put32(block + 4, 0xffffffffu);
            } else if (rep >= 9) {
               first = (first & ~0x7ffu) | modes[random32() % ARRAY_SIZE(modes)];
            }
            put32(block, first);
            stela_astc_reference(block, width, height, srgb, expected);
            legal = rep < 9;
            for (unsigned i = 0; i < width * height; i++)
               legal |= expected[i][0] != magenta[0] || expected[i][1] != magenta[1];
         }
         uint8_t memory[64] = {0};
         memcpy(memory, block, 16);
         put32(memory + 40, srgb);
         for (unsigned y = 0; y < height; y++) {
            for (unsigned x = 0; x < width; x++) {
               uint32_t in[4] = {x, y, width, height};
               memcpy(memory + 16, in, sizeof(in));
               const struct air_effect_environment environment = {
                  .base = BASE, .bytes = memory, .size = sizeof(memory),
               };
               struct air_effect_store trace[4];
               struct air_effect_run result =
                  air_effect_execute_in(b.shader, 1000000, trace, ARRAY_SIZE(trace), &environment);
               if (result.status != AIR_EFFECT_COMPLETE)
                  fprintf(stderr, "astc: %s\n", result.detail);
               assert(result.status == AIR_EFFECT_COMPLETE);
               uint32_t got[2] = {get32(memory + 32), get32(memory + 36)};
               uint32_t *want = expected[y * width + x];
               if (got[0] != want[0] || got[1] != want[1])
                  fprintf(stderr, "astc %ux%u%s %08x %08x %08x %08x (%u, %u): %08x %08x, expected %08x %08x\n",
                          width, height, srgb ? " srgb" : "", get32(block), get32(block + 4),
                          get32(block + 8), get32(block + 12), x, y, got[0], got[1], want[0], want[1]);
               assert(got[0] == want[0] && got[1] == want[1]);
            }
         }
         blocks++;
      }
   }
   assert(blocks == ARRAY_SIZE(sizes) * 24);
   ralloc_free(b.shader);
}

int main(void)
{
   glsl_type_singleton_init_or_ref();
   etc_blocks_decode_as_specified();
   pvrtc_blocks_decode_as_apple_does();
   reorder_kernel_twiddles_regions();
   astc_blocks_decode_as_apple_does();
   glsl_type_singleton_decref();
   puts("metal blocks: ok");
   return 0;
}

/*
 * Copyright 2015 Advanced Micro Devices, Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include "ac_debug.h"
#include "sid.h"
#define SID_TABLE_IMPLEMENTATION
#include "sid_tables.h"

const struct si_reg *ac_find_register(enum amd_gfx_level gfx_level, enum radeon_family family,
                                      unsigned offset)
{
   const struct si_reg *table;
   unsigned table_size;

   switch (gfx_level) {
   case GFX12:
      table = gfx12_reg_table;
      table_size = gfx12_reg_table_size;
      break;
   case GFX11_5:
      table = gfx115_reg_table;
      table_size = gfx115_reg_table_size;
      break;
   case GFX11:
      table = gfx11_reg_table;
      table_size = gfx11_reg_table_size;
      break;
   case GFX10_3:
      table = gfx103_reg_table;
      table_size = gfx103_reg_table_size;
      break;
   case GFX10:
      table = gfx10_reg_table;
      table_size = gfx10_reg_table_size;
      break;
   case GFX9:
      if (family == CHIP_GFX940) {
         table = gfx940_reg_table;
         table_size = gfx940_reg_table_size;
         break;
      }
      table = gfx9_reg_table;
      table_size = gfx9_reg_table_size;
      break;
   case GFX8:
      if (family == CHIP_STONEY) {
         table = gfx81_reg_table;
         table_size = gfx81_reg_table_size;
         break;
      }
      table = gfx8_reg_table;
      table_size = gfx8_reg_table_size;
      break;
   case GFX7:
      table = gfx7_reg_table;
      table_size = gfx7_reg_table_size;
      break;
   case GFX6:
      table = gfx6_reg_table;
      table_size = gfx6_reg_table_size;
      break;
   default:
      return NULL;
   }

   for (unsigned i = 0; i < table_size; i++) {
      const struct si_reg *reg = &table[i];

      if (reg->offset == offset)
         return reg;
   }

   return NULL;
}

const char *ac_get_register_name(enum amd_gfx_level gfx_level, enum radeon_family family,
                                 unsigned offset)
{
   const struct si_reg *reg = ac_find_register(gfx_level, family, offset);

   return reg ? sid_strings + reg->name_offset : "(no name)";
}

bool ac_register_exists(enum amd_gfx_level gfx_level, enum radeon_family family,
                        unsigned offset)
{
   return ac_find_register(gfx_level, family, offset) != NULL;
}


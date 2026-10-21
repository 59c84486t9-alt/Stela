/*
 * Copyright © 2022 Collabora, LTD
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

/* Pure color value helpers shared by runtime wrappers and hardware encoders.
 * Only Vulkan value declarations are required; no object/lifecycle dependency.
 */
#ifndef VK_COLOR_VALUE_H
#define VK_COLOR_VALUE_H
#include <stdbool.h>
#include <vulkan/vulkan_core.h>
#include "util/macros.h"

static inline bool
vk_color_value_is_int(VkBorderColor color)
{
   switch (color) {
   case VK_BORDER_COLOR_FLOAT_TRANSPARENT_BLACK:
   case VK_BORDER_COLOR_FLOAT_OPAQUE_BLACK:
   case VK_BORDER_COLOR_FLOAT_OPAQUE_WHITE:
   case VK_BORDER_COLOR_FLOAT_CUSTOM_EXT:
      return false;
   case VK_BORDER_COLOR_INT_TRANSPARENT_BLACK:
   case VK_BORDER_COLOR_INT_OPAQUE_BLACK:
   case VK_BORDER_COLOR_INT_OPAQUE_WHITE:
   case VK_BORDER_COLOR_INT_CUSTOM_EXT:
      return true;
   default:
      UNREACHABLE("Invalid border color enum");
   }
}

static inline uint32_t
swizzled_color_component(const VkClearColorValue *color,
                         VkComponentSwizzle swizzle,
                         uint32_t comp, bool is_int)
{
   switch (swizzle) {
   case VK_COMPONENT_SWIZZLE_IDENTITY: return color->uint32[comp];
   case VK_COMPONENT_SWIZZLE_ZERO:     return 0;
   case VK_COMPONENT_SWIZZLE_ONE:      return is_int ? 1 : 0x3f800000;
   case VK_COMPONENT_SWIZZLE_R:        return color->uint32[0];
   case VK_COMPONENT_SWIZZLE_G:        return color->uint32[1];
   case VK_COMPONENT_SWIZZLE_B:        return color->uint32[2];
   case VK_COMPONENT_SWIZZLE_A:        return color->uint32[3];
   default: UNREACHABLE("Invalid component swizzle");
   }
}

static inline VkClearColorValue
vk_color_value_swizzle(VkClearColorValue color,
                       VkComponentMapping swizzle, bool is_int)
{
   return (VkClearColorValue) { .uint32 = {
      swizzled_color_component(&color, swizzle.r, 0, is_int),
      swizzled_color_component(&color, swizzle.g, 1, is_int),
      swizzled_color_component(&color, swizzle.b, 2, is_int),
      swizzled_color_component(&color, swizzle.a, 3, is_int),
   }};
}

#endif

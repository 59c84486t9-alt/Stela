/*
 * Copyright © 2013 Intel Corporation
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

#include <string.h>
#include "intel_device_info_private.h"
#include "intel_hwconfig.h"
#include "intel_wa.h"
#include "i915/intel_device_info.h"
#include "xe/intel_device_info.h"
#include "virtio/intel_virtio.h"
#include "common/intel_gem.h"
#include "util/libdrm.h"
#include "util/log.h"
#include "util/os_misc.h"
#include "util/u_debug.h"

bool
intel_device_info_compute_system_memory(struct intel_device_info *devinfo, bool update)
{
   if (!update) {
      if (!os_get_total_physical_memory(&devinfo->mem.sram.mappable.size))
         return false;
   }

   os_get_available_system_memory(&devinfo->mem.sram.mappable.free);

   return true;
}

static void
intel_device_info_adjust_memory(struct intel_device_info *devinfo)
{
   uint64_t available;

   /* Applications running without elevated privileges don't report valid
    * numbers for free sram
    */
   if (os_get_available_system_memory(&available)) {
      devinfo->mem.sram.mappable.free = MIN3(devinfo->mem.sram.mappable.free,
                                             devinfo->mem.sram.mappable.size,
                                             available);
   }
}

static void
init_max_scratch_ids(struct intel_device_info *devinfo)
{
   /* Determine the max subslice that potentially might be used in
    * scratch space ids.
    */
   unsigned subslices = intel_device_info_dual_subslice_id_bound(devinfo);
   assert(subslices >= devinfo->subslice_total);

   unsigned scratch_ids_per_subslice;
   if (devinfo->ver >= 12) {
      /* Same as ICL below, but with 16 EUs. */
      scratch_ids_per_subslice = 16 * 8;
   } else if (devinfo->ver >= 11) {
      /* The MEDIA_VFE_STATE docs say:
       *
       *    "Starting with this configuration, the Maximum Number of
       *     Threads must be set to (#EU * 8) for GPGPU dispatches.
       *
       *     Although there are only 7 threads per EU in the configuration,
       *     the FFTID is calculated as if there are 8 threads per EU,
       *     which in turn requires a larger amount of Scratch Space to be
       *     allocated by the driver."
       */
      scratch_ids_per_subslice = 8 * 8;
   } else if (devinfo->platform == INTEL_PLATFORM_HSW) {
      /* WaCSScratchSize:hsw
       *
       * Haswell's scratch space address calculation appears to be sparse
       * rather than tightly packed. The Thread ID has bits indicating
       * which subslice, EU within a subslice, and thread within an EU it
       * is. There's a maximum of two slices and two subslices, so these
       * can be stored with a single bit. Even though there are only 10 EUs
       * per subslice, this is stored in 4 bits, so there's an effective
       * maximum value of 16 EUs. Similarly, although there are only 7
       * threads per EU, this is stored in a 3 bit number, giving an
       * effective maximum value of 8 threads per EU.
       *
       * This means that we need to use 16 * 8 instead of 10 * 7 for the
       * number of threads per subslice.
       */
      scratch_ids_per_subslice = 16 * 8;
   } else if (devinfo->platform == INTEL_PLATFORM_CHV) {
      /* Cherryview devices have either 6 or 8 EUs per subslice, and each
       * EU has 7 threads. The 6 EU devices appear to calculate thread IDs
       * as if it had 8 EUs.
       */
      scratch_ids_per_subslice = 8 * 7;
   } else {
      scratch_ids_per_subslice = devinfo->max_cs_threads;
   }

   unsigned max_thread_ids = scratch_ids_per_subslice * subslices;

   if (devinfo->verx10 >= 125) {
      /* On GFX version 12.5, scratch access changed to a surface-based model.
       * Instead of each shader type having its own layout based on IDs passed
       * from the relevant fixed-function unit, all scratch access is based on
       * thread IDs like it always has been for compute.
       */
      for (int i = MESA_SHADER_VERTEX; i < MESA_SHADER_STAGES; i++)
         devinfo->max_scratch_ids[i] = max_thread_ids;
   } else {
      unsigned max_scratch_ids[] = {
         [MESA_SHADER_VERTEX]    = devinfo->max_vs_threads,
         [MESA_SHADER_TESS_CTRL] = devinfo->max_tcs_threads,
         [MESA_SHADER_TESS_EVAL] = devinfo->max_tes_threads,
         [MESA_SHADER_GEOMETRY]  = devinfo->max_gs_threads,
         [MESA_SHADER_FRAGMENT]  = devinfo->max_wm_threads,
         [MESA_SHADER_COMPUTE]   = max_thread_ids,
      };
      STATIC_ASSERT(sizeof(devinfo->max_scratch_ids) == sizeof(max_scratch_ids));
      memcpy(devinfo->max_scratch_ids, max_scratch_ids,
             sizeof(devinfo->max_scratch_ids));
   }
}

static unsigned
intel_device_info_calc_engine_prefetch(const struct intel_device_info *devinfo,
                                       enum intel_engine_class engine_class)
{
   if (devinfo->verx10 >= 200) {
      switch (engine_class) {
      case INTEL_ENGINE_CLASS_RENDER:
         return 4096;
      case INTEL_ENGINE_CLASS_COMPUTE:
         return 1024;
      default:
         return 512;
      }
   }

   if (intel_device_info_is_mtl_or_arl(devinfo)) {
      switch (engine_class) {
      case INTEL_ENGINE_CLASS_RENDER:
         return 2048;
      case INTEL_ENGINE_CLASS_COMPUTE:
         return 1024;
      default:
         return 512;
      }
   }

   /* DG2 */
   if (devinfo->verx10 == 125)
      return 1024;

   /* Older than DG2/MTL */
   return 512;
}

static void
intel_device_info_update_after_hwconfig(struct intel_device_info *devinfo)
{
   /* After applying hwconfig values, some items need to be recalculated. */
   devinfo->max_cs_threads =
      devinfo->max_eus_per_subslice * devinfo->num_thread_per_eu;

   intel_device_info_update_cs_workgroup_threads(devinfo);

   /* On Skylake through Xe, the 3DSTATE_GS_BODY docs include a note:
    *
    *   "The driver must send pipe control with a cs stall after a
    *    3dstate_gs state change and the Dispatch Mode is simd8 and
    *    the number of handles allocated to gs is less than 16."
    *
    * We don't implement such a PIPE_CONTROL, so instead we set the minimum
    * number of GS URB entries to 16.  The Xe2+ docs don't have such a note,
    * but considering they use SIMD16 GS threads, retaining 16 as the minimum
    * likely makes sense there as well.
    *
    * Assuming we did implement that flush, the 3DSTATE_GS docs also note:
    *
    *   "At least 8 URB entries must be allocated in order to use SIMD8
    *    DispatchMode."
    *
    * The hardware config tables instead have the limit set as 2, which is
    * likely an older limit from the SIMD4x2 dual-object/instance era which
    * is no longer accurate.
    */
   devinfo->urb.min_entries[MESA_SHADER_GEOMETRY] =
      MAX2(16, devinfo->urb.min_entries[MESA_SHADER_GEOMETRY]);
}

bool
intel_get_device_info_from_fd(int fd, struct intel_device_info *devinfo, int min_ver, int max_ver)
{
   if (NULL != os_get_option("INTEL_STUB_GPU_JSON")) {
      /* This call will succeed when shim-drm has been initialized with a
       * serialized intel_device_info structure.
       */
      struct drm_intel_stub_devinfo arg = {
         .addr = (uintptr_t)devinfo,
         .size = sizeof(*devinfo),
      };
      if (0 == intel_ioctl(fd, DRM_IOCTL_INTEL_STUB_DEVINFO, &arg)) {
         intel_device_info_init_was(devinfo);
         intel_device_info_apply_workarounds(devinfo);
         return true;
      }
   }

   /* Get PCI info.
    *
    * Some callers may already have a valid drm device which holds values of
    * PCI fields queried here prior to calling this function. But making this
    * query optional leads to a more cumbersome implementation. These callers
    * still need to initialize the fields somewhere out of this function and
    * rely on an ioctl to get PCI device id for the next step when skipping
    * this drm query.
    */
   if (is_intel_virtio_fd(fd)) {
      if (!intel_virtio_get_pci_device_info(fd, devinfo))
         return false;

      if (!intel_device_info_init_common(devinfo->pci_device_id,
                                         false, devinfo))
         return false;

      devinfo->is_virtio = true;
   } else {
      drmDevicePtr drmdev = NULL;
      if (drmGetDevice2(fd, DRM_DEVICE_GET_PCI_REVISION, &drmdev)) {
         mesa_loge("Failed to query drm device.");
         return false;
      }
      if (!intel_device_info_init_common(drmdev->deviceinfo.pci->device_id,
                                         false, devinfo)) {
         drmFreeDevice(&drmdev);
         return false;
      }

      devinfo->pci_domain = drmdev->businfo.pci->domain;
      devinfo->pci_bus = drmdev->businfo.pci->bus;
      devinfo->pci_dev = drmdev->businfo.pci->dev;
      devinfo->pci_func = drmdev->businfo.pci->func;
      devinfo->pci_device_id = drmdev->deviceinfo.pci->device_id;
      devinfo->pci_revision_id = drmdev->deviceinfo.pci->revision_id;
      drmFreeDevice(&drmdev);
   }

   if ((min_ver > 0 && devinfo->ver < min_ver) || (max_ver > 0 && devinfo->ver > max_ver))
      return false;

   devinfo->no_hw = debug_get_bool_option("INTEL_NO_HW", false);

   devinfo->kmd_type = intel_get_kmd_type(fd);
   if (devinfo->kmd_type == INTEL_KMD_TYPE_INVALID) {
      mesa_loge("Unknown kernel mode driver");
      return false;
   }

   /* remaining initialization queries the kernel for device info */
   if (devinfo->no_hw) {
      /* Provide some sensible values for NO_HW. */
      devinfo->gtt_size =
         devinfo->ver >= 8 ? (1ull << 48) : 2ull * 1024 * 1024 * 1024;
      intel_device_info_compute_system_memory(devinfo, false);
      return true;
   }

   bool ret;
   switch (devinfo->kmd_type) {
   case INTEL_KMD_TYPE_I915:
      ret = intel_device_info_i915_get_info_from_fd(fd, devinfo);
      break;
   case INTEL_KMD_TYPE_XE:
      ret = intel_device_info_xe_get_info_from_fd(fd, devinfo);
      if (devinfo->verx10 < 200) {
         if (!debug_get_bool_option("INTEL_XE_IGNORE_EXPERIMENTAL_WARNING", false))
            mesa_logw("Support for this platform is experimental with Xe KMD, bug reports may be ignored.");
      }
      break;
   default:
      ret = false;
      UNREACHABLE("Missing");
   }
   if (!ret) {
      mesa_logw("Could not get intel_device_info.");
      return false;
   }

   /* region info is required for lmem support */
   if (devinfo->has_local_mem && !devinfo->mem.use_class_instance) {
      mesa_logw("Could not query local memory size.");
      return false;
   }

   if (intel_hwconfig_is_required(devinfo))
      intel_device_info_update_after_hwconfig(devinfo);
   intel_device_info_adjust_memory(devinfo);

   /* Gfx7 and older do not support EU/Subslice info */
   assert(devinfo->subslice_total >= 1 || devinfo->ver <= 7);
   devinfo->subslice_total = MAX2(devinfo->subslice_total, 1);

   init_max_scratch_ids(devinfo);

   for (enum intel_engine_class engine = INTEL_ENGINE_CLASS_RENDER;
        engine < ARRAY_SIZE(devinfo->engine_class_prefetch); engine++)
      devinfo->engine_class_prefetch[engine] =
            intel_device_info_calc_engine_prefetch(devinfo, engine);

   intel_device_info_init_was(devinfo);
   intel_device_info_apply_workarounds(devinfo);

   return true;
}

bool intel_device_info_update_memory_info(struct intel_device_info *devinfo, int fd)
{
   bool ret;

   switch (devinfo->kmd_type) {
   case INTEL_KMD_TYPE_I915:
      ret = intel_device_info_i915_query_regions(devinfo, fd, true);
      break;
   case INTEL_KMD_TYPE_XE:
      ret = intel_device_info_xe_query_regions(fd, devinfo, true);
      break;
   default:
      ret = false;
   }

   if (ret)
      intel_device_info_adjust_memory(devinfo);
   return ret;
}

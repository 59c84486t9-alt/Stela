/* SPDX-License-Identifier: MIT */
/* Original source in separate object, no LTO. Test-only scalar metadata and
 * write trace context; no Linux/device/IRQ provider or fake hardware ACK. */
#include "pat_donor.h"
#include "regs/xe_reg_defs.h"
#include <linux/build_bug.h>
#include <drm/intel/pick.h>
#include <assert.h>
#include <string.h>
#include <linux/array_size.h>
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wmissing-field-initializers"
#include "donor-pat-tables.inc"
#pragma clang diagnostic pop
struct test_ops { bool dump, program_graphics, program_media, entry_dump; uint32_t id; };
/* Only identity/capability shape, not a callable successful fake programmer.
 * Original source assignments are checked separately against retained ops. */
static const struct test_ops xelp_pat_ops={true,true,false,false,1},
 xehp_pat_ops={true,true,false,false,2},xehpc_pat_ops={true,true,false,false,3},
 xelpg_pat_ops={true,true,true,false,4},xe2_pat_ops={true,true,true,true,5},
 xe3p_xpc_pat_ops={true,true,true,true,6};
struct stela_pat_model {
 struct {enum xe_platform platform;bool has_llc;} info;
 struct { const struct test_ops *ops; const struct xe_pat_table_entry *table,
  *pat_ats,*pat_primary_pta,*pat_media_pta;int n_entries;u16 idx[__XE_CACHE_LEVEL_COUNT]; } pat;
 uint32_t graphics, media, drm;bool discrete,warning,missing;
};
static struct stela_pat_model *active;
#define xe_device stela_pat_model
#define GRAPHICS_VERx100(xe) ((xe)->graphics)
#define GRAPHICS_VER(xe) ((xe)->graphics/100)
#define MEDIA_VER(xe) ((xe)->media/100)
#define IS_DGFX(xe) ((xe)->discrete)
#define WARN_ON_ONCE(condition) (active->warning |= !!(condition))
#define drm_err(printer, ...) ((void)(printer), active->missing=true)
#define xe_assert(xe, condition) ((void)(xe),assert(condition))
#define xe_pat_init_early donor_init
#include "donor-pat-select.inc"
#undef xe_pat_init_early
#undef xe_device
/* Compile the actual retained Linux caller adaptation too, in this scalar
 * context. Its shared tables are byte-identical to the frozen tables above. */
#define XE_PAT_TABLES_H
#define xe_device stela_pat_model
#define xe_pat_init_early current_init
#include "current-pat-wrapper.inc"
#undef xe_pat_init_early
#undef xe_device
void stela_pat_donor_policy(enum xe_platform platform, uint32_t graphics, bool discrete,
                           bool llc, struct stela_pat_test_policy *out)
{
 struct stela_pat_model xe={.info={platform,llc},.graphics=graphics,
  .media=1200,.discrete=discrete};
 /* Existing ops are retained in original missing-policy path. No table or
  * programmer is claimed available there; n_entries remains zero. */
 xe.pat.ops=&xe2_pat_ops;
 struct stela_pat_model current=xe;
 active=&xe;donor_init(&xe);
 active=&current;current_init(&current);
 assert(xe.pat.ops==current.pat.ops && xe.pat.table==current.pat.table &&
  xe.pat.n_entries==current.pat.n_entries && xe.pat.pat_ats==current.pat.pat_ats &&
  xe.pat.pat_primary_pta==current.pat.pat_primary_pta &&
  xe.pat.pat_media_pta==current.pat.pat_media_pta &&
  !memcmp(xe.pat.idx,current.pat.idx,sizeof(xe.pat.idx)) &&
  xe.warning==current.warning && xe.missing==current.missing);
 *out=(struct stela_pat_test_policy){.profile=xe.pat.ops->id,
  .count=(uint32_t)xe.pat.n_entries,.warning=xe.warning,.missing=xe.missing};
 memcpy(out->indices,xe.pat.idx,sizeof(out->indices));
 if(xe.pat.n_entries)memcpy(out->entries,xe.pat.table,(size_t)xe.pat.n_entries*sizeof(*xe.pat.table));
 if(xe.pat.pat_ats){out->special|=1;out->ats=*xe.pat.pat_ats;}
 if(xe.pat.pat_primary_pta){out->special|=2;out->primary=*xe.pat.pat_primary_pta;}
 if(xe.pat.pat_media_pta){out->special|=4;out->media=*xe.pat.pat_media_pta;}
}
struct stela_pat_gt_model {
 struct stela_pat_model *device;
 struct stela_pat_trace *mmio;
 const struct xe_pat_table_entry *pta;
};
#define xe_gt stela_pat_gt_model
#define xe_device stela_pat_model
#define gt_to_xe(gt) ((gt)->device)
#define gt_pta_entry(gt) ((gt)->pta)
static void xe_mmio_write32(struct stela_pat_trace **trace,struct xe_reg reg,u32 value)
{
 struct stela_pat_trace *out=*trace;assert(out->count<34);
 out->offset[out->count]=reg.addr;out->value[out->count++]=value;
}
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wsign-conversion"
#include "donor-pat-program.inc"
#pragma clang diagnostic pop
void stela_pat_donor_program(const struct stela_pat_test_policy *policy, struct stela_pat_trace *out)
{
 *out=(struct stela_pat_trace){0};
 struct stela_pat_model xe={0};
 if(policy->special&1)xe.pat.pat_ats=&policy->ats;
 struct stela_pat_gt_model gt={&xe,out,policy->special&2?&policy->primary:NULL};
 program_pat(&gt,policy->entries,(int)policy->count);
}

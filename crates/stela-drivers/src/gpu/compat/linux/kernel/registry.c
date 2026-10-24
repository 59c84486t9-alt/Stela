// SPDX-License-Identifier: GPL-2.0-only
/* Static registry ownership is Stela code. The setup/early option adapters are
 * derived from Linux init/main.c, Copyright (C) 1991, 1992 Linus Torvalds
 * (Linux pin cc9de5d4), retaining the original
 * prefix, warning and consumed conventions. No driver initializer is copied.
 * One entered serialized Linux context; no native interrupt/module loader ABI. */
#include <linux/ctype.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/limits.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/tty.h>
#include <stela/linux.h>
#include <stela/params.h>
#include <stela/registry.h>
#include <stela/task.h>

#define PARSE_PASSES 10U /* early, initial, then levels 0..7 */
struct stela_linux_registry {
 const struct stela_linux_registry_image *image;
 struct stela_linux_registration_status *status;
 const struct kernel_param **parameters;
 size_t *completed;
 char *arguments;
 char *parse_results[PARSE_PASSES];
 unsigned int parsed_passes;
 size_t allocation_size, stride, record_count, completed_count;
 unsigned int option_phase, next_stage;
 bool busy, quarantined, parameter_error, retired;
 struct stela_linux_registry_report report;
};
static struct stela_linux_registry *active;
static const struct stela_linux_registry_image *owned_image;
static bool permanently_retired;
#ifdef STELA_LINUX_REGISTRY_TEST
static bool fail_registry_allocation;
static size_t registry_allocations, registry_releases;
#endif

struct call_guard {
 struct stela_linux_lease lease;
 const struct stela_linux_services *services;
 void *context;
};
struct parse_context {
 struct stela_linux_registry *registry;
 const struct call_guard *guard;
 const struct stela_linux_registry_unknown_options *policy;
 bool early, positive_callback;
};

static int guard_begin(struct call_guard *guard)
{
 stela_linux_lease_snapshot(&guard->lease);
 if (!guard->lease.owner || !stela_linux_quiescent())
  return -EPERM;
 guard->services = guard->lease.owner->services;
 guard->context = guard->lease.owner->context;
 return 0;
}
static int guard_check(struct stela_linux_registry *r, const struct call_guard *guard)
{
 if (!stela_linux_lease_matches(&guard->lease) ||
     guard->lease.owner->services != guard->services ||
     guard->lease.owner->context != guard->context || !stela_linux_quiescent()) {
  r->quarantined = true;
  r->report.terminal = 1;
  r->report.last_error = -EPROTO;
  return -EPROTO;
 }
 return 0;
}
static int enter_call(struct stela_linux_registry *r, struct call_guard *guard)
{
 if (!r || r != active || r->retired)
  return -EINVAL;
 if (r->quarantined)
  return -EPROTO;
 if (r->busy)
  return -EBUSY;
 int error = guard_begin(guard);
 if (!error)
  r->busy = true;
 return error;
}
static int leave_call(struct stela_linux_registry *r, const struct call_guard *guard,
 int error, struct stela_linux_registry_report *out)
{
 int fault = guard_check(r, guard);
 if (!fault)
  r->busy = false;
 r->report.next_stage = r->next_stage;
 if (out)
  *out = r->report;
 return fault ?: error;
}
static bool add_size(size_t *value, size_t count, size_t item)
{
 if (count > (SIZE_MAX - *value) / item)
  return false;
 *value += count * item;
 return true;
}
static bool aligned_size(size_t *value, size_t align)
{
 if (*value > SIZE_MAX - (align - 1))
  return false;
 *value = (*value + align - 1) & ~(align - 1);
 return true;
}
static size_t status_offset(const struct stela_linux_registry_image *im, unsigned kind)
{
 size_t n = 0;
 if (kind == STELA_LINUX_REG_INIT || kind == STELA_LINUX_REG_MODULE_INIT ||
     kind == STELA_LINUX_REG_CONSOLE)
  return n;
 n += im->init_count;
 if (kind == STELA_LINUX_REG_EXIT || kind == STELA_LINUX_REG_MODULE_EXIT)
  return n;
 n += im->exit_count;
 if (kind == STELA_LINUX_REG_PARAMETER)
  return n;
 n += im->parameter_count;
 if (kind == STELA_LINUX_REG_INFO)
  return n;
 n += im->info_count;
 if (kind == STELA_LINUX_REG_DEVICE)
  return n;
 return n + im->device_count;
}
static const struct stela_linux_registration_header *record_header(
 const struct stela_linux_registry_image *im, size_t index)
{
 if (index < im->init_count) return &im->inits[index]->header;
 index -= im->init_count;
 if (index < im->exit_count) return &im->exits[index]->header;
 index -= im->exit_count;
 if (index < im->parameter_count) return &im->parameters[index]->header;
 index -= im->parameter_count;
 if (index < im->info_count) return &im->infos[index]->header;
 index -= im->info_count;
 if (index < im->device_count) return &im->devices[index]->header;
 index -= im->device_count;
 return &im->setups[index]->header;
}
static bool group_member(const struct stela_linux_registry_image *im,
 const struct stela_linux_build_group *group)
{
 for (size_t i = 0; i < im->group_count; ++i)
  if (im->groups[i] == group) return true;
 return false;
}
static size_t unit_index(const struct stela_linux_registry_image *im,
 const struct stela_linux_build_unit *unit)
{
 for (size_t i = 0; i < im->unit_count; ++i)
  if (im->units[i] == unit) return i;
 return im->unit_count;
}
static int header_shape(const struct stela_linux_registry_image *im,
 const struct stela_linux_registration_header *h,
 const struct stela_linux_build_group *group,
 const struct stela_linux_build_unit *unit, const char *label)
{
 if (!h || h->abi_version != STELA_LINUX_REGISTRY_ABI || !label ||
     !group_member(im, group) || unit_index(im, unit) == im->unit_count ||
     unit->group != group || h->unit_ordinal != unit->ordinal)
  return -EINVAL;
 if (h->flags & ~STELA_LINUX_REG_SYNC)
  return -EOPNOTSUPP;
 return 0;
}
/* No callback/allocation precedes complete static shape/relationship checking.
 * Pointer readability, full strings, source provenance and pinned lifetime are
 * producer obligations; C cannot validate arbitrary foreign addresses. */
static int image_shape(const struct stela_linux_registry_image *im, size_t *total)
{
 if (!im || im->abi_version != STELA_LINUX_REGISTRY_ABI || im->reserved ||
     (im->init_count && !im->inits) || (im->exit_count && !im->exits) ||
     (im->parameter_count && !im->parameters) || (im->info_count && !im->infos) ||
     (im->device_count && !im->devices) || (im->setup_count && !im->setups) ||
     (im->group_count && !im->groups) || (im->unit_count && !im->units) ||
     im->parameter_count > UINT_MAX)
  return -EINVAL;
 size_t n = 0;
 const size_t counts[] = {im->init_count, im->exit_count, im->parameter_count,
  im->info_count, im->device_count, im->setup_count};
 for (size_t i = 0; i < ARRAY_SIZE(counts); ++i)
  if (!add_size(&n, counts[i], 1)) return -EOVERFLOW;
 if (n > SIZE_MAX / sizeof(struct stela_linux_registration_status) ||
     im->group_count > SIZE_MAX / sizeof(void *) || im->unit_count > SIZE_MAX / sizeof(void *))
  return -EOVERFLOW;
 for (size_t i = 0; i < im->group_count; ++i) {
  const struct stela_linux_build_group *g = im->groups[i];
  if (!g || g->abi_version != STELA_LINUX_REGISTRY_ABI || g->reserved ||
      !g->module_name || !*g->module_name || !g->module_file || !*g->module_file ||
      !g->provenance || !*g->provenance)
   return -EINVAL;
  for (size_t j = 0; j < i; ++j)
   if (im->groups[j] == g || (im->groups[j]->domain_ordinal == g->domain_ordinal &&
       im->groups[j]->group_ordinal == g->group_ordinal)) return -EINVAL;
 }
 for (size_t i = 0; i < im->unit_count; ++i) {
  const struct stela_linux_build_unit *u = im->units[i];
  if (!u || u->abi_version != STELA_LINUX_REGISTRY_ABI || !group_member(im, u->group) ||
      !u->source_path || !*u->source_path || !u->provenance || !*u->provenance)
   return -EINVAL;
  for (size_t j = 0; j < i; ++j)
   if (im->units[j] == u || im->units[j]->ordinal == u->ordinal) return -EINVAL;
 }
#define CHECK_RECORD(rec) do { \
 if (!(rec)) return -EINVAL; \
 int shape = header_shape(im, &(rec)->header, (rec)->group, (rec)->unit, (rec)->label); \
 if (shape) return shape; \
} while (0)
 for (size_t i = 0; i < im->init_count; ++i) {
  const struct stela_linux_init_record *v = im->inits[i]; CHECK_RECORD(v);
  const struct stela_linux_registration_header *h = &v->header;
  if (!v->target) return -EINVAL;
  if (h->kind == STELA_LINUX_REG_MODULE_INIT) {
   if (h->level != 6 || h->flags) return -EINVAL;
   for (size_t j = 0; j < i; ++j)
    if (im->inits[j]->header.kind == STELA_LINUX_REG_MODULE_INIT &&
        im->inits[j]->group == v->group) return -EINVAL;
  } else if (h->kind == STELA_LINUX_REG_CONSOLE) {
   if (h->level != STELA_LINUX_REG_CONSOLE_LEVEL || h->flags) return -EINVAL;
  } else if (h->kind == STELA_LINUX_REG_INIT) {
   if (!((h->level >= 0 && h->level <= 7) || h->level == STELA_LINUX_REG_EARLY_LEVEL ||
         h->level == STELA_LINUX_REG_ROOTFS_LEVEL) || (h->level < 1 && h->flags)) return -EINVAL;
  } else return -EINVAL;
 }
 for (size_t i = 0; i < im->exit_count; ++i) {
  const struct stela_linux_exit_record *v = im->exits[i]; CHECK_RECORD(v);
  if (!v->target || v->header.level != -1 || v->header.flags ||
      (v->header.kind != STELA_LINUX_REG_EXIT && v->header.kind != STELA_LINUX_REG_MODULE_EXIT))
   return -EINVAL;
  if (v->header.kind == STELA_LINUX_REG_MODULE_EXIT)
   for (size_t j = 0; j < i; ++j)
    if (im->exits[j]->header.kind == STELA_LINUX_REG_MODULE_EXIT &&
        im->exits[j]->group == v->group) return -EINVAL;
 }
 for (size_t i = 0; i < im->parameter_count; ++i) {
  const struct stela_linux_parameter_record *v = im->parameters[i]; CHECK_RECORD(v);
  const struct kernel_param *p = v->target;
  if (!p || !p->name || !p->ops || v->header.kind != STELA_LINUX_REG_PARAMETER ||
      v->header.flags || p->level < -1 || p->level > 7 || v->header.level != p->level)
   return -EINVAL;
  if (p->flags & ~(KERNEL_PARAM_FL_UNSAFE | KERNEL_PARAM_FL_HWPARAM) ||
      p->ops->flags & ~KERNEL_PARAM_OPS_FL_NOARG) return -EOPNOTSUPP;
  for (size_t j = 0; j < i; ++j)
   if (im->parameters[j]->target == p) return -EINVAL;
 }
 for (size_t i = 0; i < im->setup_count; ++i) {
  const struct stela_linux_setup_record *v = im->setups[i]; CHECK_RECORD(v);
  if (v->header.level != -1 || v->header.flags ||
      (v->header.kind != STELA_LINUX_REG_SETUP && v->header.kind != STELA_LINUX_REG_EARLY) ||
      (v->header.kind == STELA_LINUX_REG_EARLY && !v->target)) return -EINVAL;
 }
#undef CHECK_RECORD
 for (size_t i = 0; i < im->info_count; ++i) {
  const struct stela_linux_info_record *v = im->infos[i];
  if (!v) return -EINVAL;
  int error = header_shape(im, &v->header, v->group, v->unit, v->tag);
  if (error) return error;
  if (!v->text || v->header.kind != STELA_LINUX_REG_INFO || v->header.level != -1 ||
      v->header.flags) return -EINVAL;
 }
 for (size_t i = 0; i < im->device_count; ++i) {
  const struct stela_linux_device_record *v = im->devices[i];
  if (!v) return -EINVAL;
  int error = header_shape(im, &v->header, v->group, v->unit, v->type);
  if (error) return error;
  if (!v->table || !v->size || v->header.kind != STELA_LINUX_REG_DEVICE ||
      v->header.level != -1 || v->header.flags) return -EINVAL;
 }
 /* Global sequence uniqueness; each typed array retains source/link order. */
 for (size_t i = 0; i < n; ++i) {
  const struct stela_linux_registration_header *h = record_header(im, i);
  for (size_t j = 0; j < i; ++j) {
   const struct stela_linux_registration_header *p = record_header(im, j);
   if (p->unit_ordinal == h->unit_ordinal && p->emission_sequence == h->emission_sequence)
    return -EINVAL;
  }
 }
 size_t off = 0;
 for (size_t a = 0; a < ARRAY_SIZE(counts); ++a) {
  for (size_t j = 1; j < counts[a]; ++j) {
   const struct stela_linux_registration_header *prev = record_header(im, off + j - 1);
   const struct stela_linux_registration_header *cur = record_header(im, off + j);
   size_t pi = im->unit_count, ci = im->unit_count;
   for (size_t k = 0; k < im->unit_count; ++k) {
    if (im->units[k]->ordinal == prev->unit_ordinal) pi = k;
    if (im->units[k]->ordinal == cur->unit_ordinal) ci = k;
   }
   if (pi > ci || (pi == ci && prev->emission_sequence >= cur->emission_sequence))
    return -EINVAL;
  }
  off += counts[a];
 }
 *total = n;
 return 0;
}
int stela_linux_registry_begin(const struct stela_linux_registry_image *im,
 const char *bytes, size_t length, struct stela_linux_registry **out)
{
 if (!out) return -EINVAL;
 *out = NULL;
 struct call_guard guard;
 int error = guard_begin(&guard);
 if (error) return error;
 if (active || owned_image || permanently_retired) return -EBUSY;
 if ((!bytes && length) || length == SIZE_MAX) return -EINVAL;
 /* Original next_arg indexes one token with unsigned int. Preserve that
  * admitted domain; do not wrap its genuine loop for a >4GiB token. */
 if (length > UINT_MAX) return -E2BIG;
 if (length && memchr(bytes, 0, length)) return -EINVAL;
 size_t records;
 error = image_shape(im, &records);
 if (error) return error;
 /* Every diagnostic/status counter is exact; reject an unrepresentable worst
  * case before callbacks instead of wrapping a progress ledger. */
 size_t bound = 0;
 if (im->setup_count == SIZE_MAX ||
     !add_size(&bound, length + 1, im->setup_count + 1) ||
     bound > (SIZE_MAX - im->init_count - im->exit_count) / PARSE_PASSES)
  return -EOVERFLOW;
 size_t size = sizeof(struct stela_linux_registry), status_at, view_at, order_at, args_at;
 if (!aligned_size(&size, __alignof__(struct stela_linux_registration_status))) return -EOVERFLOW;
 status_at = size;
 if (!add_size(&size, records, sizeof(struct stela_linux_registration_status)) ||
     !aligned_size(&size, __alignof__(const struct kernel_param *))) return -EOVERFLOW;
 view_at = size;
 if (!add_size(&size, im->parameter_count, sizeof(const struct kernel_param *)) ||
     !aligned_size(&size, __alignof__(size_t))) return -EOVERFLOW;
 order_at = size;
 if (!add_size(&size, im->init_count, sizeof(size_t))) return -EOVERFLOW;
 args_at = size;
 if (!add_size(&size, PARSE_PASSES, length + 1)) return -EOVERFLOW;
 struct stela_linux_registry *r;
#ifdef STELA_LINUX_REGISTRY_TEST
 r = fail_registry_allocation ? NULL : stela_linux_heap_alloc(size, __alignof__(*r));
 if (r) registry_allocations++;
#else
 r = stela_linux_heap_alloc(size, __alignof__(*r));
#endif
 if (!r) return -ENOMEM;
 memset(r, 0, size);
 r->image = im;
 r->status = (void *)((char *)r + status_at);
 r->parameters = (void *)((char *)r + view_at);
 r->completed = (void *)((char *)r + order_at);
 r->arguments = (char *)r + args_at;
 r->allocation_size = size;
 r->stride = length + 1;
 r->record_count = records;
 for (size_t i = 0; i < PARSE_PASSES; ++i) {
  if (length) memcpy(r->arguments + i * r->stride, bytes, length);
  r->arguments[i * r->stride + length] = 0;
 }
 for (size_t i = 0; i < im->parameter_count; ++i) r->parameters[i] = im->parameters[i]->target;
 for (size_t i = 0; i < records; ++i) {
  const struct stela_linux_registration_header *h = record_header(im, i);
  r->status[i].kind = h->kind;
  r->status[i].unit_ordinal = h->unit_ordinal;
  r->status[i].emission_sequence = h->emission_sequence;
  r->status[i].level = h->level;
 }
 /* Heap service is canonical and cannot transfer Linux execution ownership. */
 if (guard_check(r, &guard)) {
  active = r; owned_image = im; /* quarantine: never free via changed context */
  return -EPROTO;
 }
 active = r;
 owned_image = im;
 *out = r;
 return 0;
}
static void started(struct stela_linux_registry *r, size_t index)
{
 r->status[index].state = STELA_LINUX_RECORD_RUNNING;
 r->status[index].invocations++;
 r->report.invocations++;
}
static void returned(struct stela_linux_registry *r, size_t index, int result)
{
 struct stela_linux_registration_status *s = &r->status[index];
 s->returned = result;
 s->state = result < 0 ? STELA_LINUX_RECORD_NEGATIVE :
            result > 0 ? STELA_LINUX_RECORD_POSITIVE : STELA_LINUX_RECORD_ZERO;
 if (result < 0) r->report.returned_negative++;
 else if (result > 0) r->report.returned_positive++;
 else r->report.returned_zero++;
}
static int observe(void *argument, enum stela_linux_param_event event,
 const struct kernel_param *parameter, char *param, char *val, int result)
{
 struct parse_context *c = argument;
 struct stela_linux_registry *r = c->registry;
 (void)param; (void)val;
 int error = guard_check(r, c->guard);
 if (error) return error;
 if ((event == STELA_LINUX_PARAM_AFTER_SET || event == STELA_LINUX_PARAM_AFTER_UNKNOWN) && result > 0)
  c->positive_callback = true;
 if (!parameter) return 0;
 for (size_t i = 0; i < r->image->parameter_count; ++i)
  if (r->parameters[i] == parameter) {
   size_t index = status_offset(r->image, STELA_LINUX_REG_PARAMETER) + i;
   if (event == STELA_LINUX_PARAM_BEFORE_SET) started(r, index);
   else if (event == STELA_LINUX_PARAM_AFTER_SET) returned(r, index, result);
   return 0;
  }
 return -EPROTO;
}
/* Original init/main.c repair_env_string, with an explicit terminal boundary
 * for its impossible tokenizer-shape BUG. */
static void repair_env_string(char *param, char *val)
{
 if (val) {
  if (val == param + strlen(param) + 1) val[-1] = '=';
  else if (val == param + strlen(param) + 2) {
   val[-2] = '=';
   memmove(val - 1, val, strlen(val) + 1);
  } else __builtin_trap();
 }
}
static int option_unknown(char *param, char *val, const char *doing, void *argument)
{
 struct parse_context *c = argument;
 struct stela_linux_registry *r = c->registry;
 const struct stela_linux_registry_image *im = r->image;
 (void)doing;
 bool had_early = false;
 if (!c->early) repair_env_string(param, val);
 for (size_t i = 0; i < im->setup_count; ++i) {
  const struct stela_linux_setup_record *s = im->setups[i];
  bool is_early = s->header.kind == STELA_LINUX_REG_EARLY;
  size_t n = strlen(s->label);
  if (c->early ? (!is_early || !parameq(param, s->label)) : !parameqn(param, s->label, n))
   continue;
  if (!c->early && is_early) {
   if (!param[n] || param[n] == '=') had_early = true;
   continue;
  }
  size_t index = status_offset(im, STELA_LINUX_REG_SETUP) + i;
  if (guard_check(r, c->guard)) return -EPROTO;
  if (!s->target) {
   pr_warn("Parameter %s is obsolete, ignored\n", s->label);
   r->status[index].warnings++; r->report.warnings++;
   r->status[index].consumed++; r->report.consumed++;
   return guard_check(r, c->guard) ?: 0;
  }
  started(r, index);
  int ret = s->target(c->early ? val : param + n);
  returned(r, index, ret);
  if (guard_check(r, c->guard)) return -EPROTO;
  if (c->early) {
   if (ret) {
    pr_warn("Malformed early option '%s'\n", param);
    r->status[index].warnings++; r->report.warnings++;
    if (guard_check(r, c->guard)) return -EPROTO;
   }
  } else if (ret) {
   r->status[index].consumed++; r->report.consumed++;
   return 0;
  }
 }
 if (c->early || had_early) {
  if (had_early) r->report.consumed++;
  return 0;
 }
 r->report.unhandled++;
 if (!c->policy || !c->policy->unhandled_option) return -ENOENT;
 int ret = c->policy->unhandled_option(c->policy->context, param);
 return guard_check(r, c->guard) ?: ret;
}
static int ignore_unknown(char *param, char *val, const char *doing, void *argument)
{
 (void)param; (void)val; (void)doing; (void)argument;
 return 0;
}
static int parse_pass(struct stela_linux_registry *r, const struct call_guard *guard,
 unsigned int pass, int level, bool early,
 const struct stela_linux_registry_unknown_options *policy)
{
 struct parse_context c = {.registry = r, .guard = guard, .policy = policy, .early = early};
 const struct stela_linux_param_observer observer = {.observe = observe, .context = &c};
 bool initial = pass < 2;
 struct stela_linux_params_result parsed = stela_linux_parse_args_view(
  early ? "early options" : initial ? "Booting kernel" : "initcall",
  r->arguments + pass * r->stride, early ? NULL : r->parameters,
  early ? 0 : (unsigned int)r->image->parameter_count, (s16)level, (s16)level,
  &c, initial ? option_unknown : ignore_unknown, &observer);
 r->parse_results[pass] = parsed.result;
 r->parsed_passes |= 1U << pass;
 if (parsed.observer_error) {
  r->quarantined = true; r->report.terminal = 1;
  r->report.last_error = parsed.observer_error;
  return parsed.observer_error;
 }
 if (guard_check(r, guard)) return -EPROTO;
 int error = IS_ERR(parsed.result) ? (int)PTR_ERR(parsed.result) : 0;
 if (!error && parsed.result) {
  unsigned long value = (unsigned long)parsed.result;
  unsigned long start = (unsigned long)(r->arguments + pass * r->stride);
  /* Original parse_args encodes a positive callback result as ERR_PTR(ret),
   * which IS_ERR cannot recognize. Preserve those exact source bytes/result,
   * but never grant startup on that invalid callback contract or treat a low
   * integer as a -- tail (even if its address aliases a low native heap). */
  if (c.positive_callback || value < start || value - start >= r->stride) error = -EPROTO;
 }
 if (error) { r->parameter_error = true; r->report.last_error = error; }
 /* Every pass keeps its writable bytes and original -- tail alive. No Linux
  * init argv/env policy or ownership of arbitrary tail consumers is invented. */
 return error;
}
int stela_linux_registry_early_parameters(struct stela_linux_registry *r,
 struct stela_linux_registry_report *out)
{
 struct call_guard guard;
 int error = enter_call(r, &guard);
 if (error) return error;
 if (r->option_phase || r->parameter_error) error = -EALREADY;
 else { r->option_phase = 1; error = parse_pass(r, &guard, 0, 0, true, NULL); }
 return leave_call(r, &guard, error, out);
}
int stela_linux_registry_initial_parameters(struct stela_linux_registry *r,
 const struct stela_linux_registry_unknown_options *policy,
 struct stela_linux_registry_report *out)
{
 struct call_guard guard;
 int error = enter_call(r, &guard);
 if (error) return error;
 if (r->option_phase != 1 || r->parameter_error) error = -EALREADY;
 else { r->option_phase = 2; error = parse_pass(r, &guard, 1, -1, false, policy); }
 return leave_call(r, &guard, error, out);
}
static bool stage_record(const struct stela_linux_init_record *v, unsigned int stage, unsigned sync)
{
 if (stage == STELA_LINUX_STAGE_CONSOLE) return v->header.kind == STELA_LINUX_REG_CONSOLE;
 if (stage == STELA_LINUX_STAGE_EARLY)
  return v->header.kind == STELA_LINUX_REG_INIT && v->header.level == STELA_LINUX_REG_EARLY_LEVEL;
 int level = (int)stage - STELA_LINUX_STAGE_PURE;
 if (sync == 2) return level == 5 && v->header.level == STELA_LINUX_REG_ROOTFS_LEVEL;
 return v->header.kind != STELA_LINUX_REG_CONSOLE && v->header.level == level &&
        (unsigned int)!!(v->header.flags & STELA_LINUX_REG_SYNC) == sync;
}
int stela_linux_registry_run_stage(struct stela_linux_registry *r, unsigned int stage,
 struct stela_linux_registry_report *out)
{
 struct call_guard guard;
 int error = enter_call(r, &guard);
 if (error) return error;
 if (r->option_phase != 2 || r->parameter_error || stage != r->next_stage ||
     stage >= STELA_LINUX_STAGE_DONE)
  return leave_call(r, &guard, -EINVAL, out);
 if (stage >= STELA_LINUX_STAGE_PURE) {
  unsigned level = stage - STELA_LINUX_STAGE_PURE;
  error = parse_pass(r, &guard, level + 2, (int)level, false, NULL);
  if (error) return leave_call(r, &guard, error, out);
 }
 if (stage == STELA_LINUX_STAGE_CONSOLE) {
#ifdef CONFIG_NULL_TTY_DEFAULT_CONSOLE
  /* Genuine preferred-console state/provider must be supplied before enabling
   * this configuration. No invented default-console policy. */
  return leave_call(r, &guard, -EOPNOTSUPP, out);
#else
  n_tty_init();
  if (guard_check(r, &guard)) return leave_call(r, &guard, -EPROTO, out);
#endif
 }
 int first_error = 0;
 unsigned passes = stage == STELA_LINUX_STAGE_FS ? 3 : stage >= STELA_LINUX_STAGE_PURE ? 2 : 1;
 for (unsigned sync = 0; sync < passes; ++sync)
  for (size_t i = 0; i < r->image->init_count; ++i) {
   const struct stela_linux_init_record *v = r->image->inits[i];
   if (!stage_record(v, stage, sync)) continue;
   started(r, i);
   int ret = v->target();
   returned(r, i, ret);
   if (guard_check(r, &guard)) return leave_call(r, &guard, -EPROTO, out);
   if (v->header.kind == STELA_LINUX_REG_MODULE_INIT && !ret)
    r->completed[r->completed_count++] = i;
   if (ret < 0) { if (!first_error) first_error = ret; r->report.last_error = ret; }
   else if (ret > 0 && v->header.kind != STELA_LINUX_REG_CONSOLE) {
    pr_warn("initcall %s returned with positive result %d\n", v->label, ret);
    r->status[i].warnings++; r->report.warnings++;
    if (guard_check(r, &guard)) return leave_call(r, &guard, -EPROTO, out);
   }
  }
 r->next_stage++;
 return leave_call(r, &guard, first_error, out);
}
int stela_linux_registry_status(const struct stela_linux_registry *r, size_t index,
 struct stela_linux_registration_status *out)
{
 struct call_guard guard;
 if (!r || r != active || !out || index >= r->record_count) return -EINVAL;
 int error = guard_begin(&guard);
 if (error) return error;
 *out = r->status[index];
 return 0;
}
int stela_linux_registry_parse_result(const struct stela_linux_registry *r, unsigned int pass,
 char **out)
{
 struct call_guard guard;
 if (!r || r != active || !out || pass >= PARSE_PASSES || !(r->parsed_passes & (1U << pass)))
  return -EINVAL;
 int error = guard_begin(&guard);
 if (error) return error;
 *out = r->parse_results[pass];
 return 0;
}
static const struct stela_linux_exit_record *paired_exit(
 const struct stela_linux_registry_image *im, const struct stela_linux_build_group *group,
 size_t *index)
{
 for (size_t i = 0; i < im->exit_count; ++i)
  if (im->exits[i]->header.kind == STELA_LINUX_REG_MODULE_EXIT && im->exits[i]->group == group) {
   *index = i;
   return im->exits[i];
  }
 return NULL;
}
int stela_linux_registry_retire(struct stela_linux_registry **handle,
 const struct stela_linux_registry_retirement *authority)
{
 if (!handle) return -EINVAL;
 struct stela_linux_registry *r = *handle;
 struct call_guard guard;
 int error = enter_call(r, &guard);
 if (error) return error;
 const struct stela_linux_registry_image *im = r->image;
 if (!authority || !authority->drain_all_consumers || authority->image != im ||
     authority->group_count != im->group_count || (im->group_count && !authority->groups))
  return leave_call(r, &guard, -EOPNOTSUPP, NULL);
 for (size_t i = 0; i < im->group_count; ++i)
  if (authority->groups[i] != im->groups[i])
   return leave_call(r, &guard, -EOPNOTSUPP, NULL);
 /* There is no invented inverse for arbitrary builtin/console initcalls. Any
  * invoked one is conservatively permanent, including a failed one with
  * unknown residual effects. Do not free values it may still reference. */
 for (size_t i = 0; i < im->init_count; ++i) {
  const struct stela_linux_init_record *v = im->inits[i];
  if (r->status[i].invocations && v->header.kind != STELA_LINUX_REG_MODULE_INIT)
   return leave_call(r, &guard, -EOPNOTSUPP, NULL);
 }
 for (size_t i = 0; i < r->completed_count; ++i) {
  size_t ignored;
  if (!paired_exit(im, im->inits[r->completed[i]]->group, &ignored))
   return leave_call(r, &guard, -EOPNOTSUPP, NULL);
 }
 error = authority->drain_all_consumers(authority->context);
 if (guard_check(r, &guard)) return leave_call(r, &guard, -EPROTO, NULL);
 if (error) return leave_call(r, &guard, error < 0 ? error : -EPROTO, NULL);
 /* Once actual draining has committed, context faults quarantine the remaining
  * state. No repeat drain/exit/free is then possible through this handle. */
 for (size_t n = r->completed_count; n; --n) {
  size_t i;
  const struct stela_linux_exit_record *v = paired_exit(im, im->inits[r->completed[n-1]]->group, &i);
  size_t index = status_offset(im, STELA_LINUX_REG_EXIT) + i;
  started(r, index);
  v->target();
  returned(r, index, 0);
  if (guard_check(r, &guard)) return leave_call(r, &guard, -EPROTO, NULL);
 }
 stela_linux_rcu_finish();
 if (guard_check(r, &guard)) return leave_call(r, &guard, -EPROTO, NULL);
 for (size_t i = 0; i < im->parameter_count; ++i) {
  const struct kernel_param *p = im->parameters[i]->target;
  if (p->ops->free) {
   p->ops->free(p->arg);
   if (guard_check(r, &guard)) return leave_call(r, &guard, -EPROTO, NULL);
  }
 }
 stela_linux_rcu_finish();
 if (guard_check(r, &guard)) return leave_call(r, &guard, -EPROTO, NULL);
 size_t size = r->allocation_size;
 r->retired = true;
 permanently_retired = true;
 active = NULL;
 *handle = NULL;
 stela_linux_heap_free(r, size, __alignof__(*r));
#ifdef STELA_LINUX_REGISTRY_TEST
 registry_releases++;
#endif
 return 0;
}

#ifdef STELA_LINUX_REGISTRY_TEST
#include <linux/irqflags.h>
#include <linux/preempt.h>
#include <stela/test.h>
/* Each finite scenario runs in its own process. This never resets production
 * singleton/retirement state or turns a returned callback into a fake driver. */
int stela_test_registry_case(void (*run)(void));
static unsigned events[128], event_count, drains, frees, live_i2c;
static bool consumers_stopped;
static const char *retained_value;
static struct stela_linux_registry *test_registry;
static struct stela_linux_owner *mutable_owner;
static void event(unsigned id) { assert(event_count < ARRAY_SIZE(events)); events[event_count++] = id; }
#define INIT_FN(n, result) static int init_##n(void) { event(n); return result; }
INIT_FN(1, 0) INIT_FN(2, -ENODEV) INIT_FN(3, 0)
INIT_FN(10, 0) INIT_FN(11, 0) INIT_FN(12, 0) INIT_FN(13, 0)
INIT_FN(14, 0) INIT_FN(15, 0) INIT_FN(16, 0) INIT_FN(17, 0)
INIT_FN(18, 0) INIT_FN(19, 0) INIT_FN(20, 0) INIT_FN(21, 0)
INIT_FN(22, 0) INIT_FN(23, 0) INIT_FN(24, 0)
INIT_FN(26, 3) INIT_FN(27, -EINVAL) INIT_FN(28, 0)
#undef INIT_FN
static void exit_1(void) { assert(consumers_stopped && !live_i2c); event(101); }
static void exit_2(void) { event(102); assert(0); }
static void exit_3(void) { assert(consumers_stopped && !live_i2c); event(103); }
static int drain_consumers(void *context)
{
 assert(context == &live_i2c);
 drains++;
 if (live_i2c) return -EBUSY;
 consumers_stopped = true;
 return 0;
}
static int set_retained(const char *v, const struct kernel_param *p)
{
 assert(p->arg == &retained_value);
 retained_value = v;
 event(50);
 return 0;
}
static void free_retained(void *arg)
{
 assert(arg == &retained_value && consumers_stopped);
 assert(event_count >= 2 && events[event_count-1] == 101 && events[event_count-2] == 103);
 assert(!strcmp(retained_value, "kept after owner exit"));
 frees++; event(150);
}
static const struct kernel_param_ops retained_ops = {.set = set_retained, .free = free_retained};
struct registry_fixture {
 struct stela_linux_build_group group[3];
 const struct stela_linux_build_group *groups[3];
 struct stela_linux_build_unit unit[3];
 const struct stela_linux_build_unit *units[3];
 struct stela_linux_init_record init[24];
 const struct stela_linux_init_record *inits[24];
 struct stela_linux_exit_record exit[3];
 const struct stela_linux_exit_record *exits[3];
 struct stela_linux_parameter_record parameter[3];
 const struct stela_linux_parameter_record *parameters[3];
 struct stela_linux_setup_record setup[10];
 const struct stela_linux_setup_record *setups[10];
 struct stela_linux_registry_image image;
 u32 sequence[3];
};
static void fixture_init(struct registry_fixture *f)
{
 memset(f, 0, sizeof(*f));
 for (unsigned i = 0; i < 3; ++i) {
  f->group[i] = (struct stela_linux_build_group){.abi_version = 1, .domain_ordinal = 7,
   .group_ordinal = i + 1, .module_name = "same-name", .module_file = "fixture/real-group",
   .provenance = "explicit test-only compiled cohort"};
  f->unit[i] = (struct stela_linux_build_unit){.abi_version = 1, .ordinal = i + 1,
   .group = &f->group[i], .source_path = "fixture/unit.c", .provenance = "reviewed link position"};
  f->groups[i] = &f->group[i]; f->units[i] = &f->unit[i];
 }
 f->image = (struct stela_linux_registry_image){.abi_version = 1,
  .inits = f->inits, .exits = f->exits, .parameters = f->parameters, .setups = f->setups,
  .groups = f->groups, .group_count = 3, .units = f->units, .unit_count = 3};
}
static struct stela_linux_registration_header fixture_header(struct registry_fixture *f,
 unsigned u, unsigned kind, int level, unsigned flags)
{
 return (struct stela_linux_registration_header){.abi_version = 1, .kind = (u16)kind,
  .level = (s8)level, .flags = (u8)flags, .unit_ordinal = u + 1, .emission_sequence = f->sequence[u]++};
}
static void fixture_call(struct registry_fixture *f, unsigned u, unsigned kind, int level,
 unsigned flags, initcall_t fn)
{
 size_t i = f->image.init_count++;
 f->init[i] = (struct stela_linux_init_record){.header = fixture_header(f,u,kind,level,flags),
  .group = &f->group[u], .unit = &f->unit[u], .label = "original-static-init", .target = fn};
 f->inits[i] = &f->init[i];
}
static void fixture_exit(struct registry_fixture *f, unsigned u, exitcall_t fn)
{
 size_t i = f->image.exit_count++;
 f->exit[i] = (struct stela_linux_exit_record){.header = fixture_header(f,u,STELA_LINUX_REG_MODULE_EXIT,-1,0),
  .group = &f->group[u], .unit = &f->unit[u], .label = "original-static-exit", .target = fn};
 f->exits[i] = &f->exit[i];
}
static void fixture_parameter(struct registry_fixture *f, unsigned u, const struct kernel_param *p)
{
 size_t i = f->image.parameter_count++;
 f->parameter[i] = (struct stela_linux_parameter_record){
  .header = fixture_header(f,u,STELA_LINUX_REG_PARAMETER,p->level,0),
  .group = &f->group[u], .unit = &f->unit[u], .label = p->name, .target = p};
 f->parameters[i] = &f->parameter[i];
}
static void fixture_setup(struct registry_fixture *f, unsigned u, bool early,
 const char *name, int (*fn)(char *))
{
 size_t i = f->image.setup_count++;
 f->setup[i] = (struct stela_linux_setup_record){
  .header = fixture_header(f,u,early ? STELA_LINUX_REG_EARLY : STELA_LINUX_REG_SETUP,-1,0),
  .group = &f->group[u], .unit = &f->unit[u], .label = name, .target = fn};
 f->setups[i] = &f->setup[i];
}
static void begin_fixture(struct registry_fixture *f, const char *args)
{
 assert(!stela_linux_registry_begin(&f->image, args, strlen(args), &test_registry));
 assert(test_registry && test_registry == active);
}
static void option_phases(void)
{
 assert(!stela_linux_registry_early_parameters(test_registry, NULL));
 assert(!stela_linux_registry_initial_parameters(test_registry, NULL, NULL));
}
static void all_stages(int device_error)
{
 for (unsigned stage = 0; stage < STELA_LINUX_STAGE_DONE; ++stage)
  assert(stela_linux_registry_run_stage(test_registry, stage, NULL) ==
   (stage == STELA_LINUX_STAGE_DEVICE ? device_error : 0));
}
static struct stela_linux_registry_retirement fixture_authority(struct registry_fixture *f)
{
 return (struct stela_linux_registry_retirement){.image = &f->image,
  .groups = f->groups, .group_count = 3, .drain_all_consumers = drain_consumers,
  .context = &live_i2c};
}
static void lifecycle_case(void)
{
 stela_linux_enter(&stela_linux_bare);
 struct registry_fixture f; fixture_init(&f);
 fixture_call(&f,0,STELA_LINUX_REG_MODULE_INIT,6,0,init_1);
 fixture_call(&f,1,STELA_LINUX_REG_MODULE_INIT,6,0,init_2);
 fixture_call(&f,2,STELA_LINUX_REG_MODULE_INIT,6,0,init_3);
 fixture_exit(&f,0,exit_1); fixture_exit(&f,1,exit_2); fixture_exit(&f,2,exit_3);
 struct kernel_param p = {.name = "borrow", .ops = &retained_ops, .level = -1, .arg = &retained_value};
 fixture_parameter(&f,0,&p);
 begin_fixture(&f, "borrow=\"kept after owner exit\"");
 option_phases();
 assert(event_count == 1 && events[0] == 50);
 const char *kept = retained_value;
 stela_linux_exit();
 const struct stela_linux_services s = {};
 const struct stela_linux_owner different = {.services = &s, .context = &f};
 stela_linux_enter(&different);
 assert(retained_value == kept && !strcmp(kept,"kept after owner exit"));
 assert(stela_linux_registry_run_stage(test_registry,STELA_LINUX_STAGE_DEVICE,NULL) == -EINVAL);
 all_stages(-ENODEV);
 assert(event_count == 4 && events[1] == 1 && events[2] == 2 && events[3] == 3);
 struct stela_linux_registration_status status;
 assert(!stela_linux_registry_status(test_registry,1,&status));
 assert(status.state == STELA_LINUX_RECORD_NEGATIVE && status.returned == -ENODEV && status.invocations == 1);
 assert(stela_linux_registry_retire(&test_registry,NULL) == -EOPNOTSUPP && !drains && !frees);
 struct stela_linux_registry_retirement a = fixture_authority(&f);
 a.group_count--;
 assert(stela_linux_registry_retire(&test_registry,&a) == -EOPNOTSUPP && !drains);
 a.group_count++;
 live_i2c = 1;
 assert(stela_linux_registry_retire(&test_registry,&a) == -EBUSY && drains == 1 && event_count == 4 && !frees);
 assert(!strcmp(retained_value,"kept after owner exit"));
 live_i2c = 0;
 assert(!stela_linux_registry_retire(&test_registry,&a));
 assert(!test_registry && !active && permanently_retired && frees == 1 && drains == 2);
 assert(event_count == 7 && events[4] == 103 && events[5] == 101 && events[6] == 150);
 struct stela_linux_registry *second = (void *)1;
 assert(stela_linux_registry_begin(&f.image,"",0,&second) == -EBUSY && !second);
 stela_linux_exit();
}
static void ordering_case(void)
{
 stela_linux_enter(&stela_linux_bare);
 struct registry_fixture f; fixture_init(&f);
 /* Unit0 emits sync before normal; reviewed section order still places ALL
  * normal calls from BOTH units before either unit's sync entry. */
 fixture_call(&f,0,STELA_LINUX_REG_INIT,1,1,init_13);
 fixture_call(&f,0,STELA_LINUX_REG_CONSOLE,-4,0,init_10);
 fixture_call(&f,0,STELA_LINUX_REG_INIT,-2,0,init_11);
 fixture_call(&f,0,STELA_LINUX_REG_INIT,0,0,init_12);
 fixture_call(&f,0,STELA_LINUX_REG_INIT,1,0,init_14);
 fixture_call(&f,0,STELA_LINUX_REG_INIT,2,0,init_17);
 fixture_call(&f,0,STELA_LINUX_REG_INIT,3,0,init_18);
 fixture_call(&f,0,STELA_LINUX_REG_INIT,4,0,init_19);
 fixture_call(&f,0,STELA_LINUX_REG_INIT,5,1,init_21);
 fixture_call(&f,0,STELA_LINUX_REG_INIT,-3,0,init_22);
 fixture_call(&f,0,STELA_LINUX_REG_INIT,5,0,init_20);
 fixture_call(&f,0,STELA_LINUX_REG_INIT,6,0,init_23);
 fixture_call(&f,0,STELA_LINUX_REG_INIT,7,0,init_24);
 fixture_call(&f,1,STELA_LINUX_REG_INIT,1,1,init_16);
 fixture_call(&f,1,STELA_LINUX_REG_INIT,1,0,init_15);
 begin_fixture(&f, ""); option_phases(); all_stages(0);
 const unsigned expected[] = {10,11,12,14,15,13,16,17,18,19,20,21,22,23,24};
 assert(event_count == ARRAY_SIZE(expected) && !memcmp(events,expected,sizeof(expected)));
 struct stela_linux_registry_retirement a = fixture_authority(&f);
 assert(stela_linux_registry_retire(&test_registry,&a) == -EOPNOTSUPP && !drains);
 stela_linux_exit(); /* Permanent original globals/token storage stay pinned. */
}
static unsigned early_count, normal_count, warnings, policies;
static char policy_option[80];
static int early_match(char *v) { early_count++; assert(v && !strcmp(v,"abc")); return -EINVAL; }
static int early_second(char *v) { early_count++; assert(v && !strcmp(v,"abc")); return 0; }
static int bare_early(char *v) { early_count++; assert(!v); return 0; }
static int legacy_zero(char *v) { normal_count++; assert(!strcmp(v,"abc")); return 0; }
static int legacy_negative(char *v) { normal_count++; assert(!strcmp(v,"abc")); return -EIO; }
static int suffix_handler(char *v) { normal_count++; assert(!strcmp(v,"Suffix")); return 1; }
static int should_not_run(char *v) { (void)v; assert(0); return 0; }
static void option_log(void *context, int level, const char *message)
{
 assert(context == &warnings);
 if (!strcmp(message,"Malformed early option 'same-name'\n")) { assert(level == 4); warnings++; }
 else if (!strcmp(message,"Parameter obsolete is obsolete, ignored\n")) { assert(level == 4); warnings++; }
}
static int policy_handler(void *context, char *text)
{
 assert(context == &policies);
 policies++;
 assert(strlen(text) < sizeof(policy_option)); strcpy(policy_option,text);
 return 0;
}
static void option_case(void)
{
 const struct stela_linux_services services = {.log = option_log};
 const struct stela_linux_owner owner = {.services = &services,.context = &warnings};
 stela_linux_enter(&owner);
 struct registry_fixture f; fixture_init(&f);
 fixture_setup(&f,0,true,"same_name",early_match);
 fixture_setup(&f,0,true,"same_name",early_second);
 fixture_setup(&f,0,true,"bare",bare_early);
 fixture_setup(&f,0,false,"same_name=",legacy_zero);
 fixture_setup(&f,0,false,"same_name=",legacy_negative);
 fixture_setup(&f,0,false,"prefix",suffix_handler);
 fixture_setup(&f,0,false,"obsolete",NULL);
 fixture_setup(&f,0,false,"known=",should_not_run);
 fixture_setup(&f,0,true,"earlycon",should_not_run);
 int known = 0;
 struct kernel_param kp = {.name="known",.ops=&param_ops_int,.level=2,.arg=&known};
 fixture_parameter(&f,0,&kp);
 begin_fixture(&f,"same-name=abc bare prefixSuffix obsolete known=9 console=ttyS0 unhandled=\"quoted value\" -- tail untouched");
 assert(!stela_linux_registry_early_parameters(test_registry,NULL));
 assert(early_count == 3 && !normal_count && warnings == 1 && !known);
 assert(stela_linux_registry_early_parameters(test_registry,NULL) == -EALREADY && early_count == 3);
 struct stela_linux_registry_unknown_options policy = {.unhandled_option=policy_handler,.context=&policies};
 assert(!stela_linux_registry_initial_parameters(test_registry,&policy,NULL));
 assert(early_count == 3 && normal_count == 3 && warnings == 2 && !known);
 assert(policies == 2 && !strcmp(policy_option,"unhandled=quoted value"));
 char *tail = NULL;
 assert(!stela_linux_registry_parse_result(test_registry,1,&tail) && !strcmp(tail,"tail untouched"));
 assert(!stela_linux_registry_parse_result(test_registry,0,&tail) && !strcmp(tail,"tail untouched"));
 assert(stela_linux_registry_parse_result(test_registry,2,&tail) == -EINVAL);
 all_stages(0);
 assert(known == 9 && early_count == 3 && normal_count == 3 && policies == 2);
 stela_linux_exit();
}
static int violate_irq(void) { event(60); arch_local_irq_disable(); return 0; }
static int violate_owner(void) { event(61); stela_linux_exit(); stela_linux_enter(&stela_linux_bare); return 0; }
static int violate_same_owner(void) { event(64); stela_linux_exit(); stela_linux_enter(mutable_owner); return 0; }
static int violate_context(void) { event(62); mutable_owner->context = &events; return 0; }
static int reentrant_call(void)
{
 assert(stela_linux_registry_run_stage(test_registry,STELA_LINUX_STAGE_DEVICE,NULL) == -EBUSY);
 event(63); return 0;
}
static void context_case_with(initcall_t fn)
{
 struct stela_linux_services services = {};
 struct stela_linux_owner owner = {.services=&services,.context=&drains};
 mutable_owner = &owner;
 stela_linux_enter(&owner);
 struct registry_fixture f; fixture_init(&f);
 fixture_call(&f,0,STELA_LINUX_REG_MODULE_INIT,6,0,fn);
 fixture_call(&f,1,STELA_LINUX_REG_MODULE_INIT,6,0,init_3);
 begin_fixture(&f, ""); option_phases();
 for (unsigned stage=0;stage<STELA_LINUX_STAGE_DEVICE;++stage)
  assert(!stela_linux_registry_run_stage(test_registry,stage,NULL));
 assert(stela_linux_registry_run_stage(test_registry,STELA_LINUX_STAGE_DEVICE,NULL) == -EPROTO);
 assert(test_registry->quarantined && active == test_registry && event_count == 1 && !frees && !drains);
 assert(stela_linux_registry_run_stage(test_registry,STELA_LINUX_STAGE_LATE,NULL) == -EPROTO);
 /* Fault state is retained; no counter/owner repair or cleanup is performed. */
}
static void irq_case(void) { context_case_with(violate_irq); }
static void owner_case(void) { context_case_with(violate_owner); }
static void context_case(void) { context_case_with(violate_context); }
static void same_owner_case(void) { context_case_with(violate_same_owner); }
static void reentry_case(void)
{
 stela_linux_enter(&stela_linux_bare);
 struct registry_fixture f; fixture_init(&f);
 fixture_call(&f,0,STELA_LINUX_REG_MODULE_INIT,6,0,reentrant_call);
 begin_fixture(&f, ""); option_phases(); all_stages(0);
 assert(event_count == 1 && events[0] == 63 && !test_registry->quarantined);
 stela_linux_exit();
}
static void shape_case(void)
{
 stela_linux_enter(&stela_linux_bare);
 struct registry_fixture f; fixture_init(&f);
 fixture_call(&f,0,STELA_LINUX_REG_MODULE_INIT,6,0,init_1);
 struct stela_linux_registry *r=(void *)1;
 f.init[0].header.flags=1;
 assert(stela_linux_registry_begin(&f.image,"",0,&r) == -EINVAL && !r && !active && !event_count);
 f.init[0].header.flags=0;
 f.units[1]=f.units[0];
 assert(stela_linux_registry_begin(&f.image,"",0,&r) == -EINVAL && !r && !active);
 f.units[1]=&f.unit[1];
 const char embedded[]={'a',0,'b'};
 assert(stela_linux_registry_begin(&f.image,embedded,sizeof(embedded),&r) == -EINVAL && !r && !active);
 assert(stela_linux_registry_begin(&f.image,NULL,SIZE_MAX,&r) == -EINVAL && !r && !active);
 assert(stela_linux_registry_begin(&f.image,"x",(size_t)UINT_MAX+1,&r) == -E2BIG && !r && !active);
 fail_registry_allocation = true;
 assert(stela_linux_registry_begin(&f.image,"",0,&r) == -ENOMEM && !r && !active && !owned_image);
 assert(!registry_allocations && !registry_releases && !event_count);
 fail_registry_allocation = false;
 assert(!stela_linux_registry_begin(&f.image,"",0,&r) && r && registry_allocations == 1);
 assert(stela_linux_registry_begin(&f.image,"",0,&test_registry) == -EBUSY && !test_registry);
 test_registry=r;
 assert(stela_linux_registry_initial_parameters(r,NULL,NULL) == -EALREADY);
 assert(stela_linux_registry_run_stage(r,STELA_LINUX_STAGE_CONSOLE,NULL) == -EINVAL && !event_count);
 stela_linux_exit();
}
static void parameter_failure_case(void)
{
 stela_linux_enter(&stela_linux_bare);
 struct registry_fixture f; fixture_init(&f);
 fixture_call(&f,0,STELA_LINUX_REG_MODULE_INIT,6,0,init_1);
 int first=81, later=82;
 struct kernel_param a={.name="first",.ops=&param_ops_int,.level=-1,.arg=&first};
 struct kernel_param b={.name="later",.ops=&param_ops_int,.level=-1,.arg=&later};
 fixture_parameter(&f,0,&a); fixture_parameter(&f,0,&b);
 begin_fixture(&f,"first=invalid later=42 unknown -- tail");
 assert(!stela_linux_registry_early_parameters(test_registry,NULL));
 struct stela_linux_registry_report report;
 assert(stela_linux_registry_initial_parameters(test_registry,NULL,&report) == -ENOENT);
 assert(first == 81 && later == 42 && !event_count && report.last_error == -ENOENT);
 char *result=NULL;
 assert(!stela_linux_registry_parse_result(test_registry,1,&result) && IS_ERR(result) && PTR_ERR(result)==-ENOENT);
 assert(stela_linux_registry_initial_parameters(test_registry,NULL,NULL) == -EALREADY);
 assert(stela_linux_registry_run_stage(test_registry,0,NULL) == -EINVAL && !event_count);
 struct stela_linux_registry_retirement authority=fixture_authority(&f);
 assert(!stela_linux_registry_retire(&test_registry,&authority));
 assert(!test_registry && !event_count && drains==1 && registry_releases==1);
 stela_linux_exit();
}
static void missing_exit_case(void)
{
 stela_linux_enter(&stela_linux_bare);
 struct registry_fixture f; fixture_init(&f);
 fixture_call(&f,0,STELA_LINUX_REG_MODULE_INIT,6,0,init_1);
 begin_fixture(&f,""); option_phases(); all_stages(0);
 struct stela_linux_registry_retirement authority=fixture_authority(&f);
 assert(stela_linux_registry_retire(&test_registry,&authority)==-EOPNOTSUPP);
 assert(event_count==1 && events[0]==1 && !drains && !registry_releases);
 stela_linux_exit();
}
static void console_returns_case(void)
{
 stela_linux_enter(&stela_linux_bare);
 struct registry_fixture f; fixture_init(&f);
 fixture_call(&f,0,STELA_LINUX_REG_CONSOLE,-4,0,init_26);
 fixture_call(&f,0,STELA_LINUX_REG_CONSOLE,-4,0,init_27);
 fixture_call(&f,1,STELA_LINUX_REG_CONSOLE,-4,0,init_28);
 begin_fixture(&f,""); option_phases();
 struct stela_linux_registry_report report;
 assert(stela_linux_registry_run_stage(test_registry,0,&report)==-EINVAL);
 assert(event_count==3 && events[0]==26 && events[1]==27 && events[2]==28);
 assert(report.returned_positive==1 && report.returned_negative==1 && report.returned_zero==1);
 assert(!report.warnings && report.next_stage==STELA_LINUX_STAGE_EARLY);
 struct stela_linux_registration_status status;
 assert(!stela_linux_registry_status(test_registry,0,&status) && status.returned==3);
 assert(!stela_linux_registry_status(test_registry,1,&status) && status.returned==-EINVAL);
 assert(!stela_linux_registry_status(test_registry,2,&status) && status.returned==0);
 for(unsigned stage=STELA_LINUX_STAGE_EARLY;stage<STELA_LINUX_STAGE_DONE;++stage)
  assert(!stela_linux_registry_run_stage(test_registry,stage,NULL));
 stela_linux_exit();
}
static int positive_set(const char *v,const struct kernel_param *p)
{
 *(int *)p->arg=(!strcmp(v,"new")); return 7;
}
static void positive_parameter_case(void)
{
 stela_linux_enter(&stela_linux_bare);
 struct registry_fixture f; fixture_init(&f);
 int value=0;
 const struct kernel_param_ops ops={.set=positive_set};
 struct kernel_param p={.name="positive",.ops=&ops,.level=-1,.arg=&value};
 fixture_parameter(&f,0,&p);
 begin_fixture(&f,"positive=new -- tail");
 assert(!stela_linux_registry_early_parameters(test_registry,NULL));
 struct stela_linux_registry_report report;
 assert(stela_linux_registry_initial_parameters(test_registry,NULL,&report)==-EPROTO);
 assert(value==1 && report.last_error==-EPROTO && !report.terminal);
 char *result=NULL;
 assert(!stela_linux_registry_parse_result(test_registry,1,&result) && result==ERR_PTR(7));
 struct stela_linux_registration_status status;
 assert(!stela_linux_registry_status(test_registry,0,&status) && status.returned==7);
 assert(stela_linux_registry_run_stage(test_registry,0,NULL)==-EINVAL && !event_count);
 stela_linux_exit();
}
#include <stela/registry_setup_test.h>
int main(void)
{
 for(setup_differential_index=0;setup_differential_index<ARRAY_SIZE(setup_differential_inputs);++setup_differential_index)
  assert(stela_test_registry_case(setup_differential_case));
 assert(stela_test_registry_case(lifecycle_case));
 assert(stela_test_registry_case(ordering_case));
 assert(stela_test_registry_case(option_case));
 assert(stela_test_registry_case(irq_case));
 assert(stela_test_registry_case(owner_case));
 assert(stela_test_registry_case(context_case));
 assert(stela_test_registry_case(same_owner_case));
 assert(stela_test_registry_case(reentry_case));
 assert(stela_test_registry_case(shape_case));
 assert(stela_test_registry_case(parameter_failure_case));
 assert(stela_test_registry_case(missing_exit_case));
 assert(stela_test_registry_case(console_returns_case));
 assert(stela_test_registry_case(positive_parameter_case));
 printf("Linux static registry: source lifecycle/order/options/context fixtures passed\n");
 return 0;
}
#endif

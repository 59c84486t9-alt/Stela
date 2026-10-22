/* SPDX-License-Identifier: MIT */
/* Original source fragments compile in their own object, without LTO. Hosted
 * mutex serialization is real; this supplies no Linux IRQ/power/timer runtime. */
#include "activation_donor.h"
#include <linux/types.h>
#include "regs/xe_reg_defs.h"
#include "xe_force_wake_domain_types.h"
#include <assert.h>
#include <pthread.h>
#define for_each_if(condition) if (!(condition)) {} else
#define ffs(value) __builtin_ffs((int)(value))
#include "xe_force_wake_core.h"
struct donor_fw {
    struct stela_intel_policy_result *gt;
    unsigned initialized_domains, awake_domains, failures;
    struct xe_force_wake_domain *domains;
};
static void control(struct stela_intel_policy_result *r, struct xe_force_wake_domain *d, bool wake)
{
    assert(r->used < 256); r->words[r->used++] = d->id * 4u + (wake ? 1u : 0u);
}
static int wait(struct donor_fw *fw, struct xe_force_wake_domain *d, bool wake)
{
    assert(fw->gt->used < 256); fw->gt->words[fw->gt->used++] = d->id * 4u + (wake ? 3u : 2u);
    return fw->failures & (1u << d->id) ? -110 : 0;
}
#define domain_wake(gt, domain) control(gt, domain, true)
#define domain_wake_wait(gt, domain) wait(fw, domain, true)
#define domain_sleep(gt, domain) control(gt, domain, false)
#define domain_sleep_wait(gt, domain) wait(fw, domain, false)
#define xe_gt_assert(gt, condition) assert(condition)
static unsigned donor_get(struct donor_fw *fw, unsigned domains, unsigned *failed)
{
    struct stela_intel_policy_result *gt = fw->gt;
    struct xe_force_wake_domain *domain;
    unsigned ref_incr = 0, awake_rqst = 0, awake_failed = 0, tmp, ref_rqst;
#include "donor-get.inc"
    *failed = awake_failed; return ref_incr;
}
static unsigned donor_put(struct donor_fw *fw, unsigned fw_ref)
{
    struct stela_intel_policy_result *gt = fw->gt;
    struct xe_force_wake_domain *domain;
    unsigned tmp, sleep = 0; int ack_fail = 0;
#include "donor-put.inc"
    return (unsigned)ack_fail;
}
void stela_intel_donor_policy(unsigned initialized, unsigned failures, unsigned nested,
                             struct stela_intel_policy_result *result)
{
    *result = (struct stela_intel_policy_result){0};
    struct xe_force_wake_domain domains[XE_FW_DOMAIN_ID_COUNT] = {0};
    for (unsigned i = 0; i < 3; ++i) {
        domains[i].id = (enum xe_force_wake_domain_id)i;
        domains[i].reg_ctl.addr = 4 * (i + 1);
        domains[i].ref = initialized & (1u << i) ? nested : 0;
    }
    struct donor_fw fw = {result, initialized, nested ? initialized : 0, failures, domains};
    pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
    assert(pthread_mutex_lock(&lock) == 0);
    result->get = donor_get(&fw, XE_FORCEWAKE_ALL, &result->failed);
    result->put_failed = donor_put(&fw, result->get);
    result->awake = fw.awake_domains;
    for (unsigned i = 0; i < 3; ++i) result->refs[i] = domains[i].ref;
    assert(pthread_mutex_unlock(&lock) == 0 && pthread_mutex_destroy(&lock) == 0);
}

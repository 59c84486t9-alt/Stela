// SPDX-License-Identifier: MIT
/*
 * Copyright © 2022 Intel Corporation
 */
#ifndef XE_FORCE_WAKE_CORE_H
#define XE_FORCE_WAKE_CORE_H
#define XE_FORCE_WAKE_ACK_TIMEOUT_MS 50
#define for_each_fw_domain_masked(domain__, mask__, fw__, tmp__) \
	for (tmp__ = (mask__); tmp__; tmp__ &= ~BIT(ffs(tmp__) - 1)) \
		for_each_if(((domain__) = ((fw__)->domains + \
					 (ffs(tmp__) - 1))) && \
					 (domain__)->reg_ctl.addr)


struct xe_force_wake_core_ops {
	void (*control)(void *, struct xe_force_wake_domain *, bool);
	int (*wait)(void *, struct xe_force_wake_domain *, bool);
	void (*invariant)(void *, bool);
};
struct xe_force_wake_core {
	void *context;
	const struct xe_force_wake_core_ops *ops;
	unsigned int initialized_domains;
	unsigned int *awake_domains;
	struct xe_force_wake_domain *domains;
};
/* Caller holds real exclusive serialization across the entire operation.
 * Required operations have no defaults. Live domain records are borrowed.
 * Public-call validation, ALL-flag normalization, IRQsave locking and diagnostic
 * reporting remain in the original Xe wrapper; this is only its locked core. */
static inline unsigned int xe_force_wake_get_locked(struct xe_force_wake_core *fw,
		unsigned int domains, unsigned int *failed)
{
	struct xe_force_wake_domain *domain;
	unsigned int ref_incr = 0, awake_rqst = 0, awake_failed = 0;
	unsigned int tmp, ref_rqst;
	ref_rqst = (domains == XE_FORCEWAKE_ALL) ? fw->initialized_domains : domains;
	for_each_fw_domain_masked(domain, ref_rqst, fw, tmp) {
		if (!domain->ref++) {
			awake_rqst |= BIT(domain->id);
			fw->ops->control(fw->context, domain, true);
		}
		ref_incr |= BIT(domain->id);
	}
	for_each_fw_domain_masked(domain, awake_rqst, fw, tmp) {
		if (fw->ops->wait(fw->context, domain, true) == 0) {
			*fw->awake_domains |= BIT(domain->id);
		} else {
			awake_failed |= BIT(domain->id);
			--domain->ref;
		}
	}
	ref_incr &= ~awake_failed;
	*failed = awake_failed;
	return ref_incr;
}
static inline unsigned int xe_force_wake_put_locked(struct xe_force_wake_core *fw,
		unsigned int fw_ref)
{
	struct xe_force_wake_domain *domain;
	unsigned int tmp, sleep = 0, ack_fail = 0;
	for_each_fw_domain_masked(domain, fw_ref, fw, tmp) {
		fw->ops->invariant(fw->context, domain->ref != 0);

		if (!--domain->ref) {
			sleep |= BIT(domain->id);
			fw->ops->control(fw->context, domain, false);
		}
	}
	for_each_fw_domain_masked(domain, sleep, fw, tmp) {
		if (fw->ops->wait(fw->context, domain, false) == 0)
			*fw->awake_domains &= ~BIT(domain->id);
		else
			ack_fail |= BIT(domain->id);
	}
	return ack_fail;
}
#endif

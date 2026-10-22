/* SPDX-License-Identifier: MIT */
#ifndef STELA_INTEL_ACTIVATION_DONOR_H
#define STELA_INTEL_ACTIVATION_DONOR_H
struct stela_intel_policy_result {
    unsigned get, failed, put_failed, awake, refs[3], words[256], used;
};
void stela_intel_donor_policy(unsigned initialized, unsigned failures, unsigned nested,
                             struct stela_intel_policy_result *);
#endif

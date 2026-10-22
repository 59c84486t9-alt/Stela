/* SPDX-License-Identifier: MIT */
/* Kbuild generates the scheduler run queue's offsets here. Stela has no run
 * queue: its uniprocessor configuration reads none, and the runqueues symbol
 * an offset would apply to is undefined, so a use fails to link. */
#define RQ_nr_pinned 0

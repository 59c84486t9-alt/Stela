/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_STELA_PTRACE_H
#define _ASM_STELA_PTRACE_H
/* Linux code under Stela takes no trap or interrupt, so it never sees saved
 * registers: they are only the instruction and stack pointers of x86-64's
 * pt_regs, and never come from user mode. */
struct pt_regs {
	unsigned long ip;
	unsigned long sp;
};

#define instruction_pointer(regs)	((regs)->ip)
#define user_stack_pointer(regs)	((regs)->sp)
#define profile_pc(regs)		instruction_pointer(regs)

static inline int user_mode(struct pt_regs *regs)
{
	return 0;
}
#endif

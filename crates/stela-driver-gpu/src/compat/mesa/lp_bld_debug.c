/* SPDX-License-Identifier: MIT */
/* gallivm's debugging: the upstream unit prints through C++ streams, which this
 * libc++ leaves out. Only GALLIVM_DEBUG reaches the disassembler and the debug
 * information, and this image has no environment to set it in. */
#include "gallivm/lp_bld_debug.h"
#include "util/u_debug.h"
#include <llvm-c/Core.h>

bool lp_check_alignment(const void *ptr, unsigned alignment)
{
	return ((uintptr_t)ptr & (alignment - 1)) == 0;
}

void lp_debug_dump_value(LLVMValueRef value)
{
	char *text = LLVMPrintValueToString(value);
	if (text) {
		os_log_message(text);
		LLVMDisposeMessage(text);
	}
}

void lp_disassemble(LLVMValueRef func, const void *code)
{
	(void)func;
	(void)code;
	os_log_message("gallivm: this image has no disassembler\n");
}

void lp_profile(LLVMValueRef func, const void *code)
{
	(void)func;
	(void)code;
}

LLVMMetadataRef lp_bld_debug_info_type(struct gallivm_state *gallivm, LLVMTypeRef type)
{
	(void)gallivm;
	(void)type;
	return NULL;
}

void lp_function_add_debug_info(struct gallivm_state *gallivm, LLVMValueRef func, LLVMTypeRef func_type)
{
	(void)gallivm;
	(void)func;
	(void)func_type;
}

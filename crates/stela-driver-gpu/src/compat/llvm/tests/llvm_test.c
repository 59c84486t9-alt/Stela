// SPDX-License-Identifier: MIT
/* LLVM as `stela.efi` links it, over the C library and libc++, doing what the
 * AIR compiler does, as a static Linux program: `cargo xtask gpu llvm --test`
 * builds and runs it. */
#include "llvm-c/Analysis.h"
#include "llvm-c/BitReader.h"
#include "llvm-c/Core.h"
#include "llvm-c/Error.h"
#include "llvm-c/Linker.h"
#include "llvm-c/Target.h"
#include "llvm-c/Transforms/PassBuilder.h"
#include <stdio.h>
#include <string.h>
#include "host.h"

__asm__(".section .rodata\n"
	"fixture:\n"
	".incbin \"" FIXTURE "\"\n"
	"fixture_end:\n"
	".text\n");
extern const char fixture[], fixture_end[];

static int failures;

#define CHECK(condition)                                                                          \
	do {                                                                                      \
		if (!(condition)) {                                                               \
			fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #condition);           \
			failures++;                                                               \
		}                                                                                 \
	} while (0)

static unsigned int count(LLVMModuleRef module, LLVMOpcode opcode)
{
	unsigned int found = 0;
	for (LLVMValueRef function = LLVMGetFirstFunction(module); function;
	     function = LLVMGetNextFunction(function)) {
		for (LLVMBasicBlockRef block = LLVMGetFirstBasicBlock(function); block;
		     block = LLVMGetNextBasicBlock(block)) {
			for (LLVMValueRef instruction = LLVMGetFirstInstruction(block); instruction;
			     instruction = LLVMGetNextInstruction(instruction))
				found += LLVMGetInstructionOpcode(instruction) == opcode;
		}
	}
	return found;
}

/* Calls of anything but an intrinsic: inlining leaves `llvm.lifetime.*`. */
static unsigned int calls(LLVMModuleRef module)
{
	unsigned int found = 0;
	for (LLVMValueRef function = LLVMGetFirstFunction(module); function;
	     function = LLVMGetNextFunction(function)) {
		for (LLVMBasicBlockRef block = LLVMGetFirstBasicBlock(function); block;
		     block = LLVMGetNextBasicBlock(block)) {
			for (LLVMValueRef instruction = LLVMGetFirstInstruction(block); instruction;
			     instruction = LLVMGetNextInstruction(instruction)) {
				if (LLVMGetInstructionOpcode(instruction) == LLVMCall)
					found += !LLVMGetIntrinsicID(LLVMGetCalledValue(instruction));
			}
		}
	}
	return found;
}

static int valid(LLVMModuleRef module)
{
	char *message = NULL;
	int broken = LLVMVerifyModule(module, LLVMReturnStatusAction, &message);
	if (broken)
		fprintf(stderr, "%s\n", message);
	LLVMDisposeMessage(message);
	return !broken;
}

/* Runs a pipeline AIR runs; true when LLVM ran it. */
static int run(LLVMModuleRef module, const char *pipeline)
{
	LLVMPassBuilderOptionsRef options = LLVMCreatePassBuilderOptions();
	LLVMErrorRef error = LLVMRunPasses(module, pipeline, NULL, options);
	LLVMDisposePassBuilderOptions(options);
	if (error)
		LLVMConsumeError(error);
	return !error;
}

static int run_on(LLVMValueRef function, const char *pipeline)
{
	LLVMPassBuilderOptionsRef options = LLVMCreatePassBuilderOptions();
	LLVMErrorRef error = LLVMRunPassesOnFunction(function, pipeline, NULL, options);
	LLVMDisposePassBuilderOptions(options);
	if (error)
		LLVMConsumeError(error);
	return !error;
}

/* `int name(void)` with a branch only one way of which can run. */
static LLVMValueRef add_decided(LLVMContextRef context, LLVMModuleRef module, const char *name)
{
	LLVMTypeRef word = LLVMInt32TypeInContext(context);
	LLVMTypeRef type = LLVMFunctionType(word, NULL, 0, 0);
	LLVMValueRef function = LLVMAddFunction(module, name, type);
	LLVMBasicBlockRef entry = LLVMAppendBasicBlockInContext(context, function, "entry");
	LLVMBasicBlockRef taken = LLVMAppendBasicBlockInContext(context, function, "taken");
	LLVMBasicBlockRef dead = LLVMAppendBasicBlockInContext(context, function, "dead");
	LLVMBuilderRef builder = LLVMCreateBuilderInContext(context);
	LLVMValueRef always = LLVMConstInt(LLVMInt1TypeInContext(context), 1, 0);
	LLVMPositionBuilderAtEnd(builder, entry);
	LLVMBuildCondBr(builder, always, taken, dead);
	LLVMPositionBuilderAtEnd(builder, taken);
	LLVMBuildRet(builder, LLVMConstInt(word, 1, 0));
	LLVMPositionBuilderAtEnd(builder, dead);
	LLVMBuildRet(builder, LLVMConstInt(word, 2, 0));
	LLVMDisposeBuilder(builder);
	return function;
}

int test(void)
{
	LLVMContextRef context = LLVMContextCreate();
	LLVMMemoryBufferRef junk =
		LLVMCreateMemoryBufferWithMemoryRange("not bitcode", 11, "junk", 0);
	LLVMModuleRef module = NULL;
	CHECK(LLVMParseBitcodeInContext2(context, junk, &module));
	LLVMDisposeMemoryBuffer(junk);

	LLVMMemoryBufferRef air = LLVMCreateMemoryBufferWithMemoryRange(
		fixture, (size_t)(fixture_end - fixture), "fixture", 0);
	CHECK(!LLVMParseBitcodeInContext2(context, air, &module));
	LLVMDisposeMemoryBuffer(air);
	CHECK(valid(module));
	CHECK(LLVMGetNamedFunction(module, "pick"));
	CHECK(calls(module) == 1);
	CHECK(count(module, LLVMSwitch) == 1);

	CHECK(run(module, "always-inline"));
	CHECK(calls(module) == 0);

	LLVMValueRef pick = LLVMGetNamedFunction(module, "pick");
	CHECK(run_on(pick, "lower-switch"));
	CHECK(count(module, LLVMSwitch) == 0);
	CHECK(valid(module));

	LLVMValueRef decided = add_decided(context, module, "decided");
	CHECK(LLVMCountBasicBlocks(decided) == 3);
	CHECK(run_on(decided, "sccp,unreachableblockelim,dce"));
	CHECK(LLVMCountBasicBlocks(decided) < 3);
	CHECK(valid(module));

	LLVMTypeRef word = LLVMInt32TypeInContext(context);
	LLVMValueRef unused = LLVMAddGlobal(module, word, "unused");
	LLVMSetInitializer(unused, LLVMConstInt(word, 7, 0));
	LLVMSetLinkage(unused, LLVMInternalLinkage);
	CHECK(run(module, "globalopt"));
	CHECK(!LLVMGetNamedGlobal(module, "unused"));
	CHECK(valid(module));

	CHECK(!run(module, "instcombine"));
	CHECK(!run_on(pick, "instcombine"));

	LLVMModuleRef clone = LLVMCloneModule(module);
	CHECK(valid(clone));
	LLVMDisposeModule(clone);

	LLVMModuleRef other = LLVMModuleCreateWithNameInContext("other", context);
	add_decided(context, other, "other");
	CHECK(!LLVMLinkModules2(module, other));
	CHECK(LLVMGetNamedFunction(module, "other"));
	CHECK(valid(module));

	LLVMTargetDataRef data = LLVMCreateTargetData("e-p:32:32");
	CHECK(LLVMPointerSize(data) == 4);
	CHECK(LLVMABISizeOfType(data, LLVMInt64TypeInContext(context)) == 8);
	LLVMDisposeTargetData(data);

	LLVMDisposeModule(module);
	LLVMContextDispose(context);
	if (failures)
		fprintf(stderr, "%d of LLVM's checks failed\n", failures);
	return failures != 0;
}

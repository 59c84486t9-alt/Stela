// SPDX-License-Identifier: MIT
// LLVM's pass C API (`llvm-c/Transforms/PassBuilder.h`) over only the passes
// the AIR compiler names. `PassBuilder` parses a pipeline by reaching every pass
// LLVM has, every code generator's included, so the image would carry them all;
// these run the same passes under the same analyses, and any other name fails.
// The verifier's C entry lives here too, as its own unit reaches the legacy passes.
#include "llvm-c/Analysis.h"
#include "llvm-c/Transforms/PassBuilder.h"
#include "llvm/Analysis/AliasAnalysis.h"
#include "llvm/Analysis/AssumptionCache.h"
#include "llvm/Analysis/BlockFrequencyInfo.h"
#include "llvm/Analysis/BranchProbabilityInfo.h"
#include "llvm/Analysis/CGSCCPassManager.h"
#include "llvm/Analysis/LazyValueInfo.h"
#include "llvm/Analysis/LoopAnalysisManager.h"
#include "llvm/Analysis/LoopInfo.h"
#include "llvm/Analysis/OptimizationRemarkEmitter.h"
#include "llvm/Analysis/PostDominators.h"
#include "llvm/Analysis/ProfileSummaryInfo.h"
#include "llvm/Analysis/TargetLibraryInfo.h"
#include "llvm/Analysis/TargetTransformInfo.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassInstrumentation.h"
#include "llvm/IR/PassManager.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/Error.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/IPO/AlwaysInliner.h"
#include "llvm/Transforms/IPO/GlobalOpt.h"
#include "llvm/Transforms/Scalar/DCE.h"
#include "llvm/Transforms/Scalar/SCCP.h"
#include "llvm/Transforms/Scalar/SROA.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/LowerSwitch.h"
#include <string.h>

using namespace llvm;

/* Nothing configures the passes. */
struct LLVMOpaquePassBuilderOptions {};

namespace {

struct Analyses {
	LoopAnalysisManager loops;
	FunctionAnalysisManager functions;
	CGSCCAnalysisManager components;
	ModuleAnalysisManager modules;

	Analyses()
	{
		functions.registerPass([] { return AAManager(); });
		functions.registerPass([] { return AssumptionAnalysis(); });
		functions.registerPass([] { return BlockFrequencyAnalysis(); });
		functions.registerPass([] { return BranchProbabilityAnalysis(); });
		functions.registerPass([] { return DominatorTreeAnalysis(); });
		functions.registerPass([] { return LazyValueAnalysis(); });
		functions.registerPass([] { return LoopAnalysis(); });
		functions.registerPass([] { return OptimizationRemarkEmitterAnalysis(); });
		functions.registerPass([] { return PassInstrumentationAnalysis(); });
		functions.registerPass([] { return PostDominatorTreeAnalysis(); });
		functions.registerPass([] { return TargetIRAnalysis(); });
		functions.registerPass([] { return TargetLibraryAnalysis(); });
		functions.registerPass([this] { return ModuleAnalysisManagerFunctionProxy(modules); });
		functions.registerPass([this] { return CGSCCAnalysisManagerFunctionProxy(components); });
		functions.registerPass(
			[this] { return LoopAnalysisManagerFunctionProxy(loops); });
		loops.registerPass([] { return PassInstrumentationAnalysis(); });
		loops.registerPass([this] { return FunctionAnalysisManagerLoopProxy(functions); });
		components.registerPass([] { return PassInstrumentationAnalysis(); });
		components.registerPass([this] { return ModuleAnalysisManagerCGSCCProxy(modules); });
		components.registerPass(
			[this] { return FunctionAnalysisManagerCGSCCProxy(); });
		modules.registerPass([] { return PassInstrumentationAnalysis(); });
		modules.registerPass([] { return ProfileSummaryAnalysis(); });
		modules.registerPass([this] { return FunctionAnalysisManagerModuleProxy(functions); });
		modules.registerPass([this] { return CGSCCAnalysisManagerModuleProxy(components); });
	}
};

/* The IR half of CodeGen's `unreachableblockelim`, whose unit is the machine pass's too. */
struct UnreachableBlocks : PassInfoMixin<UnreachableBlocks> {
	PreservedAnalyses run(Function &function, FunctionAnalysisManager &)
	{
		if (!EliminateUnreachableBlocks(function))
			return PreservedAnalyses::all();
		PreservedAnalyses preserved;
		preserved.preserve<DominatorTreeAnalysis>();
		return preserved;
	}
};

LLVMErrorRef unknown(StringRef pipeline)
{
	return wrap(make_error<StringError>("no such pass in Stela's LLVM: " + pipeline,
					    inconvertibleErrorCode()));
}

} // namespace

extern "C" {

LLVMBool LLVMVerifyModule(LLVMModuleRef module, LLVMVerifierFailureAction action, char **messages)
{
	std::string text;
	raw_string_ostream stream(text);
	raw_ostream *debug = action != LLVMReturnStatusAction ? &errs() : nullptr;
	LLVMBool broken = verifyModule(*unwrap(module), messages ? &stream : debug);
	if (debug && messages)
		*debug << text;
	if (action == LLVMAbortProcessAction && broken)
		report_fatal_error("Broken module found, compilation aborted!");
	if (messages)
		*messages = strdup(text.c_str());
	return broken;
}

LLVMPassBuilderOptionsRef LLVMCreatePassBuilderOptions(void)
{
	return new LLVMOpaquePassBuilderOptions;
}

void LLVMDisposePassBuilderOptions(LLVMPassBuilderOptionsRef options)
{
	delete options;
}

LLVMErrorRef LLVMRunPasses(LLVMModuleRef module, const char *passes, LLVMTargetMachineRef machine,
			   LLVMPassBuilderOptionsRef)
{
	if (machine)
		return unknown("a target machine");
	ModulePassManager manager;
	StringRef pipeline(passes);
	if (pipeline == "always-inline")
		manager.addPass(AlwaysInlinerPass());
	else if (pipeline == "globalopt")
		manager.addPass(GlobalOptPass());
	else
		return unknown(pipeline);
	Analyses analyses;
	manager.run(*unwrap(module), analyses.modules);
	return LLVMErrorSuccess;
}

LLVMErrorRef LLVMRunPassesOnFunction(LLVMValueRef function, const char *passes,
				     LLVMTargetMachineRef machine, LLVMPassBuilderOptionsRef)
{
	if (machine)
		return unknown("a target machine");
	FunctionPassManager manager;
	StringRef pipeline(passes);
	if (pipeline == "lower-switch") {
		manager.addPass(LowerSwitchPass());
	} else if (pipeline == "sroa") {
		manager.addPass(SROAPass(SROAOptions::PreserveCFG));
	} else if (pipeline == "sccp,unreachableblockelim,dce") {
		manager.addPass(SCCPPass());
		manager.addPass(UnreachableBlocks());
		manager.addPass(DCEPass());
	} else {
		return unknown(pipeline);
	}
	Analyses analyses;
	manager.run(*unwrap<Function>(function), analyses.functions);
	return LLVMErrorSuccess;
}
}

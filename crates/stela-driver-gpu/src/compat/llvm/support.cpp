// SPDX-License-Identifier: MIT
// What LLVM's process-bound units give the libraries the AIR compiler links:
// the image has no signals, no processes and no difference of text from binary,
// reads no profiles and parses no assembly. Each entry stands for a unit that
// would pull in a file format or a code generator the compiler never runs.
#include "llvm/IR/Module.h"
#include "llvm/MC/TargetRegistry.h"
#include "llvm/Object/IRSymtab.h"
#include "llvm/Object/ModuleSymbolTable.h"
#include "llvm/ProfileData/InstrProfReader.h"
#include "llvm/Support/CrashRecoveryContext.h"
#include "llvm/Support/Errc.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/Program.h"
#include "llvm/Support/Signals.h"
#include "llvm/TargetParser/RISCVTargetParser.h"
#include <stela/host.h>

using namespace llvm;

namespace llvm {
void initSignalsOptions();
}

void llvm::initSignalsOptions() {}

void sys::RunInterruptHandlers() {}

bool sys::RemoveFileOnSignal(StringRef, std::string *)
{
	return false;
}

void sys::DontRemoveFileOnSignal(StringRef) {}

std::error_code sys::ChangeStdinMode(fs::OpenFlags)
{
	return {};
}

std::error_code sys::ChangeStdoutMode(fs::OpenFlags)
{
	return {};
}

ErrorOr<std::string> sys::findProgramByName(StringRef, ArrayRef<StringRef>)
{
	return errc::no_such_file_or_directory;
}

int sys::ExecuteAndWait(StringRef, ArrayRef<StringRef>, std::optional<ArrayRef<StringRef>>,
			ArrayRef<std::optional<StringRef>>, unsigned, unsigned, std::string *message,
			bool *failed, std::optional<ProcessStatistics> *, BitVector *)
{
	if (message)
		*message = "the image runs no processes";
	if (failed)
		*failed = true;
	return -1;
}

sys::ProcessInfo::ProcessInfo() : Pid(0), Process(0), ReturnCode(0) {}

sys::ProcessInfo sys::ExecuteNoWait(StringRef, ArrayRef<StringRef>, std::optional<ArrayRef<StringRef>>,
				    ArrayRef<std::optional<StringRef>>, unsigned, std::string *message,
				    bool *failed, BitVector *, bool)
{
	if (message)
		*message = "the image runs no processes";
	if (failed)
		*failed = true;
	return {};
}

CrashRecoveryContext *CrashRecoveryContext::GetCurrent()
{
	return nullptr;
}

void CrashRecoveryContext::HandleExit(int)
{
	stela_libc_fatal("LLVM exited");
}

/* AIR has no inline assembly; a module that did would need a target's parser. */
void ModuleSymbolTable::CollectAsmSymvers(const Module &module,
					  function_ref<void(StringRef, StringRef)>)
{
	if (!module.getModuleInlineAsm().empty())
		report_fatal_error("module assembly in AIR");
}

/* The bitcode writer's symbol table serves linkers of bitcode files, and LLVM
 * writes a module without one when this declines. */
Error irsymtab::build(ArrayRef<Module *>, SmallVector<char, 0> &, StringTableBuilder &,
		      BumpPtrAllocator &)
{
	return createStringError(errc::not_supported, "the image writes no symbol tables");
}

#ifdef STELA_LLVM_AIR_ONLY
/* The writer asks this only of a module with assembly. */
const Target *TargetRegistry::lookupTarget(const Triple &, std::string &error)
{
	error = "the program has no targets";
	return nullptr;
}
#endif

Expected<std::unique_ptr<InstrProfReader>>
InstrProfReader::create(const Twine &, vfs::FileSystem &, const InstrProfCorrelator *,
			const object::BuildIDFetcher *, InstrProfCorrelator::ProfCorrelatorKind,
			std::function<void(Error)>)
{
	return createStringError(errc::not_supported, "the image reads no profiles");
}

void InstrProfReader::accumulateCounts(CountSumOrPercent &, bool)
{
	report_fatal_error("the image reads no profiles");
}

/* Value tracking asks this of RISC-V's intrinsics alone. */
unsigned RISCVVType::getSEWLMULRatio(unsigned, VLMUL)
{
	report_fatal_error("a RISC-V vector type in AIR");
}

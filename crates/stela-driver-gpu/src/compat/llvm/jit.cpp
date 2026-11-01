// SPDX-License-Identifier: MIT
// What MCJIT finds in a process: the image has no dynamic loader, so a name in
// generated code resolves against this table of what llvmpipe's code calls and
// what LLVM lowers into calls. Its heap never runs, so code goes in pages the
// host maps to, writable and executable for their whole life.
#include "llvm/ADT/StringRef.h"
#include "llvm/CodeGen/AssignmentTrackingAnalysis.h"
#include "llvm/ExecutionEngine/JITEventListener.h"
#include "llvm/IR/PassManager.h"
#include "llvm/MC/MCStreamer.h"
#include "llvm/Object/Error.h"
#include "llvm/IR/DebugInfo.h"
#include "llvm/InitializePasses.h"
#include "llvm/Object/IRObjectFile.h"
#include "llvm/Object/ModuleSymbolTable.h"
#include "llvm/Object/OffloadBinary.h"
#include "llvm/Support/DynamicLibrary.h"
#include "llvm/Support/Errc.h"
#include "llvm/Support/Memory.h"
#include "llvm/TargetParser/RISCVISAInfo.h"
#include "llvm/Transforms/Instrumentation/AddressSanitizer.h"
#include "llvm/Transforms/Instrumentation/AddressSanitizerCommon.h"
#include <math.h>
#include <string.h>
#include <sys/utsname.h>

using namespace llvm;

/* Windows' stack probe, which the target calls for a frame above a page. Every
 * stack the image runs on is mapped through, so there is nothing to touch. */
__asm__(".globl stela_chkstk\nstela_chkstk:\n\tret\n");
extern "C" void stela_chkstk();

namespace {

struct Symbol {
	StringRef name;
	void *address;
};

template <typename Function> void *address(Function *function)
{
	return reinterpret_cast<void *>(function);
}

} // namespace

void *sys::DynamicLibrary::SearchForAddressOfSymbol(const char *name)
{
	const Symbol symbols[] = {
		{"__chkstk", address(stela_chkstk)},
		{"___chkstk_ms", address(stela_chkstk)},
		{"memcpy", address(static_cast<void *(*)(void *, const void *, size_t)>(memcpy))},
		{"memmove", address(static_cast<void *(*)(void *, const void *, size_t)>(memmove))},
		{"memset", address(static_cast<void *(*)(void *, int, size_t)>(memset))},
		{"ceil", address(static_cast<double (*)(double)>(::ceil))},
		{"ceilf", address(static_cast<float (*)(float)>(::ceilf))},
		{"cos", address(static_cast<double (*)(double)>(::cos))},
		{"cosf", address(static_cast<float (*)(float)>(::cosf))},
		{"exp", address(static_cast<double (*)(double)>(::exp))},
		{"expf", address(static_cast<float (*)(float)>(::expf))},
		{"floor", address(static_cast<double (*)(double)>(::floor))},
		{"floorf", address(static_cast<float (*)(float)>(::floorf))},
		{"fmod", address(static_cast<double (*)(double, double)>(::fmod))},
		{"fmodf", address(static_cast<float (*)(float, float)>(::fmodf))},
		{"log", address(static_cast<double (*)(double)>(::log))},
		{"logf", address(static_cast<float (*)(float)>(::logf))},
		{"pow", address(static_cast<double (*)(double, double)>(::pow))},
		{"powf", address(static_cast<float (*)(float, float)>(::powf))},
		{"rint", address(static_cast<double (*)(double)>(::rint))},
		{"rintf", address(static_cast<float (*)(float)>(::rintf))},
		{"sin", address(static_cast<double (*)(double)>(::sin))},
		{"sinf", address(static_cast<float (*)(float)>(::sinf))},
		{"sqrt", address(static_cast<double (*)(double)>(::sqrt))},
		{"sqrtf", address(static_cast<float (*)(float)>(::sqrtf))},
		{"trunc", address(static_cast<double (*)(double)>(::trunc))},
		{"truncf", address(static_cast<float (*)(float)>(::truncf))},
	};
	for (const Symbol &symbol : symbols)
		if (symbol.name == name)
			return symbol.address;
	return nullptr;
}

extern "C" void *stela_libc_map_code(size_t bytes);
extern "C" void stela_libc_unmap_code(void *code);

sys::MemoryBlock sys::Memory::allocateMappedMemory(size_t bytes, const MemoryBlock *, unsigned,
						   std::error_code &error)
{
	error = std::error_code();
	void *code = bytes ? stela_libc_map_code(bytes) : nullptr;
	if (!code) {
		if (bytes)
			error = make_error_code(errc::not_enough_memory);
		return MemoryBlock();
	}
	return MemoryBlock(code, (bytes + 4095) & ~size_t(4095));
}

std::error_code sys::Memory::releaseMappedMemory(MemoryBlock &block)
{
	if (block.base())
		stela_libc_unmap_code(block.base());
	block = MemoryBlock();
	return std::error_code();
}

std::error_code sys::Memory::protectMappedMemory(const MemoryBlock &, unsigned)
{
	return std::error_code();
}

/* x86 keeps its instruction caches coherent. */
void sys::Memory::InvalidateInstructionCache(const void *, size_t)
{
}

char sys::DynamicLibrary::Invalid;

void *sys::DynamicLibrary::getAddressOfSymbol(const char *)
{
	return nullptr;
}

/* The program is open already, and it is all this image can open. */
sys::DynamicLibrary sys::DynamicLibrary::getPermanentLibrary(const char *name, std::string *error)
{
	static char program;
	if (!name)
		return DynamicLibrary(&program);
	if (error)
		*error = "this image loads no libraries";
	return DynamicLibrary();
}

/* What MCJIT and the object readers link but llvmpipe's code never reaches:
 * it carries no debug information, no sanitizer, and only ELF of this target. */
JITEventListener *JITEventListener::createGDBRegistrationListener()
{
	return nullptr;
}

Expected<MemoryBufferRef> object::IRObjectFile::findBitcodeInObject(const ObjectFile &)
{
	return errorCodeToError(object::object_error::invalid_file_type);
}

Expected<std::unique_ptr<object::IRObjectFile>> object::IRObjectFile::create(MemoryBufferRef, LLVMContext &)
{
	return errorCodeToError(object::object_error::invalid_file_type);
}

llvm::Expected<std::unique_ptr<RISCVISAInfo>> RISCVISAInfo::parseNormalizedArchString(StringRef)
{
	return errorCodeToError(object::object_error::invalid_file_type);
}

std::vector<std::string> RISCVISAInfo::toFeatures(bool, bool) const
{
	return {};
}

namespace llvm::PPC {
StringRef normalizeCPUName(StringRef name)
{
	return name;
}
} // namespace llvm::PPC

ASanAccessInfo::ASanAccessInfo(int32_t packed)
	: Packed(packed), AccessSizeIndex(0), IsWrite(false), CompileKernel(false)
{
}

void llvm::getAddressSanitizerParams(const Triple &, int, bool, uint64_t *, int *, bool *)
{
	report_fatal_error("this image has no sanitizers");
}

Expected<SmallVector<std::unique_ptr<object::OffloadBinary>>>
object::OffloadBinary::create(MemoryBufferRef, std::optional<uint64_t>)
{
	return errorCodeToError(object::object_error::invalid_file_type);
}

StringRef object::IRObjectFile::getTargetTriple() const
{
	return StringRef();
}

void ModuleSymbolTable::CollectAsmSymbols(const Module &,
					  function_ref<void(StringRef, object::BasicSymbolRef::Flags)>)
{
}

/* Instruction selection requires this pass whatever a module holds, and its
 * unit needs C++ streams. llvmpipe's modules carry no debug information. */
char AssignmentTrackingAnalysis::ID = 0;
AnalysisKey DebugAssignmentTrackingAnalysis::Key;

AssignmentTrackingAnalysis::AssignmentTrackingAnalysis()
	: FunctionPass(ID), Results(std::make_unique<FunctionVarLocs>())
{
}

bool AssignmentTrackingAnalysis::runOnFunction(Function &function)
{
	if (isAssignmentTrackingEnabled(*function.getParent()))
		report_fatal_error("this image has no assignment tracking");
	return false;
}

INITIALIZE_PASS(AssignmentTrackingAnalysis, "debug-ata", "Assignment Tracking Analysis", false, true)

/* What Host.cpp asks of a Darwin triple, which this image never has. */
extern "C" int uname(struct utsname *)
{
	return -1;
}

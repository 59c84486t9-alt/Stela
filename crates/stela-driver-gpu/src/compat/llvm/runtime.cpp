// SPDX-License-Identifier: MIT
// What a C++ program expects below libc++, on compat/libc: allocation, the
// compiler's runtime calls and static constructors. Nothing here throws: the
// image has no unwinder, so a failed allocation is fatal, as LLVM's own
// `bad_alloc` handler makes it.
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <exception>
#include <new>
#include <stela/host.h>

using Constructor = void (*)();

/* The linker sorts each object's `.ctors$m` between these. Writable as those
 * are, or the two would land in a section of their own, around nothing. */
[[gnu::section(".ctors$a"), gnu::used]] static Constructor first = nullptr;
[[gnu::section(".ctors$z"), gnu::used]] static Constructor last = nullptr;

extern "C" {
void *__dso_handle = nullptr;

void stela_constructors()
{
	bool any = false;
	auto at = reinterpret_cast<std::uintptr_t>(&first) + sizeof(first);
	for (; at < reinterpret_cast<std::uintptr_t>(&last); at += sizeof(first)) {
		/* The linker may pad between objects' parts. */
		if (auto constructor = *reinterpret_cast<const Constructor *>(at)) {
			constructor();
			any = true;
		}
	}
	/* LLVM always has some: none means the bounds surround nothing. */
	if (!any)
		stela_libc_fatal("no static constructors between their bounds");
}

[[noreturn]] void __cxa_pure_virtual()
{
	stela_libc_fatal("a pure virtual function was called");
}

/* Nothing in the image ever exits. */
int __cxa_atexit(void (*)(void *), void *, void *)
{
	return 0;
}
}

const std::nothrow_t std::nothrow{};

std::exception::~exception() noexcept {}

const char *std::exception::what() const noexcept
{
	return "std::exception";
}

[[noreturn]] void std::terminate() noexcept
{
	stela_libc_fatal("std::terminate");
}

/* With exceptions off, the only `exception_ptr` is the null one. */
std::exception_ptr::~exception_ptr() noexcept {}

std::exception_ptr::exception_ptr(const exception_ptr &other) noexcept : __ptr_(other.__ptr_) {}

std::exception_ptr &std::exception_ptr::operator=(const exception_ptr &other) noexcept
{
	__ptr_ = other.__ptr_;
	return *this;
}

[[noreturn]] void std::rethrow_exception(exception_ptr)
{
	std::terminate();
}

static void *allocate(std::size_t size, std::size_t alignment)
{
	void *block = aligned_alloc(alignment, size ? size : 1);
	if (!block)
		stela_libc_fatal("LLVM is out of memory");
	return block;
}

void *operator new(std::size_t size)
{
	return allocate(size, __STDCPP_DEFAULT_NEW_ALIGNMENT__);
}

void *operator new[](std::size_t size)
{
	return allocate(size, __STDCPP_DEFAULT_NEW_ALIGNMENT__);
}

void *operator new(std::size_t size, std::align_val_t alignment)
{
	return allocate(size, static_cast<std::size_t>(alignment));
}

void *operator new[](std::size_t size, std::align_val_t alignment)
{
	return allocate(size, static_cast<std::size_t>(alignment));
}

void *operator new(std::size_t size, const std::nothrow_t &) noexcept
{
	return allocate(size, __STDCPP_DEFAULT_NEW_ALIGNMENT__);
}

void *operator new[](std::size_t size, const std::nothrow_t &) noexcept
{
	return allocate(size, __STDCPP_DEFAULT_NEW_ALIGNMENT__);
}

void *operator new(std::size_t size, std::align_val_t alignment, const std::nothrow_t &) noexcept
{
	return allocate(size, static_cast<std::size_t>(alignment));
}

void *operator new[](std::size_t size, std::align_val_t alignment, const std::nothrow_t &) noexcept
{
	return allocate(size, static_cast<std::size_t>(alignment));
}

void operator delete(void *block) noexcept
{
	free(block);
}

void operator delete[](void *block) noexcept
{
	free(block);
}

void operator delete(void *block, std::size_t) noexcept
{
	free(block);
}

void operator delete[](void *block, std::size_t) noexcept
{
	free(block);
}

void operator delete(void *block, std::align_val_t) noexcept
{
	free(block);
}

void operator delete[](void *block, std::align_val_t) noexcept
{
	free(block);
}

void operator delete(void *block, std::size_t, std::align_val_t) noexcept
{
	free(block);
}

void operator delete[](void *block, std::size_t, std::align_val_t) noexcept
{
	free(block);
}

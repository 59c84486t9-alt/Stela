/*
 * Whether the guest's global preferences already answer CoreVideo's
 * `disable-buffer-compression`, in C without a library, so the kext
 * (compression.cpp) and the host's tests (tests/compression_policy.c) run the
 * same code.
 *
 * macOS offers Apple's universal lossless buffer formats ('&BGA' and the
 * like) by SoC generation alone. StelaGPU stores them plain, which only GPU
 * writers and readers agree on, and a process that paints them on the CPU,
 * such as one whose sandbox keeps the Metal plugin out, leaves rows nothing
 * can read. CoreVideo's own default `disable-buffer-compression`, read from
 * the any-user global domain, makes it offer plain formats instead.
 */
#pragma once

/* CoreVideo's key, which its areUniversalCompressionFormatsSupported reads. */
#define STELA_COMPRESSION_KEY "disable-buffer-compression"

/*
 * Whether `length` bytes of a property list, binary or XML, name `key`. A
 * binary list keeps an ASCII key's bytes as they are, so any value the owner
 * gave it counts, and a key named nowhere does not.
 */
static inline int
stela_compression_key_named(const char *bytes, int length, const char *key)
{
	int size = 0;
	while (key[size]) {
		size++;
	}
	if (!bytes || size == 0 || length < size) {
		return 0;
	}
	for (int start = 0; start <= length - size; start++) {
		int matched = 0;
		while (matched < size && bytes[start + matched] == key[matched]) {
			matched++;
		}
		if (matched == size) {
			return 1;
		}
	}
	return 0;
}

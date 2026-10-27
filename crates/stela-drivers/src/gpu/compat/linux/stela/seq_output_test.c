// SPDX-License-Identifier: MIT
/* Actual original seq buffer-output helpers. Buffers are owned by this test;
 * no filesystem, process, credentials, user-copy or mapping authority exists. */
#include <linux/seq_file.h>
#include <linux/stdarg.h>
#include <linux/string.h>
#include <stela/test.h>

static unsigned int checked;

static void binary_writes(void)
{
	u8 guarded[68], expected[68], source[68];
	for (unsigned int i = 0; i < sizeof(source); i++)
		source[i] = (u8)(i ^ 0x59U);
	for (size_t size = 0; size <= 64; size++) {
		for (size_t count = 0; count <= size; count++) {
			for (size_t len = 0; len <= 66; len++) {
				memset(guarded, 0xcc, sizeof(guarded));
				memcpy(expected, guarded, sizeof(expected));
				struct seq_file seq = {.buf = (char *)guarded + 1,
					.size = size, .count = count};
				bool success = count + len < size;
				if (success)
					memcpy(expected + 1 + count, source, len);
				int result = seq_write(&seq, source, len);
				assert(result == (success ? 0 : -1));
				assert(seq.count == (success ? count + len : size));
				assert(seq_has_overflowed(&seq) == !success);
				assert(!memcmp(guarded, expected, sizeof(guarded)));
				checked++;
			}
		}
	}
}

static void strings(void)
{
	char text[67];
	u8 guarded[68], expected[68];
	for (size_t len = 0; len <= 66; len++) {
		memset(text, 'a', len);
		text[len] = '\0';
		for (size_t size = 0; size <= 64; size++) {
			for (size_t count = 0; count <= size; count++) {
				memset(guarded, 0xa7, sizeof(guarded));
				memcpy(expected, guarded, sizeof(expected));
				struct seq_file seq = {.buf = (char *)guarded + 1,
					.size = size, .count = count};
				bool success = count + len < size;
				if (success)
					memcpy(expected + 1 + count, text, len);
				__seq_puts(&seq, text);
				assert(seq.count == (success ? count + len : size));
				assert(!memcmp(guarded, expected, sizeof(guarded)));
				checked++;
			}
		}
	}
}

static void variadic(struct seq_file *seq, const char *format, ...)
{
	va_list args;
	va_start(args, format);
	seq_vprintf(seq, format, args);
	va_end(args);
}

static void formatted(void)
{
	char text[67];
	u8 guarded[68], expected[68];
	for (size_t len = 0; len <= 66; len++) {
		memset(text, 'k', len);
		text[len] = '\0';
		for (size_t size = 0; size <= 64; size++) {
			for (size_t count = 0; count <= size; count++) {
				for (unsigned int direct = 0; direct < 2; direct++) {
					memset(guarded, 0x39, sizeof(guarded));
					memcpy(expected, guarded, sizeof(expected));
					struct seq_file seq = {.buf = (char *)guarded + 1,
						.size = size, .count = count};
					size_t room = size - count;
					if (room) {
						size_t copied = len < room ? len : room - 1;
						memcpy(expected + 1 + count, text, copied);
						expected[1 + count + copied] = 0;
					}
					if (direct)
						seq_printf(&seq, "%s", text);
					else
						variadic(&seq, "%s", text);
					assert(seq.count == (count + len < size ? count + len : size));
					assert(!memcmp(guarded, expected, sizeof(guarded)));
					checked++;
				}
			}
		}
	}

	char buffer[64] = "pre";
	struct seq_file seq = {.buf = buffer, .size = sizeof(buffer), .count = 3};
	seq_printf(&seq, "%u/%d/%s", 42U, -17, "alpha");
	assert(seq.count == 15 && !strcmp(buffer, "pre42/-17/alpha"));
	/* Once overflowed, a later append neither consumes the suffix nor restarts
	 * the stream. The caller must perform its real resize/retry lifecycle. */
	seq.count = seq.size;
	char before[64];
	memcpy(before, buffer, sizeof(before));
	seq_printf(&seq, "must-not-appear");
	assert(seq.count == seq.size && !memcmp(before, buffer, sizeof(before)));
}

int main(void)
{
	binary_writes();
	strings();
	formatted();
	printf("Linux seq output: %u actual binary/string/printf/vprintf guarded cases\n", checked);
	return 0;
}

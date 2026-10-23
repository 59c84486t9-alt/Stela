// SPDX-License-Identifier: MIT
/* Linux's formatted output, as lib/vsprintf.c defines it for this
 * configuration: without KALLSYMS a symbol prints as its address, without
 * SYMBOLIC_ERRNAME an error pointer as its number, and pointers print
 * unhashed, as with no_hash_pointers. Other %p extensions are unsupported. */
#include <linux/err.h>
#include <linux/minmax.h>
#include <asm/page.h>
#include <linux/slab.h>
#include <linux/sprintf.h>
#include <linux/string.h>
#include <stela/linux.h>

enum {
	LEFT = 1 << 0,
	PLUS = 1 << 1,
	SPACE = 1 << 2,
	SPECIAL = 1 << 3,
	ZEROPAD = 1 << 4,
	SMALL = 1 << 5,
	SIGN = 1 << 6,
};

static bool digit(char c)
{
	return c >= '0' && c <= '9';
}

static bool alphanumeric(char c)
{
	return digit(c) || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

struct spec {
	unsigned int flags, base;
	int width, precision;
};

/* The output; length counts what would be written without a limit. */
struct out {
	char *buf;
	size_t size, length;
};

static void put(struct out *out, char c)
{
	if (out->length + 1 < out->size)
		out->buf[out->length] = c;
	out->length++;
}

static void pad(struct out *out, char c, int count)
{
	while (count-- > 0)
		put(out, c);
}

static void string(struct out *out, const char *s, struct spec spec)
{
	size_t length = strnlen(s, spec.precision < 0 ? SIZE_MAX : (size_t)spec.precision);
	int fill = spec.width > (int)length ? spec.width - (int)length : 0;
	if (!(spec.flags & LEFT))
		pad(out, ' ', fill);
	for (size_t i = 0; i < length; i++)
		put(out, s[i]);
	if (spec.flags & LEFT)
		pad(out, ' ', fill);
}

static void number(struct out *out, unsigned long long value, bool negative, struct spec spec)
{
	const char *digits = spec.flags & SMALL ? "0123456789abcdef" : "0123456789ABCDEF";
	char tmp[24];
	int count = 0;
	char sign = 0;
	if (spec.flags & SIGN) {
		if (negative)
			sign = '-';
		else if (spec.flags & PLUS)
			sign = '+';
		else if (spec.flags & SPACE)
			sign = ' ';
	}
	const char *prefix = !(spec.flags & SPECIAL) ? "" :
			     spec.base == 16 ? (spec.flags & SMALL ? "0x" : "0X") :
			     spec.base == 8 && value ? "0" : "";
	do {
		tmp[count++] = digits[value % spec.base];
		value /= spec.base;
	} while (value);
	int precision = spec.precision > count ? spec.precision : count;
	int width = spec.width - precision - (sign != 0) - (int)strlen(prefix);
	bool zeros = (spec.flags & ZEROPAD) && !(spec.flags & LEFT);
	if (!(spec.flags & LEFT) && !zeros)
		pad(out, ' ', width);
	if (sign)
		put(out, sign);
	for (const char *p = prefix; *p; p++)
		put(out, *p);
	if (zeros)
		pad(out, '0', width);
	pad(out, '0', precision - count);
	while (count)
		put(out, tmp[--count]);
	if (spec.flags & LEFT)
		pad(out, ' ', width);
}

/* An address as Linux's special_hex_number prints it. */
static void address(struct out *out, unsigned long long value, size_t bytes)
{
	number(out, value, false, (struct spec){
		.flags = SPECIAL | SMALL | ZEROPAD, .base = 16,
		.width = 2 + 2 * (int)bytes, .precision = -1,
	});
}

static void format(struct out *out, const char *fmt, va_list args);

static const char *pointer(struct out *out, const char *fmt, const void *ptr, struct spec spec)
{
	switch (*fmt) {
	case 'S':
	case 's':
	case 'B':
		fmt++;
		/* Offset and build ID suffixes name parts of a symbol. */
		while (*fmt == 'R' || *fmt == 'b')
			fmt++;
		address(out, (uintptr_t)ptr, sizeof(ptr));
		return fmt;
	case 'e':
		if (IS_ERR(ptr))
			number(out, (unsigned long long)-PTR_ERR(ptr), true,
			       (struct spec){.flags = SIGN, .base = 10, .precision = -1});
		else
			address(out, (uintptr_t)ptr, sizeof(ptr));
		return fmt + 1;
	case 'V': {
		const struct va_format *vaf = ptr;
		va_list va;
		va_copy(va, *vaf->va);
		format(out, vaf->fmt, va);
		va_end(va);
		return fmt + 1;
	}
	case 'a':
		if (fmt[1] == 'd') {
			address(out, *(const dma_addr_t *)ptr, sizeof(dma_addr_t));
			return fmt + 2;
		}
		address(out, *(const phys_addr_t *)ptr, sizeof(phys_addr_t));
		return fmt[1] == 'p' ? fmt + 2 : fmt + 1;
	case 'x':
		fmt++;
		break;
	default:
		if (alphanumeric(*fmt)) {
			stela_linux_unsupported("vsnprintf pointer extension");
			while (alphanumeric(*fmt))
				fmt++;
		}
		break;
	}
	if (spec.width < 0) {
		spec.width = 2 * (int)sizeof(ptr);
		spec.flags |= ZEROPAD;
	}
	spec.flags |= SMALL;
	spec.base = 16;
	number(out, (uintptr_t)ptr, false, spec);
	return fmt;
}

static void format(struct out *out, const char *fmt, va_list args)
{
	while (*fmt) {
		if (*fmt != '%') {
			put(out, *fmt++);
			continue;
		}
		fmt++;
		struct spec spec = {.base = 10, .width = -1, .precision = -1};
		for (;; fmt++) {
			if (*fmt == '-')
				spec.flags |= LEFT;
			else if (*fmt == '+')
				spec.flags |= PLUS;
			else if (*fmt == ' ')
				spec.flags |= SPACE;
			else if (*fmt == '#')
				spec.flags |= SPECIAL;
			else if (*fmt == '0')
				spec.flags |= ZEROPAD;
			else
				break;
		}
		if (*fmt == '*') {
			spec.width = va_arg(args, int);
			if (spec.width < 0) {
				spec.width = -spec.width;
				spec.flags |= LEFT;
			}
			fmt++;
		} else if (digit(*fmt)) {
			spec.width = 0;
			while (digit(*fmt))
				spec.width = spec.width * 10 + (*fmt++ - '0');
		}
		if (*fmt == '.') {
			fmt++;
			spec.precision = 0;
			if (*fmt == '*') {
				spec.precision = va_arg(args, int);
				fmt++;
			} else {
				while (digit(*fmt))
					spec.precision = spec.precision * 10 + (*fmt++ - '0');
			}
			if (spec.precision < 0)
				spec.precision = 0;
		}
		char length = 0;
		if (*fmt == 'h' || *fmt == 'l') {
			length = *fmt++;
			if (*fmt == length) {
				length = length == 'h' ? 'H' : 'L';
				fmt++;
			}
		} else if (*fmt == 'z' || *fmt == 'Z' || *fmt == 't' || *fmt == 'j' ||
			   *fmt == 'L') {
			length = *fmt == 'L' ? 'L' : 'z';
			fmt++;
		}
		unsigned long long value;
		bool negative = false;
		switch (*fmt) {
		case 'c':
			pad(out, ' ', (spec.flags & LEFT) ? 0 : spec.width - 1);
			put(out, (char)va_arg(args, int));
			pad(out, ' ', (spec.flags & LEFT) ? spec.width - 1 : 0);
			fmt++;
			continue;
		case 's': {
			const char *s = va_arg(args, const char *);
			if (!s)
				s = "(null)";
			else if ((uintptr_t)s < PAGE_SIZE || IS_ERR_VALUE(s))
				s = "(efault)";
			string(out, s, spec);
			fmt++;
			continue;
		}
		case 'p':
			fmt = pointer(out, fmt + 1, va_arg(args, const void *), spec);
			continue;
		case '%':
			put(out, '%');
			fmt++;
			continue;
		case 'o':
			spec.base = 8;
			break;
		case 'x':
			spec.flags |= SMALL;
			fallthrough;
		case 'X':
			spec.base = 16;
			break;
		case 'd':
		case 'i':
			spec.flags |= SIGN;
			break;
		case 'u':
			break;
		default:
			/* Linux stops at a conversion it does not know, %n included,
			 * as the arguments after it cannot be found. */
			stela_linux_unsupported("vsnprintf conversion");
			return;
		}
		fmt++;
		if (spec.flags & SIGN) {
			long long signed_value =
				length == 'L' ? va_arg(args, long long) :
				length == 'l' || length == 'z' ? va_arg(args, long) :
				length == 'H' ? (signed char)va_arg(args, int) :
				length == 'h' ? (short)va_arg(args, int) : va_arg(args, int);
			negative = signed_value < 0;
			value = negative ? 0ULL - (unsigned long long)signed_value :
					   (unsigned long long)signed_value;
		} else {
			value = length == 'L' ? va_arg(args, unsigned long long) :
				length == 'l' || length == 'z' ? va_arg(args, unsigned long) :
				length == 'H' ? (unsigned char)va_arg(args, unsigned int) :
				length == 'h' ? (unsigned short)va_arg(args, unsigned int) :
				va_arg(args, unsigned int);
		}
		number(out, value, negative, spec);
	}
}

int vsnprintf(char *buf, size_t size, const char *fmt, va_list args)
{
	struct out out = {.buf = buf, .size = size};
	va_list va;
	va_copy(va, args);
	format(&out, fmt, va);
	va_end(va);
	if (size)
		buf[min(out.length, size - 1)] = '\0';
	return (int)out.length;
}

int snprintf(char *buf, size_t size, const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	int length = vsnprintf(buf, size, fmt, args);
	va_end(args);
	return length;
}

int vscnprintf(char *buf, size_t size, const char *fmt, va_list args)
{
	int length = vsnprintf(buf, size, fmt, args);
	if (likely((size_t)length < size))
		return length;
	return size ? (int)size - 1 : 0;
}

int scnprintf(char *buf, size_t size, const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	int length = vscnprintf(buf, size, fmt, args);
	va_end(args);
	return length;
}

char *kvasprintf(gfp_t gfp, const char *fmt, va_list args)
{
	va_list va;
	va_copy(va, args);
	int length = vsnprintf(NULL, 0, fmt, va);
	va_end(va);
	char *buf = kmalloc((size_t)length + 1, gfp);
	if (buf)
		vsnprintf(buf, (size_t)length + 1, fmt, args);
	return buf;
}

char *kasprintf(gfp_t gfp, const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	char *buf = kvasprintf(gfp, fmt, args);
	va_end(args);
	return buf;
}

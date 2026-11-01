// SPDX-License-Identifier: MIT
/* Formatted output into memory, and the two streams that reach the host's log.
 * A memory stream is the only file that can be opened. */
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <math.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stela/host.h>

struct __file {
	/* Null for the log. */
	char **buffer;
	size_t *size;
	size_t capacity;
};

static struct __file log_stream;
FILE *const stdin = &log_stream;
FILE *const stdout = &log_stream;
FILE *const stderr = &log_stream;

/* Formatted characters go through one of these. */
struct sink {
	char *at;
	size_t left;
	size_t total;
};

static void put(struct sink *sink, char c)
{
	if (sink->left > 1) {
		*sink->at++ = c;
		sink->left--;
	}
	sink->total++;
}

static void put_padded(struct sink *sink, const char *prefix, const char *text, size_t size,
		       int width, bool left, char fill)
{
	size_t prefix_size = strlen(prefix);
	size_t used = prefix_size + size;
	size_t pad = width > 0 && (size_t)width > used ? (size_t)width - used : 0;
	if (!left && fill == ' ')
		for (size_t at = 0; at < pad; at++)
			put(sink, ' ');
	for (size_t at = 0; at < prefix_size; at++)
		put(sink, prefix[at]);
	if (!left && fill == '0')
		for (size_t at = 0; at < pad; at++)
			put(sink, '0');
	for (size_t at = 0; at < size; at++)
		put(sink, text[at]);
	if (left)
		for (size_t at = 0; at < pad; at++)
			put(sink, ' ');
}

static size_t integer_text(char *end, unsigned long long value, unsigned int base, bool upper)
{
	const char *digits = upper ? "0123456789ABCDEF" : "0123456789abcdef";
	char *at = end;
	do {
		*--at = digits[value % base];
		value /= base;
	} while (value);
	return (size_t)(end - at);
}

/* `digits` decimal places of a non-negative value, rounded, into `out`. */
static size_t fixed_text(char *out, size_t room, long double value, int digits)
{
	long double round = 0.5L;
	for (int at = 0; at < digits; at++)
		round /= 10;
	value += round;
	long double whole = floorl(value), fraction = value - whole;
	char integer[5000];
	char *end = integer + sizeof(integer);
	char *at = end;
	do {
		long double next = floorl(whole / 10);
		*--at = (char)('0' + (int)(whole - next * 10));
		whole = next;
	} while (whole > 0 && at > integer);
	size_t size = (size_t)(end - at);
	if (size > room)
		size = room;
	memcpy(out, at, size);
	if (digits && size < room)
		out[size++] = '.';
	for (int place = 0; place < digits && size < room; place++) {
		fraction *= 10;
		int digit = (int)fraction;
		out[size++] = (char)('0' + digit);
		fraction -= digit;
	}
	return size;
}

static int decimal_exponent(long double *value)
{
	int exponent = 0;
	if (*value == 0)
		return 0;
	while (*value >= 10) {
		*value /= 10;
		exponent++;
	}
	while (*value < 1) {
		*value *= 10;
		exponent--;
	}
	return exponent;
}

static size_t exponent_text(char *out, size_t room, long double value, int digits, bool upper)
{
	int exponent = decimal_exponent(&value);
	long double round = 0.5L;
	for (int at = 0; at < digits; at++)
		round /= 10;
	if (value + round >= 10) {
		value /= 10;
		exponent++;
	}
	size_t size = fixed_text(out, room - 8, value, digits);
	out[size++] = upper ? 'E' : 'e';
	out[size++] = exponent < 0 ? '-' : '+';
	if (exponent < 0)
		exponent = -exponent;
	char tail[8];
	size_t count = integer_text(tail + sizeof(tail), (unsigned int)exponent, 10, false);
	if (count < 2)
		out[size++] = '0';
	memcpy(out + size, tail + sizeof(tail) - count, count);
	return size + count;
}

static size_t general_text(char *out, size_t room, long double value, int digits, bool upper,
			   bool alternate)
{
	if (!digits)
		digits = 1;
	long double scaled = value;
	int exponent = decimal_exponent(&scaled);
	size_t size;
	if (exponent < -4 || exponent >= digits)
		size = exponent_text(out, room, value, digits - 1, upper);
	else
		size = fixed_text(out, room, value, digits - 1 - exponent);
	if (alternate || !memchr(out, '.', size))
		return size;
	size_t tail = 0;
	char *mark = memchr(out, upper ? 'E' : 'e', size);
	if (mark) {
		tail = size - (size_t)(mark - out);
		memmove(out + size, mark, 0);
	}
	size_t end = size - tail;
	while (out[end - 1] == '0')
		end--;
	if (out[end - 1] == '.')
		end--;
	memmove(out + end, out + size - tail, tail);
	return end + tail;
}

int vsnprintf(char *buffer, size_t size, const char *format, va_list arguments)
{
	struct sink sink = {buffer, size ? size : 1, 0};
	char text[5200];
	for (; *format; format++) {
		if (*format != '%') {
			put(&sink, *format);
			continue;
		}
		bool left = false, plus = false, space = false, alternate = false, zero = false;
		for (;; format++) {
			char flag = format[1];
			if (flag == '-')
				left = true;
			else if (flag == '+')
				plus = true;
			else if (flag == ' ')
				space = true;
			else if (flag == '#')
				alternate = true;
			else if (flag == '0')
				zero = true;
			else
				break;
		}
		format++;
		int width = 0, precision = -1;
		if (*format == '*') {
			width = va_arg(arguments, int);
			if (width < 0) {
				left = true;
				width = -width;
			}
			format++;
		} else {
			while (*format >= '0' && *format <= '9')
				width = width * 10 + *format++ - '0';
		}
		if (*format == '.') {
			format++;
			precision = 0;
			if (*format == '*') {
				precision = va_arg(arguments, int);
				format++;
			} else {
				while (*format >= '0' && *format <= '9')
					precision = precision * 10 + *format++ - '0';
			}
		}
		int length = 0; /* -2 hh, -1 h, 1 l or z or t or j, 2 L. */
		for (;; format++) {
			if (*format == 'h')
				length--;
			else if (*format == 'l' || *format == 'z' || *format == 't' ||
				 *format == 'j' || *format == 'q')
				length = 1;
			else if (*format == 'L')
				length = 2;
			else
				break;
		}
		char conversion = *format;
		char *end = text + sizeof(text);
		const char *prefix = "";
		size_t count;
		switch (conversion) {
		case 'd':
		case 'i': {
			long long value = length >= 1 ? va_arg(arguments, long) :
							va_arg(arguments, int);
			if (length == -1)
				value = (short)value;
			else if (length <= -2)
				value = (signed char)value;
			prefix = value < 0 ? "-" : plus ? "+" : space ? " " : "";
			unsigned long long magnitude =
				value < 0 ? -(unsigned long long)value : (unsigned long long)value;
			count = integer_text(end, magnitude, 10, false);
			break;
		}
		case 'u':
		case 'x':
		case 'X':
		case 'o': {
			unsigned long long value = length >= 1 ? va_arg(arguments, unsigned long) :
								 va_arg(arguments, unsigned int);
			if (length == -1)
				value = (unsigned short)value;
			else if (length <= -2)
				value = (unsigned char)value;
			unsigned int base = conversion == 'o' ? 8 : conversion == 'u' ? 10 : 16;
			if (alternate && value && base == 16)
				prefix = conversion == 'x' ? "0x" : "0X";
			count = integer_text(end, value, base, conversion == 'X');
			break;
		}
		case 'p':
			prefix = "0x";
			count = integer_text(end, (unsigned long long)va_arg(arguments, void *), 16,
					     false);
			break;
		case 'c':
			text[0] = (char)va_arg(arguments, int);
			put_padded(&sink, "", text, 1, width, left, ' ');
			continue;
		case 's': {
			const char *string = va_arg(arguments, const char *);
			if (!string)
				string = "(null)";
			size_t limit = precision < 0 ? SIZE_MAX : (size_t)precision;
			put_padded(&sink, "", string, strnlen(string, limit), width, left, ' ');
			continue;
		}
		case 'f':
		case 'F':
		case 'e':
		case 'E':
		case 'g':
		case 'G':
		case 'a':
		case 'A': {
			long double value = length == 2 ? va_arg(arguments, long double) :
							  va_arg(arguments, double);
			bool upper = conversion < 'a';
			bool negative = signbit(value);
			if (negative)
				value = -value;
			prefix = negative ? "-" : plus ? "+" : space ? " " : "";
			if (value != value || value > __LDBL_MAX__) {
				const char *name = value != value ? (upper ? "NAN" : "nan") :
								    (upper ? "INF" : "inf");
				put_padded(&sink, prefix, name, 3, width, left, ' ');
				continue;
			}
			int digits = precision < 0 ? 6 : precision;
			if ((conversion | 0x20) == 'f')
				count = fixed_text(text, sizeof(text), value, digits);
			else if ((conversion | 0x20) == 'e' || (conversion | 0x20) == 'a')
				count = exponent_text(text, sizeof(text), value, digits, upper);
			else
				count = general_text(text, sizeof(text), value, digits, upper,
						     alternate);
			put_padded(&sink, prefix, text, count, width, left, zero ? '0' : ' ');
			continue;
		}
		case '%':
			put(&sink, '%');
			continue;
		default:
			put(&sink, '%');
			put(&sink, conversion);
			continue;
		}
		const char *digits = end - count;
		if (precision >= 0 && (size_t)precision > count) {
			size_t pad = (size_t)precision - count;
			digits -= pad;
			memset((char *)digits, '0', pad);
			count += pad;
		}
		put_padded(&sink, prefix, digits, count, width, left,
			   zero && precision < 0 ? '0' : ' ');
	}
	if (size)
		*sink.at = 0;
	return (int)sink.total;
}

int vsprintf(char *buffer, const char *format, va_list arguments)
{
	return vsnprintf(buffer, SIZE_MAX, format, arguments);
}

int snprintf(char *buffer, size_t size, const char *format, ...)
{
	va_list arguments;
	va_start(arguments, format);
	int result = vsnprintf(buffer, size, format, arguments);
	va_end(arguments);
	return result;
}

int sprintf(char *buffer, const char *format, ...)
{
	va_list arguments;
	va_start(arguments, format);
	int result = vsprintf(buffer, format, arguments);
	va_end(arguments);
	return result;
}

int vasprintf(char **buffer, const char *format, va_list arguments)
{
	va_list measure;
	va_copy(measure, arguments);
	int size = vsnprintf(NULL, 0, format, measure);
	va_end(measure);
	*buffer = malloc((size_t)size + 1);
	if (!*buffer)
		return -1;
	return vsnprintf(*buffer, (size_t)size + 1, format, arguments);
}

int asprintf(char **buffer, const char *format, ...)
{
	va_list arguments;
	va_start(arguments, format);
	int result = vasprintf(buffer, format, arguments);
	va_end(arguments);
	return result;
}

static size_t write_stream(FILE *file, const char *text, size_t size)
{
	if (!file->buffer) {
		stela_libc_log(text, size);
		return size;
	}
	size_t used = *file->size;
	if (used + size + 1 > file->capacity) {
		size_t capacity = (used + size + 1) * 2;
		char *grown = realloc(*file->buffer, capacity);
		if (!grown)
			return 0;
		*file->buffer = grown;
		file->capacity = capacity;
	}
	memcpy(*file->buffer + used, text, size);
	(*file->buffer)[used + size] = 0;
	*file->size = used + size;
	return size;
}

int vfprintf(FILE *file, const char *format, va_list arguments)
{
	char *text;
	int size = vasprintf(&text, format, arguments);
	if (size < 0)
		return -1;
	write_stream(file, text, (size_t)size);
	free(text);
	return size;
}

int fprintf(FILE *file, const char *format, ...)
{
	va_list arguments;
	va_start(arguments, format);
	int result = vfprintf(file, format, arguments);
	va_end(arguments);
	return result;
}

int vprintf(const char *format, va_list arguments)
{
	return vfprintf(stdout, format, arguments);
}

int printf(const char *format, ...)
{
	va_list arguments;
	va_start(arguments, format);
	int result = vprintf(format, arguments);
	va_end(arguments);
	return result;
}

int fputs(const char *text, FILE *file)
{
	return (int)write_stream(file, text, strlen(text));
}

int puts(const char *text)
{
	fputs(text, stdout);
	return fputs("\n", stdout);
}

int fputc(int c, FILE *file)
{
	char byte = (char)c;
	return write_stream(file, &byte, 1) ? (unsigned char)c : EOF;
}

int putchar(int c)
{
	return fputc(c, stdout);
}

size_t fwrite(const void *buffer, size_t size, size_t count, FILE *file)
{
	return size ? write_stream(file, buffer, size * count) / size : 0;
}

FILE *open_memstream(char **buffer, size_t *size)
{
	FILE *file = calloc(1, sizeof(*file));
	if (!file)
		return NULL;
	*buffer = calloc(1, 1);
	*size = 0;
	file->buffer = buffer;
	file->size = size;
	file->capacity = 1;
	return file;
}

int fclose(FILE *file)
{
	if (file != &log_stream)
		free(file);
	return 0;
}

int fflush(FILE *file)
{
	(void)file;
	return 0;
}

FILE *fopen(const char *path, const char *mode)
{
	(void)path;
	(void)mode;
	errno = ENOENT;
	return NULL;
}

FILE *fdopen(int fd, const char *mode)
{
	(void)fd;
	(void)mode;
	errno = EBADF;
	return NULL;
}

FILE *popen(const char *command, const char *mode)
{
	(void)command;
	(void)mode;
	errno = ENOSYS;
	return NULL;
}

int pclose(FILE *file)
{
	(void)file;
	errno = EBADF;
	return -1;
}

size_t fread(void *buffer, size_t size, size_t count, FILE *file)
{
	(void)buffer;
	(void)size;
	(void)count;
	(void)file;
	return 0;
}

int fseek(FILE *file, long offset, int whence)
{
	(void)file;
	(void)offset;
	(void)whence;
	return -1;
}

long ftell(FILE *file)
{
	return file->buffer ? (long)*file->size : -1;
}

int ferror(FILE *file)
{
	(void)file;
	return 0;
}

int feof(FILE *file)
{
	(void)file;
	return 1;
}

int fileno(FILE *file)
{
	(void)file;
	errno = EBADF;
	return -1;
}

char *fgets(char *buffer, int size, FILE *file)
{
	(void)buffer;
	(void)size;
	(void)file;
	return NULL;
}

int getc(FILE *file)
{
	(void)file;
	return EOF;
}

void rewind(FILE *file)
{
	(void)file;
}

int remove(const char *path)
{
	(void)path;
	errno = ENOENT;
	return -1;
}

int rename(const char *from, const char *to)
{
	(void)from;
	(void)to;
	errno = ENOENT;
	return -1;
}

void perror(const char *prefix)
{
	fprintf(stderr, "%s: %s\n", prefix, strerror(errno));
}

/* What Mesa scans is unsigned numbers and words between literal text. */
static const char *skip_space(const char *text)
{
	while (isspace((unsigned char)*text))
		text++;
	return text;
}

int sscanf(const char *input, const char *format, ...)
{
	va_list arguments;
	va_start(arguments, format);
	const char *start = input;
	int matched = 0;
	for (; *format; format++) {
		if (isspace((unsigned char)*format)) {
			input = skip_space(input);
			continue;
		}
		if (*format != '%') {
			if (*input != *format)
				break;
			input++;
			continue;
		}
		format++;
		size_t width = SIZE_MAX;
		if (isdigit((unsigned char)*format))
			width = strtoul(format, (char **)&format, 10);
		bool wide = false;
		while (*format == 'l' || *format == 'z' || *format == 'h') {
			wide = *format != 'h';
			format++;
		}
		char *end;
		if (*format == 'n') {
			*va_arg(arguments, int *) = (int)(input - start);
			continue;
		}
		if (*format == 'c') {
			if (!*input)
				break;
			*va_arg(arguments, char *) = *input++;
			matched++;
			continue;
		}
		input = skip_space(input);
		if (*format == 's') {
			if (!*input)
				break;
			char *out = va_arg(arguments, char *);
			while (*input && !isspace((unsigned char)*input) && width--)
				*out++ = *input++;
			*out = 0;
			matched++;
			continue;
		}
		if (*format == 'f' || *format == 'g' || *format == 'e') {
			double value = strtod(input, &end);
			if (end == input)
				break;
			input = end;
			if (wide)
				*va_arg(arguments, double *) = value;
			else
				*va_arg(arguments, float *) = (float)value;
			matched++;
			continue;
		}
		int base = *format == 'x' ? 16 : *format == 'o' ? 8 : *format == 'i' ? 0 : 10;
		unsigned long long value = strtoull(input, &end, base);
		if (end == input)
			break;
		input = end;
		if (wide)
			*va_arg(arguments, unsigned long *) = value;
		else
			*va_arg(arguments, unsigned int *) = (unsigned int)value;
		matched++;
	}
	va_end(arguments);
	return matched;
}

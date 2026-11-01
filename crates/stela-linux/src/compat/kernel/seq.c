// SPDX-License-Identifier: MIT
/* What Linux's text buffers need beyond fs/seq_output.c, following Linux
 * cc9de5d4b5ab6459f5774946aa3195ad51236fa8 lib/seq_buf.c and fs/seq_file.c. */
#include <linux/seq_buf.h>
#include <linux/seq_file.h>
#include <linux/sprintf.h>

int seq_buf_printf(struct seq_buf *s, const char *fmt, ...)
{
	va_list arguments;
	int written = -1;

	va_start(arguments, fmt);
	if (s->len < s->size) {
		int length = vsnprintf(s->buffer + s->len, s->size - s->len, fmt, arguments);

		if (s->len + (size_t)length < s->size) {
			s->len += (size_t)length;
			written = 0;
		}
	}
	va_end(arguments);
	if (written)
		seq_buf_set_overflow(s);
	return written;
}

void seq_putc(struct seq_file *m, char c)
{
	if (m->count < m->size)
		m->buf[m->count++] = c;
}

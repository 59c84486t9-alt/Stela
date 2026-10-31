/*
 * Shader logging. A log state's buffer holds what `air_log.c` appends: records
 * that carry their own strings and arguments. No record is complete while a
 * command buffer using the state runs, so they are read once none does, and a
 * state that never rests fills and drops messages, which it reports once.
 * os_log's formats are printf's, with OpenCL's `%vN` before the length.
 */
#include "Bundle.h"

/* The words of `air_log.c`. */
typedef struct {
	uint32_t next, capacity, reserved[2];
} StelaLogBuffer;

typedef struct {
	uint32_t bytes, level, subsystem, category, format, arguments;
} StelaLogRecord;

/* How `os_log_type_t` values rank as MTLLogLevel. */
static NSInteger log_level(uint32_t type)
{
	switch (type) {
	case 2:
		return MTLLogLevelDebug;
	case 1:
		return MTLLogLevelInfo;
	case 16:
		return MTLLogLevelError;
	case 17:
		return MTLLogLevelFault;
	default:
		return MTLLogLevelNotice;
	}
}

typedef struct {
	const uint8_t *at, *end;
} StelaLogArguments;

static uint64_t next_argument(StelaLogArguments *arguments, size_t bytes)
{
	uint64_t value = 0;
	if ((size_t)(arguments->end - arguments->at) >= bytes) {
		memcpy(&value, arguments->at, bytes);
		arguments->at += bytes;
	}
	return value;
}

/* Appends one lane under the conversion `spec`, whose last character is the
 * conversion: floats are 32-bit, and `l` integers and pointers 64-bit. */
static void append_lane(NSMutableData *out, const char *spec, size_t bytes, StelaLogArguments *arguments)
{
	char text[128];
	char conversion = spec[bytes - 1];
	int length;
	if (strchr("fFeEgGaA", conversion)) {
		uint32_t bits = (uint32_t)next_argument(arguments, 4);
		float value;
		memcpy(&value, &bits, sizeof(value));
		length = snprintf(text, sizeof(text), spec, (double)value);
	} else if (conversion == 'p' || memchr(spec, 'l', bytes)) {
		length = snprintf(text, sizeof(text), spec, (unsigned long long)next_argument(arguments, 8));
	} else {
		length = snprintf(text, sizeof(text), spec, (unsigned)next_argument(arguments, 4));
	}
	[out appendBytes:text length:length < (int)sizeof(text) ? length : sizeof(text) - 1];
}

/* Appends the conversion after the `%` at `format`, and answers its length. */
static size_t append_conversion(NSMutableData *out, const char *format, size_t bytes, StelaLogArguments *arguments)
{
	char spec[32] = "%";
	size_t length = 1, at = 1;
	unsigned lanes = 1;
	while (at < bytes && strchr("-+ #0", format[at]) && length < sizeof(spec) - 1) {
		spec[length++] = format[at++];
	}
	while (at < bytes && format[at] >= '0' && format[at] <= '9' && length < sizeof(spec) - 1) {
		spec[length++] = format[at++];
	}
	if (at < bytes && format[at] == '.') {
		spec[length++] = format[at++];
		while (at < bytes && format[at] >= '0' && format[at] <= '9' && length < sizeof(spec) - 1) {
			spec[length++] = format[at++];
		}
	}
	if (at < bytes && format[at] == 'v') {
		lanes = 0;
		for (at++; at < bytes && format[at] >= '0' && format[at] <= '9'; at++) {
			lanes = lanes * 10 + (unsigned)(format[at] - '0');
		}
	}
	/* Records widen a vector's lanes to 32 bits, and OpenCL's `hl` is those. */
	bool vector = lanes != 1, narrow = false;
	while (at < bytes && strchr("hl", format[at]) && length < sizeof(spec) - 1) {
		narrow |= format[at] == 'h';
		if (!vector || !narrow) {
			spec[length++] = format[at];
		}
		at++;
	}
	if (at >= bytes || length >= sizeof(spec) - 1) {
		[out appendBytes:format length:bytes];
		return bytes;
	}
	spec[length++] = format[at++];
	spec[length] = 0;
	for (unsigned lane = 0; lane < lanes; lane++) {
		if (lane) {
			[out appendBytes:"," length:1];
		}
		append_lane(out, spec, length, arguments);
	}
	return at;
}

static NSString *format_message(const char *format, size_t bytes, StelaLogArguments *arguments)
{
	NSMutableData *out = [NSMutableData dataWithLength:0];
	for (size_t at = 0; at < bytes;) {
		if (format[at] != '%') {
			[out appendBytes:&format[at++] length:1];
		} else if (at + 1 < bytes && format[at + 1] == '%') {
			[out appendBytes:"%" length:1];
			at += 2;
		} else {
			at += append_conversion(out, &format[at], bytes - at, arguments);
		}
	}
	[out appendBytes:"" length:1];
	return [NSString stringWithUTF8String:out.bytes];
}

static NSString *record_string(const char *bytes, size_t length)
{
	char text[length + 1];
	memcpy(text, bytes, length);
	text[length] = 0;
	return [NSString stringWithUTF8String:text];
}

@implementation StelaGPULogState {
	StelaGPUBuffer *_buffer;
	NSMutableArray *_handlers;
	NSInteger _level;
	os_unfair_lock _lock;
	NSUInteger _running;
	bool _full;
}

- (instancetype)initWithBuffer:(StelaGPUBuffer *)buffer level:(NSInteger)level capacity:(NSUInteger)capacity
{
	self = [super init];
	if (self) {
		_buffer = buffer;
		_level = level;
		_lock = OS_UNFAIR_LOCK_INIT;
		_handlers = [NSMutableArray arrayWithCapacity:2];
		StelaLogBuffer *header = buffer->_contents;
		header->capacity = (uint32_t)capacity;
	}
	return self;
}

- (uint64_t)bufferHandle
{
	return _buffer->_handle;
}

- (void)addLogHandler:(void (^)(NSString *, NSString *, NSInteger, NSString *))handler
{
	os_unfair_lock_lock(&_lock);
	[_handlers addObject:[handler copy]];
	os_unfair_lock_unlock(&_lock);
}

- (void)commandBufferStarted
{
	os_unfair_lock_lock(&_lock);
	_running++;
	os_unfair_lock_unlock(&_lock);
}

- (void)deliver:(const StelaLogRecord *)record handlers:(NSArray *)handlers
{
	const char *text = (const char *)(record + 1);
	size_t strings = record->subsystem + record->category + record->format;
	const uint8_t *arguments = (const uint8_t *)text + ((strings + 3) & ~(size_t)3);
	NSInteger level = log_level(record->level);
	if (level < _level) {
		return;
	}
	StelaLogArguments reader = {arguments, arguments + record->arguments};
	NSString *subsystem = record_string(text, record->subsystem);
	NSString *category = record_string(text + record->subsystem, record->category);
	NSString *message = format_message(text + record->subsystem + record->category, record->format, &reader);
	for (NSUInteger index = 0; index < handlers.count; index++) {
		void (^handler)(NSString *, NSString *, NSInteger, NSString *) = handlers[index];
		handler(subsystem, category, level, message);
	}
	if (!handlers.count) {
		NSLog(@"%@ %@: %@", subsystem, category, message);
	}
}

/* Copies the records out once nothing writes them, so a handler may commit. */
- (void)commandBufferEnded
{
	os_unfair_lock_lock(&_lock);
	if (--_running) {
		os_unfair_lock_unlock(&_lock);
		return;
	}
	StelaLogBuffer *header = _buffer->_contents;
	uint32_t next = header->next < header->capacity ? header->next : header->capacity;
	bool dropped = header->next > header->capacity;
	NSData *records = [NSData dataWithBytes:header + 1 length:next];
	NSArray *handlers = [_handlers copy];
	header->next = 0;
	os_unfair_lock_unlock(&_lock);

	const uint8_t *at = records.bytes;
	const uint8_t *end = at + next;
	while ((size_t)(end - at) >= sizeof(StelaLogRecord)) {
		const StelaLogRecord *record = (const StelaLogRecord *)at;
		if (record->bytes < sizeof(*record) || record->bytes > (size_t)(end - at)) {
			break;
		}
		[self deliver:record handlers:handlers];
		at += record->bytes;
	}
	if (dropped) {
		StelaFailure failure = {.reason = "a log state's buffer filled and dropped messages"};
		stela_report("shader logging", &failure);
	}
}

@end

@implementation StelaGPUDevice (Logging)

- (id)newLogStateWithDescriptor:(id)descriptor error:(NSError **)error
{
	NSInteger capacity = [descriptor bufferSize];
	if (capacity < 1024) {
		if (error) {
			StelaFailure failure = {.reason = "a log state's buffer is at least 1024 bytes"};
			*error = stela_error(MTLLogStateErrorDomain, MTLLogStateErrorInvalidSize, &failure);
		}
		return nil;
	}
	StelaGPUBuffer *buffer = [self newBufferWithLength:sizeof(StelaLogBuffer) + (NSUInteger)capacity
				      options:MTLStorageModeShared << 4];
	if (!buffer) {
		if (error) {
			StelaFailure failure = {.reason = "a log state's buffer"};
			*error = stela_error(MTLLogStateErrorDomain, MTLLogStateErrorInvalid, &failure);
		}
		return nil;
	}
	return [[StelaGPULogState alloc] initWithBuffer:buffer level:(NSInteger)[descriptor level] capacity:(NSUInteger)capacity];
}

@end

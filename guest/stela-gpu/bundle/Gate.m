/* The gate call, failures and the command stream. */
#include "Bundle.h"

#define PAGE 0x4000u

/* Maps each page of `span`. Touching an output keeps what it holds. */
static void touch(StelaSpan span, bool write)
{
	if (span.length == 0) {
		return;
	}
	uint64_t last = span.address + span.length - 1;
	for (uint64_t page = span.address; page <= last; page = (page & ~(uint64_t)(PAGE - 1)) + PAGE) {
		if (write) {
			__atomic_fetch_or((uint8_t *)page, 0, __ATOMIC_RELAXED);
		} else {
			(void)*(volatile uint8_t *)page;
		}
	}
}

uint32_t stela_gate_call(StelaGate *gate, uint32_t operation, const void *request, size_t request_bytes,
			 void *response, size_t response_bytes, StelaSpans spans, StelaFailure *failure)
{
	StelaFailure unread;
	failure = failure ? failure : &unread;
	volatile StelaGateCall call;
	do {
		for (size_t i = 0; i < spans.read_count; i++) {
			touch(spans.reads[i], false);
		}
		for (size_t i = 0; i < spans.write_count; i++) {
			touch(spans.writes[i], true);
		}
		call = (StelaGateCall){
			.operation = operation,
			.status = StelaStatusClosed,
			.request = stela_span(request, request_bytes),
			.response = stela_span(response, response_bytes),
			.reason = stela_span(failure->reason, sizeof(failure->reason) - 1),
		};
		/* The store runs the call: `call` holds its answer at the next instruction. */
		gate->page[STELA_GATE_CALL / sizeof(uint64_t)] = (uint64_t)&call;
	} while (call.status == StelaStatusUnmapped);
	failure->status = call.status;
	size_t length = call.reason_length < sizeof(failure->reason) ? call.reason_length : sizeof(failure->reason) - 1;
	failure->reason[call.status == StelaStatusOk ? 0 : length] = 0;
	return call.status;
}

NSError *stela_error(NSString *domain, NSInteger code, const StelaFailure *failure)
{
	NSString *key = NSLocalizedDescriptionKey;
	NSString *reason = [NSString stringWithUTF8String:failure->reason];
	NSDictionary *information = [NSDictionary dictionaryWithObjects:&reason forKeys:&key count:1];
	return [NSError errorWithDomain:domain code:code userInfo:information];
}

void stela_report(const char *what, const StelaFailure *failure)
{
	static os_unfair_lock lock = OS_UNFAIR_LOCK_INIT;
	static NSMutableDictionary *reported;
	NSString *message = [NSString stringWithFormat:@"%s: %s", what, failure->reason];
	os_unfair_lock_lock(&lock);
	reported = reported ?: [NSMutableDictionary dictionary];
	bool first = [reported objectForKey:message] == nil;
	[reported setObject:message forKey:message];
	os_unfair_lock_unlock(&lock);
	if (first) {
		NSLog(@"StelaGPU: %@", message);
	}
}

static void *reserve(StelaStream *stream, size_t bytes)
{
	if (stream->capacity - stream->length < bytes) {
		size_t capacity = stream->capacity ? stream->capacity : 4096;
		while (capacity - stream->length < bytes) {
			capacity *= 2;
		}
		stream->bytes = realloc(stream->bytes, capacity);
		if (!stream->bytes) {
			abort();
		}
		stream->capacity = capacity;
	}
	void *at = stream->bytes + stream->length;
	stream->length += bytes;
	return at;
}

void stela_stream_entry(StelaStream *stream, uint32_t code, const void *record, size_t record_bytes,
			const void *data, size_t data_bytes)
{
	size_t length = record_bytes + data_bytes;
	size_t padded = (length + 7) & ~(size_t)7;
	uint8_t *entry = reserve(stream, sizeof(StelaCommandHeader) + padded);
	*(StelaCommandHeader *)entry = (StelaCommandHeader){.code = code, .length = (uint32_t)length};
	entry += sizeof(StelaCommandHeader);
	if (record_bytes) {
		memcpy(entry, record, record_bytes);
	}
	if (data_bytes) {
		memcpy(entry + record_bytes, data, data_bytes);
	}
	memset(entry + length, 0, padded - length);
}

void stela_stream_append(StelaStream *stream, const StelaStream *other)
{
	if (other->length) {
		memcpy(reserve(stream, other->length), other->bytes, other->length);
	}
}

void stela_stream_free(StelaStream *stream)
{
	free(stream->bytes);
	*stream = (StelaStream){0};
}

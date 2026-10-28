// SPDX-License-Identifier: MIT
/* Original DSM helper bodies over deterministic client responses. This fixture
 * installs no portal, interpreter, native owner or hardware capability. */
#define CONFIG_ACPI 1
#undef acpi_evaluate_object
#define acpi_evaluate_object fixture_evaluate_object
#define acpi_evaluate_dsm fixture_evaluate_dsm
#define acpi_check_dsm fixture_check_dsm
#include <linux/acpi.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <stela/linux.h>
#include <stela/test.h>

static acpi_status status;
static acpi_object_type response_type;
static u64 integer, revision, function;
static u8 buffer[16];
static u32 buffer_length;
static const guid_t *expected_guid;
static const union acpi_object *fourth;
static size_t calls, warnings, frees;
static void *allocation;
static acpi_handle expected_handle;

acpi_status fixture_evaluate_object(acpi_handle handle, acpi_string path,
                                   struct acpi_object_list *input,
                                   struct acpi_buffer *output)
{
    calls++;
    assert(handle == expected_handle && !strcmp(path, "_DSM"));
    assert(input && input->count == 4 && input->pointer);
    union acpi_object *params = input->pointer;
    assert(params[0].type == ACPI_TYPE_BUFFER && params[0].buffer.length == 16);
    assert(!memcmp(params[0].buffer.pointer, expected_guid, 16));
    assert(params[1].type == ACPI_TYPE_INTEGER && params[1].integer.value == revision);
    assert(params[2].type == ACPI_TYPE_INTEGER && params[2].integer.value == function);
    if (fourth) {
        assert(!memcmp(&params[3], fourth, sizeof(*fourth)));
    } else {
        assert(params[3].type == ACPI_TYPE_PACKAGE && !params[3].package.count);
        assert(!params[3].package.elements);
    }
    assert(output && output->length == ACPI_ALLOCATE_BUFFER && !output->pointer);
    assert(!allocation);
    if (status != AE_OK)
        return status;
    union acpi_object *object = kmalloc(sizeof(*object) + sizeof(buffer), GFP_KERNEL);
    assert(object);
    memset(object, 0, sizeof(*object) + sizeof(buffer));
    object->type = response_type;
    if (response_type == ACPI_TYPE_INTEGER)
        object->integer.value = integer;
    else if (response_type == ACPI_TYPE_BUFFER) {
        object->buffer.length = buffer_length;
        object->buffer.pointer = buffer_length ? (u8 *)(object + 1) : NULL;
        memcpy(object + 1, buffer, sizeof(buffer));
    }
    output->pointer = object;
    output->length = sizeof(*object) + sizeof(buffer);
    allocation = object;
    return AE_OK;
}
static void fixture_free(void *object)
{
    assert(object && object == allocation);
    allocation = NULL;
    frees++;
    kfree(object);
}
static void fixture_warn(acpi_handle handle, const char *format, ...)
{
    assert(handle == expected_handle && format);
    warnings++;
}
#undef ACPI_FREE
#define ACPI_FREE(pointer) fixture_free(pointer)
#undef acpi_handle_warn
#define acpi_handle_warn(...) fixture_warn(__VA_ARGS__)
#include "../kernel/acpi_dsm.c"

static void reset(const guid_t *guid)
{
    assert(!allocation);
    calls = warnings = frees = 0;
    status = AE_OK;
    response_type = ACPI_TYPE_INTEGER;
    integer = 0;
    revision = 0xfedcba9876543210ULL;
    function = 0;
    buffer_length = 0;
    memset(buffer, 0, sizeof(buffer));
    expected_guid = guid;
    fourth = NULL;
    expected_handle = (acpi_handle)0x1234UL; /* opaque fixture identity, never dereferenced */
}
static void evaluation_arguments(const guid_t *guid)
{
    union acpi_object values[3] = {};
    values[0].type = ACPI_TYPE_INTEGER;
    values[0].integer.value = 0x8877665544332211ULL;
    values[1].type = ACPI_TYPE_BUFFER;
    values[1].buffer.length = 3;
    u8 data[] = {0xa5, 0, 0xff};
    values[1].buffer.pointer = data;
    values[2].type = ACPI_TYPE_PACKAGE;
    values[2].package.count = 2;
    values[2].package.elements = values;
    for (size_t i = 0; i < 4; i++) {
        reset(guid);
        function = 0xabcdef0187654321ULL;
        fourth = i ? &values[i - 1] : NULL;
        integer = 0x13579bdf2468ace0ULL;
        union acpi_object *object = fixture_evaluate_dsm(expected_handle, guid, revision, function, (union acpi_object *)fourth);
        assert(object == allocation && object->type == ACPI_TYPE_INTEGER);
        assert(object->integer.value == integer && calls == 1 && !warnings && !frees);
        fixture_free(object);
        assert(frees == 1 && !allocation);
    }
    for (size_t i = 0; i < 2; i++) {
        reset(guid);
        status = i ? AE_ERROR : AE_NOT_FOUND;
        assert(!fixture_evaluate_dsm(expected_handle, guid, revision, function, NULL));
        assert(calls == 1 && warnings == i && !allocation && !frees);
    }
}
static void integer_masks(const guid_t *guid)
{
    const u64 requested[] = {0, 1, 2, 4, 0x8000000000000000ULL, ~0ULL};
    const u64 masks[] = {0, 1, 2, 3, 5, 0x8000000000000001ULL, ~0ULL};
    for (size_t i = 0; i < ARRAY_SIZE(requested); i++) {
        for (size_t j = 0; j < ARRAY_SIZE(masks); j++) {
            reset(guid);
            integer = masks[j];
            bool expected = requested[i] && (integer & 1) && (integer & requested[i]) == requested[i];
            assert(fixture_check_dsm(expected_handle, guid, revision, requested[i]) == expected);
            assert(calls == !!requested[i] && frees == calls && !warnings && !allocation);
        }
    }
}
static void buffer_masks(const guid_t *guid)
{
    for (u32 length = 0; length <= sizeof(buffer); length++) {
        reset(guid);
        response_type = ACPI_TYPE_BUFFER;
        buffer_length = length;
        for (size_t i = 0; i < sizeof(buffer); i++)
            buffer[i] = i ? 0x80 : 3;
        u64 mask = 0;
        for (size_t i = 0; i < length && i < 8; i++)
            mask |= (u64)buffer[i] << (i * 8);
        u64 wanted = length > 7 ? 0x8000000000000000ULL : 2;
        assert(fixture_check_dsm(expected_handle, guid, revision, wanted) == (!!(mask & 1) && (mask & wanted) == wanted));
        assert(calls == 1 && frees == 1 && !warnings && !allocation);
    }
    for (u32 kind = 0; kind < 25; kind++) {
        if (kind == ACPI_TYPE_INTEGER || kind == ACPI_TYPE_BUFFER)
            continue;
        reset(guid);
        response_type = kind;
        assert(!fixture_check_dsm(expected_handle, guid, revision, 2));
        assert(calls == 1 && frees == 1 && !allocation);
    }
}
int main(void)
{
    guid_t guid;
    for (size_t i = 0; i < sizeof(guid.b); i++)
        guid.b[i] = (u8)(i * 17);
    stela_linux_enter(&stela_linux_bare);
    evaluation_arguments(&guid);
    integer_masks(&guid);
    buffer_masks(&guid);
    stela_linux_exit();
    printf("Original DSM helpers: arguments, status, masks and owned frees passed\n");
    return 0;
}

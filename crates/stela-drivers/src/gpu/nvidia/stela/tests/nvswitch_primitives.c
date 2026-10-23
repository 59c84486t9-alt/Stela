/* SPDX-License-Identifier: MIT */
/* CPU-only original-hook fixture. The optional renamed-provider object observes
 * ABI forwarding without pretending a short buffer covers a huge byte range. */
#include "export_nvswitch.h"
#include <assert.h>
#include <stdint.h>
#include <stdio.h>

#ifdef NDEBUG
#error "NVSwitch primitive tests require active assertions"
#endif
_Static_assert(sizeof(NvLength) == 8, "native NVSwitch lengths remain 64-bit");

#ifdef STELA_NVSWITCH_FORWARD_TEST
static void *destination;
static const void *source;
static NvLength count;
static int byte_value;
static unsigned copy_calls, set_calls, length_calls;

void *stela_nvswitch_test_memcpy(void *dest, const void *src, size_t size);
void *stela_nvswitch_test_memset(void *dest, int value, size_t size);
size_t stela_nvswitch_test_strlen(const char *str);

void *stela_nvswitch_test_memcpy(void *dest, const void *src, size_t size)
{
    assert(dest == destination && src == source && size == count);
    copy_calls++;
    return dest;
}

void *stela_nvswitch_test_memset(void *dest, int value, size_t size)
{
    assert(dest == destination && value == byte_value && size == count);
    set_calls++;
    return dest;
}

size_t stela_nvswitch_test_strlen(const char *str)
{
    assert(str == source);
    length_calls++;
    return count;
}

int main(void)
{
    unsigned char actual_destination = 0xa5;
    const unsigned char actual_source = 0x81;
    destination = &actual_destination;
    source = &actual_source;
    const NvLength sizes[] = {0, 1, UINT64_C(0x100000001), UINT64_MAX};
    const int values[] = {-1, 0, 0x180, INT32_MIN, INT32_MAX};
    for (unsigned i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++)
    {
        count = sizes[i];
        assert(nvswitch_os_memcpy(destination, source, count) == destination);
        assert(nvswitch_os_strlen(source) == count);
        for (unsigned v = 0; v < sizeof(values) / sizeof(values[0]); v++)
        {
            byte_value = values[v];
            assert(nvswitch_os_memset(destination, byte_value, count) == destination);
        }
    }
    assert(copy_calls == 4 && length_calls == 4 && set_calls == 20);
    assert(actual_destination == 0xa5 && actual_source == 0x81);
    puts("original NVSwitch wrappers preserve full-width scalar/provider forwarding");
    return 0;
}
#else
int main(void)
{
    unsigned char source[4096 + 32], destination[4096 + 32];
    const NvLength sizes[] = {0, 1, 2, 7, 8, 15, 16, 31, 32, 127, 128, 129, 4096};
    const int values[] = {-1, 0, 0x80, 0x180, INT32_MIN, INT32_MAX};
    for (unsigned i = 0; i < sizeof(source); i++)
        source[i] = (unsigned char)(i * 37 + 0x81);
    for (unsigned s = 0; s < sizeof(sizes) / sizeof(sizes[0]); s++)
    {
        NvLength size = sizes[s];
        for (unsigned offset = 0; offset < 16; offset++)
        {
            for (unsigned i = 0; i < sizeof(destination); i++)
                destination[i] = 0xa5;
            assert(nvswitch_os_memcpy(destination + offset, source + 15 - offset, size)
                   == destination + offset);
            for (unsigned i = 0; i < sizeof(destination); i++)
                assert(destination[i] == ((i >= offset && i - offset < size)
                       ? (unsigned char)((i - offset + 15 - offset) * 37 + 0x81) : 0xa5));
            for (unsigned v = 0; v < sizeof(values) / sizeof(values[0]); v++)
            {
                for (unsigned i = 0; i < sizeof(destination); i++)
                    destination[i] = 0xa5;
                assert(nvswitch_os_memset(destination + offset, values[v], size)
                       == destination + offset);
                for (unsigned i = 0; i < sizeof(destination); i++)
                    assert(destination[i] == ((i >= offset && i - offset < size)
                           ? (unsigned char)values[v] : 0xa5));
            }
            for (unsigned i = 0; i < sizeof(destination); i++)
                destination[i] = 0x80;
            destination[offset + size] = 0;
            assert(nvswitch_os_strlen((const char *)destination + offset) == size);
        }
    }
    puts("original NVSwitch CPU primitives preserve bytes, returns and untouched spans");
    return 0;
}
#endif

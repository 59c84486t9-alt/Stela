/* SPDX-License-Identifier: MIT */
/* Each negative mode is compiled into a GENUINE ordinary object separately.
 * Do not synthesize or patch binary object bytes. It is deliberately invalid
 * registry input; no negative definition is linked into production. */
#if defined(FIXTURE_NOANCHOR)
#include <stela/registry.h>
int fixture_has_no_capture_header;
#else
#include <stela/registration.h>
#endif
#if defined(FIXTURE_NOANCHOR)
/* No record and no capture anchor: must fail rather than silently omit TU. */
#elif defined(FIXTURE_EMBEDDED_NUL)
MODULE_INFO(description, "visible\0hidden");
#elif defined(FIXTURE_BAD_INIT_TYPE)
static void wrong_init(void) { }
module_init(wrong_init);
#elif defined(FIXTURE_BAD_EXIT_TYPE)
static int wrong_exit(void) { return 0; }
module_exit(wrong_exit);
#elif defined(FIXTURE_BAD_SETUP_TYPE)
static int wrong_setup(const char *value) { (void)value; return 1; }
__setup("wrong=", wrong_setup);
#elif defined(FIXTURE_UNDEFINED)
extern const struct stela_linux_init_record stela_linux_reg__Fixture__Bad__i__0;
const void *fixture_reference = &stela_linux_reg__Fixture__Bad__i__0;
#elif defined(FIXTURE_COMMON)
/* Compile with -fcommon so the actual symbol table reports common data. */
struct stela_linux_init_record stela_linux_reg__Fixture__Bad__i__0;
#elif defined(FIXTURE_WEAK)
const struct stela_linux_init_record stela_linux_reg__Fixture__Bad__i__0
 __attribute__((weak)) = { };
#elif defined(FIXTURE_MALFORMED)
const struct stela_linux_init_record stela_linux_reg__Fixture__Bad__unknown__0 = { };
#elif defined(FIXTURE_LOCAL)
static const struct stela_linux_init_record stela_linux_reg__Fixture__Bad__i__0
 __attribute__((used)) = { };
#elif defined(FIXTURE_PREFIX)
const struct stela_linux_init_record stela_linux_reg__Fixture__Bad__i__0 = { };
#else
#error "Select one exact negative fixture mode"
#endif

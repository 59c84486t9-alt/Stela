/* SPDX-License-Identifier: MIT */
/* Configuration and owned-byte boundary tests; no private compiler is loaded. */
#include "apple_source.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned checks;
#define CHECK(x) do { checks++; if (!(x)) { \
   fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); exit(1); } \
} while (0)

int
main(void)
{
   struct stela_msl_error error;
   struct stela_msl_apple_config config = stela_msl_apple_default_config();
   struct stela_msl_request request = {
      .source = "x", .source_bytes = 1, .language_version = 0x40001,
      .fast_math = true, .target_triple = "air64_v29-apple-macosx27.2.0",
   };
   CHECK(stela_msl_apple_validate_request(&config, &request, &error) == STELA_MSL_OK);
   CHECK(error.status == STELA_MSL_OK && !error.detail[0]);
   CHECK(stela_msl_apple_validate_config(NULL, &error) == STELA_MSL_INPUT);
   CHECK(stela_msl_apple_validate_request(&config, NULL, &error) == STELA_MSL_INPUT);
   config.max_source_bytes = 0;
   CHECK(stela_msl_apple_validate_config(&config, &error) == STELA_MSL_INPUT);
   config.max_source_bytes = 64u * 1024u * 1024u + 1;
   CHECK(stela_msl_apple_validate_config(&config, &error) == STELA_MSL_INPUT);
   config = stela_msl_apple_default_config();
   config.max_air_bytes = 3;
   CHECK(stela_msl_apple_validate_config(&config, &error) == STELA_MSL_INPUT);
   config.max_air_bytes = 64u * 1024u * 1024u + 1;
   CHECK(stela_msl_apple_validate_config(&config, &error) == STELA_MSL_INPUT);
   config = stela_msl_apple_default_config();
   config.profile = (enum stela_msl_apple_profile)99;
   CHECK(stela_msl_apple_validate_config(&config, &error) == STELA_MSL_UNQUALIFIED_CONFIG);
   config = stela_msl_apple_default_config();
   config.require_detailed_diagnostics = true;
   CHECK(stela_msl_apple_validate_config(&config, &error) == STELA_MSL_UNQUALIFIED_CONFIG);
   config = stela_msl_apple_default_config();
   request.source = NULL;
   CHECK(stela_msl_apple_validate_request(&config, &request, &error) == STELA_MSL_INPUT);
   request.source = "x";
   request.source_bytes = 0;
   CHECK(stela_msl_apple_validate_request(&config, &request, &error) == STELA_MSL_INPUT);
   /* An oversized declared input must be rejected before even scanning its
    * bytes. The backing literal deliberately has only two accessible bytes. */
   request.source_bytes = config.max_source_bytes + 1;
   CHECK(stela_msl_apple_validate_request(&config, &request, &error) == STELA_MSL_INPUT);
   const char embedded[] = {'a', 0, 'b'};
   request.source = embedded;
   request.source_bytes = sizeof(embedded);
   CHECK(stela_msl_apple_validate_request(&config, &request, &error) == STELA_MSL_INPUT);
   request.source = "x";
   request.source_bytes = 1;
   request.language_version = 0x40000;
   CHECK(stela_msl_apple_validate_request(&config, &request, &error) == STELA_MSL_UNQUALIFIED_CONFIG);
   request.language_version = 0x40001;
   request.fast_math = false;
   CHECK(stela_msl_apple_validate_request(&config, &request, &error) == STELA_MSL_UNQUALIFIED_CONFIG);
   request.fast_math = true;
   request.target_triple = NULL;
   CHECK(stela_msl_apple_validate_request(&config, &request, &error) == STELA_MSL_UNQUALIFIED_CONFIG);
   request.target_triple = "air64_v29-apple-macosx27.2.0-injected";
   CHECK(stela_msl_apple_validate_request(&config, &request, &error) == STELA_MSL_UNQUALIFIED_CONFIG);
   request.target_triple = "air64_v28-apple-macosx27.2.0";
   CHECK(stela_msl_apple_validate_request(&config, &request, &error) == STELA_MSL_UNQUALIFIED_CONFIG);
   request.target_triple = "air64_v29-apple-macosx27.2.0";
   config.max_source_bytes = 1;
   config.max_air_bytes = 4;
   CHECK(stela_msl_apple_validate_request(&config, &request, NULL) == STELA_MSL_OK);
   struct stela_msl_output output = {.air = malloc(13), .air_bytes = 13};
   CHECK(output.air);
   memset(output.air, 0xa5, output.air_bytes);
   stela_msl_output_destroy(&output);
   CHECK(!output.air && !output.air_bytes);
   stela_msl_output_destroy(&output);
   stela_msl_output_destroy(NULL);
#if !defined(__APPLE__) || !defined(__arm64__)
   struct stela_msl_apple_compiler *compiler = NULL;
   CHECK(stela_msl_apple_open(&config, &compiler, &error) == STELA_MSL_UNSUPPORTED_HOST);
   CHECK(!compiler);
   CHECK(stela_msl_apple_compile(NULL, &request, &output, &error) == STELA_MSL_UNSUPPORTED_HOST);
   CHECK(!output.air && !output.air_bytes);
#endif
   printf("Apple MSL adapter configuration/ownership: %u checks; no private compiler call\n", checks);
   return 0;
}

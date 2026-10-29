/* SPDX-License-Identifier: MIT */
#ifdef NDEBUG
#error "This ownership test requires active assertions"
#endif
#include "../input.h"
#include <assert.h>
#include <stddef.h>
#include <string.h>
_Static_assert(sizeof(struct stela_metal_input_limits) == 24, "limits ABI");
_Static_assert(sizeof(struct stela_metal_input_error) == 24, "error ABI");
_Static_assert(sizeof(struct stela_metal_input_info) == 88, "input info ABI");
_Static_assert(sizeof(struct stela_metal_input_entry) == 80, "entry ABI");
_Static_assert(sizeof(struct stela_metal_input_entry_metadata) == 88, "metadata facts ABI");
_Static_assert(offsetof(struct stela_metal_input_entry_metadata,function_offset) == 24, "metadata range ABI");
_Static_assert(sizeof(struct stela_metal_input_view) == 32, "view ABI");
_Static_assert(offsetof(struct stela_metal_input_view,original_offset) == 24, "view offset ABI");
int main(void)
{
   uint8_t original[] = {'B','C',0xc0,0xde,1,2,3,4};
   struct stela_metal_input_limits limits = {
      .size=sizeof(limits),.abi=1,.kind=STELA_METAL_INPUT_RAW_AIR,.max_entries=4,.max_bytes=64,
   };
   struct stela_metal_input *input = NULL;
   struct stela_metal_input_error error = {0};
   assert(stela_metal_input_open(&limits,original,sizeof(original),&input,&error)==0 && input);
   memset(original,0,sizeof(original));
   struct stela_metal_input_info info = {.size=sizeof(info),.abi=1};
   assert(stela_metal_input_info(input,&info,&error)==0 && info.kind==STELA_METAL_INPUT_RAW_AIR && info.original_bytes==8);
   struct stela_metal_input_view view = {.size=sizeof(view),.abi=1};
   assert(stela_metal_input_air(input,0,&view,&error)==0 && view.length==8 && view.original_offset==0);
   const uint8_t expected[] = {'B','C',0xc0,0xde,1,2,3,4};
   assert(!memcmp(view.bytes,expected,8));
   assert(stela_metal_input_original(input,&view,&error)==0 && view.length==8 && view.original_offset==0);
   assert(!memcmp(view.bytes,expected,8));
   assert(stela_metal_input_name(input,0,&view,&error)==STELA_METAL_INPUT_NOT_ARCHIVE && view.length==8);
   struct stela_metal_input_entry_metadata facts = {.size=sizeof(facts),.abi=1,.function_tags=99};
   assert(stela_metal_input_entry_metadata(input,0,&facts,&error)==STELA_METAL_INPUT_NOT_ARCHIVE && facts.function_tags==99);
   facts.abi=2;
   assert(stela_metal_input_entry_metadata(input,0,&facts,&error)==STELA_METAL_INPUT_ABI_MISMATCH && facts.function_tags==99);
   view.abi=2;
   assert(stela_metal_input_air(input,0,&view,&error)==STELA_METAL_INPUT_ABI_MISMATCH && view.length==8);
   stela_metal_input_destroy(&input); assert(!input);
   stela_metal_input_destroy(&input); stela_metal_input_destroy(NULL);
   limits.abi=2;
   assert(stela_metal_input_open(&limits,original,sizeof(original),&input,&error)==STELA_METAL_INPUT_ABI_MISMATCH && !input);
   return 0;
}

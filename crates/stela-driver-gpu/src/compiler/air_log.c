/* SPDX-License-Identifier: MIT */
/* os_log's methods, as Apple's compiler emits them under -fmetal-enable-logging:
 * a variadic function that loads the os_log's strings and calls
 *
 *   air.os_log(subsystem, category, level, format, va_list, bytes)
 *
 * Variadic functions do not inline, so each call of such a method lowers here.
 * It appends a record to the log buffer the push constants name, or to nothing
 * when the command buffer has no log state. A record carries its strings, so
 * compiled code owes the frontend no table: six 32-bit words of its bytes, level
 * and the lengths of subsystem, category, format and arguments, the strings
 * padded to a word, and the arguments, each lane a float, a 32-bit integer or a
 * 64-bit one at word alignment. The buffer starts with the next record's offset
 * and the capacity, which a record past it leaves untouched but for the offset.
 * C's promotions make a float a double; the function has no doubles, so such a
 * conversion is left to the call that uses it. */
#define STELA_AIR_METADATA_INTERNAL
#include "air_log.h"
#include "nir_builder.h"
#include <string.h>

#define LOG_RECORDS_OFFSET 16u
#define LOG_CAPACITY_OFFSET 4u
#define RECORD_HEADER_WORDS 6u
/* Beyond any message, it bounds the stores of a call. */
#define MAX_RECORD_BYTES 4096u

static bool
named_os_log(LLVMValueRef function)
{
   size_t bytes;
   const char *name = LLVMGetValueName2(function, &bytes);
   return stela_air_call_named(name, bytes, "air.os_log");
}

/* The air.os_log a variadic method calls, or NULL for any other function. */
static LLVMValueRef
method_log(LLVMValueRef function)
{
   if (!function || !LLVMIsAFunction(function) || LLVMIsDeclaration(function) ||
       !LLVMIsFunctionVarArg(LLVMGlobalGetValueType(function)))
      return NULL;
   for (LLVMBasicBlockRef block = LLVMGetFirstBasicBlock(function); block;
        block = LLVMGetNextBasicBlock(block)) {
      for (LLVMValueRef inst = LLVMGetFirstInstruction(block); inst;
           inst = LLVMGetNextInstruction(inst)) {
         LLVMValueRef callee = LLVMIsACallInst(inst) ? LLVMGetCalledValue(inst) : NULL;
         if (callee && LLVMIsAFunction(callee) && named_os_log(callee))
            return inst;
      }
   }
   return NULL;
}

bool
stela_air_log_promotion(LLVMValueRef inst)
{
   if (LLVMGetTypeKind(LLVMTypeOf(inst)) != LLVMDoubleTypeKind)
      return false;
   for (LLVMUseRef use = LLVMGetFirstUse(inst); use; use = LLVMGetNextUse(use)) {
      LLVMValueRef user = LLVMGetUser(use);
      if (!LLVMIsACallInst(user) || !method_log(LLVMGetCalledValue(user)))
         return false;
   }
   return LLVMGetFirstUse(inst) != NULL;
}

bool
stela_air_log_only(LLVMValueRef value)
{
   for (LLVMUseRef use = LLVMGetFirstUse(value); use; use = LLVMGetNextUse(use)) {
      LLVMValueRef user = LLVMGetUser(use);
      if (LLVMIsACallInst(user) ? !method_log(LLVMGetCalledValue(user)) :
          !LLVMIsAConstant(user) || !stela_air_log_only(user))
         return false;
   }
   return LLVMGetFirstUse(value) != NULL;
}

/* The bytes of a constant string, without its terminator. */
static const char *
constant_string(LLVMValueRef value, size_t *bytes)
{
   if (value && LLVMIsAConstantExpr(value))
      value = LLVMGetOperand(value, 0);
   LLVMValueRef initializer =
      value && LLVMIsAGlobalVariable(value) ? LLVMGetInitializer(value) : NULL;
   if (!initializer || !LLVMIsAConstantDataSequential(initializer) ||
       !LLVMIsConstantString(initializer))
      return NULL;
   const char *text = LLVMGetAsString(initializer, bytes);
   *bytes = strnlen(text, *bytes);
   return text;
}

/* An os_log's strings. os_log_default is a declaration, of no subsystem or
 * category. */
static bool
log_strings(LLVMValueRef object, const char *strings[2], size_t bytes[2])
{
   if (!LLVMIsAGlobalVariable(object))
      return false;
   LLVMValueRef initializer = LLVMGetInitializer(object);
   for (unsigned i = 0; i < 2; i++) {
      strings[i] = "";
      bytes[i] = 0;
      if (initializer) {
         strings[i] = constant_string(LLVMGetAggregateElement(initializer, i), &bytes[i]);
         if (!strings[i])
            return false;
      }
   }
   return true;
}

struct record {
   nir_builder *b;
   nir_def *address;
};

static void
put(struct record *record, nir_def *value)
{
   nir_store_global(record->b, value, record->address, .align_mul = 4);
   record->address = nir_iadd_imm(record->b, record->address, value->bit_size / 8);
}

/* Writes the strings as words, padding the last with zeros. */
static void
put_strings(struct record *record, const char *const *strings, const size_t *bytes, unsigned count)
{
   uint32_t word = 0;
   unsigned filled = 0;
   for (unsigned i = 0; i < count; i++) {
      for (size_t j = 0; j < bytes[i]; j++) {
         word |= (uint32_t)(uint8_t)strings[i][j] << (filled * 8);
         if (++filled == 4) {
            put(record, nir_imm_int(record->b, word));
            word = filled = 0;
         }
      }
   }
   if (filled)
      put(record, nir_imm_int(record->b, word));
}

/* What an argument puts: the value of a float its call promoted, or of a
 * constant double as a float. False for a value the function cannot have. */
static bool
argument_shape(LLVMValueRef value, LLVMValueRef *stored, bool *wide, unsigned *lanes)
{
   LLVMTypeRef element = stela_air_call_element(LLVMTypeOf(value), lanes);
   if (LLVMGetTypeKind(element) == LLVMDoubleTypeKind) {
      *stored = LLVMIsAFPExtInst(value) ? LLVMGetOperand(value, 0) : value;
      *wide = false;
      return LLVMIsAFPExtInst(value) || LLVMIsAConstantFP(value);
   }
   *stored = value;
   *wide = LLVMGetTypeKind(element) == LLVMIntegerTypeKind && LLVMGetIntTypeWidth(element) == 64;
   return LLVMGetTypeKind(element) == LLVMIntegerTypeKind ||
          LLVMGetTypeKind(element) == LLVMFloatTypeKind ||
          LLVMGetTypeKind(element) == LLVMHalfTypeKind;
}

static bool
put_argument(const struct stela_air_log_context *context, struct record *record, LLVMValueRef stored)
{
   nir_builder *b = context->call.b;
   LLVMBool lost;
   if (LLVMGetTypeKind(LLVMTypeOf(stored)) == LLVMDoubleTypeKind) {
      put(record, nir_imm_float(b, LLVMConstRealGetDouble(stored, &lost)));
      return true;
   }
   unsigned lanes;
   LLVMTypeRef element = stela_air_call_element(LLVMTypeOf(stored), &lanes);
   nir_def *value = context->call.operand(context->call.translator, stored);
   if (!value)
      return false;
   bool integer = LLVMGetTypeKind(element) == LLVMIntegerTypeKind;
   for (unsigned lane = 0; lane < lanes; lane++) {
      nir_def *channel = nir_channel(b, value, lane);
      if (!integer)
         put(record, nir_f2f32(b, channel));
      else
         put(record, channel->bit_size < 32 ? nir_i2i32(b, channel) : channel);
   }
   return true;
}

enum stela_air_call_status
stela_air_log_call(const struct stela_air_log_context *context, LLVMValueRef call,
                   LLVMValueRef callee)
{
   const struct stela_air_call_context *c = &context->call;
   LLVMValueRef log = method_log(callee);
   if (!log)
      return STELA_AIR_CALL_OTHER;
   unsigned arguments = LLVMGetNumArgOperands(call);
   LLVMValueRef level = LLVMGetOperand(log, 2);
   const char *strings[3];
   size_t bytes[3];
   if (arguments < 3 || !LLVMIsAConstantInt(level) ||
       !log_strings(LLVMGetOperand(call, 0), strings, bytes) ||
       !(strings[2] = constant_string(LLVMGetOperand(call, 1), &bytes[2]))) {
      stela_air_call_fail(c, STELA_AIR_INSTRUCTION, "an os_log whose strings are not constants");
      return STELA_AIR_CALL_FAILED;
   }
   size_t text_bytes = bytes[0] + bytes[1] + bytes[2];
   size_t argument_bytes = 0;
   for (unsigned i = 3; i < arguments; i++) {
      LLVMValueRef stored;
      bool wide;
      unsigned lanes;
      if (!argument_shape(LLVMGetOperand(call, i), &stored, &wide, &lanes)) {
         stela_air_call_fail(c, STELA_AIR_INSTRUCTION, "an os_log argument of an unknown type");
         return STELA_AIR_CALL_FAILED;
      }
      argument_bytes += lanes * (wide ? 8 : 4);
   }
   size_t total = RECORD_HEADER_WORDS * 4 + ALIGN_POT(text_bytes, 4) + argument_bytes;
   if (total > MAX_RECORD_BYTES) {
      stela_air_call_fail(c, STELA_AIR_LIMIT, "an os_log message of %zu bytes", total);
      return STELA_AIR_CALL_FAILED;
   }

   nir_builder *b = c->b;
   nir_def *buffer = context->buffer(c->translator);
   if (!buffer)
      return STELA_AIR_CALL_FAILED;
   /* Writes of a helper invocation have no effect. */
   nir_def *logs = nir_ine(b, buffer, nir_imm_int64(b, 0));
   if (c->fragment)
      logs = nir_iand(b, logs, nir_inot(b, nir_load_helper_invocation(b, 1)));
   nir_block *logging[3], *fitting[3];
   if (!context->guard_begin(c->translator, logs, logging))
      return STELA_AIR_CALL_FAILED;
   nir_def *offset = nir_global_atomic(b, 32, buffer, nir_imm_int(b, total),
                                       .atomic_op = nir_atomic_op_iadd);
   nir_def *capacity = nir_load_global(b, 1, 32, nir_iadd_imm(b, buffer, LOG_CAPACITY_OFFSET),
                                       .align_mul = 4);
   nir_def *start = nir_u2u64(b, offset);
   nir_def *fits = nir_uge(b, nir_u2u64(b, capacity), nir_iadd_imm(b, start, total));
   if (!context->guard_begin(c->translator, fits, fitting))
      return STELA_AIR_CALL_FAILED;
   struct record record = {
      b, nir_iadd(b, buffer, nir_iadd_imm(b, start, LOG_RECORDS_OFFSET)),
   };
   const uint32_t header[RECORD_HEADER_WORDS] = {
      total, LLVMConstIntGetZExtValue(level), bytes[0], bytes[1], bytes[2], argument_bytes,
   };
   for (unsigned i = 0; i < RECORD_HEADER_WORDS; i++)
      put(&record, nir_imm_int(b, header[i]));
   put_strings(&record, strings, bytes, ARRAY_SIZE(strings));
   for (unsigned i = 3; i < arguments; i++) {
      LLVMValueRef stored;
      bool wide;
      unsigned lanes;
      argument_shape(LLVMGetOperand(call, i), &stored, &wide, &lanes);
      if (!put_argument(context, &record, stored))
         return STELA_AIR_CALL_FAILED;
   }
   context->guard_end(c->translator, fitting);
   context->guard_end(c->translator, logging);
   return STELA_AIR_CALL_LOWERED;
}

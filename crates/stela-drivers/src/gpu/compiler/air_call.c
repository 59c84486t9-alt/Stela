/* SPDX-License-Identifier: MIT */
#include "air_call.h"
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

bool
stela_air_call_fail(const struct stela_air_call_context *c, enum stela_air_error_kind kind,
                    const char *format, ...)
{
   if (c->error->kind == STELA_AIR_OK) {
      c->error->kind = kind;
      va_list args;
      va_start(args, format);
      vsnprintf(c->error->detail, sizeof(c->error->detail), format, args);
      va_end(args);
   }
   return false;
}

bool
stela_air_call_plain(const struct stela_air_call_context *c, LLVMValueRef call, LLVMValueRef callee,
                     unsigned operands)
{
   if (!LLVMIsAFunction(callee) || !LLVMIsDeclaration(callee) ||
       LLVMGetFunctionCallConv(callee) != LLVMCCallConv ||
       LLVMGetInstructionCallConv(call) != LLVMCCallConv ||
       LLVMGetNumArgOperands(call) != operands || LLVMCountParams(callee) != operands ||
       LLVMIsFunctionVarArg(LLVMGlobalGetValueType(callee)) ||
       LLVMGetCalledFunctionType(call) != LLVMGlobalGetValueType(callee) ||
       LLVMGetNumOperandBundles(call))
      return stela_air_call_fail(c, STELA_AIR_TYPE, "unsupported AIR function call signature");
   unsigned strict = LLVMGetEnumAttributeKindForName("strictfp", strlen("strictfp"));
   if (strict && (LLVMGetEnumAttributeAtIndex(callee, LLVMAttributeFunctionIndex, strict) ||
                  LLVMGetCallSiteEnumAttribute(call, LLVMAttributeFunctionIndex, strict)))
      return stela_air_call_fail(c, STELA_AIR_TYPE, "strict floating-point calls are unsupported");
   return true;
}

bool
stela_air_call_named(const char *name, size_t bytes, const char *expected)
{
   return strlen(expected) == bytes && !memcmp(name, expected, bytes);
}

LLVMTypeRef
stela_air_call_element(LLVMTypeRef type, unsigned *lanes)
{
   *lanes = 1;
   if (LLVMGetTypeKind(type) == LLVMVectorTypeKind) {
      *lanes = LLVMGetVectorSize(type);
      type = LLVMGetElementType(type);
   }
   return type;
}

/* A scalar's type or a 2- to 4-lane vector's element type; otherwise NULL. */
static LLVMTypeRef
shaped(LLVMTypeRef type)
{
   unsigned lanes;
   LLVMTypeRef element = stela_air_call_element(type, &lanes);
   bool vector = LLVMGetTypeKind(type) == LLVMVectorTypeKind;
   return lanes <= 4 && (!vector || lanes >= 2) ? element : NULL;
}

bool
stela_air_call_floating(LLVMTypeRef type)
{
   LLVMTypeRef element = shaped(type);
   return element && (LLVMGetTypeKind(element) == LLVMFloatTypeKind ||
                      LLVMGetTypeKind(element) == LLVMHalfTypeKind);
}

bool
stela_air_call_integer(LLVMTypeRef type)
{
   LLVMTypeRef element = shaped(type);
   if (!element || LLVMGetTypeKind(element) != LLVMIntegerTypeKind)
      return false;
   unsigned bits = LLVMGetIntTypeWidth(element);
   return bits == 8 || bits == 16 || bits == 32 || bits == 64;
}

void
stela_air_call_overload(LLVMTypeRef type, char *name, size_t size)
{
   unsigned lanes;
   LLVMTypeRef scalar = stela_air_call_element(type, &lanes);
   char base[8];
   if (LLVMGetTypeKind(scalar) == LLVMIntegerTypeKind)
      snprintf(base, sizeof(base), "i%u", LLVMGetIntTypeWidth(scalar));
   else
      snprintf(base, sizeof(base), LLVMGetTypeKind(scalar) == LLVMHalfTypeKind ? "f16" : "f32");
   if (lanes > 1)
      snprintf(name, size, "v%u%s", lanes, base);
   else
      snprintf(name, size, "%s", base);
}

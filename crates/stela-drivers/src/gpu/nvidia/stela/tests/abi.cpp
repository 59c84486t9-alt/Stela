/* SPDX-License-Identifier: MIT */
/* Compile these actual driver types under both the LP64 and native LLP64 ABI. */
#include "os/workitem.h"

constexpr OsQueueWorkItemFlags read_only = {
    .apiLock = WORKITEM_FLAGS_API_LOCK_READ_ONLY,
};
static_assert(read_only.apiLock == WORKITEM_FLAGS_API_LOCK_READ_ONLY,
              "read-only lock selection must survive packed storage");
static_assert(sizeof(OsQueueWorkItemFlags) == sizeof(NvU32),
              "preserve the vendor flag ABI");

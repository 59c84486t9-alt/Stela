// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *  acpi_utils.c - ACPI Utility Functions ($Revision: 10 $)
 *
 *  Copyright (C) 2001, 2002 Andy Grover <andrew.grover@intel.com>
 *  Copyright (C) 2001, 2002 Paul Diefenbaugh <paul.s.diefenbaugh@intel.com>
 */

/* Original DSM helpers from drivers/acpi/utils.c at Linux
 * cc9de5d4b5ab6459f5774946aa3195ad51236fa8 (canonical patched tree
 * 8d0a987907fe264b5688fa9c76e25b533c31a3dd). Public client includes replace
 * private ACPI-core includes; the sole body adaptation makes C's existing unsigned comparison conversion
 * explicit for the strict Stela warning policy.
 * Evaluation requires the separate owned portal, not a second interpreter.
 */
#include <linux/acpi.h>
#ifdef CONFIG_ACPI
/**
 * acpi_evaluate_dsm - evaluate device's _DSM method
 * @handle: ACPI device handle
 * @guid: GUID of requested functions, should be 16 bytes
 * @rev: revision number of requested function
 * @func: requested function number
 * @argv4: the function specific parameter
 *
 * Evaluate device's _DSM method with specified GUID, revision id and
 * function number. Caller needs to free the returned object.
 *
 * Though ACPI defines the fourth parameter for _DSM should be a package,
 * some old BIOSes do expect a buffer or an integer etc.
 */
union acpi_object *
acpi_evaluate_dsm(acpi_handle handle, const guid_t *guid, u64 rev, u64 func,
		  union acpi_object *argv4)
{
	acpi_status ret;
	struct acpi_buffer buf = {ACPI_ALLOCATE_BUFFER, NULL};
	union acpi_object params[4];
	struct acpi_object_list input = {
		.count = 4,
		.pointer = params,
	};

	params[0].type = ACPI_TYPE_BUFFER;
	params[0].buffer.length = 16;
	params[0].buffer.pointer = (u8 *)guid;
	params[1].type = ACPI_TYPE_INTEGER;
	params[1].integer.value = rev;
	params[2].type = ACPI_TYPE_INTEGER;
	params[2].integer.value = func;
	if (argv4) {
		params[3] = *argv4;
	} else {
		params[3].type = ACPI_TYPE_PACKAGE;
		params[3].package.count = 0;
		params[3].package.elements = NULL;
	}

	ret = acpi_evaluate_object(handle, "_DSM", &input, &buf);
	if (ACPI_SUCCESS(ret))
		return (union acpi_object *)buf.pointer;

	if (ret != AE_NOT_FOUND)
		acpi_handle_warn(handle,
				 "failed to evaluate _DSM %pUb rev:%lld func:%lld (0x%x)\n",
				 guid, rev, func, ret);

	return NULL;
}
EXPORT_SYMBOL(acpi_evaluate_dsm);

/**
 * acpi_check_dsm - check if _DSM method supports requested functions.
 * @handle: ACPI device handle
 * @guid: GUID of requested functions, should be 16 bytes at least
 * @rev: revision number of requested functions
 * @funcs: bitmap of requested functions
 *
 * Evaluate device's _DSM method to check whether it supports requested
 * functions. Currently only support 64 functions at maximum, should be
 * enough for now.
 */
bool acpi_check_dsm(acpi_handle handle, const guid_t *guid, u64 rev, u64 funcs)
{
	int i;
	u64 mask = 0;
	union acpi_object *obj;

	if (funcs == 0)
		return false;

	obj = acpi_evaluate_dsm(handle, guid, rev, 0, NULL);
	if (!obj)
		return false;

	/* For compatibility, old BIOSes may return an integer */
	if (obj->type == ACPI_TYPE_INTEGER)
		mask = obj->integer.value;
	else if (obj->type == ACPI_TYPE_BUFFER)
		for (i = 0; (u32)i < obj->buffer.length && i < 8; i++)
			mask |= (((u64)obj->buffer.pointer[i]) << (i * 8));
	ACPI_FREE(obj);

	/*
	 * Bit 0 indicates whether there's support for any functions other than
	 * function 0 for the specified GUID and revision.
	 */
	if ((mask & 0x1) && (mask & funcs) == funcs)
		return true;

	return false;
}
EXPORT_SYMBOL(acpi_check_dsm);
#endif

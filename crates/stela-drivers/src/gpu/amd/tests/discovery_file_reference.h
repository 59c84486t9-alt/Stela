/*
 * Copyright 2018-2024 Advanced Micro Devices, Inc. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE COPYRIGHT HOLDER(S) OR AUTHOR(S) BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 */

/* Frozen a239 guarded original file consumer, test only. */
#define amdgpu_discovery_read_binary_from_file original_read_file
static int amdgpu_discovery_read_binary_from_file(struct amdgpu_device *adev,
						  uint8_t *binary,
						  const char *fw_name)
{
	const struct firmware *fw;
	int r;

	r = firmware_request_nowarn(&fw, fw_name, adev->dev);
	if (r) {
		if (amdgpu_discovery == 2)
			dev_err(adev->dev, "can't load firmware \"%s\"\n", fw_name);
		else
			drm_info(&adev->ddev, "Optional firmware \"%s\" was not found\n", fw_name);
		return r;
	}

	if (fw->size > adev->discovery.size) {
		dev_err(adev->dev,
			"ip discovery firmware \"%s\" too large (%zu > %u)\n",
			fw_name, fw->size, adev->discovery.size);
		release_firmware(fw);
		return -EINVAL;
	}

	/* Ensure the firmware is at least large enough to contain the
	 * binary header fields.
	 */
	if (fw->size < offsetof(struct binary_header, binary_size) +
			sizeof(((struct binary_header *)0)->binary_size)) {
		dev_err(adev->dev,
			"ip discovery firmware \"%s\" too small (%zu)\n",
			fw_name, fw->size);
		release_firmware(fw);
		return -EINVAL;
	}

	/* A short file must not borrow zero-filled TMR padding as firmware data. */
	if (amdgpu_discovery_binary_validate(fw->data, fw->size) !=
	    AMDGPU_DISCOVERY_BINARY_OK) {
		release_firmware(fw);
		return -EINVAL;
	}

	memcpy((u8 *)binary, (u8 *)fw->data, fw->size);
	release_firmware(fw);

	return 0;
}
#undef amdgpu_discovery_read_binary_from_file

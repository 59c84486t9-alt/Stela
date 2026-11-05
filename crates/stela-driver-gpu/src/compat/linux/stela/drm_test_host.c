// SPDX-License-Identifier: MIT
/* drm_mm_print's, the one piece of DRM's printing the hosted allocators reach
 * when the real one is not linked; no test prints an allocator. */
struct drm_printer;
void drm_printf(struct drm_printer *printer, const char *format, ...);

__attribute__((weak)) void drm_printf(struct drm_printer *printer, const char *format, ...)
{
 (void)printer;
 (void)format;
}

#ifndef APP_ISOLATION_RANGES_H
#define APP_ISOLATION_RANGES_H
#include <stdbool.h>
#include <stdint.h>

struct rh_app_isolation_layout {
    uint64_t stock_size;
    uint64_t patched_size;
    uint64_t stock_cache_function;
    uint64_t patched_cache_function;
    uint64_t patched_trampoline;
};

static inline bool rh_app_isolation_span(uint64_t offset, uint64_t length,
    uint64_t image_size, uint64_t first_kept_offset)
{
    return length > 0 && offset >= first_kept_offset && offset < image_size &&
        length <= image_size - offset;
}

/* The existing hook writes20 bytes at the function and40 in its trampoline. */
static inline bool rh_app_isolation_layout_valid(struct rh_app_isolation_layout layout,
    uint64_t page_size)
{
    return page_size > 0 &&
        rh_app_isolation_span(layout.stock_cache_function, 20, layout.stock_size, page_size) &&
        rh_app_isolation_span(layout.patched_cache_function, 20, layout.patched_size, page_size) &&
        rh_app_isolation_span(layout.patched_trampoline, 40, layout.patched_size, page_size);
}

static inline bool rh_app_isolation_address_span(uint64_t base, uint64_t offset,
    uint64_t length)
{
    return length > 0 && offset <= UINT64_MAX - base &&
        length - 1 <= UINT64_MAX - (base + offset);
}
#endif

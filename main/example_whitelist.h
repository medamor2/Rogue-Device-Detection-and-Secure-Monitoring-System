#pragma once

#include "config.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    const char *label;
    const char *mac;
    const char *ssid;
    const char *allowed_ouis[MAX_ALLOWED_OUIS];
    size_t allowed_oui_count;
    int8_t min_rssi;
    int8_t max_rssi;
} whitelist_entry_t;

const whitelist_entry_t *example_whitelist_get(size_t *count);

#ifdef __cplusplus
}
#endif

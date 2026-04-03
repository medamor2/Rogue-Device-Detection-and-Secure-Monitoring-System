#pragma once

#include <stdbool.h>

#include "example_whitelist.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    bool exact_whitelisted;
    bool oui_whitelisted;
    const whitelist_entry_t *matched_entry;
} device_policy_match_t;

device_policy_match_t device_policy_match(const char *mac, const char *ssid);

#ifdef __cplusplus
}
#endif

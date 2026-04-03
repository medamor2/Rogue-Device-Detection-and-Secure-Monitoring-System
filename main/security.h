#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "example_whitelist.h"

#ifdef __cplusplus
extern "C" {
#endif

bool security_is_valid_mac(const char *mac);
bool security_mac_matches_entry(const char *mac, const whitelist_entry_t *entry);
bool security_mac_matches_any_oui(const char *mac, const whitelist_entry_t *entry);
bool security_rssi_delta_is_suspicious(int8_t previous_rssi, int8_t current_rssi);
bool security_observation_is_flapping(uint32_t missed_scans, uint32_t seen_count);

#ifdef __cplusplus
}
#endif

#include "device_policy.h"

#include <strings.h>

#include "security.h"

device_policy_match_t device_policy_match(const char *mac, const char *ssid)
{
    device_policy_match_t result = {
        .exact_whitelisted = false,
        .oui_whitelisted = false,
        .matched_entry = NULL,
    };

    size_t whitelist_count = 0;
    const whitelist_entry_t *whitelist = example_whitelist_get(&whitelist_count);

    for (size_t i = 0; i < whitelist_count; ++i) {
        const whitelist_entry_t *entry = &whitelist[i];
        if (entry->mac != NULL && strcasecmp(mac, entry->mac) == 0) {
            if (ssid != NULL && entry->ssid != NULL && entry->ssid[0] != '\0' && strcasecmp(ssid, entry->ssid) != 0) {
                continue;
            }

            result.exact_whitelisted = true;
            result.matched_entry = entry;
            return result;
        }

        if (!result.oui_whitelisted && security_mac_matches_any_oui(mac, entry)) {
            result.oui_whitelisted = true;
            if (result.matched_entry == NULL) {
                result.matched_entry = entry;
            }
        }
    }

    return result;
}

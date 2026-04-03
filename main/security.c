#include "security.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "config.h"

bool security_is_valid_mac(const char *mac)
{
    if (mac == NULL) {
        return false;
    }

    const size_t expected_length = MAC_STRING_LENGTH - 1;
    if (strlen(mac) != expected_length) {
        return false;
    }

    for (size_t i = 0; i < expected_length; ++i) {
        if ((i + 1) % 3 == 0) {
            if (mac[i] != ':') {
                return false;
            }
            continue;
        }

        if (!isxdigit((unsigned char)mac[i])) {
            return false;
        }
    }

    return true;
}

bool security_mac_matches_any_oui(const char *mac, const whitelist_entry_t *entry)
{
    if (!security_is_valid_mac(mac) || entry == NULL) {
        return false;
    }

    for (size_t i = 0; i < entry->allowed_oui_count && i < MAX_ALLOWED_OUIS; ++i) {
        const char *oui = entry->allowed_ouis[i];
        if (oui == NULL) {
            continue;
        }

        if (strncmp(mac, oui, 8) == 0) {
            return true;
        }
    }

    return false;
}

bool security_mac_matches_entry(const char *mac, const whitelist_entry_t *entry)
{
    if (!security_is_valid_mac(mac) || entry == NULL) {
        return false;
    }

    if (entry->mac != NULL && strcasecmp(mac, entry->mac) == 0) {
        return true;
    }

    return security_mac_matches_any_oui(mac, entry);
}

bool security_rssi_delta_is_suspicious(int8_t previous_rssi, int8_t current_rssi)
{
    const int delta = abs((int)previous_rssi - (int)current_rssi);
    return delta >= WIFI_RSSI_FLAP_DELTA_DB;
}

bool security_observation_is_flapping(uint32_t missed_scans, uint32_t seen_count)
{
    return seen_count > 1U && missed_scans > 0U && missed_scans <= WIFI_FLAP_WINDOW_SCANS;
}

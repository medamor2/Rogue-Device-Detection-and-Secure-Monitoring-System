#include "device_manager.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

#include "esp_err.h"
#include "esp_log.h"
#include "device_policy.h"
#include "security.h"

static const char *TAG = "device_manager";

typedef struct {
    char mac[MAC_STRING_LENGTH];
    int8_t last_rssi;
    uint32_t last_seen_scan;
    uint32_t seen_count;
    uint32_t missed_scans;
    bool active;
    bool whitelisted;
} managed_device_t;

static managed_device_t s_devices[MAX_TRACKED_DEVICES];
static uint32_t s_scan_epoch;

static managed_device_t *find_device(const char *mac)
{
    for (size_t i = 0; i < MAX_TRACKED_DEVICES; ++i) {
        if (s_devices[i].active && strcasecmp(s_devices[i].mac, mac) == 0) {
            return &s_devices[i];
        }
    }

    return NULL;
}

static managed_device_t *allocate_device(const char *mac)
{
    for (size_t i = 0; i < MAX_TRACKED_DEVICES; ++i) {
        if (!s_devices[i].active) {
            memset(&s_devices[i], 0, sizeof(s_devices[i]));
            snprintf(s_devices[i].mac, sizeof(s_devices[i].mac), "%s", mac);
            s_devices[i].active = true;
            return &s_devices[i];
        }
    }

    return NULL;
}

static void append_alert(security_alert_t *alerts,
                         size_t alert_capacity,
                         size_t *alert_count,
                         const char *alert,
                         const char *mac,
                         int8_t rssi,
                         const char *details,
                         uint32_t scan_index)
{
    if (alerts == NULL || alert_count == NULL || *alert_count >= alert_capacity) {
        return;
    }

    security_alert_t *out = &alerts[*alert_count];
    snprintf(out->alert, sizeof(out->alert), "%s", alert);
    snprintf(out->mac, sizeof(out->mac), "%s", mac);
    out->rssi = rssi;
    snprintf(out->details, sizeof(out->details), "%s", details);
    out->scan_index = scan_index;
    ++(*alert_count);
}

void device_manager_init(void)
{
    memset(s_devices, 0, sizeof(s_devices));
    s_scan_epoch = 0;
    ESP_LOGI(TAG, "Device manager initialized with %u tracked slots", (unsigned)MAX_TRACKED_DEVICES);
}

esp_err_t device_manager_analyze_scan(const scan_batch_t *batch,
                                     security_alert_t *alerts,
                                     size_t alert_capacity,
                                     size_t *alert_count)
{
    if (batch == NULL || alerts == NULL || alert_count == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    *alert_count = 0;
    ++s_scan_epoch;

    for (size_t i = 0; i < batch->count; ++i) {
        const scan_result_t *result = &batch->results[i];
        if (!security_is_valid_mac(result->mac)) {
            continue;
        }

        const device_policy_match_t policy = device_policy_match(result->mac, result->ssid);

        managed_device_t *device = find_device(result->mac);
        if (device == NULL) {
            device = allocate_device(result->mac);
        }

        if (device == NULL) {
            ESP_LOGW(TAG, "Tracking table full, dropping %s", result->mac);
            continue;
        }

        const bool is_new_device = device->seen_count == 0U;
        const uint32_t previous_missed_scans = device->missed_scans;
        device->seen_count++;
        device->last_seen_scan = s_scan_epoch;
        device->missed_scans = 0;
        device->whitelisted = policy.exact_whitelisted;

        if (!policy.exact_whitelisted && !policy.oui_whitelisted) {
            append_alert(alerts, alert_capacity, alert_count, "unknown_device", result->mac, result->rssi,
                         "Device is not present in the whitelist", s_scan_epoch);
        } else if (!policy.exact_whitelisted && policy.oui_whitelisted) {
            append_alert(alerts, alert_capacity, alert_count, "spoofing_suspected", result->mac, result->rssi,
                         "MAC OUI matches a trusted vendor but the exact address does not", s_scan_epoch);
        }

        if (policy.exact_whitelisted && policy.matched_entry != NULL) {
            if (result->rssi < policy.matched_entry->min_rssi || result->rssi > policy.matched_entry->max_rssi) {
                append_alert(alerts, alert_capacity, alert_count, "rssi_anomaly", result->mac, result->rssi,
                             "Trusted device is outside the expected RSSI band", s_scan_epoch);
            }
        }

        if (!is_new_device && security_rssi_delta_is_suspicious(device->last_rssi, result->rssi)) {
            append_alert(alerts, alert_capacity, alert_count, "rssi_fluctuation", result->mac, result->rssi,
                         "RSSI changed sharply between scan intervals", s_scan_epoch);
        }

        if (!is_new_device && security_observation_is_flapping(previous_missed_scans, device->seen_count)) {
            append_alert(alerts, alert_capacity, alert_count, "flapping_device", result->mac, result->rssi,
                         "Device disappears and reappears across scans", s_scan_epoch);
        }

        device->last_rssi = result->rssi;
    }

    for (size_t i = 0; i < MAX_TRACKED_DEVICES; ++i) {
        managed_device_t *device = &s_devices[i];
        if (!device->active || device->last_seen_scan == s_scan_epoch) {
            continue;
        }

        device->missed_scans++;
        if (device->whitelisted && device->missed_scans == WIFI_FLAP_WINDOW_SCANS) {
            append_alert(alerts, alert_capacity, alert_count, "trusted_device_missing", device->mac, device->last_rssi,
                         "Whitelisted device has gone missing for several scan cycles", s_scan_epoch);
        }
    }

    ESP_LOGI(TAG, "Analysis produced %u alerts", (unsigned)*alert_count);
    return ESP_OK;
}

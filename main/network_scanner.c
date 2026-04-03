#include "network_scanner.h"

#include <stdio.h>
#include <string.h>

#include "esp_log.h"
#include "esp_timer.h"
#include "esp_wifi.h"

static const char *TAG = "network_scanner";

esp_err_t network_scanner_init(void)
{
    ESP_LOGI(TAG, "Scanner initialized with active dwell %d ms", WIFI_SCAN_ACTIVE_DWELL_MS);
    return ESP_OK;
}

esp_err_t network_scanner_perform_scan(scan_batch_t *batch)
{
    if (batch == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    memset(batch, 0, sizeof(*batch));
    batch->captured_at_ms = esp_timer_get_time() / 1000;

    wifi_scan_config_t scan_config = {
        .scan_type = WIFI_SCAN_TYPE_ACTIVE,
        .ssid = NULL,
        .bssid = NULL,
        .channel = 0,
        .show_hidden = true,
        .scan_time = {
            .active = {
                .min = WIFI_SCAN_ACTIVE_DWELL_MS,
                .max = WIFI_SCAN_ACTIVE_DWELL_MS,
            },
        },
    };

    esp_err_t err = esp_wifi_scan_start(&scan_config, true);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Scan start failed: %s", esp_err_to_name(err));
        return err;
    }

    uint16_t ap_count = WIFI_SCAN_MAX_RESULTS_PER_RUN;
    wifi_ap_record_t ap_records[WIFI_SCAN_MAX_RESULTS_PER_RUN];
    memset(ap_records, 0, sizeof(ap_records));

    err = esp_wifi_scan_get_ap_records(&ap_count, ap_records);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to retrieve AP records: %s", esp_err_to_name(err));
        return err;
    }

    batch->scan_index++;
    batch->count = ap_count;

    for (size_t i = 0; i < batch->count; ++i) {
        const wifi_ap_record_t *record = &ap_records[i];
        scan_result_t *result = &batch->results[i];

        snprintf(result->mac, sizeof(result->mac), "%02X:%02X:%02X:%02X:%02X:%02X",
                 record->bssid[0], record->bssid[1], record->bssid[2],
                 record->bssid[3], record->bssid[4], record->bssid[5]);
        snprintf(result->ssid, sizeof(result->ssid), "%.*s", SSID_STRING_LENGTH - 1, (const char *)record->ssid);
        result->rssi = record->rssi;
        result->channel = record->primary;
        result->authmode = record->authmode;
        result->hidden = record->hidden;
    }

    ESP_LOGI(TAG, "Captured %u nearby networks", (unsigned)batch->count);
    return ESP_OK;
}

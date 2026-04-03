#pragma once

#include <stddef.h>
#include <stdint.h>

#include "config.h"
#include "esp_err.h"
#include "esp_wifi_types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char mac[MAC_STRING_LENGTH];
    char ssid[SSID_STRING_LENGTH];
    int8_t rssi;
    uint8_t channel;
    wifi_auth_mode_t authmode;
    bool hidden;
} scan_result_t;

typedef struct {
    scan_result_t results[MAX_SCAN_RESULTS];
    size_t count;
    int64_t captured_at_ms;
    uint32_t scan_index;
} scan_batch_t;

esp_err_t network_scanner_init(void);
esp_err_t network_scanner_perform_scan(scan_batch_t *batch);

#ifdef __cplusplus
}
#endif

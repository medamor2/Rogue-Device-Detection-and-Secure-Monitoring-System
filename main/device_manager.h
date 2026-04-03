#pragma once

#include <stddef.h>
#include <stdint.h>

#include "config.h"
#include "network_scanner.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char alert[ALERT_STRING_LENGTH];
    char mac[MAC_STRING_LENGTH];
    int8_t rssi;
    char details[DETAILS_STRING_LENGTH];
    uint32_t scan_index;
} security_alert_t;

void device_manager_init(void);
esp_err_t device_manager_analyze_scan(const scan_batch_t *batch,
                                     security_alert_t *alerts,
                                     size_t alert_capacity,
                                     size_t *alert_count);

#ifdef __cplusplus
}
#endif

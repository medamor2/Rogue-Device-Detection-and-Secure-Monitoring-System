#pragma once

#include "device_manager.h"

#ifdef __cplusplus
extern "C" {
#endif

esp_err_t communication_init(void);
esp_err_t communication_publish_alert(const security_alert_t *alert);
bool communication_is_connected(void);

#ifdef __cplusplus
}
#endif

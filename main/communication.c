#include "communication.h"

#include <stdio.h>
#include <string.h>

#include "esp_event.h"
#include "esp_crt_bundle.h"
#include "esp_log.h"
#include "esp_mqtt_client.h"

static const char *TAG = "communication";
static esp_mqtt_client_handle_t s_client;
static bool s_connected;

static esp_err_t publish_topic(const char *topic, const char *payload)
{
    if (s_client == NULL || !s_connected) {
        return ESP_ERR_INVALID_STATE;
    }

    const int message_id = esp_mqtt_client_publish(s_client, topic, payload, 0, 1, 0);
    if (message_id < 0) {
        ESP_LOGW(TAG, "MQTT publish failed for topic %s", topic);
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "Published MQTT message id %d to %s", message_id, topic);
    return ESP_OK;
}

static void mqtt_event_handler(void *handler_args,
                               esp_event_base_t base,
                               int32_t event_id,
                               void *event_data)
{
    (void)handler_args;
    (void)base;
    (void)event_data;
    switch (event_id) {
        case MQTT_EVENT_CONNECTED:
            s_connected = true;
            ESP_LOGI(TAG, "MQTT broker connected");
            break;
        case MQTT_EVENT_DISCONNECTED:
            s_connected = false;
            ESP_LOGW(TAG, "MQTT broker disconnected");
            break;
        case MQTT_EVENT_ERROR:
            s_connected = false;
            ESP_LOGE(TAG, "MQTT broker error");
            break;
        default:
            break;
    }
}

esp_err_t communication_init(void)
{
    esp_mqtt_client_config_t mqtt_cfg = {
        .broker.address.uri = MQTT_BROKER_URI,
        .broker.verification.crt_bundle_attach = esp_crt_bundle_attach,
        .credentials.client_id = MQTT_CLIENT_ID,
        .session.keepalive = 60,
        .network.timeout_ms = 5000,
    };

    s_client = esp_mqtt_client_init(&mqtt_cfg);
    if (s_client == NULL) {
        return ESP_FAIL;
    }

    esp_mqtt_client_register_event(s_client, ESP_EVENT_ANY_ID, mqtt_event_handler, NULL);
    esp_err_t err = esp_mqtt_client_start(s_client);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to start MQTT client: %s", esp_err_to_name(err));
        return err;
    }

    ESP_LOGI(TAG, "MQTT client started against %s", MQTT_BROKER_URI);
    return ESP_OK;
}

bool communication_is_connected(void)
{
    return s_connected;
}

esp_err_t communication_publish_alert(const security_alert_t *alert)
{
    if (alert == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    char payload[JSON_STRING_LENGTH];
    const int written = snprintf(payload,
                                 sizeof(payload),
                                 "{\"alert\":\"%s\",\"mac\":\"%s\",\"rssi\":%d,\"details\":\"%s\",\"scan_index\":%u}",
                                 alert->alert,
                                 alert->mac,
                                 alert->rssi,
                                 alert->details,
                                 (unsigned)alert->scan_index);
    if (written < 0 || written >= (int)sizeof(payload)) {
        return ESP_ERR_NO_MEM;
    }

    return publish_topic(MQTT_TOPIC_ALERTS, payload);
}

#include <stdio.h>
#include <string.h>

#include "communication.h"
#include "device_manager.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "nvs_flash.h"
#include "network_scanner.h"

static const char *TAG = "app_main";
static QueueHandle_t s_scan_queue;
static QueueHandle_t s_alert_queue;
static int s_wifi_retry_count;

static void wifi_event_handler(void *arg,
                               esp_event_base_t event_base,
                               int32_t event_id,
                               void *event_data)
{
    (void)arg;
    (void)event_data;

    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
        return;
    }

    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        if (s_wifi_retry_count < WIFI_MAX_RETRY) {
            ++s_wifi_retry_count;
            ESP_LOGW(TAG, "Wi-Fi disconnected, retrying (%d/%d)", s_wifi_retry_count, WIFI_MAX_RETRY);
            esp_wifi_connect();
        } else {
            ESP_LOGE(TAG, "Wi-Fi connection retries exhausted");
        }
    }
}

static void wifi_init_sta(void)
{
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT,
                                               ESP_EVENT_ANY_ID,
                                               &wifi_event_handler,
                                               NULL));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_ps(WIFI_PS_NONE));

    wifi_config_t wifi_config = { 0 };
    wifi_config.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;
    snprintf((char *)wifi_config.sta.ssid, sizeof(wifi_config.sta.ssid), "%s", WIFI_STA_SSID);
    snprintf((char *)wifi_config.sta.password, sizeof(wifi_config.sta.password), "%s", WIFI_STA_PASSWORD);

    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());
    ESP_LOGI(TAG, "Wi-Fi station initialized for monitoring and MQTT reporting");
}

static void scan_task(void *param)
{
    (void)param;

    for (;;) {
        scan_batch_t batch;
        esp_err_t err = network_scanner_perform_scan(&batch);
        if (err == ESP_OK) {
            if (xQueueSend(s_scan_queue, &batch, pdMS_TO_TICKS(1000)) != pdTRUE) {
                ESP_LOGW(TAG, "Scan queue full, dropping batch");
            }
        }

        vTaskDelay(pdMS_TO_TICKS(WIFI_SCAN_INTERVAL_MS));
    }
}

static void analysis_task(void *param)
{
    (void)param;

    for (;;) {
        scan_batch_t batch;
        if (xQueueReceive(s_scan_queue, &batch, portMAX_DELAY) != pdTRUE) {
            continue;
        }

        security_alert_t alerts[MAX_ALERTS_PER_BATCH];
        size_t alert_count = 0;
        if (device_manager_analyze_scan(&batch, alerts, MAX_ALERTS_PER_BATCH, &alert_count) != ESP_OK) {
            continue;
        }

        for (size_t i = 0; i < alert_count; ++i) {
            if (xQueueSend(s_alert_queue, &alerts[i], pdMS_TO_TICKS(1000)) != pdTRUE) {
                ESP_LOGW(TAG, "Alert queue full, dropping %s", alerts[i].alert);
            }
        }
    }
}

static void communication_task(void *param)
{
    (void)param;

    for (;;) {
        security_alert_t alert;
        if (xQueueReceive(s_alert_queue, &alert, portMAX_DELAY) != pdTRUE) {
            continue;
        }

        esp_err_t err = communication_publish_alert(&alert);
        if (err != ESP_OK) {
            ESP_LOGW(TAG, "Failed to publish alert %s for %s", alert.alert, alert.mac);
        }
    }
}

void app_main(void)
{
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    wifi_init_sta();
    device_manager_init();
    ESP_ERROR_CHECK(network_scanner_init());
    ESP_ERROR_CHECK(communication_init());

    s_scan_queue = xQueueCreate(4, sizeof(scan_batch_t));
    s_alert_queue = xQueueCreate(8, sizeof(security_alert_t));
    if (s_scan_queue == NULL || s_alert_queue == NULL) {
        ESP_LOGE(TAG, "Failed to create FreeRTOS queues");
        return;
    }

    xTaskCreatePinnedToCore(scan_task, "scan_task", 4096, NULL, 5, NULL, 0);
    xTaskCreatePinnedToCore(analysis_task, "analysis_task", 4096, NULL, 6, NULL, 1);
    xTaskCreatePinnedToCore(communication_task, "communication_task", 4096, NULL, 5, NULL, 1);

    ESP_LOGI(TAG, "Rogue Device Detection and Secure Monitoring System started");
}

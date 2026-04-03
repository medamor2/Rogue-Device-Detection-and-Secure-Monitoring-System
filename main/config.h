#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define PROJECT_NAME "Rogue Device Detection and Secure Monitoring System"
#define PROJECT_TAG "RDSSM"

#define WIFI_STA_SSID "CHANGE_ME_WIFI_SSID"
#define WIFI_STA_PASSWORD "CHANGE_ME_WIFI_PASSWORD"
#define WIFI_MAX_RETRY 5

#define WIFI_SCAN_INTERVAL_MS 15000
#define WIFI_SCAN_ACTIVE_DWELL_MS 120
#define WIFI_SCAN_MAX_RESULTS_PER_RUN MAX_SCAN_RESULTS
#define WIFI_SCAN_MIN_RSSI_ALERT_DBM (-80)
#define WIFI_RSSI_FLAP_DELTA_DB 25
#define WIFI_FLAP_WINDOW_SCANS 3

#define MAX_SCAN_RESULTS 16
#define MAX_TRACKED_DEVICES 24
#define MAX_ALERTS_PER_BATCH 8
#define MAX_WHITELIST_ENTRIES 8

#define MAC_STRING_LENGTH 18
#define SSID_STRING_LENGTH 33
#define ALERT_STRING_LENGTH 32
#define DETAILS_STRING_LENGTH 128
#define JSON_STRING_LENGTH 256

#define MQTT_BROKER_URI "mqtts://broker.example.com:8883"
#define MQTT_CLIENT_ID "rdssm-esp32-01"
#define MQTT_TOPIC_ALERTS "factory/security/rogue-devices/alerts"
#define MQTT_TOPIC_STATUS "factory/security/rogue-devices/status"

#define DEVICE_LABEL_LENGTH 32
#define OUI_STRING_LENGTH 9
#define MAX_ALLOWED_OUIS 4


#include "example_whitelist.h"

static const whitelist_entry_t s_whitelist[] = {
    {
        .label = "Factory Gateway",
        .mac = "A4:CF:12:10:20:30",
        .ssid = "Factory-Gateway-01",
        .allowed_ouis = { "A4:CF:12", NULL, NULL, NULL },
        .allowed_oui_count = 1,
        .min_rssi = -85,
        .max_rssi = -20,
    },
    {
        .label = "Vision Sensor Hub",
        .mac = "18:FE:34:AA:BB:CC",
        .ssid = "Vision-Hub-01",
        .allowed_ouis = { "18:FE:34", NULL, NULL, NULL },
        .allowed_oui_count = 1,
        .min_rssi = -80,
        .max_rssi = -25,
    },
    {
        .label = "Maintenance Tablet",
        .mac = "D8:3A:DD:01:02:03",
        .ssid = "Maintenance-Tablet",
        .allowed_ouis = { "D8:3A:DD", NULL, NULL, NULL },
        .allowed_oui_count = 1,
        .min_rssi = -75,
        .max_rssi = -15,
    },
};

const whitelist_entry_t *example_whitelist_get(size_t *count)
{
    if (count != NULL) {
        *count = sizeof(s_whitelist) / sizeof(s_whitelist[0]);
    }

    return s_whitelist;
}

#include <esp_netif.h>
#include <esp_netif_net_stack.h>
#include <esp_wifi.h>
#include "dns32_nvs.h"

#define DNS32_WIFI_AP_SSID "dns32"
#define DNS32_WIFI_AP_PASS "savethenetwork"
#define DNS32_WIFI_AP_MAX_CONN 10
#define DNS32_WIFI_AP_MAX_APS 15
#define DNS32_WIFI_STA_MAX_RETRY 5

typedef enum {
    DNS32_WIFI_SCAN_STARTED,
    DNS32_WIFI_SCAN_FAILED,
    DNS32_WIFI_SCAN_COMPLETED,
} dns32_wifi_event_t;

static void wifi_event_handler(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data);
esp_err_t initiate_common_wifi();
esp_err_t setup_softap();
esp_err_t setup_station();
esp_err_t initiate_wifi_scan_async();
esp_err_t log_wifi_scan_to_serial();
esp_err_t is_wifi_scan_done(bool *status);
esp_err_t get_wifi_scan_results(uint16_t *count, wifi_ap_record_t *scan_results);
esp_err_t get_current_ip_address(char *ip_address);
bool validate_wifi_credentials(char *wifiindex, char *wifipassword);
esp_err_t store_wifi_credentials(char *wifiindex, char *wifipassword);
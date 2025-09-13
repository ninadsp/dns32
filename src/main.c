#include "dns32.h"
#include "dns32_nvs.h"
#include "dns32_wifi.h"
#include "dns32_http.h"
#include "dns32_server.h"

// Define the global log tags
const char *TAG_DNS32 = "dns32";
const char *TAG_AP = "softap";
const char *TAG_STA = "sta";
const char *TAG_HTTP = "http";


void app_main(void)
{
    httpd_handle_t *http_server = NULL;
    bool is_station_mode;

    esp_log_level_set("httpd_uri", ESP_LOG_ERROR);
    esp_log_level_set("httpd_txrx", ESP_LOG_ERROR);
    esp_log_level_set("httpd_parse", ESP_LOG_ERROR);
    esp_log_level_set("wifi", ESP_LOG_ERROR);
    esp_log_level_set("esp_netif_lwip", ESP_LOG_ERROR);

    ESP_ERROR_CHECK(esp_netif_init());
    // Need to handle ESP_ERR_NVS_NO_FREE_PAGES and ESP_ERR_NVS_NEW_VERSION_FOUND
    ESP_ERROR_CHECK(nvs_flash_init());
    ESP_ERROR_CHECK(initiate_common_wifi());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    ESP_ERROR_CHECK(mdns_init());
    
    // Initialize DNS server
    ESP_ERROR_CHECK(dns_server_init());
    // At some point of time, figure out how to respond to multiple names on mdns
    ESP_ERROR_CHECK(mdns_hostname_set("dns32"));

    if (is_wifi_stored() == ESP_OK)
    {
        ESP_LOGI(TAG_DNS32, "Found stored wifi");
        ESP_ERROR_CHECK_WITHOUT_ABORT(setup_station());
        is_station_mode = true;
    }
    else
    {
        // There can be multiple reasons why this failed. For now, let us just assume
        // that storage is fine, and we don't have the wifi info
        ESP_LOGI(TAG_DNS32, "No stored wifi");
        ESP_ERROR_CHECK_WITHOUT_ABORT(setup_softap());
        ESP_ERROR_CHECK_WITHOUT_ABORT(initiate_wifi_scan_async());
        is_station_mode = false;
        // TODO: Implement a basic DNS server so that mDNS can work?
    }

    assert(http_server == NULL);
    ESP_ERROR_CHECK_WITHOUT_ABORT(start_webserver(http_server));

    // Start DNS server
    ESP_ERROR_CHECK_WITHOUT_ABORT(dns_server_start(is_station_mode));

    while (http_server != NULL)
    {
        vTaskDelay(100000 / portTICK_PERIOD_MS);
    }
}
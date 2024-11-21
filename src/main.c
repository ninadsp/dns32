#include "dns32.h"
#include "dns32_nvs.h"
#include "dns32_wifi.h"
#include "dns32_http.h"

void app_main(void)
{
    httpd_handle_t *server = NULL;
    ESP_ERROR_CHECK(esp_netif_init());
    // Need to handle ESP_ERR_NVS_NO_FREE_PAGES and ESP_ERR_NVS_NEW_VERSION_FOUND
    ESP_ERROR_CHECK(nvs_flash_init());
    ESP_ERROR_CHECK(initiate_common_wifi());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    if (is_wifi_stored() == ESP_OK)
    {
        ESP_LOGI(TAG_DNS32, "Found stored wifi");
        ESP_ERROR_CHECK_WITHOUT_ABORT(setup_station());
    }
    else
    {
        // There can be multiple reasons why this failed. For now, let us just assume
        // that storage is fine, and we don't have the wifi info
        ESP_LOGI(TAG_DNS32, "No stored wifi");
        ESP_ERROR_CHECK_WITHOUT_ABORT(setup_softap());
        ESP_ERROR_CHECK_WITHOUT_ABORT(initiate_wifi_scan_async());
        // Figure out how to start a web server now, and render the list of APs
    }

    assert(server == NULL);
    ESP_ERROR_CHECK_WITHOUT_ABORT(start_webserver(server));

    while (server != NULL)
    {
        vTaskDelay(100000 / portTICK_PERIOD_MS);
    }
}
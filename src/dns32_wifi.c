#include "dns32.h"
#include "dns32_wifi.h"

int32_t wifi_scan_last_status = NULL;

static void wifi_event_handler(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data)
{
    if (event_id == WIFI_EVENT_SCAN_DONE)
    {
        ESP_LOGI(TAG_AP, "WiFi scan completed in the background");
        wifi_scan_last_status = DNS32_WIFI_SCAN_COMPLETED;
        //log_wifi_scan_to_serial();
    }
};

esp_err_t initiate_common_wifi()
{
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    return esp_wifi_init(&cfg);
};

esp_err_t setup_station()
{
    char *station_ssid;
    char *station_password;
    station_ssid = malloc(MAX_SSID_LEN + 1);
    station_password = malloc(MAX_PASSPHRASE_LEN + 1);
    assert(station_ssid != NULL);
    assert(station_password != NULL);
    ESP_ERROR_CHECK_WITHOUT_ABORT(get_wifi_credentials(station_ssid, station_password));
    // We are pretty sure that this will not fail, as is_wifi_stored has returned successfully
    ESP_ERROR_CHECK_WITHOUT_ABORT(esp_wifi_set_mode(WIFI_MODE_STA));

    wifi_config_t station_config = {
        .ap = {
            .authmode = WIFI_AUTH_WPA2_PSK}};

    strcpy((char *)station_config.ap.ssid, station_ssid);
    strcpy((char *)station_config.ap.password, station_password);

    ESP_ERROR_CHECK_WITHOUT_ABORT(esp_wifi_set_config(WIFI_IF_STA, &station_config));
    ESP_ERROR_CHECK(esp_wifi_start());
    return ESP_OK;
};

esp_err_t setup_softap()
{
    ESP_ERROR_CHECK_WITHOUT_ABORT(esp_wifi_set_mode(WIFI_MODE_APSTA));

    esp_netif_create_default_wifi_ap();
    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, NULL, NULL));

    wifi_config_t ap_config = {
        .ap = {
            .ssid = DNS32_WIFI_AP_SSID,
            .ssid_len = strlen(DNS32_WIFI_AP_SSID),
            .password = DNS32_WIFI_AP_PASS,
            .authmode = WIFI_AUTH_WPA2_PSK,
            .max_connection = DNS32_WIFI_AP_MAX_CONN}};

    ESP_ERROR_CHECK_WITHOUT_ABORT(esp_wifi_set_config(WIFI_IF_AP, &ap_config));
    ESP_ERROR_CHECK(esp_wifi_start());

    return ESP_OK;
};

esp_err_t initiate_wifi_scan_async()
{
    esp_netif_t *netif_station = esp_netif_create_default_wifi_sta();
    assert(netif_station);

    ESP_ERROR_CHECK_WITHOUT_ABORT(esp_wifi_scan_start(NULL, false));
    wifi_scan_last_status = DNS32_WIFI_SCAN_STARTED;
    ESP_LOGI(TAG_AP, "Triggered wifi scan");

    return ESP_OK;
};

esp_err_t log_wifi_scan_to_serial()
{
    uint16_t count = 0;
    uint16_t number = DNS32_WIFI_AP_MAX_APS;
    wifi_ap_record_t *neighbouring_aps = (wifi_ap_record_t *)malloc(sizeof(wifi_ap_record_t) * number);

    if (neighbouring_aps == NULL)
    {
        ESP_LOGE(TAG_AP, "No memory available to allocate for scan results");
        return ESP_ERR_NO_MEM;
    }

    memset(neighbouring_aps, 0, sizeof(wifi_ap_record_t) * number);
    ESP_ERROR_CHECK(esp_wifi_scan_get_ap_num(&count));
    ESP_LOGI(TAG_AP, "Current count of networks scanned is %u", count);
    ESP_ERROR_CHECK(esp_wifi_scan_get_ap_records(&number, neighbouring_aps));
    ESP_LOGI(TAG_STA, "Total APs scanned: %u, actual APs found:%u", number, count);

    for (int i = 0; i < count; i++)
    {
        ESP_LOGI(TAG_STA, "SSID: %s, RSSI: %d, Auth: ", neighbouring_aps[i].ssid, neighbouring_aps[i].rssi);
    }

    ESP_LOGI(TAG_STA, "Done scanning and printing all networks");
    free(neighbouring_aps);
    return ESP_OK;
};

esp_err_t is_wifi_scan_done(bool *status)
{
    *status = false;
    if (wifi_scan_last_status == DNS32_WIFI_SCAN_COMPLETED) {
        *status = true;
    }
    return ESP_OK;
};

esp_err_t get_wifi_scan_results(uint16_t *count, wifi_ap_record_t *scan_results)
{
    uint16_t number = DNS32_WIFI_AP_MAX_APS;
    scan_results = (wifi_ap_record_t *)malloc(sizeof(wifi_ap_record_t) * number);
    count = (uint16_t *)malloc(sizeof(uint16_t));

    if (scan_results == NULL)
    {
        ESP_LOGE(TAG_AP, "No memory available to allocate for scan results");
        return ESP_ERR_NO_MEM;
    }

    memset(scan_results, 0, sizeof(wifi_ap_record_t) * number);
    ESP_ERROR_CHECK(esp_wifi_scan_get_ap_num(count));
    ESP_ERROR_CHECK(esp_wifi_scan_get_ap_records(&number, scan_results));

   return ESP_OK;
};

esp_err_t get_current_ip_address(char *ip_address)
{
    esp_netif_t *default_netif_stack;
    esp_netif_ip_info_t ip_info;

    default_netif_stack = esp_netif_get_default_netif();
    ESP_RETURN_ON_ERROR(esp_netif_get_ip_info(default_netif_stack, &ip_info), TAG_STA, "Cannot query for IP address of the device");
    char *rc = esp_ip4addr_ntoa(&ip_info.ip, ip_address, IP4ADDR_STRLEN_MAX);
    if (rc == NULL)
    {
        ESP_LOGI(TAG_STA, "Failed converting IP address to string");
        return ESP_FAIL;
    }

    return ESP_OK;
};
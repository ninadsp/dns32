#include "dns32.h"
#include "dns32_nvs.h"

esp_err_t is_wifi_stored()
{
    nvs_handle_t nvs_wifi_ro;
    nvs_type_t stored_ssid_found_type;
    ESP_RETURN_ON_ERROR(nvs_open(DNS32_NVS_WIFI_NS, NVS_READONLY, &nvs_wifi_ro), TAG_DNS32, "Cannot open storage to fetch WiFi credentials");
    ESP_RETURN_ON_ERROR(nvs_find_key(nvs_wifi_ro, "ssid", &stored_ssid_found_type), TAG_DNS32, "Cannot find WiFi credentials in storage");
    ESP_RETURN_ON_FALSE(stored_ssid_found_type == NVS_TYPE_STR, ESP_ERR_INVALID_STATE, TAG_DNS32, "WiFi credentials in storage are corrupted");
    nvs_close(nvs_wifi_ro);
    return ESP_OK;
};

/*
We only call this when is_mb_wifi_stored has returned true
So, the only reason nvs_open will fail is due to memory or other real hardware failures
*/
esp_err_t get_wifi_credentials(char *ssid, char *password)
{
    nvs_handle_t nvs_wifi_ro;
    size_t ssid_size, password_size;

    ESP_RETURN_ON_ERROR(nvs_open(DNS32_NVS_WIFI_NS, NVS_READONLY, &nvs_wifi_ro), TAG_DNS32, "Failed to access NVS for getting WiFi credentials");
    ESP_RETURN_ON_ERROR(nvs_get_str(nvs_wifi_ro, "ssid", NULL, &ssid_size), TAG_DNS32, "Cannot get length of WiFi name");
    ESP_RETURN_ON_ERROR(nvs_get_str(nvs_wifi_ro, "password", NULL, &password_size), TAG_DNS32, "Cannot get length of WiFi password");
    ESP_RETURN_ON_ERROR(nvs_get_str(nvs_wifi_ro, "ssid", ssid, &ssid_size), TAG_DNS32, "Cannot get WiFi name");
    ESP_RETURN_ON_ERROR(nvs_get_str(nvs_wifi_ro, "password", password, &password_size), TAG_DNS32, "Cannot get WiFi password");
    nvs_close(nvs_wifi_ro);
    return ESP_OK;
};

esp_err_t set_wifi_credentials(char *ssid, char *password)
{
    nvs_handle nvs_wifi_rw;

    ESP_RETURN_ON_ERROR(nvs_open(DNS32_NVS_WIFI_NS, NVS_READWRITE, &nvs_wifi_rw), TAG_DNS32, "Failed to access NVS for writing WiFi credentials");
    ESP_RETURN_ON_ERROR(nvs_set_str(nvs_wifi_rw, "ssid", ssid), TAG_DNS32, "Cannot write WiFi name");
    ESP_RETURN_ON_ERROR(nvs_set_str(nvs_wifi_rw, "password", password), TAG_DNS32, "Cannot write WiFi password");
    ESP_ERROR_CHECK(nvs_commit(nvs_wifi_rw));
    nvs_close(nvs_wifi_rw);
    return ESP_OK;
};
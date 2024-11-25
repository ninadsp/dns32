#include <esp_flash.h>
#include <nvs_flash.h>
#include <nvs.h>

#define DNS32_NVS_WIFI_NS "WiFi"

esp_err_t is_wifi_stored();

esp_err_t get_wifi_credentials(char *ssid, char *password);

esp_err_t set_wifi_credentials(char *ssid, char *password);
esp_err_t clear_wifi_credentials();
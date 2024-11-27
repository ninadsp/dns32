#include "dns32.h"
#include "dns32_http.h"
#include "dns32_web_fragments.h"
#include "dns32_wifi.h"

static esp_err_t hello_get_handler(httpd_req_t *req)
{

    ESP_LOGI(TAG_HTTP, "Handling hello get request");
    ESP_RETURN_ON_ERROR(httpd_resp_send(req, HTML_FRAGMENT_HELLO_WORLD, HTTPD_RESP_USE_STRLEN), TAG_HTTP, "Error sending hello world response");

    return ESP_OK;
};

static esp_err_t index_get_handler(httpd_req_t *req)
{
    char current_ip_address_string[IP4ADDR_STRLEN_MAX];
    bool wifi_scan_status = false;
    ESP_LOGI(TAG_HTTP, "Received Index get request");

    ESP_RETURN_ON_ERROR(httpd_resp_send_chunk(req,
                                              HTML_FRAGMENT_COMMON_HEADER,
                                              strlen(HTML_FRAGMENT_COMMON_HEADER)),
                        TAG_HTTP,
                        "Error sending index handler");

    is_wifi_scan_done(&wifi_scan_status);
    wifi_mode_t current_mode;
    uint8_t wifi_mac[6];
    ESP_ERROR_CHECK(esp_wifi_get_mode(&current_mode));

    ESP_ERROR_CHECK(esp_wifi_get_mac(current_mode == WIFI_MODE_APSTA ? WIFI_MODE_AP : current_mode, wifi_mac));
    get_current_ip_address(current_ip_address_string);
    RENDER_AND_SEND_CHUNK(
        req, HTML_FRAGMENT_WIFI_STATUS,
         current_ip_address_string,
         wifi_mac[0], wifi_mac[1], wifi_mac[2], wifi_mac[3], wifi_mac[4], wifi_mac[5]);

    if (current_mode == WIFI_MODE_AP)
    {
        RENDER_AND_SEND_CHUNK(req, HTML_FRAGMENT_WIFI_SELECTOR_SCAN_STATUS_FRAGMENT, wifi_scan_status ? WIFI_STATUS_COMPLETE : WIFI_STATUS_IN_PROGRESS);
    }

    if (wifi_scan_status)
    {

        wifi_ap_record_t *scan_results = (wifi_ap_record_t *)malloc(sizeof(wifi_ap_record_t) * DNS32_WIFI_AP_MAX_APS);
        uint16_t *count = (uint16_t *)malloc(sizeof(uint16_t));
        get_wifi_scan_results(count, scan_results);

        RENDER_AND_SEND_CHUNK(req, HTML_FRAGMENT_WIFI_SELECTOR_TABLE_HEADER, *count);

        for (int i = 0; i < *count; i++)
        {
            RENDER_AND_SEND_CHUNK(req, HTML_FRAGMENT_WIFI_SELECTOR_TABLE_BODY_ROW, scan_results[i].ssid, scan_results[i].rssi, i, i);
        }

        ESP_RETURN_ON_ERROR(httpd_resp_send_chunk(req,
                                                  HTML_FRAGMENT_WIFI_SELECTOR_TABLE_FOOTER,
                                                  strlen(HTML_FRAGMENT_WIFI_SELECTOR_TABLE_FOOTER)),
                            TAG_HTTP,
                            "Error sending index handler");
        free(scan_results);
        free(count);
    } else {
        wifi_ap_record_t current_ap_info;
        ESP_ERROR_CHECK(esp_wifi_sta_get_ap_info(&current_ap_info));
        RENDER_AND_SEND_CHUNK(req, HTML_FRAGMENT_STATUS_PAGE, current_ap_info.ssid );
    }

    ESP_RETURN_ON_ERROR(httpd_resp_send_chunk(req,
                                              HTML_FRAGMENT_COMMON_END, strlen(HTML_FRAGMENT_COMMON_END)),
                        TAG_HTTP,
                        "Error sending index handler");

    ESP_RETURN_ON_ERROR(httpd_resp_send_chunk(req, NULL, 0), TAG_HTTP, "Error sending index handler");

    return ESP_OK;
};

static esp_err_t wifi_configure_post_handler(httpd_req_t *req)
{
    char content[100]; // TODO: What happens if 100 chars is insufficient?
    int ret = 0;
    memset(content, 0, sizeof(content));
    size_t recv_size;
    if (req->content_len > sizeof(content) - 1)
    {
        recv_size = sizeof(content) - 1;
    }
    else
    {
        recv_size = req->content_len;
    }
    // we can now guarantee that the last byte in content is going to be null;
    ret = httpd_req_recv(req, content, recv_size);
    assert(content[recv_size] == '\0');
    if (ret <= 0)
    {
        if (ret == HTTPD_SOCK_ERR_TIMEOUT)
        {
            httpd_resp_send_408(req);
        }
        return ESP_FAIL;
    }

    /*
        At the end of this code block, we convert:
        wifiindex=1&wifipassword=testpassword\0
        into
        wifiindex\01\0wifipassword\0testpassword\0
        the original string has now been mangled to replace
        = and & with end of string, and that simplifies a lot of
        our string pointer dance down below
    */
    char *wifiindex = NULL;
    char wifissid[MAX_SSID_LEN + 1];
    char *wifipass = NULL;
    char *start_of_content = content;
    char *end_of_content = content + recv_size;
    char *equal_pos = NULL;
    char *ampersand_pos = strchrnul(start_of_content, '&');
    while (ampersand_pos <= end_of_content)
    {
        *ampersand_pos = '\0';
        equal_pos = strchrnul(start_of_content, '=');
        *equal_pos = '\0';
        if (strlen(equal_pos + 1) == 0)
        {
            // ideally, we'll validate this on the client side
            ESP_LOGI(TAG_HTTP, "Received an empty form field %s", start_of_content);
            const char resp[] = "Please select a Wifi network";
            httpd_resp_send(req, resp, strlen(resp));
            return ESP_FAIL;
        };
        // key = start_of_content, value = equal_pos + 1
        // This is not at all generic
        if (strcmp(start_of_content, "wifiindex") == 0)
        {
            wifiindex = equal_pos + 1;
        }
        else if (strcmp(start_of_content, "wifipassword") == 0)
        {
            wifipass = equal_pos + 1;
        };
        start_of_content = ampersand_pos + 1;
        ampersand_pos = strchrnul(start_of_content, '&');
    };

    if (validate_wifi_credentials(wifiindex, wifipass))
    {
        ESP_RETURN_ON_ERROR(store_wifi_credentials(wifiindex, wifipass), TAG_HTTP, "Unable to store wifi credentials");

        const char resp[] = "WIFI configuration received, will restart in 10 seconds";
        httpd_resp_send(req, resp, strlen(resp));
        // reboot in 10 seconds
        vTaskDelay(10000 / portTICK_PERIOD_MS);
        esp_restart();
        return ESP_OK;
    }
    else
    {
        ESP_LOGE(TAG_HTTP, "Incorrect WiFi information provided");
        const char resp[] = "WiFi configuration failed during validation";
        httpd_resp_send(req, resp, strlen(resp));
        return ESP_FAIL;
    }
};

esp_err_t wifi_reset_get_handler(httpd_req_t *req)
{
    ESP_LOGI(TAG_HTTP, "Handling wifi reset request");
    ESP_RETURN_ON_ERROR(clear_wifi_credentials(), TAG_HTTP, "Unable to clear wifi information");
    ESP_RETURN_ON_ERROR(httpd_resp_send(req, "Wifi configuration reset successfully", HTTPD_RESP_USE_STRLEN), TAG_HTTP, "Error sending hello world response");

    vTaskDelay(10000 / portTICK_PERIOD_MS);
    esp_restart();
    return ESP_OK;
}

esp_err_t start_webserver(httpd_handle_t *server)
{
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.max_uri_handlers = 10;

    ESP_RETURN_ON_ERROR(httpd_start(&server, &config), TAG_HTTP, "Error starting webserver");
    ESP_ERROR_CHECK_WITHOUT_ABORT(httpd_register_uri_handler(server, &hello_handler));
    ESP_ERROR_CHECK_WITHOUT_ABORT(httpd_register_uri_handler(server, &index_handler));
    ESP_ERROR_CHECK_WITHOUT_ABORT(httpd_register_uri_handler(server, &wifi_configure_handler));
    ESP_ERROR_CHECK_WITHOUT_ABORT(httpd_register_uri_handler(server, &wifi_reset_handler));
    ESP_LOGI(TAG_HTTP, "Registered all HTTPD handlers");

    return ESP_OK;
}
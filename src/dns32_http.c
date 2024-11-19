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
    ESP_LOGI(TAG_HTTP, "Received Index get request");
    // We need the current IP address, state of wifi scanning,
    // and the list of wifi APs in range, if the scan has completed

    ESP_RETURN_ON_ERROR(httpd_resp_send_chunk(req,
                                              HTML_FRAGMENT_COMMON_HEADER,
                                              strlen(HTML_FRAGMENT_COMMON_HEADER)),
                        TAG_HTTP,
                        "Error sending index handler");

    char *buffer = NULL;
    char current_ip_address_string[IP4ADDR_STRLEN_MAX];
    get_current_ip_address(current_ip_address_string);
    int rc = asprintf(&buffer, HTML_FRAGMENT_WIFI_SELECTOR_HEADER, current_ip_address_string);
    if (rc < 0)
    {
        ESP_LOGI(TAG_HTTP, "Unable to render wifi selector header fragment");
        return ESP_FAIL;
    }
    esp_err_t chunk_sending_error;
    chunk_sending_error = httpd_resp_send_chunk(req, buffer, strlen(buffer));
    free(buffer);
    ESP_RETURN_ON_ERROR(chunk_sending_error,
                        TAG_HTTP,
                        "Error sending index handler");

    char *buffer2 = NULL;
    bool wifi_scan_status = false;
    is_wifi_scan_done(&wifi_scan_status);
    int rc1;
    if (wifi_scan_status)
    {
        rc1 = asprintf(&buffer2, HTML_FRAGMENT_WIFI_SELECTOR_SCAN_STATUS_FRAGMENT, WIFI_STATUS_COMPLETE);
        if (rc1 < 0)
        {
            ESP_LOGI(TAG_HTTP, "Unable to render wifi scan status fragment (true)");
            return ESP_FAIL;
        }
    }
    else
    {
        rc1 = asprintf(&buffer2, HTML_FRAGMENT_WIFI_SELECTOR_SCAN_STATUS_FRAGMENT, WIFI_STATUS_IN_PROGRESS);
        if (rc1 < 0)
        {
            ESP_LOGI(TAG_HTTP, "Unable to render wifi scan status fragment (true)");
            return ESP_FAIL;
        }
    }
    chunk_sending_error = httpd_resp_send_chunk(req, buffer2, strlen(buffer2));
    free(buffer2);
    ESP_RETURN_ON_ERROR(chunk_sending_error, TAG_HTTP, "Error sending index handler");

    if (wifi_scan_status) {
        wifi_ap_record_t *scan_results = NULL;
        uint16_t *count = NULL;
        get_wifi_scan_results(count, scan_results);

        char *buffer3 = NULL;
        int rc3 = asprintf(&buffer3, HTML_FRAGMENT_WIFI_SELECTOR_TABLE_HEADER, count);
        if (rc3 < 0){
            ESP_LOGI(TAG_HTTP, "Unable to render wifi table header");
        }
        else {
            httpd_resp_send_chunk(req, buffer3, strlen(buffer3));
            char *buffer4 = NULL;
            int rc4;
            for(int i=0; i < count; i++) {
                rc4 = asprintf(&buffer4, HTML_FRAGMENT_WIFI_SELECTOR_TABLE_BODY_ROW, scan_results[i].ssid, scan_results[i].rssi);
                if(rc4 < 0) {
                    ESP_LOGI(TAG_HTTP, "Unable to render a Wifi table row");
                }
                httpd_resp_send_chunk(req, buffer4, strlen(buffer4));
                free(buffer4);
            }

            httpd_resp_send_chunk(req, HTML_FRAGMENT_WIFI_SELECTOR_TABLE_FOOTER, strlen(HTML_FRAGMENT_WIFI_SELECTOR_TABLE_FOOTER));
        }
        free(buffer3);

        free(scan_results);
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
    ESP_LOGW(TAG_HTTP, "Method not implemented");
    return ESP_OK;
};

esp_err_t start_webserver(httpd_handle_t *server)
{
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.max_uri_handlers = 10;

    ESP_RETURN_ON_ERROR(httpd_start(&server, &config), TAG_HTTP, "Error starting webserver");
    ESP_ERROR_CHECK_WITHOUT_ABORT(httpd_register_uri_handler(server, &hello_handler));
    ESP_ERROR_CHECK_WITHOUT_ABORT(httpd_register_uri_handler(server, &index_handler));
    ESP_ERROR_CHECK_WITHOUT_ABORT(httpd_register_uri_handler(server, &wifi_configure_handler));
    ESP_LOGI(TAG_HTTP, "Registered all HTTPD handlers");

    return ESP_OK;
}
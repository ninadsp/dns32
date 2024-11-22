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

    get_current_ip_address(current_ip_address_string);
    RENDER_AND_SEND_CHUNK(req, HTML_FRAGMENT_WIFI_SELECTOR_HEADER, current_ip_address_string);

    is_wifi_scan_done(&wifi_scan_status);
    RENDER_AND_SEND_CHUNK(req, HTML_FRAGMENT_WIFI_SELECTOR_SCAN_STATUS_FRAGMENT, wifi_scan_status ? WIFI_STATUS_COMPLETE : WIFI_STATUS_IN_PROGRESS);

    if (wifi_scan_status)
    {
        wifi_ap_record_t *scan_results = (wifi_ap_record_t *)malloc(sizeof(wifi_ap_record_t) * DNS32_WIFI_AP_MAX_APS);
        uint16_t *count = (uint16_t *)malloc(sizeof(uint16_t));
        get_wifi_scan_results(count, scan_results);

        RENDER_AND_SEND_CHUNK(req, HTML_FRAGMENT_WIFI_SELECTOR_TABLE_HEADER, *count);

        for (int i = 0; i < *count; i++)
        {
            RENDER_AND_SEND_CHUNK(req, HTML_FRAGMENT_WIFI_SELECTOR_TABLE_BODY_ROW, scan_results[i].ssid, scan_results[i].rssi, scan_results[i].rssi, scan_results[i].rssi);
        }

        ESP_RETURN_ON_ERROR(httpd_resp_send_chunk(req,
                                                  HTML_FRAGMENT_WIFI_SELECTOR_TABLE_FOOTER,
                                                  strlen(HTML_FRAGMENT_WIFI_SELECTOR_TABLE_FOOTER)),
                            TAG_HTTP,
                            "Error sending index handler");
        free(scan_results);
        free(count);
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
    char content[100];
    int ret = 0;
    memset(content, 0, sizeof(content));
    size_t recv_size;
    if ( req->content_len > sizeof(content)) {
        recv_size = sizeof(content);
    } else {
        recv_size = req->content_len;
    }
    ret = httpd_req_recv(req, content, recv_size);
    if ( ret <= 0) {
        if (ret == HTTPD_SOCK_ERR_TIMEOUT) {
            httpd_resp_send_408(req);
        }
        return ESP_FAIL;
    }
    ESP_LOGI(TAG_HTTP, "Received POST data: %s", content);
    // Received POST data: wifiindex=-96&wifipassword=testpassword
    // TODO: validate inputs, and then invoke set_wifi_credentials, send signals to main to switch context

    const char resp[] = "WIFI configuration received";
    httpd_resp_send(req, resp, strlen(resp));
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
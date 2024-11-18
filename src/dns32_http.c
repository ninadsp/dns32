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

static esp_err_t index_get_handler(httpd_req_t *req) {
    ESP_LOGI(TAG_HTTP, "Received Index get request");
    // We need the current IP address, state of wifi scanning,
    // and the list of wifi APs in range, if the scan has completed

    ESP_RETURN_ON_ERROR(httpd_resp_send_chunk(req, 
    HTML_FRAGMENT_COMMON_HEADER, 
    strlen(HTML_FRAGMENT_COMMON_HEADER) ),
    TAG_HTTP,
    "Error sending index handler");

    const char *buffer;
    esp_ip4_addr_t current_ip_address;
    get_current_ip_address(&current_ip_address);
    int rc = asprintf(&buffer, HTML_FRAGMENT_WIFI_SELECTOR_HEADER, IP2STR(&current_ip_address));
    if (rc != 0 ) {
        ESP_LOGI(TAG_HTTP, "Unable to copy string to new buffer for IP address");
        return ESP_FAIL;
    }
    esp_err_t chunk_sending_error;
    chunk_sending_error = httpd_resp_send_chunk(req, buffer, strlen(buffer));
    free(buffer);
    ESP_RETURN_ON_ERROR( chunk_sending_error,
    TAG_HTTP,
    "Error sending index handler");

   ESP_RETURN_ON_ERROR(httpd_resp_send_chunk(req,
   HTML_FRAGMENT_COMMON_END, strlen(HTML_FRAGMENT_COMMON_END)),
   TAG_HTTP,
   "Error sending index handler");

    ESP_RETURN_ON_ERROR(httpd_resp_send(req, HTML_FRAGMENT_HELLO_WORLD, HTTPD_RESP_USE_STRLEN), TAG_HTTP, "Error sending hello world response");

    return ESP_OK;
};

static esp_err_t wifi_configure_post_handler(httpd_req_t *req) {
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
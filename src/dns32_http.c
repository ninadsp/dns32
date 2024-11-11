#include "dns32.h"
#include "dns32_http.h"

static esp_err_t hello_get_handler(httpd_req_t *req)
{
    char buf[100] = "<html><body><h1>Hello World</h1></body></html>";

    ESP_LOGI(TAG_HTTP, "Handling hello get request");
    httpd_resp_send(req, buf, HTTPD_RESP_USE_STRLEN);

    return ESP_OK;
};

esp_err_t start_webserver(httpd_handle_t *server)
{
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.max_uri_handlers = 10;

    ESP_RETURN_ON_ERROR(httpd_start(&server, &config), TAG_HTTP, "Error starting webserver");
    ESP_ERROR_CHECK_WITHOUT_ABORT(httpd_register_uri_handler(server, &hello));

    return ESP_OK;
}
#include <esp_http_server.h>

esp_err_t start_webserver(httpd_handle_t *server);

static esp_err_t hello_get_handler(httpd_req_t *req);

static const httpd_uri_t hello = {
    .uri = "/hello",
    .method = HTTP_GET,
    .handler = hello_get_handler,
    .user_ctx = NULL};
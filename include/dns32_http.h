#include <esp_http_server.h>

esp_err_t start_webserver(httpd_handle_t *server);

static esp_err_t hello_get_handler(httpd_req_t *req);

static esp_err_t index_get_handler(httpd_req_t *req);

static esp_err_t wifi_configure_post_handler(httpd_req_t *req);

static esp_err_t wifi_reset_get_handler(httpd_req_t *req);

static const httpd_uri_t hello_handler = {
    .uri = "/hello",
    .method = HTTP_GET,
    .handler = hello_get_handler,
    .user_ctx = NULL};

static const httpd_uri_t index_handler = {
    .uri = "/",
    .method = HTTP_GET,
    .handler = index_get_handler,
    .user_ctx = NULL};

static const httpd_uri_t wifi_configure_handler = {
    .uri = "/wifi-configure",
    .method = HTTP_POST,
    .handler = wifi_configure_post_handler,
    .user_ctx = NULL};

static const httpd_uri_t wifi_reset_handler = {
    .uri = "/wifi-reset",
    .method = HTTP_POST,
    .handler = wifi_reset_get_handler,
    .user_ctx = NULL};


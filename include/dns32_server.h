#pragma once

#include "dns32.h"

// DNS server initialization and task management
esp_err_t dns_server_init(void);
esp_err_t dns_server_start(bool is_station_mode);

// DNS server configuration and upstream DNS management
void update_global_upstream_dns_servers(esp_netif_t *netif);

// DNS packet parsing utilities
char *parse_dns_name(char *raw_name, char *parsed_name, size_t parsed_name_max_len);

// DNS query handler framework
esp_err_t dns_handler_register(uint16_t query_type, dns_query_handler_t handler, const char *type_name);
dns_query_handler_t dns_handler_get(uint16_t query_type);
const char* dns_query_type_name(uint16_t query_type);

// DNS response building utilities
esp_err_t build_dns_response(
    dns_header_t *query_header,
    const char *name,
    dns_response_data_t responses[],
    int response_count,
    char *output_buffer,
    int *output_len
);

// DNS query processing
esp_err_t handle_dns_query(
    const char *name, 
    uint16_t qtype, 
    uint16_t qclass,
    char *query_buffer,
    int query_len,
    char *response_buffer, 
    int *response_len,
    dns_query_context_t *ctx
);
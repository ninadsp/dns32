#pragma once

#include "dns32.h"

// DNS server initialization and task management
esp_err_t dns_server_init(void);
esp_err_t dns_server_start(bool is_station_mode);

// DNS server configuration and upstream DNS management
void update_global_upstream_dns_servers(esp_netif_t *netif);

// DNS packet parsing utilities
char *parse_dns_name(char *raw_name, char *parsed_name, size_t parsed_name_max_len);
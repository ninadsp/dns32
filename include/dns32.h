#pragma once

#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <esp_system.h>
#include <esp_event.h>
#include <esp_log.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <freertos/event_groups.h>
#include <esp_netif.h>
#include <esp_netif_net_stack.h>
#include <esp_check.h>
#include "mdns.h"
#include <lwip/err.h>
#include <lwip/sockets.h>
#include <lwip/sys.h>

extern const char *TAG_DNS32;
extern const char *TAG_AP;
extern const char *TAG_STA;
extern const char *TAG_HTTP;

#define DNS_PORT (53)
#define DNS_MAX_LEN (256)

#define OPCODE_MASK (0x7800)
#define QR_FLAG (1 << 7)
#define ANS_TTL_SEC (300)
#define MAX_DNS_SERVERS (3)

// DNS Query Types (IPv4 focus)
#define QD_TYPE_A       (0x0001)  // IPv4 address
#define QD_TYPE_NS      (0x0002)  // Name server
#define QD_TYPE_CNAME   (0x0005)  // Canonical name
#define QD_TYPE_SOA     (0x0006)  // Start of authority
#define QD_TYPE_PTR     (0x000C)  // Pointer (reverse DNS)
#define QD_TYPE_MX      (0x000F)  // Mail exchange
#define QD_TYPE_TXT     (0x0010)  // Text record
#define QD_TYPE_SRV     (0x0021)  // Service record

// Storage for upstream DNS servers
typedef struct {
    esp_ip4_addr_t servers[MAX_DNS_SERVERS];
    int count;
} upstream_dns_servers_t;

// DNS Header Packet
typedef struct __attribute__((__packed__))
{
    uint16_t id;
    uint16_t flags;
    uint16_t qd_count;
    uint16_t an_count;
    uint16_t ns_count;
    uint16_t ar_count;
} dns_header_t;

// DNS Question Packet
typedef struct {
    uint16_t type;
    uint16_t class;
} dns_question_t;

// DNS Answer Packet
typedef struct __attribute__((__packed__))
{
    uint16_t ptr_offset;
    uint16_t type;
    uint16_t class;
    uint32_t ttl;
    uint16_t addr_len;
    uint32_t ip_addr;
} dns_answer_t;

// DNS Response Data Structure for flexible responses
typedef struct {
    uint16_t type;
    uint16_t data_len;
    void *data;
    uint32_t ttl;
} dns_response_data_t;

// Forward declaration for handler function
typedef struct dns_query_context dns_query_context_t;

// DNS Query Handler Function Pointer
typedef esp_err_t (*dns_query_handler_t)(
    dns_query_context_t *ctx,
    const char *name,
    uint16_t qtype, 
    uint16_t qclass,
    char *query_buffer,
    int query_len,
    char *response_buffer,
    int *response_len
);

// DNS Query Context (contains all needed state)
struct dns_query_context {
    bool is_station_mode;
    upstream_dns_servers_t *upstream_dns;
    esp_ip4_addr_t device_ip;
    const char *local_domain;
};

// DNS Query Type Handler Registry Entry
typedef struct {
    uint16_t query_type;
    dns_query_handler_t handler;
    const char* type_name;
} dns_query_type_handler_t;

// DNS Server Configuration
typedef struct {
    bool enable_reverse_dns;      // Handle PTR queries in AP mode
    bool enable_device_info_txt;  // Respond to TXT queries with device info
    bool forward_unknown_types;   // Forward unsupported types in station mode
    char local_domain[64];        // Local domain name (default: "dns32.local")
    esp_ip4_addr_t device_ip;     // Device IP address for AP mode responses
} dns_server_config_t;

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

static const char *TAG_DNS32 = "dns32";
static const char *TAG_AP = "softap";
static const char *TAG_STA = "sta";
static const char *TAG_HTTP = "http";

#define DNS_PORT (53)
#define DNS_MAX_LEN (256)

#define OPCODE_MASK (0x7800)
#define QR_FLAG (1 << 7)
#define QD_TYPE_A (0x0001)
#define ANS_TTL_SEC (300)

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

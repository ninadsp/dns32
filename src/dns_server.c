#include "dns32_server.h"

// Global upstream DNS servers and notification mechanism
static upstream_dns_servers_t g_upstream_dns = {0};
static SemaphoreHandle_t dns_update_semaphore = NULL;

// DNS Query Handler Registry
#define MAX_DNS_HANDLERS 16
static dns_query_type_handler_t dns_handlers[MAX_DNS_HANDLERS];
static int dns_handler_count = 0;

// DNS server configuration
static dns_server_config_t g_dns_config = {
    .enable_reverse_dns = true,
    .enable_device_info_txt = true,
    .forward_unknown_types = true,
    .local_domain = "dns32.local",
    .device_ip = {.addr = ESP_IP4TOADDR(192, 168, 4, 1)}
};

/*
    Parse the name from the packet from the DNS name format to a regular .-seperated name
    returns the pointer to the next part of the packet
*/
char *parse_dns_name(char *raw_name, char *parsed_name, size_t parsed_name_max_len)
{

    char *label = raw_name;
    char *name_itr = parsed_name;
    int name_len = 0;

    do
    {
        int sub_name_len = *label;
        // (len + 1) since we are adding  a '.'
        name_len += (sub_name_len + 1);
        if (name_len > parsed_name_max_len)
        {
            return NULL;
        }

        // Copy the sub name that follows the the label
        memcpy(name_itr, label + 1, sub_name_len);
        name_itr[sub_name_len] = '.';
        name_itr += (sub_name_len + 1);
        label += sub_name_len + 1;
    } while (*label != 0);

    // Terminate the final string, replacing the last '.'
    parsed_name[name_len - 1] = '\0';
    // Return pointer to first char after the name
    return label + 1;
}

void update_global_upstream_dns_servers(esp_netif_t *netif)
{
    if (dns_update_semaphore != NULL) {
        // Take semaphore to safely update global DNS servers
        if (xSemaphoreTake(dns_update_semaphore, pdMS_TO_TICKS(1000)) == pdTRUE) {
            g_upstream_dns.count = 0;
            esp_netif_dns_info_t dns_info;

            for (int i = ESP_NETIF_DNS_MAIN; i < ESP_NETIF_DNS_MAX && g_upstream_dns.count < MAX_DNS_SERVERS; i++) {
                esp_err_t ret = esp_netif_get_dns_info(netif, i, &dns_info);
                if (ret == ESP_OK && dns_info.ip.u_addr.ip4.addr != 0) {
                    g_upstream_dns.servers[g_upstream_dns.count] = dns_info.ip.u_addr.ip4;
                    ESP_LOGI(TAG_DNS32, "Updated global DNS server %d: " IPSTR, 
                             g_upstream_dns.count, IP2STR(&dns_info.ip.u_addr.ip4));
                    g_upstream_dns.count++;
                }
            }

            ESP_LOGI(TAG_DNS32, "Updated global upstream DNS servers count: %d", g_upstream_dns.count);
            xSemaphoreGive(dns_update_semaphore);
        } else {
            ESP_LOGW(TAG_DNS32, "Failed to take DNS update semaphore");
        }
    }
}

// DNS Handler Registry Functions
esp_err_t dns_handler_register(uint16_t query_type, dns_query_handler_t handler, const char *type_name)
{
    if (dns_handler_count >= MAX_DNS_HANDLERS) {
        ESP_LOGE(TAG_DNS32, "Maximum DNS handlers reached");
        return ESP_ERR_NO_MEM;
    }

    // Check for duplicate registration
    for (int i = 0; i < dns_handler_count; i++) {
        if (dns_handlers[i].query_type == query_type) {
            ESP_LOGW(TAG_DNS32, "DNS handler for type 0x%04X already registered, replacing", query_type);
            dns_handlers[i].handler = handler;
            dns_handlers[i].type_name = type_name;
            return ESP_OK;
        }
    }

    dns_handlers[dns_handler_count].query_type = query_type;
    dns_handlers[dns_handler_count].handler = handler;
    dns_handlers[dns_handler_count].type_name = type_name;
    dns_handler_count++;

    ESP_LOGI(TAG_DNS32, "Registered DNS handler for type 0x%04X (%s)", query_type, type_name);
    return ESP_OK;
}

dns_query_handler_t dns_handler_get(uint16_t query_type)
{
    for (int i = 0; i < dns_handler_count; i++) {
        if (dns_handlers[i].query_type == query_type) {
            return dns_handlers[i].handler;
        }
    }
    return NULL;
}

const char* dns_query_type_name(uint16_t query_type)
{
    for (int i = 0; i < dns_handler_count; i++) {
        if (dns_handlers[i].query_type == query_type) {
            return dns_handlers[i].type_name;
        }
    }
    
    // Return default names for known types not yet registered
    switch (query_type) {
        case QD_TYPE_A: return "A";
        case QD_TYPE_NS: return "NS";
        case QD_TYPE_CNAME: return "CNAME";
        case QD_TYPE_SOA: return "SOA";
        case QD_TYPE_PTR: return "PTR";
        case QD_TYPE_MX: return "MX";
        case QD_TYPE_TXT: return "TXT";
        case QD_TYPE_SRV: return "SRV";
        default: return "UNKNOWN";
    }
}

// Build a simple DNS response for A record in AP mode
static int build_simple_a_response(char *query_buffer, int query_len, char *response_buffer, const char *name, uint32_t ip_addr)
{
    // Copy the original query
    memcpy(response_buffer, query_buffer, query_len);
    
    dns_header_t *header = (dns_header_t *)response_buffer;
    
    // Set response flags
    header->flags |= htons(QR_FLAG);  // Set QR flag for response
    header->an_count = htons(1);      // One answer
    header->ar_count = htons(0);      // No additional records
    
    // The answer goes right after the question section
    char *answer_ptr = response_buffer + query_len;
    dns_answer_t *answer = (dns_answer_t *)answer_ptr;
    
    // Find where the question starts (after header)
    char *question_ptr = response_buffer + sizeof(dns_header_t);
    
    // Set up the answer with name compression (point back to question name)
    answer->ptr_offset = htons(0xC000 | (question_ptr - response_buffer));
    answer->type = htons(QD_TYPE_A);
    answer->class = htons(1);  // IN class
    answer->ttl = htonl(ANS_TTL_SEC);
    answer->addr_len = htons(4);  // IPv4 address length
    answer->ip_addr = ip_addr;
    
    int response_len = query_len + sizeof(dns_answer_t);
    
    ESP_LOGI(TAG_DNS32, "Built A record response: %d bytes, IP=0x%08lx", response_len, (unsigned long)ntohl(ip_addr));
    return response_len;
}

// Forward query to upstream DNS and return response
static int forward_to_upstream_dns(char *query_buffer, int query_len, char *response_buffer, 
                                  upstream_dns_servers_t *upstream_dns, const char *domain_name)
{
    if (!upstream_dns || upstream_dns->count == 0) {
        ESP_LOGW(TAG_DNS32, "No upstream DNS servers available");
        return 0;
    }
    
    // Create socket for upstream DNS query
    int upstream_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (upstream_sock < 0) {
        ESP_LOGE(TAG_DNS32, "Unable to create socket for upstream DNS query");
        return 0;
    }
    
    // Set up upstream DNS server address (use first server)
    struct sockaddr_in upstream_addr;
    upstream_addr.sin_family = AF_INET;
    upstream_addr.sin_port = htons(53);
    upstream_addr.sin_addr.s_addr = upstream_dns->servers[0].addr;

    char upstream_ip_str[16];
    inet_ntoa_r(upstream_dns->servers[0], upstream_ip_str, sizeof(upstream_ip_str));
    ESP_LOGI(TAG_DNS32, "Forwarding DNS query for %s to upstream server %s", domain_name, upstream_ip_str);

    // Forward the query to upstream DNS
    int send_result = sendto(upstream_sock, query_buffer, query_len, 0, 
                           (struct sockaddr *)&upstream_addr, sizeof(upstream_addr));
    if (send_result < 0) {
        ESP_LOGE(TAG_DNS32, "Failed to send query to upstream DNS: errno %s", strerror(errno));
        close(upstream_sock);
        return 0;
    }

    // Set receive timeout
    struct timeval timeout;
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;
    setsockopt(upstream_sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    // Receive response from upstream DNS
    struct sockaddr_in upstream_response_addr;
    socklen_t upstream_response_len = sizeof(upstream_response_addr);
    
    int recv_len = recvfrom(upstream_sock, response_buffer, DNS_MAX_LEN, 0,
                          (struct sockaddr *)&upstream_response_addr, &upstream_response_len);
    
    close(upstream_sock);
    
    if (recv_len > 0) {
        ESP_LOGI(TAG_DNS32, "Received %d bytes from upstream DNS server %s", recv_len, upstream_ip_str);
        
        // Parse and log the response
        dns_header_t *response_header = (dns_header_t *)response_buffer;
        ESP_LOGI(TAG_DNS32, "Upstream response: id=0x%X, flags=0x%X, answers=%d", 
                ntohs(response_header->id), ntohs(response_header->flags), ntohs(response_header->an_count));
        
        return recv_len;
    } else {
        ESP_LOGE(TAG_DNS32, "Failed to receive response from upstream DNS: errno %s", strerror(errno));
        return 0;
    }
}

// A Record Handler - Handles IPv4 address queries
static esp_err_t handle_a_query(
    dns_query_context_t *ctx,
    const char *name,
    uint16_t qtype, 
    uint16_t qclass,
    char *query_buffer,
    int query_len,
    char *response_buffer,
    int *response_len
)
{
    ESP_LOGI(TAG_DNS32, "Handling A query for %s", name);
    
    if (!ctx->is_station_mode) {
        // AP mode: Return device IP
        esp_ip4_addr_t ip = ctx->device_ip;
        
        ESP_LOGI(TAG_DNS32, "AP mode: Responding with device IP " IPSTR, IP2STR(&ip));
        
        // Build actual DNS response
        *response_len = build_simple_a_response(query_buffer, query_len, response_buffer, name, ip.addr);
        
        if (*response_len > 0) {
            return ESP_OK;
        } else {
            ESP_LOGE(TAG_DNS32, "Failed to build A record response for AP mode");
            return ESP_FAIL;
        }
        
    } else {
        // Station mode: Forward to upstream DNS
        if (ctx->upstream_dns && ctx->upstream_dns->count > 0) {
            ESP_LOGI(TAG_DNS32, "Station mode: Forwarding A query for %s to upstream DNS", name);
            
            // Forward query and get response
            *response_len = forward_to_upstream_dns(query_buffer, query_len, response_buffer, 
                                                   ctx->upstream_dns, name);
            
            if (*response_len > 0) {
                ESP_LOGI(TAG_DNS32, "Successfully forwarded A query for %s, got %d bytes", name, *response_len);
                return ESP_OK;
            } else {
                ESP_LOGE(TAG_DNS32, "Failed to get response from upstream DNS for %s", name);
                return ESP_FAIL;
            }
        } else {
            ESP_LOGW(TAG_DNS32, "No upstream DNS servers available for A query");
            return ESP_FAIL;
        }
    }
}

// Default handler for unsupported query types
static esp_err_t handle_unsupported_query(
    dns_query_context_t *ctx,
    const char *name,
    uint16_t qtype, 
    uint16_t qclass,
    char *query_buffer,
    int query_len,
    char *response_buffer,
    int *response_len
)
{
    const char *type_name = dns_query_type_name(qtype);
    ESP_LOGI(TAG_DNS32, "Handling unsupported query type %s (0x%04X) for %s", type_name, qtype, name);
    
    if (ctx->is_station_mode && g_dns_config.forward_unknown_types) {
        ESP_LOGI(TAG_DNS32, "Station mode: Forwarding unsupported query type %s", type_name);
        // Forward to upstream DNS
        *response_len = forward_to_upstream_dns(query_buffer, query_len, response_buffer, 
                                               ctx->upstream_dns, name);
        if (*response_len > 0) {
            ESP_LOGI(TAG_DNS32, "Successfully forwarded %s query, got %d bytes", type_name, *response_len);
            return ESP_OK;
        } else {
            ESP_LOGE(TAG_DNS32, "Failed to forward %s query", type_name);
            return ESP_FAIL;
        }
    } else {
        ESP_LOGI(TAG_DNS32, "AP mode: Not supporting query type %s", type_name);
        // TODO: Return proper NXDOMAIN response
        *response_len = 0;
        return ESP_FAIL;
    }
}

// Main DNS Query Handler
esp_err_t handle_dns_query(
    const char *name, 
    uint16_t qtype, 
    uint16_t qclass,
    char *query_buffer,
    int query_len,
    char *response_buffer, 
    int *response_len,
    dns_query_context_t *ctx
)
{
    const char *type_name = dns_query_type_name(qtype);
    ESP_LOGI(TAG_DNS32, "Processing DNS query: name=%s, type=%s (0x%04X), class=%d", 
             name, type_name, qtype, qclass);
    
    // Look up handler for this query type
    dns_query_handler_t handler = dns_handler_get(qtype);
    
    if (handler != NULL) {
        // Use registered handler
        ESP_LOGD(TAG_DNS32, "Using registered handler for query type %s", type_name);
        return handler(ctx, name, qtype, qclass, query_buffer, query_len, response_buffer, response_len);
    } else {
        // Use default unsupported handler
        ESP_LOGD(TAG_DNS32, "No registered handler for query type %s, using default", type_name);
        return handle_unsupported_query(ctx, name, qtype, qclass, query_buffer, query_len, response_buffer, response_len);
    }
}

// Initialize DNS handlers
static esp_err_t init_dns_handlers(void)
{
    ESP_LOGI(TAG_DNS32, "Initializing DNS query handlers");
    
    // Register A record handler
    ESP_ERROR_CHECK(dns_handler_register(QD_TYPE_A, handle_a_query, "A"));
    
    ESP_LOGI(TAG_DNS32, "DNS handlers initialized, %d handlers registered", dns_handler_count);
    return ESP_OK;
}

static void dns_server_task(void *pvParameters)
{
    char rx_buffer[128];
    char addr_str[128];
    const int addr_family = AF_INET;
    const int ip_protocol = IPPROTO_IP;
    bool is_station_mode = (bool)pvParameters;

    ESP_LOGI(TAG_DNS32, "bool is_station_mode: %s", is_station_mode ? "true" : "false");

    struct sockaddr_in dest_addr;

    while (1)
    {
        dest_addr.sin_addr.s_addr = htonl(INADDR_ANY);
        dest_addr.sin_family = addr_family;
        dest_addr.sin_port = htons(DNS_PORT);

        int sock = socket(addr_family, SOCK_DGRAM, ip_protocol);
        if (sock < 0)
        {
            ESP_LOGE(TAG_DNS32, "Unable to create UDP socket for DNS server");
            break;
        }
        ESP_LOGI(TAG_DNS32, "UDP Socket created");

        int err = bind(sock, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
        if (err < 0)
        {
            ESP_LOGE(TAG_DNS32, "Unable to bind UDP socket for DNS server: errno %s", strerror(errno));
        }
        ESP_LOGI(TAG_DNS32, "Socket bound to port 53");

        struct sockaddr_storage source_addr;
        socklen_t socklen = sizeof(source_addr);

        struct iovec iov;
        struct msghdr msg;
        struct cmsghdr *cmsgtmp;
        u8_t cmsg_buf[CMSG_SPACE(sizeof(struct in_pktinfo))];

        iov.iov_base = rx_buffer;
        iov.iov_len = sizeof(rx_buffer);
        msg.msg_control = cmsg_buf;
        msg.msg_controllen = sizeof(cmsg_buf);
        msg.msg_flags = 0;
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_name = (struct sockaddr *)&source_addr;
        msg.msg_namelen = socklen;

        while (1)
        {
            ESP_LOGI(TAG_DNS32, "waiting for data");

            int len = recvmsg(sock, &msg, 0);
            if (len < 0)
            {
                ESP_LOGE(TAG_DNS32, "recvfrom failed: errno %s", strerror(errno));
                break;
            }
            else
            {
                inet_ntoa_r(((struct sockaddr_in *)&source_addr)->sin_addr, addr_str, sizeof(addr_str) - 1);

                for (cmsgtmp = CMSG_FIRSTHDR(&msg); cmsgtmp != NULL; cmsgtmp = CMSG_NXTHDR(&msg, cmsgtmp))
                {
                    if (cmsgtmp->cmsg_level == IPPROTO_IP && cmsgtmp->cmsg_type == IP_PKTINFO)
                    {
                        struct in_pktinfo *pktinfo;
                        pktinfo = (struct in_pktinfo *)CMSG_DATA(cmsgtmp);
                        ESP_LOGI(TAG_DNS32, "dest ip: %s", inet_ntoa(pktinfo->ipi_addr));
                    }
                }

                rx_buffer[len] = 0;
                ESP_LOGI(TAG_DNS32, "Received %d bytes from %s: ", len, addr_str);
                ESP_LOGI(TAG_DNS32, "%s", rx_buffer);

                // Process DNS query using the new handler framework
                dns_header_t *header = (dns_header_t *)rx_buffer;
                ESP_LOGI(TAG_DNS32, "Received DNS query with header id: 0x%X, flags 0x%X, qd_count: %d",
                         ntohs(header->id), ntohs(header->flags), ntohs(header->qd_count));

                uint16_t qd_count = ntohs(header->qd_count);
                if (qd_count == 0) {
                    ESP_LOGW(TAG_DNS32, "Received DNS query with no questions");
                    continue;
                }

                // Set up query context
                upstream_dns_servers_t current_upstream_dns = {0};
                if (dns_update_semaphore != NULL && xSemaphoreTake(dns_update_semaphore, pdMS_TO_TICKS(100)) == pdTRUE) {
                    current_upstream_dns = g_upstream_dns;
                    xSemaphoreGive(dns_update_semaphore);
                }

                dns_query_context_t ctx = {
                    .is_station_mode = is_station_mode,
                    .upstream_dns = &current_upstream_dns,
                    .device_ip = g_dns_config.device_ip,
                    .local_domain = g_dns_config.local_domain
                };

                // Parse and process each question (for now, handle only the first one)
                char *cur_qd_ptr = rx_buffer + sizeof(dns_header_t);
                char name[128];
                char *name_end_ptr = parse_dns_name(cur_qd_ptr, name, sizeof(name));
                if (name_end_ptr == NULL) {
                    ESP_LOGE(TAG_DNS32, "Failed parsing the requested DNS name");
                    continue;
                }

                dns_question_t *question = (dns_question_t *)(name_end_ptr);
                uint16_t qd_type = ntohs(question->type);
                uint16_t qd_class = ntohs(question->class);

                const char *type_name = dns_query_type_name(qd_type);
                ESP_LOGI(TAG_DNS32, "Processing query: name=%s, type=%s (0x%04X), class=%d", 
                         name, type_name, qd_type, qd_class);

                // Use new framework to handle query
                char response_buffer[DNS_MAX_LEN];
                int response_len = 0;
                
                esp_err_t result = handle_dns_query(name, qd_type, qd_class, rx_buffer, len, response_buffer, &response_len, &ctx);
                
                if (result == ESP_OK && response_len > 0) {
                    // Send the response
                    int err = sendto(sock, response_buffer, response_len, 0, (struct sockaddr *)&source_addr, sizeof(source_addr));
                    if (err < 0) {
                        ESP_LOGE(TAG_DNS32, "Could not send DNS response: errno %s", strerror(errno));
                    } else {
                        ESP_LOGI(TAG_DNS32, "Sent DNS response: %d bytes to %s", response_len, addr_str);
                    }
                } else {
                    ESP_LOGW(TAG_DNS32, "Failed to generate DNS response for %s query", type_name);
                }

                // For backward compatibility during transition, fall back to old logic if new framework didn't generate response
                if (response_len == 0) {
                    ESP_LOGW(TAG_DNS32, "New framework didn't generate response, using simple fallback");
                    
                    // TODO: Implement proper response generation in handlers
                    // For now, just echo the query back (minimal fallback)
                    ESP_LOGI(TAG_DNS32, "Falling back to echo response");
                    int err = sendto(sock, rx_buffer, len, 0, (struct sockaddr *)&source_addr, sizeof(source_addr));
                    if (err < 0) {
                        ESP_LOGE(TAG_DNS32, "Could not send fallback response: errno %s", strerror(errno));
                    }
                }

                if (sock != -1)
                {
                    ESP_LOGI(TAG_DNS32, "Closing socket");
                    shutdown(sock, 0);
                    close(sock);
                    break;
                }
            }
        }
    }
    vTaskDelete(NULL);
}

esp_err_t dns_server_init(void)
{
    // Create semaphore for DNS server updates
    dns_update_semaphore = xSemaphoreCreateMutex();
    if (dns_update_semaphore == NULL) {
        ESP_LOGE(TAG_DNS32, "Failed to create DNS update semaphore");
        return ESP_FAIL;
    }
    
    // Initialize DNS query handlers
    ESP_ERROR_CHECK(init_dns_handlers());
    
    ESP_LOGI(TAG_DNS32, "DNS server initialized with %d handlers", dns_handler_count);
    return ESP_OK;
}

esp_err_t dns_server_start(bool is_station_mode)
{
    BaseType_t task_status = xTaskCreate(dns_server_task, "dns_server", 4096, (void *)is_station_mode, 5, NULL);
    if (task_status == pdPASS)
    {
        ESP_LOGI(TAG_DNS32, "DNS server task created successfully");
        return ESP_OK;
    }
    else
    {
        ESP_LOGE(TAG_DNS32, "Could not create DNS server task");
        return ESP_FAIL;
    }
}
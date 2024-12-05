#include "dns32.h"
#include "dns32_nvs.h"
#include "dns32_wifi.h"
#include "dns32_http.h"

/*
    Parse the name from the packet from the DNS name format to a regular .-seperated name
    returns the pointer to the next part of the packet
*/
static char *parse_dns_name(char *raw_name, char *parsed_name, size_t parsed_name_max_len)
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

        /*
        struct timeval timeout;
        timeout.tv_sec = 10;
        timeout.tv_usec = 0;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout);
        */

        int err = bind(sock, &dest_addr, sizeof(dest_addr));
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
            // int len = recvfrom(sock, rx_buffer, sizeof(rx_buffer) - 1, 0, (struct sockaddr *)&source_addr, &socklen);
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

                // if is_station_mode is false, we need to respond with the device's IP address
                // irrespective of what the domain name requested is
                if (!is_station_mode)
                {
                    char reply[DNS_MAX_LEN];
                    memset(reply, 0, DNS_MAX_LEN);
                    memcpy(reply, rx_buffer, (len - 1));

                    dns_header_t *header = (dns_header_t *)reply;
                    ESP_LOGI(TAG_DNS32, "Received DNS query with header id: 0x%X, flags 0x%X, qd_count: %d",
                             ntohs(header->id), ntohs(header->flags), ntohs(header->qd_count));

                    header->flags |= QR_FLAG;

                    uint16_t qd_count = ntohs(header->qd_count);
                    header->an_count = htons(qd_count);

                    int reply_len = qd_count * sizeof(dns_answer_t) + len;
                    if (reply_len > DNS_MAX_LEN)
                    {
                        ESP_LOGE(TAG_DNS32, "Longer reply than supported");
                        break;
                    }

                    char *cur_ans_ptr = reply + len;
                    char *cur_qd_ptr = reply + sizeof(dns_header_t);

                    // technically,we don't need to parse this, we can just copy from incoming buffer
                    // but for now, let us follow the example code
                    char name[128];

                    for (int qd_i = 0; qd_i < qd_count; qd_i++)
                    {
                        /*
                        https://en.wikipedia.org/wiki/Domain_Name_System#Question_section
                        > The domain name is broken into discrete labels which are concatenated; each label is prefixed by the length of that label

                        So, a request for `google.com` is packed into the data structure as [6]google[3]com,
                        with each label getting it's own space, preceeded by a byte that stores the length of that label string
                        And, name_end_ptr then points to the address of 'google' in the above example, which is
                        essentially the start of the question
                        */
                        char *name_end_ptr = parse_dns_name(cur_qd_ptr, name, sizeof(name));
                        if (name_end_ptr == NULL)
                        {
                            ESP_LOGE(TAG_DNS32, "Failed parsing the requested DNS name: %s", cur_qd_ptr);
                            break;
                        }

                        dns_question_t *question = (dns_question_t *)(name_end_ptr);
                        uint16_t qd_type = ntohs(question->type);
                        uint16_t qd_class = ntohs(question->class);

                        ESP_LOGI(TAG_DNS32, "Received a query type: %d, class: %d, question for: %s", qd_type, qd_class, name);

                        esp_ip4_addr_t ip = {.addr = IP_ADDR_ANY};
                        if (qd_type == QD_TYPE_A)
                        {
                            cur_ans_ptr = name_end_ptr + sizeof(dns_question_t);
                            ip.addr = ESP_IP4TOADDR(192, 168, 4, 1);
                        }

                        // set up the answer, so that we can then send it via the socket
                        dns_answer_t *answer = (dns_answer_t *)cur_ans_ptr;
                        answer->ptr_offset = htons(0xC000 | (cur_qd_ptr - reply));
                        answer->type = htons(qd_type);
                        answer->class = htons(qd_class);
                        answer->ttl = htonl(ANS_TTL_SEC);

                        ESP_LOGI(TAG_DNS32, "Answer with PTR offset: 0x%" PRIX16 " and IP 0x%" PRIX32,
                                 ntohs(answer->ptr_offset), ip.addr);

                        answer->addr_len = htons(sizeof(ip.addr));
                        answer->ip_addr = ip.addr;

                        header->an_count = htons(1);
                        header->ar_count = htons(0);
                    }

                    ESP_LOGI(TAG_DNS32, "Received %d bytes from %s | DNS reply with len: %d ", len, addr_str, reply_len);

                    int err = sendto(sock, reply, reply_len, 0, (struct sockaddr *)&source_addr, sizeof(source_addr));
                    if (err < 0)
                    {
                        ESP_LOGE(TAG_DNS32, "Could not send back DNS request response: errno %s", strerror(errno));
                        break;
                    }
                }
                else
                {

                    int err = sendto(sock, rx_buffer, len, 0, (struct sockaddr *)&source_addr, sizeof(source_addr));
                    if (err < 0)
                    {
                        ESP_LOGE(TAG_DNS32, "Could not send back UDP response: errno %s", strerror(errno));
                        break;
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

void app_main(void)
{
    httpd_handle_t *http_server = NULL;
    bool is_station_mode;
    ESP_ERROR_CHECK(esp_netif_init());
    // Need to handle ESP_ERR_NVS_NO_FREE_PAGES and ESP_ERR_NVS_NEW_VERSION_FOUND
    ESP_ERROR_CHECK(nvs_flash_init());
    ESP_ERROR_CHECK(initiate_common_wifi());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    ESP_ERROR_CHECK(mdns_init());
    ESP_ERROR_CHECK(mdns_hostname_set("dns32"));

    if (is_wifi_stored() == ESP_OK)
    {
        ESP_LOGI(TAG_DNS32, "Found stored wifi");
        ESP_ERROR_CHECK_WITHOUT_ABORT(setup_station());
        is_station_mode = true;
    }
    else
    {
        // There can be multiple reasons why this failed. For now, let us just assume
        // that storage is fine, and we don't have the wifi info
        ESP_LOGI(TAG_DNS32, "No stored wifi");
        ESP_ERROR_CHECK_WITHOUT_ABORT(setup_softap());
        ESP_ERROR_CHECK_WITHOUT_ABORT(initiate_wifi_scan_async());
        is_station_mode = false;
        // TODO: Implement a basic DNS server so that mDNS can work?
    }

    assert(http_server == NULL);
    ESP_ERROR_CHECK_WITHOUT_ABORT(start_webserver(http_server));

    BaseType_t task_status = xTaskCreate(dns_server_task, "dns_server", 4096, (void *)is_station_mode, 5, NULL);
    if (task_status == pdPASS)
    {
        ESP_LOGI(TAG_DNS32, "Registered the DNS server task successfully");
    }
    else
    {
        ESP_LOGI(TAG_DNS32, "Could not register the DNS server task");
    }

    while (http_server != NULL)
    {
        vTaskDelay(100000 / portTICK_PERIOD_MS);
    }
}
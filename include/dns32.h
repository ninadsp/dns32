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

static const char *TAG_DNS32 = "dns32";
static const char *TAG_AP = "softap";
static const char *TAG_STA = "sta";
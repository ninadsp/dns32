#include "dns32_blocklist.h"
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <math.h>
#include <esp_http_client.h>
#include <esp_timer.h>

static bloom_filter_t *g_bloom_filter = NULL;
static bool g_partition_mounted = false;
static wl_handle_t g_wl_handle;

// DJB2 hash function
uint32_t hash_djb2(const char *str, uint32_t seed) {
    uint32_t hash = 5381 + seed;
    int c;
    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + tolower(c); // Convert to lowercase for case-insensitive
    }
    return hash;
}

// FNV-1a hash function
uint32_t hash_fnv1a(const char *str, uint32_t seed) {
    uint32_t hash = 2166136261U + seed;
    while (*str) {
        hash ^= tolower(*str++); // Convert to lowercase for case-insensitive
        hash *= 16777619;
    }
    return hash;
}

// Set bit in Bloom filter
static void bloom_set_bit(bloom_filter_t *bf, uint32_t bit_index) {
    if (bit_index < bf->size_bits) {
        uint32_t byte_index = bit_index / 8;
        uint32_t bit_offset = bit_index % 8;
        bf->bits[byte_index] |= (1 << bit_offset);
    }
}

// Check bit in Bloom filter
static bool bloom_check_bit(bloom_filter_t *bf, uint32_t bit_index) {
    if (bit_index < bf->size_bits) {
        uint32_t byte_index = bit_index / 8;
        uint32_t bit_offset = bit_index % 8;
        return (bf->bits[byte_index] & (1 << bit_offset)) != 0;
    }
    return false;
}

// Mount the blocklist partition
static esp_err_t mount_blocklist_partition(void) {
    if (g_partition_mounted) {
        return ESP_OK;
    }

    const esp_partition_t *partition = esp_partition_find_first(
        ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_DATA_FAT, BLOCKLIST_PARTITION_LABEL);

    if (partition == NULL) {
        ESP_LOGE(TAG_BLOCKLIST, "Blocklist partition not found");
        return ESP_ERR_NOT_FOUND;
    }

    ESP_LOGI(TAG_BLOCKLIST, "Found blocklist partition: size=%lu", (unsigned long)partition->size);
    ESP_LOGI(TAG_BLOCKLIST, "Partition label: %s", partition->label);

    esp_vfs_fat_mount_config_t mount_config = {
        .max_files = 2,
        .format_if_mount_failed = true,
        .allocation_unit_size = 4096,  // Standard sector size
        .use_one_fat = false,
        // .disk_status_check_enable = false
    };

    esp_err_t err = esp_vfs_fat_spiflash_mount_rw_wl("/data", partition->label, &mount_config, &g_wl_handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG_BLOCKLIST, "Failed to mount blocklist partition: %s", esp_err_to_name(err));
        return err;
    }

    ESP_LOGI(TAG_BLOCKLIST, "Blocklist partition mounted at /data");
    g_partition_mounted = true;
    vTaskDelay(pdMS_TO_TICKS(100));  // Give filesystem time to settle
    return ESP_OK;
}

// Unmount the blocklist partition
static esp_err_t unmount_blocklist_partition(void) {
    if (!g_partition_mounted) {
        return ESP_OK;
    }

    esp_err_t err = esp_vfs_fat_spiflash_unmount_rw_wl("/data", g_wl_handle);
    if (err == ESP_OK) {
        g_partition_mounted = false;
        ESP_LOGI(TAG_BLOCKLIST, "Blocklist partition unmounted");
    }
    return err;
}

esp_err_t blocklist_init(void) {
    if (g_bloom_filter != NULL) {
        ESP_LOGW(TAG_BLOCKLIST, "Blocklist already initialized");
        return ESP_OK;
    }

    // Allocate Bloom filter structure
    g_bloom_filter = malloc(sizeof(bloom_filter_t));
    if (g_bloom_filter == NULL) {
        ESP_LOGE(TAG_BLOCKLIST, "Failed to allocate Bloom filter structure");
        return ESP_ERR_NO_MEM;
    }

    // Allocate bit array (~420KB)
    g_bloom_filter->bits = malloc(BLOOM_FILTER_SIZE_BYTES);
    if (g_bloom_filter->bits == NULL) {
        ESP_LOGE(TAG_BLOCKLIST, "Failed to allocate Bloom filter bit array (%d bytes)", BLOOM_FILTER_SIZE_BYTES);
        free(g_bloom_filter);
        g_bloom_filter = NULL;
        return ESP_ERR_NO_MEM;
    }

    // Initialize Bloom filter
    memset(g_bloom_filter->bits, 0, BLOOM_FILTER_SIZE_BYTES);
    g_bloom_filter->size_bits = BLOOM_FILTER_SIZE_BITS;
    g_bloom_filter->num_hashes = BLOOM_FILTER_NUM_HASHES;
    g_bloom_filter->num_items_added = 0;

    // Initialize statistics
    g_bloom_filter->stats.total_domains = 0;
    g_bloom_filter->stats.queries_blocked = 0;
    g_bloom_filter->stats.queries_allowed = 0;
    g_bloom_filter->stats.last_updated_timestamp = 0;
    g_bloom_filter->stats.is_loaded = false;
    g_bloom_filter->stats.estimated_false_positive_rate = 0.0;

    ESP_LOGI(TAG_BLOCKLIST, "Bloom filter initialized: %d bits (%d bytes), %d hash functions",
             BLOOM_FILTER_SIZE_BITS, BLOOM_FILTER_SIZE_BYTES, BLOOM_FILTER_NUM_HASHES);

    // Mount partition for file operations
    return mount_blocklist_partition();
}

esp_err_t blocklist_add_domain(const char *domain) {
    if (g_bloom_filter == NULL || domain == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    // Add domain using multiple hash functions
    for (int i = 0; i < g_bloom_filter->num_hashes; i++) {
        uint32_t hash1 = hash_djb2(domain, i);
        uint32_t hash2 = hash_fnv1a(domain, i);

        // Combine hashes for better distribution
        uint32_t combined_hash = hash1 + (i * hash2);
        uint32_t bit_index = combined_hash % g_bloom_filter->size_bits;

        bloom_set_bit(g_bloom_filter, bit_index);
    }

    g_bloom_filter->num_items_added++;

    // Update false positive rate estimate
    double fill_ratio = (double)g_bloom_filter->num_items_added * g_bloom_filter->num_hashes / g_bloom_filter->size_bits;
    g_bloom_filter->stats.estimated_false_positive_rate = pow(1.0 - exp(-fill_ratio), g_bloom_filter->num_hashes);

    return ESP_OK;
}

bool blocklist_is_blocked(const char *domain) {
    if (g_bloom_filter == NULL || domain == NULL || !g_bloom_filter->stats.is_loaded) {
        return false;
    }

    // Check using multiple hash functions - all must be set for potential match
    for (int i = 0; i < g_bloom_filter->num_hashes; i++) {
        uint32_t hash1 = hash_djb2(domain, i);
        uint32_t hash2 = hash_fnv1a(domain, i);

        // Combine hashes for better distribution
        uint32_t combined_hash = hash1 + (i * hash2);
        uint32_t bit_index = combined_hash % g_bloom_filter->size_bits;

        if (!bloom_check_bit(g_bloom_filter, bit_index)) {
            // If any bit is not set, domain is definitely not in set
            g_bloom_filter->stats.queries_allowed++;
            return false;
        }
    }

    // All bits are set - domain might be in the set (could be false positive)
    g_bloom_filter->stats.queries_blocked++;
    return true;
}

esp_err_t blocklist_load_from_partition(void) {
    if (g_bloom_filter == NULL) {
        ESP_LOGE(TAG_BLOCKLIST, "Blocklist not initialized");
        return ESP_ERR_INVALID_STATE;
    }

    FILE *file = fopen(BLOCKLIST_FILE_PATH, "r");
    if (file == NULL) {
        perror("fopen");
        ESP_LOGW(TAG_BLOCKLIST, "Blocklist file not found, starting with empty blocklist");
        return ESP_ERR_NOT_FOUND;
    }

    ESP_LOGI(TAG_BLOCKLIST, "Loading blocklist from %s", BLOCKLIST_FILE_PATH);

    // Clear existing filter
    memset(g_bloom_filter->bits, 0, BLOOM_FILTER_SIZE_BYTES);
    g_bloom_filter->num_items_added = 0;
    g_bloom_filter->stats.total_domains = 0;

    char line[BLOCKLIST_DOMAIN_MAX_LEN];
    uint32_t loaded_domains = 0;

    while (fgets(line, sizeof(line), file) != NULL && loaded_domains < BLOCKLIST_MAX_DOMAINS) {
        // Remove trailing newline/whitespace
        char *end = line + strlen(line) - 1;
        while (end > line && (*end == '\n' || *end == '\r' || *end == ' ' || *end == '\t')) {
            *end-- = '\0';
        }

        // Skip empty lines and comments
        if (line[0] == '\0' || line[0] == '#') {
            continue;
        }

        // Add domain to Bloom filter
        esp_err_t err = blocklist_add_domain(line);
        if (err == ESP_OK) {
            loaded_domains++;
        }

        // Log progress every 10k domains
        if (loaded_domains > 0 && loaded_domains % 10000 == 0) {
            ESP_LOGI(TAG_BLOCKLIST, "Loaded %lu domains...", loaded_domains);
        }
    }
    ESP_LOGI(TAG_BLOCKLIST, "Final: Loaded %lu domains...", loaded_domains);

    fclose(file);

    g_bloom_filter->stats.total_domains = loaded_domains;
    g_bloom_filter->stats.is_loaded = true;
    g_bloom_filter->stats.last_updated_timestamp = esp_timer_get_time() / 1000000; // Convert to seconds

    ESP_LOGI(TAG_BLOCKLIST, "Blocklist loaded: %lu domains, estimated FPR: %.4f%%",
             loaded_domains, g_bloom_filter->stats.estimated_false_positive_rate * 100);

    return ESP_OK;
}

esp_err_t blocklist_save_to_partition(const char *data, size_t data_len) {
    if (data == NULL || data_len == 0) {
        return ESP_ERR_INVALID_ARG;
    }

    const char *BLOCKLIST_FP = "/data/blocklist.txt";
    FILE *file = fopen(BLOCKLIST_FP, "w");
    if (file == NULL) {
        perror("fopen");
        ESP_LOGE(TAG_BLOCKLIST, "Failed to open blocklist file for writing");
        return ESP_ERR_NOT_FOUND;
    }

    size_t written = fwrite(data, 1, data_len, file);
    fclose(file);

    if (written != data_len) {
        ESP_LOGE(TAG_BLOCKLIST, "Failed to write complete blocklist data");
        return ESP_FAIL;
    }

    ESP_LOGI(TAG_BLOCKLIST, "Blocklist data saved to partition (%lu bytes)", (unsigned long)data_len);
    return ESP_OK;
}

esp_err_t blocklist_clear(void) {
    if (g_bloom_filter == NULL) {
        return ESP_ERR_INVALID_STATE;
    }

    memset(g_bloom_filter->bits, 0, BLOOM_FILTER_SIZE_BYTES);
    g_bloom_filter->num_items_added = 0;

    g_bloom_filter->stats.total_domains = 0;
    g_bloom_filter->stats.queries_blocked = 0;
    g_bloom_filter->stats.queries_allowed = 0;
    g_bloom_filter->stats.is_loaded = false;
    g_bloom_filter->stats.estimated_false_positive_rate = 0.0;

    ESP_LOGI(TAG_BLOCKLIST, "Blocklist cleared");
    return ESP_OK;
}

esp_err_t blocklist_rebuild_filter(void) {
    ESP_LOGI(TAG_BLOCKLIST, "Rebuilding Bloom filter from stored data");
    return blocklist_load_from_partition();
}

blocklist_stats_t blocklist_get_stats(void) {
    if (g_bloom_filter == NULL) {
        blocklist_stats_t empty_stats = {0};
        return empty_stats;
    }
    return g_bloom_filter->stats;
}

esp_err_t blocklist_init_with_embedded_data(const char* embedded_hosts_data, size_t data_length) {
    if (embedded_hosts_data == NULL || data_length == 0) {
        return ESP_ERR_INVALID_ARG;
    }

    ESP_LOGI(TAG_BLOCKLIST, "Initializing blocklist with embedded data (%lu bytes)", (unsigned long)data_length);

    // Save the embedded data to partition
    esp_err_t save_err = blocklist_save_to_partition(embedded_hosts_data, data_length);
    if (save_err != ESP_OK) {
        ESP_LOGE(TAG_BLOCKLIST, "Failed to save embedded hosts data to partition");
        return save_err;
    }

    // Load the data into Bloom filter
    esp_err_t load_err = blocklist_load_from_partition();
    if (load_err != ESP_OK) {
        ESP_LOGE(TAG_BLOCKLIST, "Failed to load embedded hosts data into Bloom filter");
        return load_err;
    }

    ESP_LOGI(TAG_BLOCKLIST, "Successfully initialized blocklist with embedded data");
    return ESP_OK;
}

esp_err_t blocklist_download_and_update(const char *url) {
    // This will be implemented when we add the download mechanism
    ESP_LOGI(TAG_BLOCKLIST, "Download and update functionality not yet implemented");
    return ESP_ERR_NOT_SUPPORTED;
}

esp_err_t blocklist_deinit(void) {
    if (g_bloom_filter != NULL) {
        if (g_bloom_filter->bits != NULL) {
            free(g_bloom_filter->bits);
        }
        free(g_bloom_filter);
        g_bloom_filter = NULL;
        ESP_LOGI(TAG_BLOCKLIST, "Bloom filter memory freed");
    }

    return unmount_blocklist_partition();
}
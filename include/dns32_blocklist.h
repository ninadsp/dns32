#pragma once

#include "dns32.h"
#include "esp_vfs_fat.h"
#include "esp_partition.h"
#include "wear_levelling.h"

// Blocklist configuration
#define BLOCKLIST_PARTITION_LABEL "blocklist"
// FATFS doesn't like file names larger than 8.3 by default
#define BLOCKLIST_FILE_PATH "/data/bloklst.txt"
#define BLOCKLIST_MAX_DOMAINS 350000
#define BLOCKLIST_DOMAIN_MAX_LEN 256

// Bloom filter configuration
// Adjusted for ESP32 memory constraints: ~100KB for reasonable performance
// For 50k domains with ~3% false positive rate: ~480k bits = 60KB
// For 100k domains with ~5% false positive rate: ~720k bits = 90KB
#define BLOOM_FILTER_SIZE_BITS (720000)  // 90KB, good for ~100k domains at 5% FPR
#define BLOOM_FILTER_SIZE_BYTES ((BLOOM_FILTER_SIZE_BITS + 7) / 8)  // 90KB
#define BLOOM_FILTER_NUM_HASHES 4  // Reduced hash functions for performance

// Blocklist statistics
typedef struct {
    uint32_t total_domains;
    uint32_t queries_blocked;
    uint32_t queries_allowed;
    uint32_t last_updated_timestamp;
    bool is_loaded;
    double estimated_false_positive_rate;
} blocklist_stats_t;

// Bloom filter structure
typedef struct {
    uint8_t *bits;                    // Bit array
    uint32_t size_bits;               // Size in bits
    uint32_t num_hashes;              // Number of hash functions
    uint32_t num_items_added;         // Track items for FPR calculation
    blocklist_stats_t stats;
} bloom_filter_t;

// Initialize blocklist subsystem (allocates Bloom filter memory)
esp_err_t blocklist_init(void);

// Load blocklist from partition and populate Bloom filter
esp_err_t blocklist_load_from_partition(void);

// Save raw blocklist data to partition
esp_err_t blocklist_save_to_partition(const char *data, size_t data_len);

// Check if domain is likely in blocklist (Bloom filter lookup)
bool blocklist_is_blocked(const char *domain);

// Add domain to Bloom filter
esp_err_t blocklist_add_domain(const char *domain);

// Download and update blocklist from URL
esp_err_t blocklist_download_and_update(const char *url);

// Get blocklist statistics
blocklist_stats_t blocklist_get_stats(void);

// Clear Bloom filter
esp_err_t blocklist_clear(void);

// Rebuild Bloom filter from stored data
esp_err_t blocklist_rebuild_filter(void);

// Initialize partition with embedded hosts data (for first-time setup)
esp_err_t blocklist_init_with_embedded_data(const char* embedded_hosts_data, size_t data_length);

// Deinitialize blocklist subsystem (frees memory)
esp_err_t blocklist_deinit(void);

// Hash functions for Bloom filter
uint32_t hash_djb2(const char *str, uint32_t seed);
uint32_t hash_fnv1a(const char *str, uint32_t seed);
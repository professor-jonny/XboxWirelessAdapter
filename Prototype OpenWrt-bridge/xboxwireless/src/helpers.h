/*
 * helpers.h - Xbox MN-740 Wireless Protocol Helper Functions
 *
 * Common utility functions for protocol handling, MAC address operations,
 * checksum calculation, HMAC authentication, and system integration.
 *
 * Copyright (C) 2026
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef XBOX_HELPERS_H
#define XBOX_HELPERS_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include "packets.h"

/* ============================================================================
 * PROTOCOL CONSTANTS
 * ============================================================================
 */

/* MN-740 Hardware Identity */
#define MN740_MAC_ADDR { 0x00, 0x12, 0x5a, 0x33, 0xfa, 0x31 }

/* Timing Constants */
#define HANDSHAKE_RETRY_INTERVAL_SEC    2
#define BEACON_TIMEOUT_SEC              5
#define BEACON_INTERVAL_SEC             1
#define SELECT_TIMEOUT_USEC             100000
#define SELECT_TIMEOUT_SEC              1

/* Protocol Thresholds */
#define BEACONS_FOR_LINK                3
#define MAX_HANDSHAKE_ATTEMPTS          10

/* Firmware Identity */
#define ADAPTER_NAME_DEFAULT    "Xbox Wireless Adapter (MN-740)"
#define FIRMWARE_VERSION_DEFAULT "1.0.2.26 Boot: 1.3.0.06"

/* Unknown Firmware Constants (from captures) */
#define CAPABILITY_FLAGS_DEFAULT        0x06
#define UNKNOWN_FLAG_DEFAULT            0x07
#define UNKNOWN_DATA_BYTE2              0x0f
#define UNKNOWN_DATA_BYTE3              0xfe

/* Network List Response */
#define NETWORKS_RESPONSE_TOTAL_SIZE    980  /* 1 + 15*64 + 19 */
#define NETWORKS_COMPLETE_SLOTS         15
#define NETWORKS_PARTIAL_SLOT_BYTES     19

/* Secret File Paths */
#define SECRET_HMAC_KEY_PATH        "secrets/hmac_key.bin"
#define SECRET_HMAC_SALT_PATH       "secrets/hmac_salt.bin"
#define SECRET_COPYRIGHT_PATH       "secrets/auth_copyright.bin"

#define SECRET_HMAC_KEY_SIZE        16
#define SECRET_HMAC_SALT_SIZE       117
#define SECRET_COPYRIGHT_SIZE       84

/* ============================================================================
 * MAC ADDRESS HELPERS
 * ============================================================================
 */

/**
 * @brief Print MAC address to stdout
 *
 * @param mac 6-byte MAC address
 */
void print_mac(const uint8_t *mac);

/**
 * @brief Print MAC address to file stream
 *
 * @param fp File pointer (e.g., stdout, stderr, log file)
 * @param mac 6-byte MAC address
 */
void fprint_mac(FILE *fp, const uint8_t *mac);

/**
 * @brief Parse MAC address from string
 *
 * Supports formats:
 * - Colon: aa:bb:cc:dd:ee:ff
 * - Dash: aa-bb-cc-dd-ee-ff
 * - Continuous: aabbccddeeff
 *
 * @param str Input string
 * @param mac Output 6-byte MAC address
 * @return 1 on success, 0 on failure
 */
int parse_mac(const char *str, uint8_t *mac);

/**
 * @brief Format MAC address to string
 *
 * @param mac 6-byte MAC address
 * @param str Output buffer (must be >= 18 bytes)
 */
void mac_to_string(const uint8_t *mac, char *str);

/**
 * @brief Compare two MAC addresses
 *
 * @param mac1 First MAC address
 * @param mac2 Second MAC address
 * @return 1 if equal, 0 if different
 */
int mac_equal(const uint8_t *mac1, const uint8_t *mac2);

/* ============================================================================
 * CHECKSUM & HMAC
 * ============================================================================
 */

/**
 * @brief Calculate RFC 1071 one's complement checksum
 *
 * Used for Xbox protocol packet header checksums.
 *
 * @param data Data buffer
 * @param len Length in bytes
 * @return 16-bit checksum
 */
uint16_t calculate_checksum(const uint8_t *data, size_t len);

/**
 * @brief Compute HMAC-SHA1 signature for Xbox protocol
 *
 * Uses the "poem" key: "From isolation / Deliver me o Xbox, for I am the MN-740"
 *
 * Input: 16-byte challenge + 6-byte MAC + 117-byte salt = 139 bytes
 * Output: 20-byte HMAC-SHA1 signature
 *
 * @param challenge 16-byte challenge from handshake request
 * @param adapter_mac 6-byte adapter MAC address
 * @param signature_out 20-byte output buffer
 */
void make_signature_hmac(const uint8_t *challenge,
                         const uint8_t *adapter_mac,
                         uint8_t *signature_out);

/**
 * @brief Load cryptographic secrets from files
 *
 * Loads:
 * - secrets/hmac_key.bin (16 bytes)
 * - secrets/hmac_salt.bin (117 bytes)
 * - secrets/auth_copyright.bin (84 bytes)
 *
 * @return 0 on success, -1 on failure
 */
int load_secrets(void);

/**
 * @brief Get pointer to loaded HMAC key
 * @return Pointer to 16-byte key, or NULL if not loaded
 */
const uint8_t* get_hmac_key(void);

/**
 * @brief Get pointer to loaded HMAC salt
 * @return Pointer to 117-byte salt, or NULL if not loaded
 */
const uint8_t* get_hmac_salt(void);

/**
 * @brief Get pointer to loaded copyright string
 * @return Pointer to 84-byte copyright, or NULL if not loaded
 */
const uint8_t* get_auth_copyright(void);

/* ============================================================================
 * PROTOCOL HELPERS
 * ============================================================================
 */

/**
 * @brief Get human-readable packet type name
 *
 * @param type Packet type (PKT_* constant)
 * @return String name (e.g., "HANDSHAKE_REQ")
 */
const char* get_packet_type_name(uint8_t type);

/**
 * @brief Get human-readable security type name
 *
 * @param sec_type Security type (SECURITY_* constant)
 * @return String name (e.g., "WPA2", "None")
 */
const char* get_security_name(uint8_t sec_type);

/**
 * @brief Get human-readable wireless mode name
 *
 * @param mode Wireless mode (WIRELESS_MODE_* constant)
 * @return String name (e.g., "802.11n", "802.11ac")
 */
const char* get_wireless_mode_name(uint8_t mode);

/**
 * @brief Validate Xbox protocol header
 *
 * Checks:
 * - Magic bytes "XBOX"
 * - Version numbers
 * - Checksum
 *
 * @param header Pointer to xbox_header_t
 * @param total_len Total packet length (including header)
 * @return 1 if valid, 0 if invalid
 */
int validate_xbox_header(const xbox_header_t *header, size_t total_len);

/**
 * @brief Initialize Xbox protocol header
 *
 * Sets magic, version, and zeroes checksum.
 * Does NOT calculate checksum (call calculate_and_set_checksum after payload).
 *
 * @param header Pointer to xbox_header_t
 * @param type Packet type (PKT_* constant)
 * @param nonce Transaction ID (host byte order, will be converted to BE)
 * @param payload_len Payload length in bytes (header calculates DWORDs)
 */
void init_xbox_header(xbox_header_t *header,
                      uint8_t type,
                      uint16_t nonce,
                      size_t payload_len);

/**
 * @brief Calculate and set checksum in Xbox header
 *
 * Must be called AFTER all packet data is filled.
 *
 * @param packet Pointer to complete packet (header + payload)
 * @param total_len Total packet length
 */
void calculate_and_set_checksum(uint8_t *packet, size_t total_len);

/* ============================================================================
 * HEX DUMP & LOGGING
 * ============================================================================
 */

/**
 * @brief Print hex dump of data
 *
 * @param data Data buffer
 * @param len Length in bytes
 * @param label Optional label (can be NULL)
 */
void print_hex(const uint8_t *data, size_t len, const char *label);

/**
 * @brief Print hex dump to file
 *
 * @param fp File pointer
 * @param data Data buffer
 * @param len Length in bytes
 * @param label Optional label (can be NULL)
 */
void fprint_hex(FILE *fp, const uint8_t *data, size_t len, const char *label);

/**
 * @brief Load hex data from file
 *
 * Parses hex file with optional comments (#) and whitespace.
 * Example: "58 42 4f 58 # XBOX magic"
 *
 * @param filename Path to hex file
 * @param buffer Output buffer
 * @param len Pointer to store loaded length
 * @return 0 on success, -1 on failure
 */
int load_hex_file(const char *filename, uint8_t *buffer, size_t *len);

/* ============================================================================
 * TERMINAL HELPERS
 * ============================================================================
 */

/**
 * @brief Disable terminal echo (for password input)
 */
void disable_echo(void);

/**
 * @brief Enable terminal echo (restore after password input)
 */
void enable_echo(void);

/* ============================================================================
 * WIFI SYSTEM INTEGRATION (Linux)
 * ============================================================================
 */

/**
 * @brief WiFi adapter state structure
 */
typedef struct {
    char current_ssid[33];
    uint8_t current_bssid[6];
    uint8_t current_channel;
    uint8_t current_phy_mode;       /* WIRELESS_MODE_* */
    uint8_t current_security;       /* SECURITY_* */
    uint8_t signal_quality;         /* 0-255 scale */
    uint32_t ip_address;            /* Host byte order */
    int is_connected;
    int link_quality_raw;           /* SNR in dBm */
} adapter_state_t;

/**
 * @brief Update adapter state from Linux WiFi system
 *
 * Queries system using iw/ip commands to get:
 * - BSSID (AP MAC)
 * - Signal strength (dBm → 0-255 scale)
 * - Channel (1-14)
 * - PHY mode (802.11 b/g/n/ac)
 * - IP address
 *
 * @param state Pointer to adapter_state_t to update
 * @param interface WiFi interface name (e.g., "wlan0")
 * @return 0 on success, -1 on failure
 */
int update_adapter_state_from_system(adapter_state_t *state,
                                      const char *interface);

typedef enum {
	STATE_DISCONNECTED,
	STATE_HANDSHAKE_DONE,
	STATE_LINKED
} ConnectionState;

typedef enum {
	MODE_EMULATE_ADAPTER,
	MODE_EMULATE_XBOX,
	MODE_BRIDGE,
	MODE_SEND_HEX,
	MODE_REPLAY
} OperationMode;


/**
 * @brief Convert dBm signal to 0-255 scale
 *
 * Range: -90 dBm (worst) to -30 dBm (best)
 *
 * @param signal_dbm Signal strength in dBm (e.g., -45)
 * @return Signal on 0-255 scale
 */
uint8_t dbm_to_quality(int signal_dbm);

/**
 * @brief Convert 0-255 quality to percentage
 *
 * @param quality Quality on 0-255 scale
 * @return Percentage (0-100)
 */
int quality_to_percent(uint8_t quality);

/* ============================================================================
 * NETWORK INFO STRUCTURES
 * ============================================================================
 */

/**
 * @brief Network information (for network list responses)
 */
typedef struct {
    char ssid[33];
    uint8_t security_type;
    uint8_t signal_strength;
    uint8_t bssid[6];
    int valid;
} network_info_t;

/**
 * @brief Parsed WiFi configuration from TLV
 */
typedef struct {
    char ssid[33];
    char password[64];
    uint8_t security_type;
    int valid;
} parsed_wifi_config_t;

/**
 * @brief Parse TLV-encoded connect request
 *
 * Extracts SSID, password, and security type from TLV payload.
 *
 * @param payload TLV payload data
 * @param len Payload length
 * @return Parsed configuration structure
 */
parsed_wifi_config_t parse_connect_tlv(const uint8_t *payload, size_t len);

/**
 * @brief Encode network slot into 64-byte format
 *
 * Creates a properly formatted network_slot_t for network list responses.
 *
 * @param slot Output buffer (64 bytes)
 * @param index Network index (0-15)
 * @param ssid SSID string
 * @param security_type SECURITY_* constant
 * @param signal_strength Signal quality (0-255)
 */
void encode_network_slot(network_slot_t *slot,
                         int index,
                         const char *ssid,
                         uint8_t security_type,
                         uint8_t signal_strength);

/* ============================================================================
 * ENDIANNESS CONVERSION
 * ============================================================================
 */

/**
 * @brief Convert 16-bit value to big-endian (network byte order)
 *
 * @param val Host byte order value
 * @return Big-endian value
 */
static inline uint16_t to_be16(uint16_t val) {
    #if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
        return ((val & 0xFF) << 8) | ((val >> 8) & 0xFF);
    #else
        return val;
    #endif
}

/**
 * @brief Convert 16-bit value from big-endian (network byte order)
 *
 * @param val Big-endian value
 * @return Host byte order value
 */
static inline uint16_t from_be16(uint16_t val) {
    return to_be16(val);  /* Same operation */
}

/**
 * @brief Convert 32-bit value to big-endian
 *
 * @param val Host byte order value
 * @return Big-endian value
 */
static inline uint32_t to_be32(uint32_t val) {
    #if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
        return ((val & 0xFF) << 24) |
               ((val & 0xFF00) << 8) |
               ((val >> 8) & 0xFF00) |
               ((val >> 24) & 0xFF);
    #else
        return val;
    #endif
}

/**
 * @brief Convert 32-bit value from big-endian
 *
 * @param val Big-endian value
 * @return Host byte order value
 */
static inline uint32_t from_be32(uint32_t val) {
    return to_be32(val);  /* Same operation */
}

/* ============================================================================
 * STRING UTILITIES
 * ============================================================================
 */

/**
 * @brief Safe string copy with guaranteed null termination
 *
 * @param dest Destination buffer
 * @param src Source string
 * @param dest_size Size of destination buffer
 */
static inline void safe_strncpy(char *dest, const char *src, size_t dest_size) {
    if (dest_size == 0) return;
    strncpy(dest, src, dest_size - 1);
    dest[dest_size - 1] = '\0';
}

/**
 * @brief Trim trailing whitespace from string
 *
 * @param str String to modify (in-place)
 */
void trim_trailing_whitespace(char *str);

/* ============================================================================
 * ERROR HANDLING MACROS
 * ============================================================================
 */

/**
 * @brief Check condition and return error if false
 *
 * Usage: CHECK_RET(ptr != NULL, -1, "Null pointer");
 */
#define CHECK_RET(condition, retval, msg) \
    do { \
        if (!(condition)) { \
            fprintf(stderr, "ERROR: %s (at %s:%d)\n", msg, __FILE__, __LINE__); \
            return retval; \
        } \
    } while(0)

/**
 * @brief Check condition and goto label if false
 *
 * Usage: CHECK_GOTO(fp != NULL, cleanup, "Failed to open file");
 */
#define CHECK_GOTO(condition, label, msg) \
    do { \
        if (!(condition)) { \
            fprintf(stderr, "ERROR: %s (at %s:%d)\n", msg, __FILE__, __LINE__); \
            goto label; \
        } \
    } while(0)

#endif /* XBOX_HELPERS_H */

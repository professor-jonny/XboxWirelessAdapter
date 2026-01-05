/*
 * helpers.c - Xbox MN-740 Wireless Protocol Helper Implementations
 * 
 * Implementation of common utility functions for protocol handling,
 * MAC address operations, checksum calculation, HMAC authentication,
 * and system integration.
 * 
 * Copyright (C) 2026
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "helpers.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <termios.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

/* ============================================================================
 * GLOBAL SECRET STORAGE
 * ============================================================================
 */

static uint8_t g_hmac_key[SECRET_HMAC_KEY_SIZE];
static uint8_t g_hmac_salt[SECRET_HMAC_SALT_SIZE];
static uint8_t g_auth_copyright[SECRET_COPYRIGHT_SIZE];
static int g_secrets_loaded = 0;

/* ============================================================================
 * MAC ADDRESS HELPERS
 * ============================================================================
 */

void print_mac(const uint8_t *mac) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void fprint_mac(FILE *fp, const uint8_t *mac) {
    fprintf(fp, "%02x:%02x:%02x:%02x:%02x:%02x",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

int parse_mac(const char *str, uint8_t *mac) {
    /* Try colon-separated format first (aa:bb:cc:dd:ee:ff) */
    if (sscanf(str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
               &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) == 6) {
        return 1;
    }

    /* Try dash-separated format (aa-bb-cc-dd-ee-ff) */
    if (sscanf(str, "%hhx-%hhx-%hhx-%hhx-%hhx-%hhx",
               &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) == 6) {
        return 1;
    }

    /* Try continuous format (aabbccddeeff) */
    if (strlen(str) == 12) {
        for (int i = 0; i < 6; i++) {
            if (sscanf(str + (i * 2), "%2hhx", &mac[i]) != 1) {
                return 0;
            }
        }
        return 1;
    }

    return 0;
}

void mac_to_string(const uint8_t *mac, char *str) {
    snprintf(str, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

int mac_equal(const uint8_t *mac1, const uint8_t *mac2) {
    return memcmp(mac1, mac2, MAC_ADDRESS_SIZE) == 0;
}

/* ============================================================================
 * CHECKSUM & HMAC
 * ============================================================================
 */

uint16_t calculate_checksum(const uint8_t *data, size_t len) {
    uint32_t sum = 0;
    
    /* Sum all 16-bit words */
    for (size_t i = 0; i + 1 < len; i += 2) {
        sum += ((uint32_t)data[i] << 8) | data[i+1];
        if (sum > 0xffff) {
            sum = (sum & 0xffff) + 1;  /* Add carry */
        }
    }
    
    /* Handle odd byte */
    if (len & 1) {
        sum += ((uint32_t)data[len-1] << 8);
        if (sum > 0xffff) {
            sum = (sum & 0xffff) + 1;
        }
    }
    
    /* One's complement */
    return (uint16_t)(sum ^ 0xffff);
}

void make_signature_hmac(const uint8_t *challenge, 
                         const uint8_t *adapter_mac, 
                         uint8_t *signature_out) {
    uint8_t data[139];  /* 16 + 6 + 117 */
    unsigned int len = 0;
    
    /* Concatenate: challenge + MAC + salt */
    memcpy(data, challenge, HANDSHAKE_CHALLENGE_SIZE);
    memcpy(data + HANDSHAKE_CHALLENGE_SIZE, adapter_mac, MAC_ADDRESS_SIZE);
    memcpy(data + HANDSHAKE_CHALLENGE_SIZE + MAC_ADDRESS_SIZE, 
           g_hmac_salt, SECRET_HMAC_SALT_SIZE);
    
    /* Compute HMAC-SHA1 */
    HMAC(EVP_sha1(), g_hmac_key, SECRET_HMAC_KEY_SIZE, 
         data, sizeof(data), signature_out, &len);
}

int load_secrets(void) {
    FILE *fp;
    
    /* Load HMAC key */
    fp = fopen(SECRET_HMAC_KEY_PATH, "rb");
    if (!fp) {
        fprintf(stderr, "Error: Cannot open %s: %s\n", 
                SECRET_HMAC_KEY_PATH, strerror(errno));
        return -1;
    }
    
    size_t read = fread(g_hmac_key, 1, SECRET_HMAC_KEY_SIZE, fp);
    fclose(fp);
    
    if (read != SECRET_HMAC_KEY_SIZE) {
        fprintf(stderr, "Error: %s is %zu bytes, expected %d\n",
                SECRET_HMAC_KEY_PATH, read, SECRET_HMAC_KEY_SIZE);
        return -1;
    }
    
    /* Load HMAC salt */
    fp = fopen(SECRET_HMAC_SALT_PATH, "rb");
    if (!fp) {
        fprintf(stderr, "Error: Cannot open %s: %s\n", 
                SECRET_HMAC_SALT_PATH, strerror(errno));
        return -1;
    }
    
    read = fread(g_hmac_salt, 1, SECRET_HMAC_SALT_SIZE, fp);
    fclose(fp);
    
    if (read != SECRET_HMAC_SALT_SIZE) {
        fprintf(stderr, "Error: %s is %zu bytes, expected %d\n",
                SECRET_HMAC_SALT_PATH, read, SECRET_HMAC_SALT_SIZE);
        return -1;
    }
    
    /* Load copyright string */
    fp = fopen(SECRET_COPYRIGHT_PATH, "rb");
    if (!fp) {
        fprintf(stderr, "Error: Cannot open %s: %s\n", 
                SECRET_COPYRIGHT_PATH, strerror(errno));
        return -1;
    }
    
    read = fread(g_auth_copyright, 1, SECRET_COPYRIGHT_SIZE, fp);
    fclose(fp);
    
    if (read != SECRET_COPYRIGHT_SIZE) {
        fprintf(stderr, "Error: %s is %zu bytes, expected %d\n",
                SECRET_COPYRIGHT_PATH, read, SECRET_COPYRIGHT_SIZE);
        return -1;
    }
    
    g_secrets_loaded = 1;
    printf("✓ Secrets loaded\n");
    return 0;
}

const uint8_t* get_hmac_key(void) {
    return g_secrets_loaded ? g_hmac_key : NULL;
}

const uint8_t* get_hmac_salt(void) {
    return g_secrets_loaded ? g_hmac_salt : NULL;
}

const uint8_t* get_auth_copyright(void) {
    return g_secrets_loaded ? g_auth_copyright : NULL;
}

/* ============================================================================
 * PROTOCOL HELPERS
 * ============================================================================
 */

const char* get_packet_type_name(uint8_t type) {
    switch(type) {
        case PKT_ECHO:                      return "ECHO";
        case PKT_HANDSHAKE_REQUEST:         return "HANDSHAKE_REQ";
        case PKT_HANDSHAKE_RESPONSE:        return "HANDSHAKE_RESP";
        case PKT_NETWORKS_LIST_REQUEST:     return "NETWORKS_LIST_REQ";
        case PKT_NETWORKS_LIST_RESPONSE:    return "NETWORKS_LIST_RESP";
        case PKT_ADAPTER_INFO_REQUEST:      return "ADAPTER_INFO_REQ";
        case PKT_ADAPTER_INFO_RESPONSE:     return "ADAPTER_INFO_RESP";
        case PKT_CONNECT_TO_SSID_REQUEST:   return "CONNECT_REQ";
        case PKT_CONNECT_TO_SSID_RESPONSE:  return "CONNECT_RESP";
        case PKT_BEACON_REQUEST:            return "BEACON_REQ";
        case PKT_BEACON_RESPONSE:           return "BEACON_RESP";
        case PKT_DISCOVERY:                 return "DISCOVERY";
        case PKT_DISCOVERY_RESPONSE:        return "DISCOVERY_RESP";
        default:                            return "UNKNOWN";
    }
}

const char* get_security_name(uint8_t sec_type) {
    switch (sec_type) {
        case SECURITY_NONE:         return "None";
        case SECURITY_WEP:          return "WEP";
        case SECURITY_OPEN:         return "Open";
        case SECURITY_WPA_WPA2:     return "WPA/WPA2";
        case SECURITY_WPA2:         return "WPA2";
        default:                    return "Unknown";
    }
}

const char* get_wireless_mode_name(uint8_t mode) {
    switch (mode) {
        case WIRELESS_MODE_11B:     return "802.11b";
        case WIRELESS_MODE_11G:     return "802.11g";
        case WIRELESS_MODE_11N:     return "802.11n";
        case WIRELESS_MODE_11AC:    return "802.11ac";
        default:                    return "Unknown";
    }
}

int validate_xbox_header(const xbox_header_t *header, size_t total_len) {
    /* Check magic bytes */
    if (memcmp(header->magic, "XBOX", XBOX_MAGIC_SIZE) != 0) {
        return 0;
    }
    
    /* Check version */
    if (header->version != 0x01 || header->sub_version != 0x01) {
        return 0;
    }
    
    /* Check length consistency */
    size_t expected_len = (header->body_size_dwords * 4);
    if (total_len < expected_len) {
        return 0;
    }
    
    /* TODO: Validate checksum if needed */
    
    return 1;
}

void init_xbox_header(xbox_header_t *header, 
                      uint8_t type, 
                      uint16_t nonce, 
                      size_t payload_len) {
    memcpy(header->magic, "XBOX", XBOX_MAGIC_SIZE);
    header->version = 0x01;
    header->sub_version = 0x01;
    
    /* Calculate total body size in DWORDs (header + payload) */
    size_t total_body = XBOX_BODY_HEADER_SIZE + payload_len;
    header->body_size_dwords = (total_body + 3) / 4;  /* Round up */
    
    header->packet_type = type;
    header->nonce = to_be16(nonce);  /* Convert to big-endian */
    header->checksum = 0;  /* Will be calculated later */
}

void calculate_and_set_checksum(uint8_t *packet, size_t total_len) {
    xbox_header_t *header = (xbox_header_t *)packet;
    
    /* Zero out checksum field before calculation */
    header->checksum = 0;
    
    /* Calculate checksum over entire packet */
    uint16_t checksum = calculate_checksum(packet, total_len);
    
    /* Set checksum in big-endian */
    header->checksum = checksum;
}

/* ============================================================================
 * HEX DUMP & LOGGING
 * ============================================================================
 */

void print_hex(const uint8_t *data, size_t len, const char *label) {
    fprint_hex(stdout, data, len, label);
}

void fprint_hex(FILE *fp, const uint8_t *data, size_t len, const char *label) {
    if (label) {
        fprintf(fp, "\n[%s] (%zu bytes):\n   ", label, len);
    }
    
    for (size_t i = 0; i < len; i++) {
        fprintf(fp, "%02x ", data[i]);
        if ((i + 1) % 16 == 0) {
            fprintf(fp, "\n   ");
        }
    }
    
    if (len % 16 != 0) {
        fprintf(fp, "\n");
    }
    
    fprintf(fp, "\n");
}

int load_hex_file(const char *filename, uint8_t *buffer, size_t *len) {
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        fprintf(stderr, "Error: Cannot open %s: %s\n", filename, strerror(errno));
        return -1;
    }

    *len = 0;
    char line[8192];

    while (fgets(line, sizeof(line), fp)) {
        char *p = line;
        
        /* Skip comment lines */
        if (*p == '#') continue;

        while (*p) {
            /* Skip whitespace */
            while (*p && isspace(*p)) p++;
            
            /* Check for comment */
            if (*p == '#') break;
            
            /* Parse hex byte */
            if (isxdigit(*p) && isxdigit(*(p+1))) {
                unsigned int byte;
                if (sscanf(p, "%2x", &byte) == 1) {
                    buffer[(*len)++] = (uint8_t)byte;
                    if (*len >= BUFFER_SIZE) {
                        fprintf(stderr, "Error: Hex file too large\n");
                        fclose(fp);
                        return -1;
                    }
                }
                p += 2;
            } else if (*p) {
                p++;  /* Skip invalid character */
            }
        }
    }

    fclose(fp);
    printf("✓ Loaded %zu bytes from %s\n", *len, filename);
    return 0;
}

/* ============================================================================
 * TERMINAL HELPERS
 * ============================================================================
 */

void disable_echo(void) {
    struct termios tty;
    tcgetattr(STDIN_FILENO, &tty);
    tty.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &tty);
}

void enable_echo(void) {
    struct termios tty;
    tcgetattr(STDIN_FILENO, &tty);
    tty.c_lflag |= ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &tty);
}

/* ============================================================================
 * WIFI SYSTEM INTEGRATION (Linux)
 * ============================================================================
 */

uint8_t dbm_to_quality(int signal_dbm) {
    /* Convert -90 to -30 dBm range to 0-255 scale */
    int scaled = ((signal_dbm + 90) * 255) / 60;
    
    if (scaled < 0) return 0;
    if (scaled > 255) return 255;
    
    return (uint8_t)scaled;
}

int quality_to_percent(uint8_t quality) {
    return (quality * 100) / 255;
}

int update_adapter_state_from_system(adapter_state_t *state, 
                                      const char *interface) {
    FILE *fp;
    char line[256];
    char cmd[512];
    
    /* Get BSSID (AP MAC address) */
    snprintf(cmd, sizeof(cmd), 
             "iw dev %s link 2>/dev/null | grep 'Connected to' | awk '{print $3}'", 
             interface);
    fp = popen(cmd, "r");
    if (fp) {
        if (fgets(line, sizeof(line), fp)) {
            if (sscanf(line, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                   &state->current_bssid[0], &state->current_bssid[1],
                   &state->current_bssid[2], &state->current_bssid[3],
                   &state->current_bssid[4], &state->current_bssid[5]) == 6) {
                state->is_connected = 1;
            }
        }
        pclose(fp);
    }
    
    /* Get WiFi channel */
    snprintf(cmd, sizeof(cmd),
             "iw dev %s info 2>/dev/null | grep 'channel' | awk '{print $2}'",
             interface);
    fp = popen(cmd, "r");
    if (fp) {
        if (fgets(line, sizeof(line), fp)) {
            state->current_channel = atoi(line);
        }
        pclose(fp);
    }
    
    /* Get signal strength (dBm) */
    snprintf(cmd, sizeof(cmd),
             "iw dev %s link 2>/dev/null | grep 'signal:' | awk '{print $2}'",
             interface);
    fp = popen(cmd, "r");
    if (fp) {
        if (fgets(line, sizeof(line), fp)) {
            int signal_dbm = atoi(line);
            state->signal_quality = dbm_to_quality(signal_dbm);
        }
        pclose(fp);
    }
    
    /* Get current SSID */
    snprintf(cmd, sizeof(cmd),
             "iw dev %s link 2>/dev/null | grep 'SSID:' | awk '{print $2}'",
             interface);
    fp = popen(cmd, "r");
    if (fp) {
        if (fgets(line, sizeof(line), fp)) {
            trim_trailing_whitespace(line);
            safe_strncpy(state->current_ssid, line, sizeof(state->current_ssid));
        }
        pclose(fp);
    }
    
    /* Get IP address */
    snprintf(cmd, sizeof(cmd),
             "ip -4 addr show %s 2>/dev/null | grep -oP '(?<=inet\\s)\\d+(\\.\\d+){3}'",
             interface);
    fp = popen(cmd, "r");
    if (fp) {
        if (fgets(line, sizeof(line), fp)) {
            unsigned int a, b, c, d;
            if (sscanf(line, "%u.%u.%u.%u", &a, &b, &c, &d) == 4) {
                state->ip_address = (a << 24) | (b << 16) | (c << 8) | d;
            }
        }
        pclose(fp);
    }
    
    /* Determine PHY mode (802.11 b/g/n/ac) */
    state->current_phy_mode = WIRELESS_MODE_11G;  /* Default */
    
    snprintf(cmd, sizeof(cmd),
             "iw dev %s link 2>/dev/null | grep 'VHT'",
             interface);
    fp = popen(cmd, "r");
    if (fp) {
        if (fgets(line, sizeof(line), fp)) {
            state->current_phy_mode = WIRELESS_MODE_11AC;
            pclose(fp);
            return 0;
        }
        pclose(fp);
    }
    
    snprintf(cmd, sizeof(cmd),
             "iw dev %s link 2>/dev/null | grep 'HT'",
             interface);
    fp = popen(cmd, "r");
    if (fp) {
        if (fgets(line, sizeof(line), fp)) {
            state->current_phy_mode = WIRELESS_MODE_11N;
        }
        pclose(fp);
    }
    
    return 0;
}

/* ============================================================================
 * TLV PARSING
 * ============================================================================
 */

parsed_wifi_config_t parse_connect_tlv(const uint8_t *payload, size_t len) {
    parsed_wifi_config_t config = {0};
    size_t pos = 0;

    while (pos + 2 <= len) {
        uint8_t tag = payload[pos++];
        uint8_t tag_len = payload[pos++];

        if (pos + tag_len > len) break;

        switch (tag) {
            case TLV_TAG_SSID:  /* SSID */
                if (tag_len <= 32) {
                    memcpy(config.ssid, &payload[pos], tag_len);
                    config.ssid[tag_len] = '\0';
                }
                break;

            case TLV_TAG_PASSWORD:      /* Password */
            case TLV_TAG_PASSWORD_ALT:  /* Alternate password tag */
                if (tag_len <= 63) {
                    memcpy(config.password, &payload[pos], tag_len);
                    config.password[tag_len] = '\0';
                }
                break;

            case TLV_TAG_SECURITY:      /* Security type (primary) */
            case TLV_TAG_SECURITY_ALT:  /* Security type (alternate) */
                if (tag_len >= 1) {
                    config.security_type = payload[pos];
                }
                break;
        }

        pos += tag_len;
    }

    config.valid = (config.ssid[0] != '\0');
    return config;
}

/* ============================================================================
 * NETWORK SLOT ENCODING
 * ============================================================================
 */

void encode_network_slot(network_slot_t *slot,
                         int index,
                         const char *ssid,
                         uint8_t security_type,
                         uint8_t signal_strength) {
    /* Clear entire slot */
    memset(slot, 0, NETWORK_SLOT_SIZE);
    
    /* Set BSSID (use dummy MAC with index) */
    slot->bssid[0] = 0xAA;
    slot->bssid[1] = 0xAA;
    slot->bssid[2] = 0xAA;
    slot->bssid[3] = 0xAA;
    slot->bssid[4] = 0xAA;
    slot->bssid[5] = 0xA0 + index;
    
    /* SSID TLV */
    slot->ssid_tag = TLV_TAG_SSID;
    size_t ssid_len = strlen(ssid);
    if (ssid_len > NETWORK_SSID_DATA_SIZE) {
        ssid_len = NETWORK_SSID_DATA_SIZE;
    }
    slot->ssid_length = (uint8_t)ssid_len;
    memcpy(slot->ssid, ssid, ssid_len);
    
    /* Security TLV */
    slot->security_tag = TLV_TAG_SECURITY;
    slot->security_length = 1;
    slot->security_type = security_type;
    
    /* Signal TLV (non-standard: no length byte) */
    slot->signal_tag = TLV_TAG_SIGNAL;
    slot->signal_strength = signal_strength;
    
    /* Supported rates (standard 802.11 rates) */
    slot->rates[0] = 0x02;  /* 1 Mbps */
    slot->rates[1] = 0x04;  /* 2 Mbps */
    slot->rates[2] = 0x0B;  /* 5.5 Mbps */
    slot->rates[3] = 0x16;  /* 11 Mbps */
    slot->rates[4] = 0x12;  /* 9 Mbps */
    slot->rates[5] = 0x24;  /* 18 Mbps */
    slot->rates[6] = 0x48;  /* 36 Mbps */
    slot->rates[7] = 0x6C;  /* 54 Mbps */
    slot->rates[8] = 0x0C;  /* 6 Mbps */
    slot->rates[9] = 0x18;  /* 12 Mbps */
    slot->rates[10] = 0x30; /* 24 Mbps */
    slot->rates[11] = 0x60; /* 48 Mbps */
}

/* ============================================================================
 * STRING UTILITIES
 * ============================================================================
 */

void trim_trailing_whitespace(char *str) {
    if (!str) return;
    
    size_t len = strlen(str);
    while (len > 0 && isspace((unsigned char)str[len - 1])) {
        str[--len] = '\0';
    }
}

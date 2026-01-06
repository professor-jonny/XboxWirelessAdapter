#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

// Protocol constants
#define XBOX_PROTOCOL 0x886f  // MS NLB heartbeat
#define BUFFER_SIZE 2048

// Packet types
#define PACKET_TYPE_HANDSHAKE_REQUEST 0x01
#define PACKET_TYPE_HANDSHAKE_RESPONSE 0x02
#define PACKET_TYPE_NETWORKS_LIST_REQUEST 0x03
#define PACKET_TYPE_NETWORKS_LIST_RESPONSE 0x04
#define PACKET_TYPE_ADAPTER_INFO_REQUEST 0x05
#define PACKET_TYPE_ADAPTER_INFO_RESPONSE 0x06
#define PACKET_TYPE_CONNECT_TO_SSID_REQUEST 0x07
#define PACKET_TYPE_CONNECT_TO_SSID_RESPONSE 0x08
#define PACKET_TYPE_BEACON_REQUEST 0x09
#define PACKET_TYPE_BEACON_RESPONSE 0x0a

// Header constants
#define HEADER_SIGNATURE "XBOX"
#define HEADER_VERSION_1 0x01
#define HEADER_VERSION_2 0x01

// Debug flag
static int debug_mode = 1;

// Connection states
typedef enum {
    STATE_INIT,
    STATE_HANDSHAKE_DONE,
    STATE_WAITING_CONFIG,
    STATE_CONNECTING,
    STATE_CONNECTED,
    STATE_FAILED
} connection_state_t;

// WiFi configuration structure
typedef struct {
    char ssid[33];
    uint8_t ssid_len;
    char password[64];
    uint8_t password_len;
    uint8_t security_type;
} wifi_config_t;

// Secret data structures
typedef struct {
    uint8_t hmac_salt[0x75];
    size_t hmac_salt_len;
    uint8_t hmac_key[16];
    uint8_t auth_copyright[0x54];
    size_t auth_copyright_len;
} xbox_secrets_t;

// Global state
static int sockfd = -1;
static connection_state_t current_state = STATE_INIT;
static wifi_config_t wifi_config;
static xbox_secrets_t secrets;
static uint8_t xbox_mac[6];
static uint8_t local_mac[6];
static char interface_name[IFNAMSIZ];
static volatile sig_atomic_t running = 1;

// Debug printing helper
void debug_print_hex(const char *label, const uint8_t *data, size_t len) {
    if (!debug_mode) return;
    
    printf("[DEBUG] %s (%zu bytes): ", label, len);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
        if ((i + 1) % 16 == 0 && i + 1 < len) {
            printf("\n        ");
        } else if (i + 1 < len) {
            printf(" ");
        }
    }
    printf("\n");
}

// Signal handler for clean shutdown
void signal_handler(int signum) {
    printf("\nReceived signal %d, shutting down...\n", signum);
    running = 0;
}

// Load secrets from extracted files
int load_secrets() {
    FILE *fp;
    
    printf("Loading secrets from 'secrets/' directory...\n");
    
    // Load HMAC salt
    fp = fopen("secrets/hmac_salt.bin", "rb");
    if (!fp) {
        fprintf(stderr, "Error: Could not open secrets/hmac_salt.bin\n");
        fprintf(stderr, "Have you extracted the secrets from xonlinedash?\n");
        fprintf(stderr, "Run: python3 extract_secrets.py xonlinedash.xbe\n");
        return -1;
    }
    secrets.hmac_salt_len = fread(secrets.hmac_salt, 1, sizeof(secrets.hmac_salt), fp);
    fclose(fp);
    
    if (secrets.hmac_salt_len != 0x75) {
        fprintf(stderr, "Error: HMAC salt has wrong size: %zu (expected 117)\n", 
                secrets.hmac_salt_len);
        return -1;
    }
    
    // Load HMAC key
    fp = fopen("secrets/hmac_key.bin", "rb");
    if (!fp) {
        fprintf(stderr, "Error: Could not open secrets/hmac_key.bin\n");
        return -1;
    }
    size_t key_len = fread(secrets.hmac_key, 1, sizeof(secrets.hmac_key), fp);
    fclose(fp);
    
    if (key_len != 16) {
        fprintf(stderr, "Error: HMAC key has wrong size: %zu (expected 16)\n", key_len);
        return -1;
    }
    
    // Load auth copyright
    fp = fopen("secrets/auth_copyright.bin", "rb");
    if (!fp) {
        fprintf(stderr, "Error: Could not open secrets/auth_copyright.bin\n");
        return -1;
    }
    secrets.auth_copyright_len = fread(secrets.auth_copyright, 1, 
                                       sizeof(secrets.auth_copyright), fp);
    fclose(fp);
    
    if (secrets.auth_copyright_len != 0x54) {
        fprintf(stderr, "Error: Auth copyright has wrong size: %zu (expected 84)\n", 
                secrets.auth_copyright_len);
        return -1;
    }
    
    printf("✓ Secrets loaded successfully:\n");
    printf("  - HMAC salt: %zu bytes\n", secrets.hmac_salt_len);
    printf("  - HMAC key: 16 bytes\n");
    printf("  - Auth copyright: %zu bytes\n", secrets.auth_copyright_len);
    
    if (debug_mode) {
        debug_print_hex("HMAC Key", secrets.hmac_key, 16);
        debug_print_hex("HMAC Salt", secrets.hmac_salt, secrets.hmac_salt_len);
        debug_print_hex("Auth Copyright", secrets.auth_copyright, secrets.auth_copyright_len);
    }
    
    return 0;
}

// Calculate HMAC-SHA1 signature
// Python: data = message + local_mac + hmac_salt
//         signature = hmac.new(hmac_key, data, hashlib.sha1).digest()
void make_signature_hmac(const uint8_t *message, size_t message_len,
                        const uint8_t *local_mac,
                        uint8_t *signature_out) {
    uint8_t data[BUFFER_SIZE];
    size_t data_len = 0;
    
    // Concatenate: message + local_mac + hmac_salt
    memcpy(data + data_len, message, message_len);
    data_len += message_len;
    
    memcpy(data + data_len, local_mac, 6);
    data_len += 6;
    
    memcpy(data + data_len, secrets.hmac_salt, secrets.hmac_salt_len);
    data_len += secrets.hmac_salt_len;
    
    if (debug_mode) {
        printf("[DEBUG] HMAC Input Components:\n");
        debug_print_hex("  Message", message, message_len);
        debug_print_hex("  Local MAC", local_mac, 6);
        printf("[DEBUG]   Salt: (see above, %zu bytes)\n", secrets.hmac_salt_len);
        printf("[DEBUG] Total HMAC input length: %zu bytes\n", data_len);
        debug_print_hex("Complete HMAC Input", data, data_len);
    }
    
    // Calculate HMAC-SHA1
    unsigned int sig_len;
    HMAC(EVP_sha1(), secrets.hmac_key, 16, data, data_len, signature_out, &sig_len);
    
    if (sig_len != 20) {
        fprintf(stderr, "Warning: HMAC signature length is %u (expected 20)\n", sig_len);
    }
    
    if (debug_mode) {
        debug_print_hex("HMAC-SHA1 Output", signature_out, 20);
    }
}

// Calculate checksum for packet body
uint16_t calculate_checksum(const uint8_t *data, size_t len) {
    uint32_t checksum = 0;
    
    // Process pairs of bytes
    for (size_t i = 0; i < len - 1; i += 2) {
        checksum += (data[i] << 8) + data[i + 1];
        if (checksum > 0xffff) {
            checksum = (checksum & 0xffff) + 1;
        }
    }
    
    // Handle odd length
    if (len % 2 != 0) {
        checksum += (data[len - 1] << 8);
        if (checksum > 0xffff) {
            checksum = (checksum & 0xffff) + 1;
        }
    }
    
    checksum = checksum ^ 0xffff;
    return (uint16_t)checksum;
}

// Send packet to Xbox
int send_packet(uint8_t type, uint16_t nonce, const uint8_t *payload, size_t payload_len) {
    uint8_t packet[BUFFER_SIZE];
    struct sockaddr_ll addr;
    size_t pos = 0;
    
    printf("\n[SEND] Preparing packet type 0x%02x, nonce=0x%04x, payload=%zu bytes\n", 
           type, nonce, payload_len);
    
    // Calculate body size in DWORDs FIRST (matching Python)
    // packet_size = (len(payload) // 4) + 3
    uint8_t body_size = ((payload_len / 4) + 3);
    
    if (debug_mode) {
        printf("[DEBUG] Body size calculation: (%zu / 4) + 3 = %d DWORDs\n", 
               payload_len, body_size);
    }
    
    // THEN determine if we need padding for minimum frame size
    size_t min_payload = 34;
    size_t padded_payload_len = (payload_len < min_payload) ? min_payload : payload_len;
    
    if (debug_mode && padded_payload_len != payload_len) {
        printf("[DEBUG] Padding payload from %zu to %zu bytes for minimum frame size\n",
               payload_len, padded_payload_len);
    }
    
    // Build Ethernet header
    memcpy(packet + pos, xbox_mac, 6); pos += 6;
    memcpy(packet + pos, local_mac, 6); pos += 6;
    packet[pos++] = (XBOX_PROTOCOL >> 8) & 0xFF;
    packet[pos++] = XBOX_PROTOCOL & 0xFF;
    
    // Build body (for checksum calculation)
    uint8_t body[BUFFER_SIZE];
    size_t body_pos = 0;
    
    memcpy(body + body_pos, HEADER_SIGNATURE, 4); body_pos += 4;
    body[body_pos++] = HEADER_VERSION_1;
    body[body_pos++] = HEADER_VERSION_2;
    body[body_pos++] = body_size;
    body[body_pos++] = type;
    body[body_pos++] = (nonce >> 8) & 0xFF;
    body[body_pos++] = nonce & 0xFF;
    body[body_pos++] = 0;  // Checksum placeholder
    body[body_pos++] = 0;
    
    // Add original payload
    if (payload_len > 0) {
        memcpy(body + body_pos, payload, payload_len);
        body_pos += payload_len;
    }
    
    // Pad to meet minimum payload requirement
    while (body_pos < 12 + padded_payload_len) {
        body[body_pos++] = 0;
    }
    
    if (debug_mode) {
        printf("[DEBUG] Body before checksum (%zu bytes):\n", body_pos);
        debug_print_hex("Body", body, body_pos);
    }
    
    // Calculate checksum on the body
    uint16_t checksum = calculate_checksum(body, body_pos);
    body[10] = (checksum >> 8) & 0xFF;
    body[11] = checksum & 0xFF;
    
    if (debug_mode) {
        printf("[DEBUG] Calculated checksum: 0x%04x\n", checksum);
    }
    
    // Copy body to packet
    memcpy(packet + pos, body, body_pos);
    pos += body_pos;
    
    if (debug_mode) {
        printf("[DEBUG] Complete packet (%zu bytes):\n", pos);
        debug_print_hex("Packet", packet, pos);
    }
    
    // Setup address structure
    memset(&addr, 0, sizeof(addr));
    addr.sll_ifindex = if_nametoindex(interface_name);
    addr.sll_halen = ETH_ALEN;
    memcpy(addr.sll_addr, xbox_mac, 6);
    
    ssize_t sent = sendto(sockfd, packet, pos, 0,
                         (struct sockaddr *)&addr, sizeof(addr));
    
    if (sent < 0) {
        perror("sendto");
        return -1;
    }
    
    printf("[SEND] ✓ Sent packet type 0x%02x, %zd bytes\n", type, sent);
    return 0;
}

// Handle HANDSHAKE_REQUEST
void handle_handshake_request(const uint8_t *payload, size_t len, uint16_t nonce) {
    printf("\n=== HANDSHAKE REQUEST ===\n");
    printf("Received HANDSHAKE_REQUEST from Xbox\n");
    
    if (len < 16) {
        fprintf(stderr, "Error: Handshake request payload too short: %zu bytes\n", len);
        return;
    }
    
    if (debug_mode) {
        debug_print_hex("Challenge", payload, 16);
    }
    
    // Calculate HMAC signature
    uint8_t hmac_signature[20];
    make_signature_hmac(payload, 16, local_mac, hmac_signature);
    
    printf("✓ HMAC signature calculated\n");
    
    // Build response payload
    // Structure: HMAC(20) + auth_copyright(84) + response_data(152) = 256 bytes
    uint8_t response[256];
    size_t pos = 0;
    
    // Add HMAC signature (20 bytes)
    memcpy(response + pos, hmac_signature, 20);
    pos += 20;
    
    // Add auth copyright (84 bytes)
    memcpy(response + pos, secrets.auth_copyright, secrets.auth_copyright_len);
    pos += secrets.auth_copyright_len;
    
    // Add response data (152 bytes) - from Python's hex string
    const uint8_t response_data[] = {
        0x54, 0x6F, 0x74, 0x61, 0x6C, 0x6C, 0x79, 0x20, 0x6C, 0x65, 0x67, 0x69, 0x74, 0x20, 0x77, 0x69,
        0x72, 0x65, 0x6C, 0x65, 0x73, 0x73, 0x20, 0x61, 0x64, 0x61, 0x70, 0x74, 0x65, 0x72, 0x00, 0x00,
        0x44, 0x75, 0x64, 0x65, 0x20, 0x74, 0x72, 0x75, 0x73, 0x74, 0x20, 0x6D, 0x65, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x07, 0x00, 0x00, 0x0F, 0xFE, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x01, 0xA9, 0xFE, 0x47, 0x79, 0x01, 0x02, 0x01, 0x0B, 0x02,
        0x0C, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x02, 0x01, 0x00, 0x00
    };
    
    memcpy(response + pos, response_data, sizeof(response_data));
    pos += sizeof(response_data);
    
    // Should total 256 bytes
    if (pos != 256) {
        fprintf(stderr, "Warning: Handshake response size is %zu (expected 256)\n", pos);
    }
    
    if (debug_mode) {
        printf("[DEBUG] Response payload structure:\n");
        printf("[DEBUG]   - HMAC: 20 bytes\n");
        printf("[DEBUG]   - Auth Copyright: 84 bytes\n");
        printf("[DEBUG]   - Response Data: 152 bytes\n");
        printf("[DEBUG]   - Total: %zu bytes\n", pos);
        debug_print_hex("Complete Response", response, pos);
    }
    
    current_state = STATE_HANDSHAKE_DONE;
    send_packet(PACKET_TYPE_HANDSHAKE_RESPONSE, nonce, response, 256);
    printf("✓ Handshake complete, state = HANDSHAKE_DONE\n");
}

// Handle BEACON_REQUEST
void handle_beacon_request(uint16_t nonce) {
    printf("\n=== BEACON REQUEST ===\n");
    printf("Received BEACON_REQUEST from Xbox\n");
    
    uint8_t response[4] = {0x02, 0x80, 0x00, 0x00};
    send_packet(PACKET_TYPE_BEACON_RESPONSE, nonce, response, 4);
}

// Handle ADAPTER_INFO_REQUEST  
void handle_adapter_info_request(uint16_t nonce) {
    printf("\n=== ADAPTER INFO REQUEST ===\n");
    printf("Received ADAPTER_INFO_REQUEST from Xbox\n");
    
    uint8_t response[64];
    memset(response, 0, sizeof(response));
    
    response[0] = 0x00;  // Status OK
    response[1] = 0x09;  // Some status byte
    response[2] = wifi_config.ssid_len;
    
    if (current_state == STATE_CONNECTED && wifi_config.ssid_len > 0) {
        memcpy(response + 3, wifi_config.ssid, wifi_config.ssid_len);
        printf("Current SSID: %s\n", wifi_config.ssid);
    }
    
    send_packet(PACKET_TYPE_ADAPTER_INFO_RESPONSE, nonce, response, 64);
}

// Handle NETWORKS_LIST_REQUEST
void handle_networks_list_request(uint16_t nonce) {
    printf("\n=== NETWORKS LIST REQUEST ===\n");
    printf("Received NETWORKS_LIST_REQUEST from Xbox\n");
    
    // For a real implementation, you'd scan for networks here
    // For now, return the mock data from Python
    uint8_t response[512];
    memset(response, 0, sizeof(response));
    
    // You could implement actual WiFi scanning here using iwlist or nl80211
    printf("Note: Returning mock network list. Implement real WiFi scanning for production.\n");
    
    send_packet(PACKET_TYPE_NETWORKS_LIST_RESPONSE, nonce, response, 512);
}

// Parse TLV data from connect request
void parse_connect_request(const uint8_t *payload, size_t len) {
    size_t pos = 0;
    
    printf("Parsing connect request TLV data...\n");
    memset(&wifi_config, 0, sizeof(wifi_config));
    
    while (pos + 2 <= len) {
        uint8_t tag = payload[pos];
        uint8_t tag_len = payload[pos + 1];
        
        if (pos + 2 + tag_len > len) {
            printf("Warning: Invalid TLV at offset %zu\n", pos);
            break;
        }
        
        const uint8_t *value = payload + pos + 2;
        
        if (debug_mode) {
            printf("[DEBUG] TLV: tag=0x%02x, len=%d\n", tag, tag_len);
            debug_print_hex("  Value", value, tag_len);
        }
        
        // Parse based on tag
        if (tag == 0x01 && tag_len <= 32) {  // SSID
            wifi_config.ssid_len = tag_len;
            memcpy(wifi_config.ssid, value, tag_len);
            wifi_config.ssid[tag_len] = '\0';
            printf("  ✓ SSID: %s (len=%d)\n", wifi_config.ssid, tag_len);
        } else if (tag == 0x02 && tag_len <= 63) {  // Password
            wifi_config.password_len = tag_len;
            memcpy(wifi_config.password, value, tag_len);
            wifi_config.password[tag_len] = '\0';
            printf("  ✓ Password: %s (len=%d)\n", wifi_config.password, tag_len);
        } else if (tag == 0x03 && tag_len == 1) {  // Security type
            wifi_config.security_type = value[0];
            printf("  ✓ Security type: 0x%02x\n", wifi_config.security_type);
        }
        
        pos += 2 + tag_len;
    }
}

// Execute WiFi configuration script
int apply_wifi_config() {
    char cmd[1024];
    FILE *fp;
    char result[256];
    int ret;
    
    printf("\nApplying WiFi configuration...\n");
    printf("  SSID: %s\n", wifi_config.ssid);
    printf("  Security: 0x%02x\n", wifi_config.security_type);
    
    // Build command to call helper script
    snprintf(cmd, sizeof(cmd), 
             "/usr/sbin/xboxwireless-config.sh '%s' '%s' %d 2>&1",
             wifi_config.ssid, 
             wifi_config.password,
             wifi_config.security_type);
    
    if (debug_mode) {
        printf("[DEBUG] Executing: %s\n", cmd);
    }
    
    fp = popen(cmd, "r");
    if (fp == NULL) {
        perror("popen");
        return -1;
    }
    
    // Read output
    while (fgets(result, sizeof(result), fp) != NULL) {
        printf("  [config] %s", result);
        
        if (strncmp(result, "STATUS:CONNECTED:", 17) == 0) {
            current_state = STATE_CONNECTED;
        } else if (strncmp(result, "STATUS:FAILED:", 14) == 0) {
            current_state = STATE_FAILED;
        }
    }
    
    ret = pclose(fp);
    
    if (WIFEXITED(ret)) {
        return WEXITSTATUS(ret);
    }
    
    return -1;
}

// Handle CONNECT_TO_SSID_REQUEST
void handle_connect_to_ssid_request(const uint8_t *payload, size_t len, uint16_t nonce) {
    printf("\n=== CONNECT TO SSID REQUEST ===\n");
    printf("Received CONNECT_TO_SSID_REQUEST from Xbox\n");
    
    // Parse the connection request
    parse_connect_request(payload, len);
    
    // Send immediate acknowledgment
    uint8_t response[34];
    memset(response, 0, sizeof(response));
    send_packet(PACKET_TYPE_CONNECT_TO_SSID_RESPONSE, nonce, response, 34);
    
    // Apply configuration
    current_state = STATE_CONNECTING;
    
    if (apply_wifi_config() == 0) {
        printf("✓ WiFi configured and connected successfully!\n");
    } else {
        printf("✗ WiFi configuration failed\n");
        current_state = STATE_FAILED;
    }
}

// Process received packet
void process_packet(const uint8_t *packet, size_t len) {
    if (len < 26) {  // Minimum packet size
        return;
    }
    
    // Check protocol
    uint16_t proto = (packet[12] << 8) | packet[13];
    if (proto != XBOX_PROTOCOL) {
        return;
    }
    
    // Parse header
    uint8_t *src_mac = (uint8_t *)packet + 6;
    const char *signature = (const char *)packet + 14;
    uint8_t version1 = packet[18];
    uint8_t version2 = packet[19];
    uint8_t body_size = packet[20];
    uint8_t msg_type = packet[21];
    uint16_t nonce = (packet[22] << 8) | packet[23];
    uint16_t checksum = (packet[24] << 8) | packet[25];
    
    // Verify signature
    if (memcmp(signature, HEADER_SIGNATURE, 4) != 0) {
        return;
    }
    
    // Verify version
    if (version1 != HEADER_VERSION_1 || version2 != HEADER_VERSION_2) {
        printf("Warning: Unexpected protocol version %02x:%02x\n", version1, version2);
    }
    
    const uint8_t *payload = packet + 26;
    size_t payload_len = (body_size * 4) - 12;
    
    printf("\n>>> RECEIVED PACKET <<<\n");
    printf("From: %02x:%02x:%02x:%02x:%02x:%02x\n",
           src_mac[0], src_mac[1], src_mac[2], 
           src_mac[3], src_mac[4], src_mac[5]);
    printf("Type: 0x%02x, Nonce: 0x%04x, Body size: %d DWORDs\n",
           msg_type, nonce, body_size);
    printf("Checksum: 0x%04x, Payload: %zu bytes\n", checksum, payload_len);
    
    if (debug_mode) {
        debug_print_hex("Complete Packet", packet, len);
        if (payload_len > 0) {
            debug_print_hex("Payload", payload, payload_len);
        }
    }
    
    // Save Xbox MAC on first contact
    if (current_state == STATE_INIT) {
        memcpy(xbox_mac, src_mac, 6);
        printf("✓ Xbox MAC address saved: %02x:%02x:%02x:%02x:%02x:%02x\n",
               xbox_mac[0], xbox_mac[1], xbox_mac[2],
               xbox_mac[3], xbox_mac[4], xbox_mac[5]);
    }
    
    // Handle packet type
    switch (msg_type) {
        case PACKET_TYPE_HANDSHAKE_REQUEST:
            handle_handshake_request(payload, payload_len, nonce);
            break;
        case PACKET_TYPE_BEACON_REQUEST:
            handle_beacon_request(nonce);
            break;
        case PACKET_TYPE_ADAPTER_INFO_REQUEST:
            handle_adapter_info_request(nonce);
            break;
        case PACKET_TYPE_NETWORKS_LIST_REQUEST:
            handle_networks_list_request(nonce);
            break;
        case PACKET_TYPE_CONNECT_TO_SSID_REQUEST:
            handle_connect_to_ssid_request(payload, payload_len, nonce);
            break;
        default:
            printf("Unknown message type: 0x%02x\n", msg_type);
    }
}

// Initialize raw socket
int init_socket(const char *iface) {
    struct ifreq ifr;
    struct sockaddr_ll addr;
    
    strncpy(interface_name, iface, IFNAMSIZ);
    
    printf("\nInitializing network interface: %s\n", iface);
    
    // Create raw socket
    sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd < 0) {
        perror("socket");
        fprintf(stderr, "Note: Raw sockets require root/CAP_NET_RAW capability\n");
        return -1;
    }
    
    // Get interface index
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ);
    if (ioctl(sockfd, SIOCGIFINDEX, &ifr) < 0) {
        perror("ioctl SIOCGIFINDEX");
        close(sockfd);
        return -1;
    }
    
    // Get local MAC address
    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl SIOCGIFHWADDR");
        close(sockfd);
        return -1;
    }
    memcpy(local_mac, ifr.ifr_hwaddr.sa_data, 6);
    
    printf("✓ Local MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           local_mac[0], local_mac[1], local_mac[2],
           local_mac[3], local_mac[4], local_mac[5]);
    
    // Bind to interface
    memset(&addr, 0, sizeof(addr));
    addr.sll_family = AF_PACKET;
    addr.sll_ifindex = ifr.ifr_ifindex;
    addr.sll_protocol = htons(ETH_P_ALL);
    
    if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(sockfd);
        return -1;
    }
    
    printf("✓ Listening on interface %s for protocol 0x%04x (MS NLB)\n", 
           iface, XBOX_PROTOCOL);
    return 0;
}

// Main loop
void main_loop() {
    uint8_t buffer[BUFFER_SIZE];
    
    printf("\n========================================\n");
    printf("  Xbox Wireless Adapter Ready\n");
    printf("========================================\n");
    printf("State: INIT - Waiting for Xbox...\n\n");
    
    while (running) {
        ssize_t len = recvfrom(sockfd, buffer, sizeof(buffer), 0, NULL, NULL);
        
        if (len < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("recvfrom");
            break;
        }
        
        process_packet(buffer, len);
    }
}

int main(int argc, char *argv[]) {
    printf("========================================\n");
    printf("  Xbox Wireless Adapter Emulator\n");
    printf("  Protocol: MS NLB (0x886f)\n");
    printf("========================================\n\n");
    
    if (argc < 2 || argc > 3) {
        fprintf(stderr, "Usage: %s <interface> [--no-debug]\n", argv[0]);
        fprintf(stderr, "Example: %s eth0\n", argv[0]);
        fprintf(stderr, "Example: %s eth0 --no-debug\n", argv[0]);
        return 1;
    }
    
    // Check for debug flag
    if (argc == 3 && strcmp(argv[2], "--no-debug") == 0) {
        debug_mode = 0;
        printf("Debug mode: OFF\n");
    } else {
        debug_mode = 1;
        printf("Debug mode: ON (use --no-debug to disable)\n");
    }
    
    // Setup signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // Load secrets
    if (load_secrets() < 0) {
        fprintf(stderr, "\nFailed to load secrets. Exiting.\n");
        fprintf(stderr, "Run: python3 extract_secrets.py xonlinedash.xbe\n");
        return 1;
    }
    
    // Initialize
    memset(&wifi_config, 0, sizeof(wifi_config));
    
    if (init_socket(argv[1]) < 0) {
        return 1;
    }
    
    main_loop();
    
    // Cleanup
    if (sockfd >= 0) {
        close(sockfd);
    }
    
    printf("\n========================================\n");
    printf("  Shutdown complete\n");
    printf("========================================\n");
    return 0;
}

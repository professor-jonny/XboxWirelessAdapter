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

// Protocol constants
#define XBOX_PROTOCOL 0x886f  // MS NLB heartbeat (not 0x8863!)
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

// Global state
static int sockfd = -1;
static connection_state_t current_state = STATE_INIT;
static wifi_config_t wifi_config;
static uint8_t xbox_mac[6];
static uint8_t local_mac[6];
static char interface_name[IFNAMSIZ];
static volatile sig_atomic_t running = 1;

// Signal handler for clean shutdown
void signal_handler(int signum) {
    printf("\nReceived signal %d, shutting down...\n", signum);
    running = 0;
}

// Calculate checksum for packet body
uint16_t calculate_checksum(const uint8_t *data, size_t len) {
    uint32_t checksum = 0;
    
    for (size_t i = 0; i < len - 1; i += 2) {
        checksum += (data[i] << 8) + data[i + 1];
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
    
    // Pad payload to make frame at least 64 bytes total
    size_t min_payload = 34;  // Minimum payload for 64-byte frame
    size_t actual_payload_len = payload_len < min_payload ? min_payload : payload_len;
    
    // Calculate body size in DWORDs
    uint8_t body_size = ((actual_payload_len / 4) + 3);
    
    // Build Ethernet header
    memcpy(packet + pos, xbox_mac, 6); pos += 6;  // Destination MAC
    memcpy(packet + pos, local_mac, 6); pos += 6;  // Source MAC
    packet[pos++] = (XBOX_PROTOCOL >> 8) & 0xFF;   // Protocol
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
    
    // Add payload
    if (payload_len > 0) {
        memcpy(body + body_pos, payload, payload_len);
        body_pos += payload_len;
    }
    
    // Pad to min size
    while (body_pos < 12 + actual_payload_len) {
        body[body_pos++] = 0;
    }
    
    // Calculate checksum
    uint16_t checksum = calculate_checksum(body, body_pos);
    body[10] = (checksum >> 8) & 0xFF;
    body[11] = checksum & 0xFF;
    
    // Copy body to packet
    memcpy(packet + pos, body, body_pos);
    pos += body_pos;
    
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
    
    printf("Sent packet type 0x%02x, %zd bytes\n", type, sent);
    return 0;
}

// Handle HANDSHAKE_REQUEST
void handle_handshake_request(const uint8_t *payload, size_t len, uint16_t nonce) {
    printf("Received HANDSHAKE_REQUEST from Xbox\n");
    
    // For now, send a simplified response without HMAC
    // In production, you'd need to implement HMAC authentication
    uint8_t response[256];
    memset(response, 0, sizeof(response));
    
    // Simple response structure (simplified - full implementation needs HMAC)
    const char *adapter_name = "OpenWrt Xbox Wireless";
    const char *firmware = "v1.0";
    
    strncpy((char*)response + 104, adapter_name, 32);
    strncpy((char*)response + 136, firmware, 32);
    
    current_state = STATE_HANDSHAKE_DONE;
    send_packet(PACKET_TYPE_HANDSHAKE_RESPONSE, nonce, response, 256);
}

// Handle BEACON_REQUEST
void handle_beacon_request(uint16_t nonce) {
    printf("Received BEACON_REQUEST from Xbox\n");
    
    uint8_t response[4] = {0x02, 0x80, 0x00, 0x00};
    send_packet(PACKET_TYPE_BEACON_RESPONSE, nonce, response, 4);
}

// Handle ADAPTER_INFO_REQUEST  
void handle_adapter_info_request(uint16_t nonce) {
    printf("Received ADAPTER_INFO_REQUEST from Xbox\n");
    
    uint8_t response[64];
    memset(response, 0, sizeof(response));
    
    response[0] = 0x00;  // Status OK
    response[1] = 0x09;  // Some status byte
    response[wifi_config.ssid_len] = wifi_config.ssid_len;
    
    if (current_state == STATE_CONNECTED) {
        memcpy(response + 3, wifi_config.ssid, wifi_config.ssid_len);
    }
    
    send_packet(PACKET_TYPE_ADAPTER_INFO_RESPONSE, nonce, response, 64);
}

// Handle NETWORKS_LIST_REQUEST
void handle_networks_list_request(uint16_t nonce) {
    printf("Received NETWORKS_LIST_REQUEST from Xbox\n");
    
    // For a real implementation, you'd scan for networks here
    // For now, return empty list or mock data
    uint8_t response[512];
    memset(response, 0, sizeof(response));
    
    // You could add real network scanning here
    send_packet(PACKET_TYPE_NETWORKS_LIST_RESPONSE, nonce, response, 512);
}

// Parse TLV data from connect request
void parse_connect_request(const uint8_t *payload, size_t len) {
    size_t pos = 0;
    
    memset(&wifi_config, 0, sizeof(wifi_config));
    
    while (pos + 2 <= len) {
        uint8_t tag = payload[pos];
        uint8_t tag_len = payload[pos + 1];
        
        if (pos + 2 + tag_len > len) {
            break;
        }
        
        const uint8_t *value = payload + pos + 2;
        
        // Parse based on tag
        // Note: exact TLV tags need to be determined from captures
        if (tag == 0x01 && tag_len <= 32) {  // SSID
            wifi_config.ssid_len = tag_len;
            memcpy(wifi_config.ssid, value, tag_len);
            wifi_config.ssid[tag_len] = '\0';
            printf("SSID: %s (len=%d)\n", wifi_config.ssid, tag_len);
        } else if (tag == 0x02 && tag_len <= 63) {  // Password
            wifi_config.password_len = tag_len;
            memcpy(wifi_config.password, value, tag_len);
            wifi_config.password[tag_len] = '\0';
            printf("Password: %s (len=%d)\n", wifi_config.password, tag_len);
        } else if (tag == 0x03 && tag_len == 1) {  // Security type
            wifi_config.security_type = value[0];
            printf("Security type: 0x%02x\n", wifi_config.security_type);
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
    
    // Build command to call helper script
    snprintf(cmd, sizeof(cmd), 
             "/usr/sbin/xboxwireless-config.sh '%s' '%s' %d 2>&1",
             wifi_config.ssid, 
             wifi_config.password,
             wifi_config.security_type);
    
    printf("Executing: %s\n", cmd);
    
    fp = popen(cmd, "r");
    if (fp == NULL) {
        perror("popen");
        return -1;
    }
    
    // Read output
    while (fgets(result, sizeof(result), fp) != NULL) {
        printf("Config: %s", result);
        
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
    printf("Received CONNECT_TO_SSID_REQUEST from Xbox\n");
    
    // Parse the connection request
    parse_connect_request(payload, len);
    
    // Send immediate acknowledgment
    uint8_t response[34];
    memset(response, 0, sizeof(response));
    send_packet(PACKET_TYPE_CONNECT_TO_SSID_RESPONSE, nonce, response, 34);
    
    // Apply configuration
    current_state = STATE_CONNECTING;
    printf("Configuring WiFi...\n");
    
    if (apply_wifi_config() == 0) {
        printf("WiFi configured and connected successfully!\n");
    } else {
        printf("WiFi configuration failed\n");
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
    
    printf("Received packet type 0x%02x from %02x:%02x:%02x:%02x:%02x:%02x, nonce=0x%04x\n",
           msg_type, src_mac[0], src_mac[1], src_mac[2], 
           src_mac[3], src_mac[4], src_mac[5], nonce);
    
    // Save Xbox MAC on first contact
    if (current_state == STATE_INIT) {
        memcpy(xbox_mac, src_mac, 6);
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
    
    // Create raw socket
    sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd < 0) {
        perror("socket");
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
    
    printf("Local MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
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
    
    printf("Listening on interface %s for protocol 0x%04x\n", iface, XBOX_PROTOCOL);
    return 0;
}

// Main loop
void main_loop() {
    uint8_t buffer[BUFFER_SIZE];
    
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
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <interface>\n", argv[0]);
        fprintf(stderr, "Example: %s eth0\n", argv[0]);
        return 1;
    }
    
    // Setup signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // Initialize
    memset(&wifi_config, 0, sizeof(wifi_config));
    
    if (init_socket(argv[1]) < 0) {
        return 1;
    }
    
    printf("Xbox Wireless Adapter Emulator started\n");
    printf("Protocol: MS NLB (0x886f)\n");
    printf("Waiting for Xbox connection...\n");
    
    main_loop();
    
    // Cleanup
    if (sockfd >= 0) {
        close(sockfd);
    }
    
    printf("Shutdown complete\n");
    return 0;
}

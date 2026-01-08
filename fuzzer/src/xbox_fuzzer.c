// xbox_fuzzer.c - Standalone Xbox Wireless Protocol Fuzzer
// Compile: gcc -o xbox_fuzzer xbox_fuzzer.c -lssl -lcrypto
// Usage: sudo ./xbox_fuzzer eth0 --fuzz-security-types

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <signal.h>
#include <openssl/hmac.h>

#define XBOX_PROTOCOL 0x886f
#define BUFFER_SIZE 2048

// Load your secrets (same as main implementation)
static uint8_t hmac_key[16];
static uint8_t hmac_salt[0x75];
static uint8_t auth_copyright[0x54];

static int sockfd = -1;
static uint8_t xbox_mac[6];
static uint8_t local_mac[6];
static char interface_name[IFNAMSIZ];
static volatile sig_atomic_t running = 1;
static int handshake_done = 0;

void signal_handler(int signum) {
    running = 0;
}

int load_secrets() {
    FILE *fp;
    size_t bytes_read;
    
    fp = fopen("secrets/hmac_key.bin", "rb");
    if (!fp) return -1;
    bytes_read = fread(hmac_key, 1, 16, fp);
    fclose(fp);
    if (bytes_read != 16) return -1;
    
    fp = fopen("secrets/hmac_salt.bin", "rb");
    if (!fp) return -1;
    bytes_read = fread(hmac_salt, 1, 0x75, fp);
    fclose(fp);
    if (bytes_read != 0x75) return -1;
    
    fp = fopen("secrets/auth_copyright.bin", "rb");
    if (!fp) return -1;
    bytes_read = fread(auth_copyright, 1, 0x54, fp);
    fclose(fp);
    if (bytes_read != 0x54) return -1;
    
    return 0;
}

void make_signature_hmac(const uint8_t *message, size_t message_len,
                        const uint8_t *local_mac, uint8_t *signature_out) {
    uint8_t data[BUFFER_SIZE];
    memcpy(data, message, message_len);
    memcpy(data + message_len, local_mac, 6);
    memcpy(data + message_len + 6, hmac_salt, 0x75);
    
    unsigned int sig_len;
    HMAC(EVP_sha1(), hmac_key, 16, data, message_len + 6 + 0x75, 
         signature_out, &sig_len);
}

uint16_t calculate_checksum(const uint8_t *data, size_t len) {
    uint32_t checksum = 0;
    for (size_t i = 0; i < len - 1; i += 2) {
        checksum += (data[i] << 8) + data[i + 1];
        if (checksum > 0xffff) {
            checksum = (checksum & 0xffff) + 1;
        }
    }
    if (len % 2 != 0) {
        checksum += (data[len - 1] << 8);
        if (checksum > 0xffff) {
            checksum = (checksum & 0xffff) + 1;
        }
    }
    return (uint16_t)(checksum ^ 0xffff);
}

int send_packet(uint8_t type, uint16_t nonce, const uint8_t *payload, size_t payload_len) {
    uint8_t packet[BUFFER_SIZE];
    struct sockaddr_ll addr;
    size_t pos = 0;
    
    uint8_t body_size = ((payload_len / 4) + 3);
    size_t padded_payload_len = (payload_len < 34) ? 34 : payload_len;
    
    // Ethernet header
    memcpy(packet + pos, xbox_mac, 6); pos += 6;
    memcpy(packet + pos, local_mac, 6); pos += 6;
    packet[pos++] = (XBOX_PROTOCOL >> 8) & 0xFF;
    packet[pos++] = XBOX_PROTOCOL & 0xFF;
    
    // Build body
    uint8_t body[BUFFER_SIZE];
    size_t body_pos = 0;
    
    memcpy(body + body_pos, "XBOX", 4); body_pos += 4;
    body[body_pos++] = 0x01;
    body[body_pos++] = 0x01;
    body[body_pos++] = body_size;
    body[body_pos++] = type;
    body[body_pos++] = (nonce >> 8) & 0xFF;
    body[body_pos++] = nonce & 0xFF;
    body[body_pos++] = 0;  // Checksum placeholder
    body[body_pos++] = 0;
    
    if (payload_len > 0) {
        memcpy(body + body_pos, payload, payload_len);
        body_pos += payload_len;
    }
    
    while (body_pos < 12 + padded_payload_len) {
        body[body_pos++] = 0;
    }
    
    uint16_t checksum = calculate_checksum(body, body_pos);
    body[10] = (checksum >> 8) & 0xFF;
    body[11] = checksum & 0xFF;
    
    memcpy(packet + pos, body, body_pos);
    pos += body_pos;
    
    memset(&addr, 0, sizeof(addr));
    addr.sll_ifindex = if_nametoindex(interface_name);
    addr.sll_halen = ETH_ALEN;
    memcpy(addr.sll_addr, xbox_mac, 6);
    
    return sendto(sockfd, packet, pos, 0, (struct sockaddr *)&addr, sizeof(addr));
}

void handle_handshake_request(const uint8_t *payload, size_t len, uint16_t nonce) {
    printf("Received handshake request\n");
    
    uint8_t hmac_signature[20];
    make_signature_hmac(payload, 16, local_mac, hmac_signature);
    
    uint8_t response[256];
    size_t pos = 0;
    
    memcpy(response + pos, hmac_signature, 20);
    pos += 20;
    
    memcpy(response + pos, auth_copyright, 0x54);
    pos += 0x54;
    
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
    
    send_packet(0x02, nonce, response, 256);
    handshake_done = 1;
    printf("✓ Handshake complete!\n");
}

void handle_beacon_request(uint16_t nonce) {
    uint8_t response[4] = {0x02, 0x80, 0x00, 0x00};
    send_packet(0x0a, nonce, response, 4);
}

// FUZZING FUNCTIONS START HERE

void fuzz_security_types() {
    printf("\n=== FUZZING SECURITY TYPES (0x00 - 0xFF) ===\n");
    printf("This will test all 256 possible security type values...\n\n");
    
    for (uint16_t sec = 0x00; sec <= 0xFF; sec++) {
        printf("[%3d/256] Testing security type 0x%02x... ", sec + 1, sec);
        fflush(stdout);
        
        uint8_t payload[100];
        size_t pos = 0;
        
        // SSID TLV
        payload[pos++] = 0x01;
        payload[pos++] = 0x08;
        memcpy(payload + pos, "FuzzTest", 8);
        pos += 8;
        
        // Password TLV
        payload[pos++] = 0x02;
        payload[pos++] = 0x08;
        memcpy(payload + pos, "password", 8);
        pos += 8;
        
        // Security type TLV (FUZZED VALUE)
        payload[pos++] = 0x03;
        payload[pos++] = 0x01;
        payload[pos++] = (uint8_t)sec;
        
        send_packet(0x07, 0x1000 + sec, payload, pos);
        
        // Wait and listen for response
        usleep(200000);  // 200ms
        
        printf("sent\n");
    }
    
    printf("\n✓ Security type fuzzing complete!\n");
}

void fuzz_tlv_tags() {
    printf("\n=== FUZZING UNKNOWN TLV TAGS (0x04 - 0x20) ===\n");
    printf("This will test tags beyond the known 0x01, 0x02, 0x03...\n\n");
    
    for (uint16_t tag = 0x04; tag <= 0x20; tag++) {
        printf("[%2d/29] Testing TLV tag 0x%02x... ", tag - 3, tag);
        fflush(stdout);
        
        uint8_t payload[100];
        size_t pos = 0;
        
        // Normal SSID
        payload[pos++] = 0x01;
        payload[pos++] = 0x04;
        memcpy(payload + pos, "Test", 4);
        pos += 4;
        
        // Normal password
        payload[pos++] = 0x02;
        payload[pos++] = 0x08;
        memcpy(payload + pos, "password", 8);
        pos += 8;
        
        // Normal security
        payload[pos++] = 0x03;
        payload[pos++] = 0x01;
        payload[pos++] = 0x02;
        
        // FUZZED unknown tag
        payload[pos++] = (uint8_t)tag;
        payload[pos++] = 0x04;
        payload[pos++] = 0xDE;
        payload[pos++] = 0xAD;
        payload[pos++] = 0xBE;
        payload[pos++] = 0xEF;
        
        send_packet(0x07, 0x2000 + tag, payload, pos);
        usleep(200000);
        
        printf("sent\n");
    }
    
    printf("\n✓ TLV tag fuzzing complete!\n");
}

void fuzz_ssid_lengths() {
    printf("\n=== FUZZING SSID LENGTHS (0 - 64 bytes) ===\n");
    printf("Testing beyond the normal 32 byte SSID limit...\n\n");
    
    for (uint16_t len = 0; len <= 64; len++) {
        printf("[%2d/65] Testing SSID length %d bytes... ", len + 1, len);
        fflush(stdout);
        
        uint8_t payload[200];
        size_t pos = 0;
        
        // SSID with fuzzed length
        payload[pos++] = 0x01;
        payload[pos++] = (uint8_t)len;
        
        for (size_t i = 0; i < len; i++) {
            payload[pos++] = 'A' + (i % 26);
        }
        
        // Normal password
        payload[pos++] = 0x02;
        payload[pos++] = 0x08;
        memcpy(payload + pos, "password", 8);
        pos += 8;
        
        // Normal security
        payload[pos++] = 0x03;
        payload[pos++] = 0x01;
        payload[pos++] = 0x02;
        
        send_packet(0x07, 0x3000 + len, payload, pos);
        usleep(200000);
        
        printf("sent\n");
    }
    
    printf("\n✓ SSID length fuzzing complete!\n");
}

void fuzz_password_lengths() {
    printf("\n=== FUZZING PASSWORD LENGTHS (0 - 128 bytes) ===\n");
    printf("Testing beyond the normal 63 byte password limit...\n\n");
    
    for (uint16_t len = 0; len <= 128; len++) {
        printf("[%3d/129] Testing password length %d bytes... ", len + 1, len);
        fflush(stdout);
        
        uint8_t payload[256];
        size_t pos = 0;
        
        // Normal SSID
        payload[pos++] = 0x01;
        payload[pos++] = 0x04;
        memcpy(payload + pos, "Test", 4);
        pos += 4;
        
        // Password with fuzzed length
        payload[pos++] = 0x02;
        payload[pos++] = (uint8_t)len;
        
        for (size_t i = 0; i < len; i++) {
            payload[pos++] = '0' + (i % 10);
        }
        
        // Normal security
        payload[pos++] = 0x03;
        payload[pos++] = 0x01;
        payload[pos++] = 0x02;
        
        send_packet(0x07, 0x4000 + len, payload, pos);
        usleep(200000);
        
        printf("sent\n");
    }
    
    printf("\n✓ Password length fuzzing complete!\n");
}

void process_packet(const uint8_t *packet, size_t len) {
    if (len < 26) return;
    
    uint16_t proto = (packet[12] << 8) | packet[13];
    if (proto != XBOX_PROTOCOL) return;
    
    uint8_t *src_mac = (uint8_t *)packet + 6;
    uint8_t msg_type = packet[21];
    uint16_t nonce = (packet[22] << 8) | packet[23];
    const uint8_t *payload = packet + 26;
    
    if (!handshake_done) {
        memcpy(xbox_mac, src_mac, 6);
    }
    
    if (msg_type == 0x01) {  // Handshake request
        handle_handshake_request(payload, 16, nonce);
    } else if (msg_type == 0x09) {  // Beacon request
        handle_beacon_request(nonce);
    }
}

int init_socket(const char *iface) {
    struct ifreq ifr;
    struct sockaddr_ll addr;
    
    strncpy(interface_name, iface, IFNAMSIZ - 1);
    interface_name[IFNAMSIZ - 1] = '\0';
    
    sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd < 0) {
        perror("socket");
        return -1;
    }
    
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';
    
    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl");
        return -1;
    }
    memcpy(local_mac, ifr.ifr_hwaddr.sa_data, 6);
    
    if (ioctl(sockfd, SIOCGIFINDEX, &ifr) < 0) {
        perror("ioctl");
        return -1;
    }
    
    memset(&addr, 0, sizeof(addr));
    addr.sll_family = AF_PACKET;
    addr.sll_ifindex = ifr.ifr_ifindex;
    addr.sll_protocol = htons(ETH_P_ALL);
    
    if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        return -1;
    }
    
    printf("✓ Listening on %s (MAC: %02x:%02x:%02x:%02x:%02x:%02x)\n",
           iface, local_mac[0], local_mac[1], local_mac[2],
           local_mac[3], local_mac[4], local_mac[5]);
    
    return 0;
}

int main(int argc, char *argv[]) {
    printf("========================================\n");
    printf("  Xbox Wireless Protocol Fuzzer\n");
    printf("========================================\n\n");
    
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <interface> <fuzz-mode>\n", argv[0]);
        fprintf(stderr, "Modes:\n");
        fprintf(stderr, "  --fuzz-security-types   Test all security type values\n");
        fprintf(stderr, "  --fuzz-tlv-tags         Test unknown TLV tags\n");
        fprintf(stderr, "  --fuzz-ssid-lengths     Test SSID length limits\n");
        fprintf(stderr, "  --fuzz-password-lengths Test password length limits\n");
        fprintf(stderr, "  --fuzz-all              Run all fuzzing tests\n");
        return 1;
    }
    
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    if (load_secrets() < 0) {
        fprintf(stderr, "Failed to load secrets!\n");
        return 1;
    }
    
    if (init_socket(argv[1]) < 0) {
        return 1;
    }
    
    printf("\nWaiting for Xbox handshake...\n");
    printf("(Go to Xbox Network Settings → Wireless Setup)\n\n");
    
    // Wait for handshake
    uint8_t buffer[BUFFER_SIZE];
    while (running && !handshake_done) {
        ssize_t len = recvfrom(sockfd, buffer, sizeof(buffer), 0, NULL, NULL);
        if (len > 0) {
            process_packet(buffer, len);
        }
    }
    
    if (!handshake_done) {
        printf("Handshake failed!\n");
        return 1;
    }
    
    printf("\n========================================\n");
    printf("  Starting Fuzzing Tests\n");
    printf("========================================\n");
    
    // Run selected fuzz mode
    if (strcmp(argv[2], "--fuzz-security-types") == 0) {
        fuzz_security_types();
    } else if (strcmp(argv[2], "--fuzz-tlv-tags") == 0) {
        fuzz_tlv_tags();
    } else if (strcmp(argv[2], "--fuzz-ssid-lengths") == 0) {
        fuzz_ssid_lengths();
    } else if (strcmp(argv[2], "--fuzz-password-lengths") == 0) {
        fuzz_password_lengths();
    } else if (strcmp(argv[2], "--fuzz-all") == 0) {
        fuzz_security_types();
        sleep(5);
        fuzz_tlv_tags();
        sleep(5);
        fuzz_ssid_lengths();
        sleep(5);
        fuzz_password_lengths();
    } else {
        fprintf(stderr, "Unknown fuzz mode: %s\n", argv[2]);
        return 1;
    }
    
    printf("\n========================================\n");
    printf("  Fuzzing Complete!\n");
    printf("========================================\n");
    printf("\nNow analyze the pcap file for Xbox responses.\n");
    
    close(sockfd);
    return 0;
}

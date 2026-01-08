// smart_xbox_fuzzer.c - Protocol-Aware Xbox Fuzzer
// This fuzzer maintains valid packet structure while testing edge cases
// Compile: gcc -o smart_fuzzer smart_xbox_fuzzer.c -lssl -lcrypto
// Usage: sudo ./smart_fuzzer eth0 --mode <test_mode>

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
#include <time.h>

#define XBOX_PROTOCOL 0x886f
#define BUFFER_SIZE 2048

// Secrets
static uint8_t hmac_key[16];
static uint8_t hmac_salt[0x75];
static uint8_t auth_copyright[0x54];

static int sockfd = -1;
static uint8_t xbox_mac[6];
static uint8_t local_mac[6];
static char interface_name[IFNAMSIZ];
static volatile sig_atomic_t running = 1;
static int handshake_done = 0;
static int response_count = 0;

void signal_handler(int signum) {
    running = 0;
}

int load_secrets() {
    FILE *fp;
    
    fp = fopen("secrets/hmac_key.bin", "rb");
    if (!fp) return -1;
    if (fread(hmac_key, 1, 16, fp) != 16) { fclose(fp); return -1; }
    fclose(fp);
    
    fp = fopen("secrets/hmac_salt.bin", "rb");
    if (!fp) return -1;
    if (fread(hmac_salt, 1, 0x75, fp) != 0x75) { fclose(fp); return -1; }
    fclose(fp);
    
    fp = fopen("secrets/auth_copyright.bin", "rb");
    if (!fp) return -1;
    if (fread(auth_copyright, 1, 0x54, fp) != 0x54) { fclose(fp); return -1; }
    fclose(fp);
    
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

void handle_wifi_config_response(uint16_t nonce) {
    response_count++;
    printf("  📥 Got WiFi config response for nonce 0x%04x!\n", nonce);
}

// ============================================================================
// SMART FUZZING FUNCTIONS - Maintain valid TLV structure
// ============================================================================

void test_valid_configs() {
    printf("\n=== TESTING VALID CONFIGURATIONS ===\n");
    printf("Sending legitimate WiFi configs to establish baseline...\n\n");
    
    const char *test_ssids[] = {"TestNet", "MyWiFi", "Home", "Guest"};
    const char *test_passwords[] = {"password123", "12345678", "securepass"};
    const uint8_t security_types[] = {0x00, 0x01, 0x02, 0x03};
    
    int test_num = 0;
    
    for (int s = 0; s < 4; s++) {
        for (int p = 0; p < 3; p++) {
            for (int sec = 0; sec < 4; sec++) {
                test_num++;
                printf("[%2d] SSID: %-10s | Pass: %-15s | Sec: 0x%02x... ",
                       test_num, test_ssids[s], test_passwords[p], security_types[sec]);
                fflush(stdout);
                
                uint8_t payload[128];
                size_t pos = 0;
                
                // SSID TLV
                payload[pos++] = 0x01;
                payload[pos++] = strlen(test_ssids[s]);
                memcpy(payload + pos, test_ssids[s], strlen(test_ssids[s]));
                pos += strlen(test_ssids[s]);
                
                // Password TLV
                payload[pos++] = 0x02;
                payload[pos++] = strlen(test_passwords[p]);
                memcpy(payload + pos, test_passwords[p], strlen(test_passwords[p]));
                pos += strlen(test_passwords[p]);
                
                // Security TLV
                payload[pos++] = 0x03;
                payload[pos++] = 0x01;
                payload[pos++] = security_types[sec];
                
                send_packet(0x07, 0x5000 + test_num, payload, pos);
                usleep(100000);  // 100ms
                
                printf("sent\n");
            }
        }
    }
    
    printf("\n✓ Valid config testing complete!\n");
}

void test_boundary_ssid_lengths() {
    printf("\n=== TESTING BOUNDARY SSID LENGTHS ===\n");
    printf("Testing SSID lengths at WiFi spec boundaries (0, 1, 31, 32, 33)...\n\n");
    
    int lengths[] = {0, 1, 2, 30, 31, 32};
    
    for (int i = 0; i < 6; i++) {
        int len = lengths[i];
        printf("[%d/6] Testing SSID length %d bytes... ", i + 1, len);
        fflush(stdout);
        
        uint8_t payload[128];
        size_t pos = 0;
        
        // SSID TLV with specific length
        payload[pos++] = 0x01;
        payload[pos++] = len;
        for (int j = 0; j < len; j++) {
            payload[pos++] = 'A' + (j % 26);
        }
        
        // Normal password
        payload[pos++] = 0x02;
        payload[pos++] = 8;
        memcpy(payload + pos, "testpass", 8);
        pos += 8;
        
        // Normal security
        payload[pos++] = 0x03;
        payload[pos++] = 0x01;
        payload[pos++] = 0x02;
        
        send_packet(0x07, 0x6000 + len, payload, pos);
        usleep(150000);  // 150ms
        
        printf("sent\n");
    }
    
    printf("\n✓ Boundary SSID testing complete!\n");
}

void test_special_characters() {
    printf("\n=== TESTING SPECIAL CHARACTERS IN SSID ===\n");
    printf("Testing non-ASCII, control chars, and special characters...\n\n");
    
    const char *special_ssids[] = {
        "\x00\x00\x00\x00",          // Null bytes
        "\xFF\xFF\xFF\xFF",          // High bytes
        "Test\nNetwork",             // Newline
        "Test\tNetwork",             // Tab
        "Test Network",              // Space
        "Test-Network_123",          // Valid special chars
        "网络测试",                   // Unicode (UTF-8)
        "!@#$%^&*()",                // Symbols
    };
    
    for (int i = 0; i < 8; i++) {
        printf("[%d/8] Testing special SSID... ", i + 1);
        fflush(stdout);
        
        uint8_t payload[128];
        size_t pos = 0;
        
        size_t ssid_len = strlen(special_ssids[i]);
        if (ssid_len == 0 || ssid_len > 32) ssid_len = 4;
        
        // SSID TLV
        payload[pos++] = 0x01;
        payload[pos++] = ssid_len;
        memcpy(payload + pos, special_ssids[i], ssid_len);
        pos += ssid_len;
        
        // Password
        payload[pos++] = 0x02;
        payload[pos++] = 8;
        memcpy(payload + pos, "testpass", 8);
        pos += 8;
        
        // Security
        payload[pos++] = 0x03;
        payload[pos++] = 0x01;
        payload[pos++] = 0x02;
        
        send_packet(0x07, 0x7000 + i, payload, pos);
        usleep(150000);
        
        printf("sent\n");
    }
    
    printf("\n✓ Special character testing complete!\n");
}

void test_tlv_ordering() {
    printf("\n=== TESTING TLV FIELD ORDERING ===\n");
    printf("Testing different orders and duplicate fields...\n\n");
    
    // Test 1: Reverse order
    printf("[1/5] Reverse order (Sec, Pass, SSID)... ");
    {
        uint8_t payload[128];
        size_t pos = 0;
        
        payload[pos++] = 0x03; payload[pos++] = 0x01; payload[pos++] = 0x02;
        payload[pos++] = 0x02; payload[pos++] = 8; memcpy(payload + pos, "password", 8); pos += 8;
        payload[pos++] = 0x01; payload[pos++] = 4; memcpy(payload + pos, "Test", 4); pos += 4;
        
        send_packet(0x07, 0x8001, payload, pos);
        usleep(150000);
        printf("sent\n");
    }
    
    // Test 2: Duplicate SSID
    printf("[2/5] Duplicate SSID fields... ");
    {
        uint8_t payload[128];
        size_t pos = 0;
        
        payload[pos++] = 0x01; payload[pos++] = 4; memcpy(payload + pos, "Test", 4); pos += 4;
        payload[pos++] = 0x01; payload[pos++] = 5; memcpy(payload + pos, "Test2", 5); pos += 5;
        payload[pos++] = 0x02; payload[pos++] = 8; memcpy(payload + pos, "password", 8); pos += 8;
        payload[pos++] = 0x03; payload[pos++] = 0x01; payload[pos++] = 0x02;
        
        send_packet(0x07, 0x8002, payload, pos);
        usleep(150000);
        printf("sent\n");
    }
    
    // Test 3: Missing password
    printf("[3/5] Missing password field... ");
    {
        uint8_t payload[128];
        size_t pos = 0;
        
        payload[pos++] = 0x01; payload[pos++] = 4; memcpy(payload + pos, "Test", 4); pos += 4;
        payload[pos++] = 0x03; payload[pos++] = 0x01; payload[pos++] = 0x02;
        
        send_packet(0x07, 0x8003, payload, pos);
        usleep(150000);
        printf("sent\n");
    }
    
    // Test 4: Missing security
    printf("[4/5] Missing security field... ");
    {
        uint8_t payload[128];
        size_t pos = 0;
        
        payload[pos++] = 0x01; payload[pos++] = 4; memcpy(payload + pos, "Test", 4); pos += 4;
        payload[pos++] = 0x02; payload[pos++] = 8; memcpy(payload + pos, "password", 8); pos += 8;
        
        send_packet(0x07, 0x8004, payload, pos);
        usleep(150000);
        printf("sent\n");
    }
    
    // Test 5: Empty payload
    printf("[5/5] Empty payload... ");
    {
        send_packet(0x07, 0x8005, NULL, 0);
        usleep(150000);
        printf("sent\n");
    }
    
    printf("\n✓ TLV ordering testing complete!\n");
}

void test_rapid_fire() {
    printf("\n=== TESTING RAPID REQUEST SPAM ===\n");
    printf("Sending 50 requests rapidly to test rate limiting...\n\n");
    
    for (int i = 0; i < 50; i++) {
        uint8_t payload[128];
        size_t pos = 0;
        
        payload[pos++] = 0x01; payload[pos++] = 4; memcpy(payload + pos, "Test", 4); pos += 4;
        payload[pos++] = 0x02; payload[pos++] = 8; memcpy(payload + pos, "password", 8); pos += 8;
        payload[pos++] = 0x03; payload[pos++] = 0x01; payload[pos++] = 0x02;
        
        send_packet(0x07, 0x9000 + i, payload, pos);
        usleep(10000);  // 10ms between packets
        
        if ((i + 1) % 10 == 0) {
            printf("  Sent %d/50...\n", i + 1);
        }
    }
    
    printf("\n✓ Rapid-fire testing complete!\n");
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
    
    if (msg_type == 0x01) {
        handle_handshake_request(payload, 16, nonce);
    } else if (msg_type == 0x09) {
        handle_beacon_request(nonce);
    } else if (msg_type == 0x08) {
        handle_wifi_config_response(nonce);
    }
}

int init_socket(const char *iface) {
    struct ifreq ifr;
    struct sockaddr_ll addr;
    
    strncpy(interface_name, iface, IFNAMSIZ - 1);
    
    sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd < 0) {
        perror("socket");
        return -1;
    }
    
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    
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
    printf("  Smart Xbox Protocol Fuzzer\n");
    printf("  (Valid TLV Structure)\n");
    printf("========================================\n\n");
    
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <interface> <mode>\n", argv[0]);
        fprintf(stderr, "Modes:\n");
        fprintf(stderr, "  --valid-configs        Test legitimate configurations\n");
        fprintf(stderr, "  --boundary-lengths     Test SSID/password boundary values\n");
        fprintf(stderr, "  --special-chars        Test special characters\n");
        fprintf(stderr, "  --tlv-ordering         Test TLV field ordering\n");
        fprintf(stderr, "  --rapid-fire           Test rate limiting\n");
        fprintf(stderr, "  --all                  Run all tests\n");
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
    printf("  Starting Smart Fuzzing Tests\n");
    printf("========================================\n");
    
    // Background listener for responses
    fd_set readfds;
    struct timeval tv;
    
    // Run selected test
    if (strcmp(argv[2], "--valid-configs") == 0) {
        test_valid_configs();
    } else if (strcmp(argv[2], "--boundary-lengths") == 0) {
        test_boundary_ssid_lengths();
    } else if (strcmp(argv[2], "--special-chars") == 0) {
        test_special_characters();
    } else if (strcmp(argv[2], "--tlv-ordering") == 0) {
        test_tlv_ordering();
    } else if (strcmp(argv[2], "--rapid-fire") == 0) {
        test_rapid_fire();
    } else if (strcmp(argv[2], "--all") == 0) {
        test_valid_configs();
        sleep(2);
        test_boundary_ssid_lengths();
        sleep(2);
        test_special_characters();
        sleep(2);
        test_tlv_ordering();
        sleep(2);
        test_rapid_fire();
    } else {
        fprintf(stderr, "Unknown mode: %s\n", argv[2]);
        return 1;
    }
    
    // Listen for responses for 5 seconds
    printf("\nListening for responses (5 seconds)...\n");
    time_t start_time = time(NULL);
    
    while (time(NULL) - start_time < 5) {
        FD_ZERO(&readfds);
        FD_SET(sockfd, &readfds);
        tv.tv_sec = 0;
        tv.tv_usec = 100000;  // 100ms
        
        int ret = select(sockfd + 1, &readfds, NULL, NULL, &tv);
        if (ret > 0) {
            ssize_t len = recvfrom(sockfd, buffer, sizeof(buffer), 0, NULL, NULL);
            if (len > 0) {
                process_packet(buffer, len);
            }
        }
    }
    
    printf("\n========================================\n");
    printf("  Fuzzing Complete!\n");
    printf("========================================\n");
    printf("\nResponses received: %d\n", response_count);
    
    if (response_count == 0) {
        printf("\n⚠️  Xbox did not respond to any test cases.\n");
        printf("This suggests strict input validation.\n");
    } else {
        printf("\n✓ Some test cases triggered responses!\n");
        printf("Analyze the pcap for details.\n");
    }
    
    close(sockfd);
    return 0;
}

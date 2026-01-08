// xbox_fuzzer_complete.c - Stateful Xbox Protocol Fuzzer (COMPLETE & FIXED)
// Compile: gcc -o xbox_fuzzer_complete xbox_fuzzer_complete.c -lssl -lcrypto -O2
// Usage: sudo ./xbox_fuzzer_complete <interface>
// Features: Saves Xbox connection attempts, dynamically generates network lists, debug output

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
#include <openssl/evp.h>
#include <time.h>

#define XBOX_PROTOCOL 0x886f
#define BUFFER_SIZE 8192
#define MAX_NETWORKS 16

// Packet types
#define PKT_HANDSHAKE_REQUEST           0x01
#define PKT_HANDSHAKE_RESPONSE          0x02
#define PKT_NETWORKS_LIST_REQUEST       0x03
#define PKT_NETWORKS_LIST_RESPONSE      0x04
#define PKT_ADAPTER_INFO_REQUEST        0x05
#define PKT_ADAPTER_INFO_RESPONSE       0x06
#define PKT_CONNECT_TO_SSID_REQUEST     0x07
#define PKT_CONNECT_TO_SSID_RESPONSE    0x08
#define PKT_BEACON_REQUEST              0x09
#define PKT_BEACON_RESPONSE             0x0a
#define SLOT_SIZE 64
#define NET_COUNT 16

typedef enum { STATE_DISCONNECTED, STATE_HANDSHAKE_DONE, STATE_LINKED } ConnectionState;

typedef struct {
    char ssid[33];
    char password[64];
    uint8_t sec_type;
    int is_saved;
    time_t last_connect_attempt;
} SavedProfile;

// Global state
static uint8_t hmac_key[16];
static uint8_t hmac_salt[117];
static uint8_t auth_copyright[84];
static int sockfd = -1;
static int if_index = 0;
static uint8_t xbox_mac[6];
static uint8_t local_mac[6];
static char interface_name[IFNAMSIZ];
static volatile sig_atomic_t running = 1;
static ConnectionState conn_state = STATE_DISCONNECTED;
static int beacon_count = 0;
static SavedProfile xbox_saved_profile = { .is_saved = 0 };
static int fuzz_mode = 0;  // Set to 1 to enable
static int listen_mode = 0;  // 1=passive capture only, no responses
static FILE *capture_log = NULL;
static int packet_count = 0;

uint8_t payload[1 + NET_COUNT * SLOT_SIZE];

void build_list_all_same(void)
{
    // payload[0] = count
    payload[0] = NET_COUNT;

    // known-good 64-byte block captured from Python
    uint8_t good_slot[SLOT_SIZE] = {
        /* paste the exact 64 bytes from your Python packet’s first SSID here */
    };

    for (int i = 0; i < NET_COUNT; i++) {
        memcpy(&payload[1 + i * SLOT_SIZE], good_slot, SLOT_SIZE);
    }
}

void signal_handler(int signum) { running = 0; }

int load_secrets() {
    FILE *fp;

    fp = fopen("secrets/hmac_key.bin", "rb");
    if (!fp || fread(hmac_key, 1, 16, fp) != 16) {
        if (fp) fclose(fp);
        fprintf(stderr, "Error: missing secrets/hmac_key.bin (16 bytes)\n");
        return -1;
    }
    fclose(fp);

    fp = fopen("secrets/hmac_salt.bin", "rb");
    if (!fp || fread(hmac_salt, 1, 117, fp) != 117) {
        if (fp) fclose(fp);
        fprintf(stderr, "Error: missing secrets/hmac_salt.bin (117 bytes)\n");
        return -1;
    }
    fclose(fp);

    fp = fopen("secrets/auth_copyright.bin", "rb");
    if (!fp || fread(auth_copyright, 1, 84, fp) != 84) {
        if (fp) fclose(fp);
        fprintf(stderr, "Error: missing secrets/auth_copyright.bin (84 bytes)\n");
        return -1;
    }
    fclose(fp);

    printf("✓ Secrets loaded (key:16 salt:117 copyright:84)\n");
    return 0;
}

typedef struct {
    int connected;
    char ip[16];
    int signal;
} OWRTStatus;

OWRTStatus get_openwrt_status() {
    OWRTStatus status = {0, "0.0.0.0", 0};
    FILE *fp = popen("/usr/bin/xboxwireless-config.sh --status 2>/dev/null", "r");
    if (!fp) return status;

    char line[128];
    if (fgets(line, sizeof(line), fp) != NULL) {
        // Parse: "STATUS:CONNECTED:192.168.1.50:-65"
        if (strncmp(line, "STATUS:CONNECTED:", 17) == 0) {
            status.connected = 1;
            sscanf(line, "STATUS:CONNECTED:%15[^:]:%d", status.ip, &status.signal);
        }
    }
    pclose(fp);
    return status;
}

void make_signature_hmac(const uint8_t *message16, const uint8_t *mac6, uint8_t *sig_out) {
    uint8_t data[139];
    memcpy(data, message16, 16);
    memcpy(data + 16, mac6, 6);
    memcpy(data + 22, hmac_salt, 117);
    unsigned int len = 0;
    HMAC(EVP_sha1(), hmac_key, 16, data, sizeof(data), sig_out, &len);
}

uint16_t calculate_checksum(const uint8_t *data, size_t len) {
    uint32_t sum = 0;
    for (size_t i = 0; i + 1 < len; i += 2) {
        sum += ((uint32_t)data[i] << 8) | data[i+1];
        if (sum > 0xffff) sum = (sum & 0xffff) + 1;
    }
    if (len & 1) {
        sum += ((uint32_t)data[len-1] << 8);
        if (sum > 0xffff) sum = (sum & 0xffff) + 1;
    }
    return (uint16_t)(sum ^ 0xffff);
}

static void print_frame_hex(const uint8_t *frame, size_t len, const char *label) {
    printf("\n[%s] (%zu bytes):\n   ", label, len);
    for (size_t i = 0; i < len; i++) {
        printf("%02x ", frame[i]);
        if ((i+1) % 16 == 0) printf("\n   ");
    }
    printf("\n\n");
}

int send_packet(uint8_t type, uint16_t nonce,
                const uint8_t *payload, size_t payload_len,
                const uint8_t *dest_mac) {
    uint8_t frame[BUFFER_SIZE], body[BUFFER_SIZE];
    memset(body, 0, sizeof(body));

    // Calculate body size (minimum 34 bytes payload, DWORD aligned)
    size_t effective_payload = (payload_len < 34) ? 34 : payload_len;
    size_t padded_payload = (effective_payload + 3) & ~3; // Round up to DWORD
    size_t total_body_len = 12 + padded_payload;
    uint8_t body_size_dwords = total_body_len / 4;

    // Build header
    memcpy(body, "XBOX", 4);
    body[4] = 0x01; body[5] = 0x01;
    body[6] = body_size_dwords;
    body[7] = type;
    body[8] = (nonce >> 8) & 0xff;
    body[9] = nonce & 0xff;
    body[10] = 0x00; body[11] = 0x00;

    // Copy payload
    if (payload && payload_len > 0)
        memcpy(body + 12, payload, payload_len);

    // Calculate checksum
    uint16_t checksum = calculate_checksum(body, total_body_len);
    body[10] = (checksum >> 8) & 0xff;
    body[11] = checksum & 0xff;

    // Build Ethernet frame
    size_t frame_len = 0;
    memcpy(frame + frame_len, dest_mac, 6); frame_len += 6;
    memcpy(frame + frame_len, local_mac, 6); frame_len += 6;
    frame[frame_len++] = 0x88;
    frame[frame_len++] = 0x6f;
    memcpy(frame + frame_len, body, total_body_len);
    frame_len += total_body_len;

    printf("DEBUG: type=0x%02x nonce=0x%04x dwords=%u payload=%zu body=%zu frame=%zu checksum=0x%04x\n",
           type, nonce, body_size_dwords, payload_len, total_body_len, frame_len, checksum);

    print_frame_hex(frame, frame_len, "SENDING");

    struct sockaddr_ll addr;
    memset(&addr, 0, sizeof(addr));
    addr.sll_family = AF_PACKET;
    addr.sll_ifindex = if_index;
    addr.sll_halen = ETH_ALEN;
    addr.sll_protocol = htons(XBOX_PROTOCOL);
    memcpy(addr.sll_addr, dest_mac, 6);

    // Retry loop for partial sends
    ssize_t total_sent = 0;
    while ((size_t)total_sent < frame_len) {
        ssize_t sent = sendto(sockfd, frame + total_sent, frame_len - (size_t)total_sent,
                             0, (struct sockaddr *)&addr, sizeof(addr));
        if (sent < 0) {
            perror("sendto");
            return -1;
        }
        total_sent += sent;
    }

    printf("SEND: %zd/%zu bytes transmitted\n", total_sent, frame_len);
    return (int)total_sent;
}

void log_packet_to_file(const uint8_t *packet, size_t len, const char *direction) {
    if (!capture_log) return;

    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char timestamp[32];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);

    // Extract packet details
    const uint8_t *src_mac = packet + 6;
    const uint8_t *dst_mac = packet + 0;
    uint16_t proto = (packet[12] << 8) | packet[13];

    if (proto != XBOX_PROTOCOL) return;

    const uint8_t *body = packet + 14;
    size_t body_len = len - 14;

    if (body_len < 12) return;

    uint8_t type = body[7];
    uint16_t nonce = (body[8] << 8) | body[9];
    uint16_t checksum = (body[10] << 8) | body[11];

    // Packet type names
    const char *type_names[] = {
        "UNKNOWN", "HANDSHAKE_REQ", "HANDSHAKE_RESP", "NETWORKS_LIST_REQ",
        "NETWORKS_LIST_RESP", "ADAPTER_INFO_REQ", "ADAPTER_INFO_RESP",
        "CONNECT_REQ", "CONNECT_RESP", "BEACON_REQ", "BEACON_RESP"
    };
    const char *type_name = (type <= 0x0a) ? type_names[type] : "UNKNOWN";

    // Write header
    fprintf(capture_log, "\n========== PACKET #%d ==========\n", ++packet_count);
    fprintf(capture_log, "Timestamp: %s\n", timestamp);
    fprintf(capture_log, "Direction: %s\n", direction);
    fprintf(capture_log, "SRC MAC:   %02x:%02x:%02x:%02x:%02x:%02x\n",
            src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5]);
    fprintf(capture_log, "DST MAC:   %02x:%02x:%02x:%02x:%02x:%02x\n",
            dst_mac[0], dst_mac[1], dst_mac[2], dst_mac[3], dst_mac[4], dst_mac[5]);
    fprintf(capture_log, "Type:      0x%02x (%s)\n", type, type_name);
    fprintf(capture_log, "Nonce:     0x%04x\n", nonce);
    fprintf(capture_log, "Checksum:  0x%04x\n", checksum);
    fprintf(capture_log, "Length:    %zu bytes\n", len);

    // Write hex dump
    fprintf(capture_log, "\nHex Dump:\n");
    for (size_t i = 0; i < len; i++) {
        if (i % 16 == 0) fprintf(capture_log, "  %04zx: ", i);
        fprintf(capture_log, "%02x ", packet[i]);
        if ((i + 1) % 16 == 0) fprintf(capture_log, "\n");
    }
    if (len % 16 != 0) fprintf(capture_log, "\n");

    // Write ASCII representation
    fprintf(capture_log, "\nASCII:\n  ");
    for (size_t i = 0; i < len; i++) {
        char c = packet[i];
        fprintf(capture_log, "%c", (c >= 32 && c <= 126) ? c : '.');
        if ((i + 1) % 64 == 0) fprintf(capture_log, "\n  ");
    }
    fprintf(capture_log, "\n");

    // Parse payload if it's a known type
    if (body_len > 12) {
        const uint8_t *payload = body + 12;
        size_t payload_len = body_len - 12;

        fprintf(capture_log, "\nPayload (%zu bytes):\n", payload_len);

        switch (type) {
            case PKT_HANDSHAKE_REQUEST:
                if (payload_len >= 16) {
                    fprintf(capture_log, "  Challenge: ");
                    for (int i = 0; i < 16; i++) fprintf(capture_log, "%02x", payload[i]);
                    fprintf(capture_log, "\n");
                }
                break;

            case PKT_HANDSHAKE_RESPONSE:
                if (payload_len >= 20) {
                    fprintf(capture_log, "  HMAC-SHA1: ");
                    for (int i = 0; i < 20; i++) fprintf(capture_log, "%02x", payload[i]);
                    fprintf(capture_log, "\n");
                }
                break;

            case PKT_CONNECT_TO_SSID_REQUEST:
                fprintf(capture_log, "  TLV Tags:\n");
                size_t pos = 0;
                while (pos + 2 <= payload_len) {
                    uint8_t tag = payload[pos++];
                    uint8_t tag_len = payload[pos++];
                    if (pos + tag_len > payload_len) break;

                    fprintf(capture_log, "    Tag 0x%02x (len=%d): ", tag, tag_len);

                    if (tag == 0x01) {  // SSID
                        fprintf(capture_log, "SSID=\"");
                        for (int i = 0; i < tag_len; i++) {
                            char c = payload[pos + i];
                            fprintf(capture_log, "%c", (c >= 32 && c <= 126) ? c : '?');
                        }
                        fprintf(capture_log, "\"");
                    } else if (tag == 0x02) {  // Password
                        fprintf(capture_log, "Password=\"");
                        for (int i = 0; i < tag_len; i++) {
                            char c = payload[pos + i];
                            fprintf(capture_log, "%c", (c >= 32 && c <= 126) ? c : '?');
                        }
                        fprintf(capture_log, "\"");
                    } else if (tag == 0x03) {  // Security
                        fprintf(capture_log, "Security=0x%02x", payload[pos]);
                    } else {
                        for (int i = 0; i < tag_len && i < 16; i++) {
                            fprintf(capture_log, "%02x ", payload[pos + i]);
                        }
                        if (tag_len > 16) fprintf(capture_log, "...");
                    }
                    fprintf(capture_log, "\n");
                    pos += tag_len;
                }
                break;
        }
    }

    fprintf(capture_log, "\n");
    fflush(capture_log);  // Ensure it's written immediately
}

void handle_handshake_request(const uint8_t *payload, size_t len,
                               uint16_t nonce, const uint8_t *src_mac) {
    printf("\n[HANDSHAKE REQUEST]\n");

    if (len < 16) {
        fprintf(stderr, "Error: Handshake payload too short (%zu bytes)\n", len);
        return;
    }

    // FIXED: Added missing bytes for correct alignment
    static const uint8_t response_data[152] = {
        0x54,0x6f,0x74,0x61,0x6c,0x6c,0x79,0x20,0x6c,0x65,0x67,0x69,0x74,0x20,0x77,0x69,
        0x72,0x65,0x6c,0x65,0x73,0x73,0x20,0x61,0x64,0x61,0x70,0x74,0x65,0x72,0x00,0x00,
        0x44,0x75,0x64,0x65,0x20,0x74,0x72,0x75,0x73,0x74,0x20,0x6d,0x65,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x06,0x07,0x00,0x00,0x0f,0xfe,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x05,0x01,0xa9,0xfe,0x47,0x79,0x01,0x02,
        0x01,0x0b,0x02,0x0c,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x02,0x01,0x00,0x00
    };

    uint8_t full_payload[256];
    memset(full_payload, 0, sizeof(full_payload));
    uint8_t hmac_sig[20];

    make_signature_hmac(payload, local_mac, hmac_sig);

    printf("  Challenge: ");
    for (int i = 0; i < 16; i++) printf("%02x", payload[i]);
    printf("\n  HMAC-SHA1: ");
    for (int i = 0; i < 20; i++) printf("%02x", hmac_sig[i]);
    printf("\n");

    memcpy(full_payload, hmac_sig, 20);
    memcpy(full_payload + 20, auth_copyright, 84);
    memcpy(full_payload + 104, response_data, 152);

    send_packet(PKT_HANDSHAKE_RESPONSE, nonce, full_payload, 256, src_mac);

    conn_state = STATE_HANDSHAKE_DONE;
    printf("✓ Handshake complete - waiting for link establishment\n");
}

void handle_beacon_request(uint16_t nonce, const uint8_t *dest_mac) {
    beacon_count++;

    if (conn_state == STATE_HANDSHAKE_DONE) {
        printf("[BEACON #%d] Establishing link...\n", beacon_count);
        if (beacon_count >= 3) {
            conn_state = STATE_LINKED;
            printf("\n========================================\n");
            printf("  ✓ LINK ESTABLISHED - ADAPTER READY\n");
            printf("========================================\n\n");
        }
    }

    uint8_t response[4] = {0x02, 0x80, 0x00, 0x00};
    send_packet(PKT_BEACON_RESPONSE, nonce, response, 4, dest_mac);
}

void handle_adapter_info_request(uint16_t nonce, const uint8_t *dest_mac) {
    printf("\n[ADAPTER INFO REQUEST]\n");

    // Use the ORIGINAL 48-byte fixed format that Xbox expects
    // This matches the format from your working handshake response
    static const uint8_t response[48] = {
        0x00,0x09,                          // Header
        0x01,0x04,0xa9,0xfe,0x47,0x79,      // Adapter ID/Version
        0x02,0x01,0x01,                     // Connection status (0x01 = connected)
        0x04,0x01,0x01,                     // Some flag
        0x05,0x01,0x0b,                     // Another flag
        0x06,0x06,0x00,0x00,0x00,0x00,0x00,0x00,  // MAC or placeholder
        0x07,0x0c,                          // Serial number tag (12 bytes)
        0x31,0x31,0x31,0x31,0x31,0x31,      // "111111111111" serial
        0x31,0x31,0x31,0x31,0x31,0x31,
        0x08,0x01,0x02,                     // Hardware version
        0x09,0x01,0x01,                     // Firmware version
        0x11,0x01,0x02                      // Additional info
    };

    // Make a copy so we can modify connection status dynamically
    uint8_t payload[48];
    memcpy(payload, response, sizeof(response));

    // Update connection status byte at offset 10 (tag 0x02 value)
    OWRTStatus owrt = get_openwrt_status();
    if (owrt.connected && xbox_saved_profile.is_saved) {
        payload[10] = 0x01;  // Connected
        printf("  -> Status: CONNECTED to %s\n", xbox_saved_profile.ssid);
    } else {
        payload[10] = 0x00;  // Not connected
        printf("  -> Status: DISCONNECTED\n");
    }

    send_packet(PKT_ADAPTER_INFO_RESPONSE, nonce, payload, 48, dest_mac);
}

void add_network_slot_dynamic(uint8_t *buffer, size_t *pos, int index,
                             const char *ssid, uint8_t sec_type, uint8_t signal) {
    size_t slot_start = *pos;
    size_t ssid_len = strlen(ssid);

    if (ssid_len > 32) ssid_len = 32;

    size_t tlv_pos = slot_start;

    // BSSID (6 bytes)
    buffer[tlv_pos++] = 0xAA;
    buffer[tlv_pos++] = 0xAA;
    buffer[tlv_pos++] = 0xAA;
    buffer[tlv_pos++] = 0xAA;
    buffer[tlv_pos++] = 0xAA;
    buffer[tlv_pos++] = 0xA0 + index;

    // Tag 0x01: SSID (immediately after BSSID)
    buffer[tlv_pos++] = 0x01;
    buffer[tlv_pos++] = (uint8_t)ssid_len;
    if (ssid_len > 0) {
        memcpy(&buffer[tlv_pos], ssid, ssid_len);
        tlv_pos += ssid_len;
    }

    // Tag 0x02: Capability (immediately after SSID, NO padding between tags)
    buffer[tlv_pos++] = 0x02;
    buffer[tlv_pos++] = 0x01;
    buffer[tlv_pos++] = sec_type;

    // Tag 0x06: Rates (14 bytes of data)
    buffer[tlv_pos++] = 0x06;
    buffer[tlv_pos++] = 0x0E;  // Length = 14 bytes

    // Rate bytes (use signal for first byte to vary per network)
    buffer[tlv_pos++] = signal;
    buffer[tlv_pos++] = 0x02;
    buffer[tlv_pos++] = 0x04;
    buffer[tlv_pos++] = 0x0B;
    buffer[tlv_pos++] = 0x16;
    buffer[tlv_pos++] = 0x12;
    buffer[tlv_pos++] = 0x24;
    buffer[tlv_pos++] = 0x48;
    buffer[tlv_pos++] = 0x6C;
    buffer[tlv_pos++] = 0x0C;
    buffer[tlv_pos++] = 0x18;
    buffer[tlv_pos++] = 0x30;
    buffer[tlv_pos++] = 0x60;

    // Pad rest of 64-byte slot
    while (tlv_pos < slot_start + 64) {
        buffer[tlv_pos++] = 0x00;
    }

    *pos += 64;
}

void handle_networks_list_request(uint16_t nonce, const uint8_t *dest_mac) {
    printf("\n[NETWORKS LIST REQUEST]\n");
    uint8_t buffer[1 + (16 * 64)];  // Always 16 slots like Python
    memset(buffer, 0, sizeof(buffer));
    size_t pos = 1;
    int count = 0;

    // Add your real networks
    add_network_slot_dynamic(buffer, &pos, count++, "XboxAdapter_OpenWrt", 0x00, 0xB1);

    if (xbox_saved_profile.is_saved) {
        printf("  -> Including saved network: %s (sec: 0x%02x)\n",
               xbox_saved_profile.ssid, xbox_saved_profile.sec_type);
        add_network_slot_dynamic(buffer, &pos, count++, xbox_saved_profile.ssid,
                               xbox_saved_profile.sec_type, 0xB0);
    }

    // Fill remaining slots with hidden/empty networks
    while (count < 16) {
        // Add empty network slot (hidden SSID)
        size_t slot_start = pos;
        buffer[slot_start + 0] = 0xAA;
        buffer[slot_start + 1] = 0xAA;
        buffer[slot_start + 2] = 0xAA;
        buffer[slot_start + 3] = 0xAA;
        buffer[slot_start + 4] = 0xAA;
        buffer[slot_start + 5] = 0xA0 + count;

        // Hidden SSID: Tag 0x01, Length 0
        buffer[slot_start + 6] = 0x01;
        buffer[slot_start + 7] = 0x00;

        // Standard tags for hidden network
        buffer[slot_start + 8] = 0x02;
        buffer[slot_start + 9] = 0x01;
        buffer[slot_start + 10] = 0x04;

        buffer[slot_start + 11] = 0x06;
        buffer[slot_start + 12] = 0x0E;
        buffer[slot_start + 13] = 0xA7;
        buffer[slot_start + 14] = 0x02;
        buffer[slot_start + 15] = 0x04;
        buffer[slot_start + 16] = 0x0B;
        buffer[slot_start + 17] = 0x16;
        buffer[slot_start + 18] = 0x24;
        buffer[slot_start + 19] = 0x30;
        buffer[slot_start + 20] = 0x48;
        buffer[slot_start + 21] = 0x6C;
        buffer[slot_start + 22] = 0x0C;
        buffer[slot_start + 23] = 0x12;
        buffer[slot_start + 24] = 0x18;
        buffer[slot_start + 25] = 0x60;

        pos += 64;
        count++;
    }

    buffer[0] = 16;  // Always report 16 networks
    size_t response_len = 1 + (16 * 64);  // 1025 bytes

    printf("  -> Sending %d networks, %zu bytes\n", 16, response_len);
    send_packet(PKT_NETWORKS_LIST_RESPONSE, nonce, buffer, response_len, dest_mac);
}

void handle_connect_request(const uint8_t *payload, size_t len,
    uint16_t nonce, const uint8_t *dest_mac) {
    printf("\n[CONNECT REQUEST]\n");
    size_t pos = 0;
    int found_ssid = 0, found_password = 0, found_sec_type = 0;

    // Parse TLV tags - FIXED to match spec: 0x01=SSID, 0x02=Password, 0x03=Security
    while (pos + 2 <= len) {
        uint8_t tag = payload[pos++];
        uint8_t tag_len = payload[pos++];
        if (pos + tag_len > len) {
            fprintf(stderr, "  Warning: Malformed TLV (tag=0x%02x len=%d)\n",
                tag, tag_len);
            break;
        }

        switch(tag) {
        case 0x01: // SSID
            memset(xbox_saved_profile.ssid, 0, sizeof(xbox_saved_profile.ssid));
            memcpy(xbox_saved_profile.ssid, &payload[pos],
                (tag_len > 32) ? 32 : tag_len);
            found_ssid = 1;
            printf("  -> SSID: %s\n", xbox_saved_profile.ssid);
            break;
        case 0x02: // Password/Passphrase (WPA2-PSK key)
            memset(xbox_saved_profile.password, 0,
                sizeof(xbox_saved_profile.password));
            memcpy(xbox_saved_profile.password, &payload[pos],
                (tag_len > 63) ? 63 : tag_len);
            found_password = 1;
            printf("  -> Password: %s (%d bytes)\n",
                xbox_saved_profile.password, tag_len);
            break;
        case 0x03: // Security Type
            xbox_saved_profile.sec_type = payload[pos];
            found_sec_type = 1;
            printf("  -> Security: 0x%02x ", xbox_saved_profile.sec_type);
            switch(xbox_saved_profile.sec_type) {
            case 0x00: printf("(Open)\n"); break;
            case 0x01: printf("(WEP)\n"); break;
            case 0x02: printf("(WPA-PSK)\n"); break;
            case 0x03: printf("(WPA2-PSK)\n"); break;
            default: printf("(Unknown)\n"); break;
            }
            break;
        default:
            printf("  -> Unknown tag 0x%02x (length %d)\n", tag, tag_len);
            break;
        }
        pos += tag_len;
    }

    // Mark profile as saved if we got at least SSID
    if (found_ssid) {
        xbox_saved_profile.is_saved = 1;
        xbox_saved_profile.last_connect_attempt = time(NULL);
        printf("\n  ✓ Saved Xbox profile:\n");
        printf("    SSID: %s\n", xbox_saved_profile.ssid);
        if (found_password)
            printf("    Password: %s\n", xbox_saved_profile.password);
        if (found_sec_type)
            printf("    Security: 0x%02x\n", xbox_saved_profile.sec_type);

        // Trigger OpenWrt WiFi connection (only on Linux, not in listen mode)
        #ifdef __linux__
        if (!listen_mode) {
            char cmd[512];
            snprintf(cmd, sizeof(cmd),
                     "/usr/bin/xboxwireless-config.sh '%s' '%s' %d 2>&1 | logger -t xbox_fuzzer &",
                     xbox_saved_profile.ssid,
                     xbox_saved_profile.password,
                     xbox_saved_profile.sec_type);

            printf("\n🚀 EXECUTING WIFI JOIN: %s\n", xbox_saved_profile.ssid);

            int ret = system(cmd);
            if (ret == 0) {
                printf("  ✓ WiFi configuration script started\n");
            } else {
                fprintf(stderr, "  ⚠️  WARNING: Script returned error code %d\n", ret);
            }
        }
        #endif
    }

    // Send success response (34 bytes of zeros = success)
    uint8_t response[34] = {0};
    send_packet(PKT_CONNECT_TO_SSID_RESPONSE, nonce, response, 34, dest_mac);

    // Move to LINKED state after successful connection
    conn_state = STATE_LINKED;
    printf("  ✓ Connection response sent (success)\n");
}

void process_packet(const uint8_t *packet, size_t len) {
    if (len < 26) return; // Minimum frame size

    uint16_t proto = (packet[12] << 8) | packet[13];
    if (proto != XBOX_PROTOCOL) return;

    // Determine direction based on source MAC
    const uint8_t *src_mac = packet + 6;
    const char *direction = "UNKNOWN";

    if (memcmp(src_mac, local_mac, 6) == 0) {
        direction = "ADAPTER->CONSOLE";
    } else if (xbox_mac[0] != 0 && memcmp(src_mac, xbox_mac, 6) == 0) {
        direction = "CONSOLE->ADAPTER";
    } else {
        direction = "CONSOLE->ADAPTER";  // First packet assumption
    }

    // Log to file if capture is enabled
    if (capture_log) {
        log_packet_to_file(packet, len, direction);
    }

    // Print to console
    print_frame_hex(packet, len, direction);

    // LISTEN MODE: Stop here, don't respond
    if (listen_mode) {
        printf("[LISTEN MODE] Packet captured, no response sent\n");
        return;
    }

    // ===== NORMAL EMULATION MODE BELOW =====
    const uint8_t *body = packet + 14;
    size_t body_len = len - 14;

    // Validate Xbox protocol header
    if (body_len < 12) return;
    if (memcmp(body, "XBOX", 4) != 0) return;
    if (body[4] != 0x01 || body[5] != 0x01) return;

    uint8_t body_dwords = body[6];
    size_t expected_body_len = (size_t)body_dwords * 4;
    size_t actual_body_len = (body_len < expected_body_len) ? body_len : expected_body_len;

    if (body_len < expected_body_len) {
        fprintf(stderr, "Warning: declared body %zu bytes but received %zu bytes\n",
                expected_body_len, body_len);
    }

    uint8_t type = body[7];
    uint16_t nonce = (body[8] << 8) | body[9];

    const uint8_t *dst_mac = packet;
    src_mac = packet + 6;

    // Capture Xbox MAC on first handshake
    if (type == PKT_HANDSHAKE_REQUEST && xbox_mac[0] == 0) {
        memcpy(xbox_mac, src_mac, 6);
        printf("Xbox MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
               src_mac[0], src_mac[1], src_mac[2],
               src_mac[3], src_mac[4], src_mac[5]);
    }

    size_t payload_len = 0;
    const uint8_t *payload = NULL;
    if (actual_body_len >= 12) {
        payload_len = actual_body_len - 12;
        payload = body + 12;
    }

    // Dispatch packet handlers
    switch (type) {
        case PKT_HANDSHAKE_REQUEST:
            if (memcmp(dst_mac, "\xff\xff\xff\xff\xff\xff", 6) == 0 &&
                payload && payload_len >= 16) {
                handle_handshake_request(payload, payload_len, nonce, src_mac);
            }
            break;

        case PKT_BEACON_REQUEST:
            handle_beacon_request(nonce, src_mac);
            break;

        case PKT_ADAPTER_INFO_REQUEST:
            handle_adapter_info_request(nonce, src_mac);
            break;

        case PKT_NETWORKS_LIST_REQUEST:
            handle_networks_list_request(nonce, src_mac);
            break;

        case PKT_CONNECT_TO_SSID_REQUEST:
            handle_connect_request(payload, payload_len, nonce, src_mac);
            break;

        default:
            printf("[WARNING] Unknown packet type 0x%02x\n", type);
            break;
    }
}

int init_socket(const char *iface) {
    struct ifreq ifr;
    strncpy(interface_name, iface, IFNAMSIZ - 1);

    sockfd = socket(AF_PACKET, SOCK_RAW, htons(XBOX_PROTOCOL));
    if (sockfd < 0) {
        perror("socket");
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);

    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl SIOCGIFHWADDR");
        return -1;
    }
    memcpy(local_mac, ifr.ifr_hwaddr.sa_data, 6);

    if (ioctl(sockfd, SIOCGIFINDEX, &ifr) < 0) {
        perror("ioctl SIOCGIFINDEX");
        return -1;
    }
    if_index = ifr.ifr_ifindex;

    struct sockaddr_ll addr = {0};
    addr.sll_family = AF_PACKET;
    addr.sll_ifindex = ifr.ifr_ifindex;
    addr.sll_protocol = htons(XBOX_PROTOCOL);

    if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        return -1;
    }

    printf("Xbox Wireless Adapter Emulator (Stateful + Debug)\n");
    printf("Interface: %s (%02x:%02x:%02x:%02x:%02x:%02x)\n",
           iface, local_mac[0], local_mac[1], local_mac[2],
           local_mac[3], local_mac[4], local_mac[5]);

    return 0;
}

int main(int argc, char *argv[]) {
    printf("========================================\n");
    printf("  Xbox Wireless Protocol Emulator\n");
    printf("  Stateful Mode with Debug Output\n");
    printf("========================================\n\n");

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <interface> [--fuzz] [--listen] [--capture <file>]\n", argv[0]);
        fprintf(stderr, "\nModes:\n");
        fprintf(stderr, "  (default)           Normal emulation mode\n");
        fprintf(stderr, "  --fuzz              Fuzzing mode (16 networks)\n");
        fprintf(stderr, "  --listen            Passive capture only (no responses)\n");
        fprintf(stderr, "  --capture <file>    Log packets to file\n");
        fprintf(stderr, "\nExamples:\n");
        fprintf(stderr, "  sudo %s eth0\n", argv[0]);
        fprintf(stderr, "  sudo %s eth0 --fuzz\n", argv[0]);
        fprintf(stderr, "  sudo %s eth0 --listen --capture packets.log\n", argv[0]);
        fprintf(stderr, "  sudo %s eth0 --capture real_adapter.log\n", argv[0]);
        return 1;
    }

    // Parse command line arguments
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--fuzz") == 0) {
            fuzz_mode = 1;
            printf("  MODE: Fuzzing (16 dummy networks)\n");
        } else if (strcmp(argv[i], "--listen") == 0) {
            listen_mode = 1;
            printf("  MODE: Listen (passive capture, no responses)\n");
        } else if (strcmp(argv[i], "--capture") == 0 && i + 1 < argc) {
            capture_log = fopen(argv[i + 1], "w");
            if (capture_log) {
                printf("  CAPTURE: Logging to %s\n", argv[i + 1]);
                fprintf(capture_log, "========================================\n");
                fprintf(capture_log, "Xbox Wireless Adapter Packet Capture\n");
                fprintf(capture_log, "Started: %s", ctime(&(time_t){time(NULL)}));
                fprintf(capture_log, "Interface: %s\n", argv[1]);
                fprintf(capture_log, "Mode: %s\n", listen_mode ? "Listen" : "Emulation");
                fprintf(capture_log, "========================================\n\n");
                fflush(capture_log);
            } else {
                fprintf(stderr, "Error: Cannot open capture file %s\n", argv[i + 1]);
            }
            i++;  // Skip filename
        }
    }

    if (!fuzz_mode && !listen_mode) {
        printf("  MODE: Normal (real networks only)\n");
    }
    printf("\n");

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    if (load_secrets() < 0) {
        fprintf(stderr, "Failed to load secrets from ./secrets/\n");
        return 1;
    }

    if (init_socket(argv[1]) < 0) {
        return 1;
    }

    if (listen_mode) {
        printf("\n👂 LISTEN MODE: Capturing packets between Xbox and adapter...\n");
        printf("   Set up network bridge between console and adapter.\n");
        printf("   No responses will be sent.\n\n");
    } else {
        printf("\n⏳ Waiting for Xbox handshake...\n\n");
    }

    uint8_t buffer[BUFFER_SIZE];
    while (running) {
        ssize_t len = recvfrom(sockfd, buffer, sizeof(buffer), 0, NULL, NULL);
        if (len > 0) {
            process_packet(buffer, (size_t)len);
        }
    }

    printf("\n========================================\n");
    printf("Session Statistics:\n");
    printf("  Packets captured: %d\n", packet_count);
    printf("  Beacons received: %d\n", beacon_count);
    printf("  Final state: %s\n",
           conn_state == STATE_LINKED ? "LINKED" :
           conn_state == STATE_HANDSHAKE_DONE ? "HANDSHAKE_DONE" :
           "DISCONNECTED");
    if (xbox_saved_profile.is_saved) {
        printf("  Saved profile: %s (sec: 0x%02x)\n",
               xbox_saved_profile.ssid, xbox_saved_profile.sec_type);
    }
    printf("========================================\n");

    if (capture_log) {
        fprintf(capture_log, "\n========================================\n");
        fprintf(capture_log, "Capture session ended\n");
        fprintf(capture_log, "Total packets: %d\n", packet_count);
        fprintf(capture_log, "========================================\n");
        fclose(capture_log);
        printf("\nCapture log closed.\n");
    }

    close(sockfd);
    return 0;
}

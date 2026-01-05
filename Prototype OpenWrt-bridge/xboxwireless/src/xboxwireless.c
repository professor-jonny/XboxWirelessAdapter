/* xbox_wireless.c */
/* Compile: gcc -o xbox_fuzzer xbox_wireless.c -lssl -lcrypto -O2 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <ctype.h>
#include "packets.h"
#include "helpers.h"

/* Linux-specific networking */
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>

/* OpenSSL for HMAC */
#include <openssl/hmac.h>
#include <openssl/evp.h>

/* ============================================================================

/* type definitions */

/* Globals */
static int sockfd = -1, sockfd2 = -1, if_index = 0, if_index2 = 0;
static uint8_t xbox_mac[6], adapter_mac[6], local_mac[6];
static char interface_name[IFNAMSIZ], interface_name2[IFNAMSIZ];
static volatile sig_atomic_t running = 1;
static ConnectionState conn_state = STATE_DISCONNECTED;
static int beacon_count = 0;
static SavedProfile xbox_saved_profile = {.is_saved = 0};
static FILE *capture_log = NULL;
static int packet_count = 0;
static OperationMode operation_mode = MODE_EMULATE_ADAPTER;
static uint16_t current_nonce = 0x1234;
static network_info_t discovered_networks[16];
static int discovered_count = 0;
static adapter_state_t adapter_state = {0};


void signal_handler(int signum) { running = 0; }

void print_usage(const char *prog) {
    printf("Xbox Wireless Protocol Tool\n");
    printf("Usage: %s <interface> [options]\n", prog);
    printf("  --mode xbox               Emulate Xbox\n");
    printf("  --bridge <interface2>     Bridge mode\n");
    printf("  --send <hexfile>          Send hex file\n");
    printf("  --target <MAC>            Target MAC\n");
    printf("  --capture <file>          Log packets\n");
    printf("  --listen                  Passive capture\n");
}

void add_network_slot(uint8_t *buffer, size_t *pos, int index,
                      const char *ssid, uint8_t sec_type, uint8_t signal) {
    size_t slot_start = *pos;
    size_t ssid_len = strlen(ssid);
    if (ssid_len > NETWORK_SSID_DATA_SIZE) ssid_len = 32;

    /* Clear entire 64-byte slot */
    memset(buffer + slot_start, 0, 64);

    uint8_t *slot = buffer + slot_start;

    /* Bytes 0-5: BSSID */
    slot[0] = 0xAA;
    slot[1] = 0xAA;
    slot[2] = 0xAA;
    slot[3] = 0xAA;
    slot[4] = 0xAA;
    slot[5] = 0xA0 + index;

    /* Bytes 6-7: SSID TLV header */
    slot[NETWORK_SSID_TAG_OFFSET] = TLV_TAG_SSID;                    /* Tag 0x01 (SSID) */
    slot[NETWORK_SSID_LEN_OFFSET] = (uint8_t)ssid_len;       /* Length */

    /* Bytes 8-39: SSID data (32-byte area, zero-padded) */
    if (ssid_len > 0) {
        memcpy(slot + NETWORK_SSID_DATA_OFFSET, ssid, ssid_len);
    }

    /* Bytes 40-42: Security TLV */
    slot[NETWORK_SECURITY_TAG_OFFSET] = TLV_TAG_SECURITY;;        /* Tag 0x02 (Security) */
    slot[NETWORK_SECURITY_LEN_OFFSET] = 1;        /* Length 1 */
    slot[NETWORK_SECURITY_TYPE_OFFSET] = sec_type;    /* Security type */

    /* Bytes 43-44: Signal (NOT proper TLV - no length byte!) */
    slot[NETWORK_SIGNAL_TAG_OFFSET] = TLV_TAG_SIGNAL;        /* Tag 0x06 */
    slot[NETWORK_SIGNAL_OFFSET] = signal;;      /* Signal strength */

    /* Bytes 45-56: Supported rates (12 bytes) */
    slot[45] = 0x02;
    slot[46] = 0x04;
    slot[47] = 0x0B;
    slot[48] = 0x16;
    slot[49] = 0x12;
    slot[50] = 0x24;
    slot[51] = 0x48;
    slot[52] = 0x6C;
    slot[53] = 0x0C;
    slot[54] = 0x18;
    slot[55] = 0x30;
    slot[56] = 0x60;

    /* Bytes 57-63: Padding (already zeroed by memset) */

    *pos += 64;
}

void build_handshake_response(uint8_t *response,
                               const uint8_t *challenge,
                               adapter_state_t *state) {
    memset(response, 0, 256);

    /* HMAC signature (bytes 0-19) - 20 bytes */
    make_signature_hmac(challenge, MN740_MAC_ADDR_ADDR, response);

    /* Copyright (bytes 20-103) - 84 bytes */
    memcpy(response + 20, auth_copyright, 84);

    /* Adapter name (bytes 104-135) - 32 bytes */
    const char *name = "Xbox Wireless Adapter (MN-740)";
    size_t name_len = strlen(name);
    if (name_len > 32) name_len = 32;
    memcpy(response + 104, name, name_len);

    /* Firmware version (bytes 136-167) - 32 bytes */
    const char *fw = "1.0.2.26 Boot: 1.3.0.06";
    size_t fw_len = strlen(fw);
    if (fw_len > 32) fw_len = 32;
    memcpy(response + HANDSHAKE_RESPONSE_FIRMWARE_OFFSET, fw, fw_len);

    /* Unknown data (bytes 168-218) - 51 bytes */
    response[HANDSHAKE_RESPONSE_CAPS_OFFSET] = 0x06;
    response[169] = 0x07;
    response[170] = 0x00;
    response[171] = 0x00;
    response[172] = 0x0f;
    response[173] = 0xfe;
    /* Bytes 174-213: zeros (already from memset) */

    /* CRITICAL FIX: Fixed header (bytes 214-218) */
    response[HANDSHAKE_RESPONSE_HEADER_OFFSET] = 0x01;
    response[215] = 0x02;
    response[216] = 0x01;
    response[217] = 0x0b;
    response[218] = 0x02;

    /* SSID length (byte 219) - 1 byte */
    if (state->is_connected && strlen(state->current_ssid) > 0) {
        /* Connected: SSID present */
        uint8_t ssid_len = strlen(state->current_ssid);
        if (ssid_len > NETWORK_SSID_DATA_SIZE) ssid_len = 32;

        ssid_len;	response[HANDSHAKE_RESPONSE_SSID_LEN_OFFSET] = ssid_len;

        /* SSID data (bytes 220-251) - 32 bytes */
        memcpy(response + HANDSHAKE_RESPONSE_SSID_OFFSET, state->current_ssid, ssid_len);
        /* Remainder already zeroed by memset */

        /* Final 4 bytes (252-255) - CONNECTED state */
        response[252] = 0x02;
        response[HANDSHAKE_RESPONSE_STATUS_OFFSET + 1] = 0x01;
        response[254] = 0x00;
        response[255] = 0x00;
    } else {
        /* Disconnected: SSID length = 0 */
        response[219] = 0x00;
        /* Bytes 220-251 already zero from memset */

        /* Final 4 bytes (252-255) - DISCONNECTED state */
        response[252] = 0x02;
        response[HANDSHAKE_RESPONSE_STATUS_OFFSET + 1] = 0x00;
        response[254] = 0x00;
        response[255] = 0x00;
    }
}

parsed_wifi_config_t parse_connect_tlv(const uint8_t *payload, size_t len) {
    parsed_wifi_config_t config = {0};
    size_t pos = 0;

    while (pos + 2 <= len) {
        uint8_t tag = payload[pos++];
        uint8_t tag_len = payload[pos++];

        if (pos + tag_len > len) break;

        switch (tag) {
            case 0x01:  /* SSID */
                if (tag_len <= 32) {
                    memcpy(config.ssid, &payload[pos], tag_len);
                    config.ssid[tag_len] = '\0';
                }
                break;

            case 0x02:  /* Password */
                if (tag_len <= 63) {
                    memcpy(config.password, &payload[pos], tag_len);
                    config.password[tag_len] = '\0';
                }
                break;

            case 0x03:  /* Security type (primary) */
            case 0x05:  /* Security type (alternate) */
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

void parse_networks_response(const uint8_t *payload, size_t payload_len) {
    if (payload_len < 1) return;

    int net_count = payload[0];
    discovered_count = 0;

    printf("\n========================================\n");
    printf("  NETWORKS DISCOVERED\n");
    printf("========================================\n");

    size_t pos = 1;
    int actual_networks = 0;

    /* Parse all network slots (each is 64 bytes) */
    for (int i = 0; i < net_count && i < 16; i++) {
        /* Check if we have enough data for this slot */
        if (pos + 64 > payload_len) {
            printf("  (Truncated at slot %d)\n", i);
            break;
        }

        const uint8_t *slot = payload + pos;

        /* Extract BSSID (bytes 0-5) */
        uint8_t bssid[6];
        memcpy(bssid, slot, 6);

        /* Extract SSID (Tag 0x01 at offset 6, length at offset 7) */
        uint8_t ssid_tag = slot[6];
        uint8_t ssid_len = slot[7];

        /* Extract security type (at offset 42) */
        uint8_t sec_type = slot[42];

        /* CORRECTED: Byte 44 is SIGNAL QUALITY, not channel! */
        uint8_t signal = slot[44];
        int signal_pct = (signal * 100) / 255;
        const char *sec_name = get_security_name(sec_type);

        if (ssid_tag == 0x01) {
            if (ssid_len == 0) {
                /* Hidden network */
                if (actual_networks < 16) {
                    strcpy(discovered_networks[actual_networks].ssid, "[Hidden Network]");
                    memcpy(discovered_networks[actual_networks].bssid, bssid, 6);
                    discovered_networks[actual_networks].security_type = sec_type;
                    discovered_networks[actual_networks].signal_strength = signal;
                    discovered_networks[actual_networks].valid = 1;
                }

								printf("[%2d] %-32s  BSSID:", actual_networks, "[Hidden Network]");
								print_mac(bssid);
								printf("  Sig:%3d%%  %s\n", signal_pct, sec_name);

                actual_networks++;
            } else if (ssid_len > 0 && ssid_len <= 32) {
                /* Normal network with SSID */
                char ssid[33] = {0};
                memcpy(ssid, slot + 8, ssid_len);

                if (actual_networks < 16) {
                    memcpy(discovered_networks[actual_networks].ssid, ssid, ssid_len);
                    discovered_networks[actual_networks].ssid[ssid_len] = '\0';
                    memcpy(discovered_networks[actual_networks].bssid, bssid, 6);
                    discovered_networks[actual_networks].security_type = sec_type;
                    discovered_networks[actual_networks].signal_strength = signal;
                    discovered_networks[actual_networks].valid = 1;
                }

								printf("[%2d] %-32s  BSSID:", actual_networks, ssid);
								print_mac(bssid);
								printf("  Sig:%3d%%  %s\n", signal_pct, sec_name);

                actual_networks++;
            }
        }

        pos += 64;  /* Move to next 64-byte slot */
    }

    discovered_count = actual_networks;

    printf("========================================\n");
    printf("Found %d networks\n", discovered_count);
    printf("\nNOTE: Channel information comes from\n");
    printf("      handshake response, not network list!\n");
    printf("========================================\n");
}

void parse_handshake_response(const uint8_t *payload, size_t payload_len) {
    printf("\n╔══════════════════════════════════════╗\n");
    printf("║  ✓ HANDSHAKE RESPONSE RECEIVED!   ║\n");
    printf("╚══════════════════════════════════════╝\n");

    if (payload_len < 256) {
        printf("Warning: Handshake response too short (%zu bytes, expected 256)\n", payload_len);
        return;
    }

    /* Skip HMAC (bytes 0-19) */
    /* Skip copyright (bytes 20-103) */

    /* Parse adapter name (bytes 104-135) */
    char adapter_name[33] = {0};
    memcpy(adapter_name, payload + HANDSHAKE_RESPONSE_NAME_OFFSET, HANDSHAKE_RESPONSE_NAME_SIZE);
    /* Clean non-printable characters */
    for (int i = 0; i < 32; i++) {
        if (adapter_name[i] == 0) break;
        if (!isprint((unsigned char)adapter_name[i])) adapter_name[i] = '?';
    }
    printf("\nAdapter Name: %s\n", adapter_name);

    /* Parse firmware version (bytes 136-167) */
    char fw_version[33] = {0};
    memcpy(fw_version, payload + 136, 32);
    for (int i = 0; i < 32; i++) {
        if (fw_version[i] == 0) break;
        if (!isprint((unsigned char)fw_version[i])) fw_version[i] = '?';
    }
    printf("Firmware:     %s\n", fw_version);

    /* Parse capability flags (bytes 168-173) */
    printf("\nCapabilities: %02x %02x %02x %02x %02x %02x\n",
           payload[HANDSHAKE_RESPONSE_CAPS_OFFSET], payload[169], payload[170],
           payload[171], payload[172], payload[173]);

    /* Parse current SSID (bytes 219-251)*/
    uint8_t ssid_len = payload[HANDSHAKE_RESPONSE_SSID_LEN_OFFSET];
    printf("\n--- Connection Status ---\n");

    if (ssid_len > 0 && ssid_len <= 32) {
        char current_ssid[33] = {0};
        memcpy(current_ssid, payload + 220, ssid_len);
        printf("SSID:         %s\n", current_ssid);
        printf("Status:       Connected\n");
    } else {
        printf("SSID:         (Not connected)\n");
        printf("Status:       Disconnected\n");
    }

    /* Parse final status bytes (252-255) */
    printf("Status bytes: %02x %02x %02x %02x\n",
           payload[HANDSHAKE_RESPONSE_STATUS_OFFSET], payload[HANDSHAKE_RESPONSE_STATUS_OFFSET + 1], payload[254], payload[255]);

    printf("========================================\n");
}

void parse_and_display_network_list(const uint8_t *body, size_t body_len) {
    if (body_len < 12) return;

    uint8_t body_dwords = body[6];
    size_t payload_len = (body_dwords * 4) - 12;
    if (payload_len == 0) return;

    const uint8_t *payload = body + 12;
    int net_count = payload[0];
    printf("  → Network list: %d slots\n", net_count);

    size_t pos = 1;
    int displayed = 0;

    while (pos + 64 <= payload_len && displayed < net_count) {
        const uint8_t *slot = payload + pos;

        /* Check if slot has data (SSID length > 0) */
        uint8_t ssid_tag = slot[6];
        uint8_t ssid_len = slot[7];

        if (ssid_tag == 0x01 && ssid_len > 0 && ssid_len <= 32) {
            char ssid[33] = {0};
            memcpy(ssid, slot + 8, ssid_len);

            /* Extract security type (at offset 42) */
            uint8_t sec_type = slot[42];

            /* Extract signal (at offset 44) */
            uint8_t signal = slot[44];

            printf("     [%d] SSID: %-32s  Security: 0x%02x  Signal: 0x%02x\n",
                   displayed, ssid, sec_type, signal);
        }

        pos += 64;
        displayed++;
    }

    if (displayed == 0) {
        printf("     (All slots empty)\n");
    }
}

void parse_and_display_connect_request(const uint8_t *body, size_t body_len) {
    if (body_len < 12) return;

    uint8_t body_dwords = body[6];
    size_t payload_len = (body_dwords * 4) - 12;
    if (payload_len == 0) return;

    const uint8_t *payload = body + 12;
    printf("  → Parsing connect request TLV:\n");

    size_t pos = 0;
    while (pos + 2 <= payload_len) {
        uint8_t tag = payload[pos++];
        uint8_t tag_len = payload[pos++];
        if (pos + tag_len > payload_len) break;

        if (tag == 0x01 && tag_len <= 32) {
            char ssid[33] = {0};
            memcpy(ssid, &payload[pos], tag_len);
            printf("     Tag 0x01 (SSID): \"%s\"\n", ssid);
        } else if (tag == 0x02 && tag_len <= 63) {
            printf("     Tag 0x02 (Password): %d bytes (hidden)\n", tag_len);
        } else if (tag == 0x03 || tag == 0x05) {
            printf("     Tag 0x%02x (Security): 0x%02x\n", tag, payload[pos]);
        } else {
            printf("     Tag 0x%02x: %d bytes\n", tag, tag_len);
        }

        pos += tag_len;
    }
}

/* Network I/O functions */

void print_frame_hex(const uint8_t *frame, size_t len, const char *label) {
    printf("\n[%s] (%zu bytes):\n   ", label, len);
    for (size_t i = 0; i < len; i++) {
        printf("%02x ", frame[i]);
        if ((i+1) % 16 == 0) printf("\n   ");
    }
    printf("\n\n");
}

void log_packet_to_file(const uint8_t *packet, size_t len, const char *direction) {
    if (!capture_log || len < 26) return;

    uint16_t proto = (packet[12] << 8) | packet[13];
    if (proto != XBOX_PROTOCOL) return;

    const uint8_t *body = packet + 14;
    if (len - 14 < 12) return;

    uint8_t type = body[7];
    uint16_t nonce = (body[8] << 8) | body[9];

    fprintf(capture_log, "\n========== PACKET #%d ==========\n", ++packet_count);
    fprintf(capture_log, "Direction: %s\n", direction);
    fprintf(capture_log, "Type: 0x%02x, Nonce: 0x%04x\n", type, nonce);
    fprintf(capture_log, "Length: %zu bytes\n\n", len);

    for (size_t i = 0; i < len; i++) {
        if (i % 16 == 0) fprintf(capture_log, "  %04zx: ", i);
        fprintf(capture_log, "%02x ", packet[i]);
        if ((i + 1) % 16 == 0) fprintf(capture_log, "\n");
    }
    if (len % 16 != 0) fprintf(capture_log, "\n");
    fprintf(capture_log, "\n");
    fflush(capture_log);
}

int send_raw_frame(const uint8_t *frame, size_t len, const uint8_t *dest_mac, int sock) {
    /* FIX 1: Determine interface index explicitly */
    int use_index;
    if (sock == sockfd) {
        use_index = if_index;
    } else if (sock == sockfd2 && sockfd2 != -1) {
        use_index = if_index2;
    } else {
        fprintf(stderr, "ERROR: Invalid socket %d (sockfd=%d, sockfd2=%d)\n",
                sock, sockfd, sockfd2);
        return -1;
    }

    struct sockaddr_ll addr = {0};
    addr.sll_family = AF_PACKET;
    addr.sll_ifindex = use_index;  /* Use determined index, not conditional */
    addr.sll_halen = ETH_ALEN;
    addr.sll_protocol = 0;
    memcpy(addr.sll_addr, dest_mac, 6);

    /* FIX 2: Add retry loop for partial sends (like Python and working C) */
    ssize_t total_sent = 0;
    while ((size_t)total_sent < len) {
        ssize_t sent = sendto(sock, frame + total_sent, len - (size_t)total_sent,
                             0, (struct sockaddr *)&addr, sizeof(addr));
        if (sent < 0) {
            perror("sendto");
            fprintf(stderr, "  sock=%d, if_index=%d, len=%zu\n",
                    sock, use_index, len);
            return -1;
        }
        total_sent += sent;
    }

    printf("SEND: %zd bytes transmitted\n", total_sent);
    return (int)total_sent;
}

int send_packet(uint8_t type, uint16_t nonce, const uint8_t *payload,
                size_t payload_len, const uint8_t *dest_mac, int sock) {
    uint8_t frame[BUFFER_SIZE], body[BUFFER_SIZE];
    memset(body, 0, sizeof(body));

    /* CRITICAL FIX: Different padding rules for different packet types */
    size_t actual_payload_len;

    if (type == PKT_HANDSHAKE_RESPONSE) {
        /* Handshake response: use exact payload size (should be 256) */
        actual_payload_len = payload_len;  /* Should be 268 total */
    } else if (type == PKT_BEACON_RESPONSE || type == PKT_CONNECT_TO_SSID_RESPONSE) {
        /* Short responses: pad to minimum frame size */
        actual_payload_len = (payload_len < 34) ? 34 : payload_len;
    } else {
        /* Other packets: use as-is */
        actual_payload_len = payload_len;
    }

    /* Align to DWORD boundary (multiple of 4) */
    size_t padded_payload = (actual_payload_len + 3) & ~3;

    /* Total body = 12 byte header + padded payload */
    size_t total_body_len = 12 + padded_payload;
    uint8_t body_size_dwords = total_body_len / 4;

    /* Build body header */
    memcpy(body, "XBOX", 4);
    body[4] = 0x01;  /* Version byte 1 */
    body[5] = 0x01;  /* Version byte 2 */
    body[6] = body_size_dwords;
    body[7] = type;
    body[8] = (nonce >> 8) & 0xff;
    body[9] = nonce & 0xff;
    body[10] = 0x00;  /* Checksum placeholder */
    body[11] = 0x00;

    /* Copy payload (if provided) */
    if (payload && payload_len > 0) {
        memcpy(body + 12, payload, payload_len);
    }

    /* Zero-pad the rest up to padded_payload */
    if (padded_payload > payload_len) {
        memset(body + 12 + payload_len, 0, padded_payload - payload_len);
    }

    /* Calculate checksum over entire body (with checksum bytes zeroed) */
    uint16_t checksum = calculate_checksum(body, total_body_len);
    body[10] = (checksum >> 8) & 0xff;
    body[11] = checksum & 0xff;

    /* Build Ethernet frame */
    size_t frame_len = 0;
    memcpy(frame, dest_mac, 6);        /* Destination MAC (Xbox's MAC) */
    frame_len += 6;
    memcpy(frame + 6, MN740_MAC_ADDR, 6);   /* Source MAC = REAL MN-740 MAC */
    frame_len += 6;
    frame[12] = 0x88;                  /* EtherType 0x886f */
    frame[13] = 0x6f;
    frame_len += 2;
    memcpy(frame + frame_len, body, total_body_len);
    frame_len += total_body_len;

    /* Debug output */
    printf("SEND: Type=0x%02x, Nonce=0x%04x, BodyDWORDs=0x%02x (%zu bytes), Frame=%zu bytes\n",
           type, nonce, body_size_dwords, total_body_len, frame_len);

    /* Log to capture file */
    if (capture_log) {
        log_packet_to_file(frame, frame_len, "ADAPTER->CONSOLE");
    }

    return send_raw_frame(frame, frame_len, dest_mac, sock);
}

int init_socket(const char *iface, int *sock_out, int *idx_out, uint8_t *mac_out) {
        struct ifreq ifr;

        /* Create RAW socket */
        *sock_out = socket(AF_PACKET, SOCK_RAW, htons(XBOX_PROTOCOL));
        if (*sock_out < 0) {
            perror("socket");
            return -1;
        }

        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);

        /* Get hardware address */
        if (ioctl(*sock_out, SIOCGIFHWADDR, &ifr) < 0) {
            perror("ioctl SIOCGIFHWADDR");
            close(*sock_out);
            return -1;
        }
        memcpy(mac_out, ifr.ifr_hwaddr.sa_data, 6);

        /* Get interface index */
        if (ioctl(*sock_out, SIOCGIFINDEX, &ifr) < 0) {
            perror("ioctl SIOCGIFINDEX");
            close(*sock_out);
            return -1;
        }
				printf("DEBUG: binding sock=%d to iface=%s idx=%d\n", *sock_out, iface, ifr.ifr_ifindex);
        *idx_out = ifr.ifr_ifindex;


				/* ALWAYS enable promiscuous mode for ALL modes (like tcpdump) */
				printf("Enabling promiscuous mode on %s for Xbox traffic...\n", iface);

				/* 1. Socket-level promiscuous (CRITICAL) */
				struct packet_mreq mreq = {0};
				mreq.mr_ifindex = *idx_out;  /* eth0 idx=2 */
				mreq.mr_type = PACKET_MR_PROMISC;
				if (setsockopt(*sock_out, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
				    perror("setsockopt PACKET_MR_PROMISC");
				    printf("WARNING: Socket promisc failed, trying interface-level...\n");
				} else {
				    printf("✓ Socket-level promiscuous mode enabled\n");
				}

				/* 2. Interface-level promiscuous (backup) */
				struct ifreq ifr_promo;
				memset(&ifr_promo, 0, sizeof(ifr_promo));
				strncpy(ifr_promo.ifr_name, iface, IFNAMSIZ-1);

				if (ioctl(*sock_out, SIOCGIFFLAGS, &ifr_promo) == 0) {
				    ifr_promo.ifr_flags |= IFF_PROMISC;
				    if (ioctl(*sock_out, SIOCSIFFLAGS, &ifr_promo) == 0) {
				        printf("✓ Interface-level promiscuous mode enabled\n");
				    } else {
				        perror("ioctl IFF_PROMISC");
				    }
				} else {
				    perror("ioctl SIOCGIFFLAGS");
				}


        /* Bind to interface */
        struct sockaddr_ll addr = {0};
        addr.sll_family = AF_PACKET;
        addr.sll_ifindex = *idx_out;
        addr.sll_protocol = 0;

        if (bind(*sock_out, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            perror("bind");
            close(*sock_out);
            return -1;
        }

        return 0;
    }

/* Protocol handlers */

void send_handshake_as_xbox(const uint8_t *target_mac) {
    uint8_t challenge[16];
    for (int i = 0; i < 16; i++) challenge[i] = rand() & 0xff;
    printf("\n[XBOX MODE] Sending handshake...\n");
    send_packet(PKT_HANDSHAKE_REQUEST, current_nonce++, challenge, 16, target_mac, sockfd);
}

void send_beacon_as_xbox(const uint8_t *target_mac) {
    uint8_t beacon_data[4] = {0x01, 0x00, 0x00, 0x00};
    send_packet(PKT_BEACON_REQUEST, current_nonce++, beacon_data, 4, target_mac, sockfd);
}

void send_networks_request_as_xbox(const uint8_t *target_mac) {
    uint8_t req[34] = {0};
    send_packet(PKT_NETWORKS_LIST_REQUEST, current_nonce++, req, 34, target_mac, sockfd);
}

void send_adapter_info_request_as_xbox(const uint8_t *target_mac) {
    uint8_t req[34] = {0};
    send_packet(PKT_ADAPTER_INFO_REQUEST, current_nonce++, req, 34, target_mac, sockfd);
}

void handle_handshake_request(const uint8_t *payload, size_t len,
                               uint16_t nonce, const uint8_t *src_mac,
                               const uint8_t *xbox_mac) {
    printf("\n[HANDSHAKE REQUEST]\n");
    if (len < 16) return;

    /* Update adapter state from system if connected */
    if (xbox_saved_profile.is_saved) {
        strncpy(adapter_state.current_ssid, xbox_saved_profile.ssid,
                sizeof(adapter_state.current_ssid) - 1);
        adapter_state.current_ssid[sizeof(adapter_state.current_ssid) - 1] = '\0';
        adapter_state.current_security = xbox_saved_profile.sec_type;
        adapter_state.is_connected = 1;

        /* Try to get real system info (BSSID, channel, PHY mode, signal) */
        update_adapter_state_from_system(&adapter_state, "wlan0");
    } else {
        adapter_state.is_connected = 0;
        memset(adapter_state.current_ssid, 0, sizeof(adapter_state.current_ssid));
    }

    /* Build and send response with full connection metadata */
    uint8_t full_payload[256];
    build_handshake_response(full_payload, payload, &adapter_state);

    /* Reply to Xbox's MAC (from Ethernet dest field) */
    send_packet(PKT_HANDSHAKE_RESPONSE, nonce, full_payload, 256, xbox_mac, sockfd);
    conn_state = STATE_HANDSHAKE_DONE;

    printf("✓ Handshake complete\n");
    if (adapter_state.is_connected) {
        printf("  Connected to: %s\n", adapter_state.current_ssid);
				printf("  BSSID: ");
				print_mac(adapter_state.current_bssid);
				printf("\n");
        printf("  Channel: %d\n", adapter_state.current_channel);
        const char *phy_str =
               adapter_state.current_phy_mode == 1 ? "802.11b" :
               adapter_state.current_phy_mode == 2 ? "802.11g" :
               adapter_state.current_phy_mode == 3 ? "802.11n" :
               adapter_state.current_phy_mode == 5 ? "802.11ac" : "Unknown";
        printf("  PHY Mode: %s\n", phy_str);
        printf("  Signal: %d%% (0x%02x)\n",
               (adapter_state.signal_quality * 100) / 255,
               adapter_state.signal_quality);
    }
}

void handle_beacon_request(uint16_t nonce, const uint8_t *dest_mac) {
    beacon_count++;
    if (conn_state == STATE_HANDSHAKE_DONE && beacon_count >= 3) {
        conn_state = STATE_LINKED;
        printf("\n✓ LINK ESTABLISHED\n\n");
    }
    uint8_t response[4] = {0x02, 0x80, 0x00, 0x00};
    send_packet(PKT_BEACON_RESPONSE, nonce, response, 4, dest_mac, sockfd);
}

void handle_networks_list_request(uint16_t nonce, const uint8_t *dest_mac) {
    printf("\n[NETWORKS LIST REQUEST]\n");

    /* Send 980 bytes to match Python emulator (15 complete + 1 partial slot) */
    uint8_t buffer[980];
    memset(buffer, 0, sizeof(buffer));

    buffer[0] = 15;  /* Claim 15 networks */
    size_t pos = 1;
    int count = 0;

    /* Scan for networks */
    printf("  Scanning for WiFi networks...\n");
    FILE *fp = popen("/usr/sbin/xboxwireless-config.sh --scan 2>/dev/null", "r");

    if (fp) {
        char line[256];
        while (fgets(line, sizeof(line), fp) && count < 15) {
            char ssid[33];
            int sec, signal;

            if (sscanf(line, "%32[^|]|%d|%d", ssid, &sec, &signal) == 3) {
                if (xbox_saved_profile.is_saved &&
                    strcmp(ssid, xbox_saved_profile.ssid) == 0) {
                    continue;
                }

                printf("  Found: %-32s (sec=%d, signal=0x%02x)\n", ssid, sec, signal);
                add_network_slot(buffer, &pos, count, ssid, sec, signal);
                count++;
            }
        }
        pclose(fp);
    } else {
        printf("  Warning: Could not run scan, using dummy networks\n");
        /* Fill at least 15 slots with dummy data */
        while (count < 15) {
            char dummy[33];
            snprintf(dummy, sizeof(dummy), "DummyNet_%d", count);
            add_network_slot(buffer, &pos, count, dummy, 0x00, 0xB1);
            count++;
        }
    }

    /* Add saved profile if exists */
    if (xbox_saved_profile.is_saved && count < 15) {
        printf("  Adding saved: %s\n", xbox_saved_profile.ssid);
        add_network_slot(buffer, &pos, count++,
                        xbox_saved_profile.ssid,
                        xbox_saved_profile.sec_type,
                        0xB5);
    }

    /* Fill remaining complete slots (up to 15 total) */
    while (count < 15) {
        size_t slot_start = pos;
        buffer[slot_start + 0] = 0xAA;
        buffer[slot_start + 1] = 0xAA;
        buffer[slot_start + 2] = 0xAA;
        buffer[slot_start + 3] = 0xAA;
        buffer[slot_start + 4] = 0xAA;
        buffer[slot_start + 5] = 0xA0 + count;
        buffer[slot_start + 6] = 0x01;
        buffer[slot_start + 7] = 0x00;
        buffer[slot_start + 40] = 0x02;
        buffer[slot_start + 41] = 0x01;
        buffer[slot_start + 42] = 0x04;
        buffer[slot_start + 43] = 0x06;
        buffer[slot_start + 44] = 0xA7;
        pos += 64;
        count++;
    }

    /* Add truncated 16th slot (19 bytes to reach 980 total)
     * 1 + (15 * 64) = 961, need 19 more bytes */
    buffer[pos++] = 0xAA;
    buffer[pos++] = 0xAA;
    buffer[pos++] = 0xAA;
    buffer[pos++] = 0xAA;
    buffer[pos++] = 0xAA;
    buffer[pos++] = 0xAF;  /* Slot 15 */
    buffer[pos++] = 0x01;  /* Tag */
    buffer[pos++] = 0x0B;  /* Length 11 */
    /* 11 bytes of SSID */
    for (int i = 0; i < 11; i++) {
        buffer[pos++] = 0x6B;  /* 'k' */
    }
    /* pos should now be 980 */

    printf("  Sending %d slots (%d bytes)\n", 16, 980);
    send_packet(PKT_NETWORKS_LIST_RESPONSE, nonce, buffer, 980, dest_mac, sockfd);
}

/* UI/Menu functions */

void interactive_connect_menu(void) {
    if (discovered_count == 0) {
        printf("\nNo networks available. Request network list first.\n");
        return;
    }

    printf("\n========================================\n");
    printf("  CONNECT TO NETWORK\n");
    printf("========================================\n");

    /* Show networks again */
    for (int i = 0; i < 16; i++) {
        if (discovered_networks[i].valid) {
            printf("[%2d] %s\n", i, discovered_networks[i].ssid);
        }
    }

    printf("\nSelect network (0-%d, or 'c' to cancel): ", discovered_count - 1);

    char input[10];
    if (!fgets(input, sizeof(input), stdin)) return;

    if (input[0] == 'c' || input[0] == 'C') {
        printf("Cancelled.\n");
        return;
    }

    int selection = atoi(input);
    if (selection < 0 || selection >= 16 || !discovered_networks[selection].valid) {
        printf("Invalid selection.\n");
        return;
    }

    network_info_t *net = &discovered_networks[selection];

    printf("\nSelected: %s\n", net->ssid);
    printf("Security: 0x%02x\n", net->security_type);

    char password[64] = {0};

    /* Ask for password if network is secured */
    if (net->security_type != 0x00) {
        printf("Enter password (or press Enter for none): ");
        disable_echo();
        if (fgets(password, sizeof(password), stdin)) {

            size_t len = strlen(password);
            if (len > 0 && password[len-1] == '\n') {
                password[len-1] = '\0';
            }
        }
        enable_echo();
        printf("\n");
    }

    /* Build connect request TLV payload */
    uint8_t payload[256];
    size_t pos = 0;

    /* Tag 0x01: SSID */
    payload[pos++] = 0x01;
    payload[pos++] = strlen(net->ssid);
    memcpy(payload + pos, net->ssid, strlen(net->ssid));
    pos += strlen(net->ssid);

    /* Tag 0x02: Password (if provided) */
    if (password[0] != '\0') {
        payload[pos++] = 0x02;
        payload[pos++] = strlen(password);
        memcpy(payload + pos, password, strlen(password));
        pos += strlen(password);
    }

    /* Tag 0x03: Security type */
    payload[pos++] = 0x03;
    payload[pos++] = 0x01;
    payload[pos++] = net->security_type;

    printf("\nSending connect request...\n");
    printf("  SSID: %s\n", net->ssid);
    printf("  Security: 0x%02x\n", net->security_type);

    send_packet(PKT_CONNECT_TO_SSID_REQUEST, current_nonce++,
                payload, pos, adapter_mac, sockfd);

    printf("✓ Connect request sent, waiting for response...\n");
}

void show_xbox_menu(void) {
    printf("\n========================================\n");
    printf("  XBOX EMULATION MENU\n");
    printf("========================================\n");
    printf("[1] Request network list\n");
    printf("[2] Request adapter info\n");
    printf("[3] Send beacon\n");
    printf("[4] Connect to network\n");
    printf("[5] Show discovered networks\n");
    printf("[q] Quit\n");
    printf("========================================\n");
    printf("Select option: ");
}

int handle_xbox_menu_input(char choice) {
    switch (choice) {
        case '1':
            printf("\nRequesting network list...\n");
            send_networks_request_as_xbox(adapter_mac);
            printf("✓ Request sent, waiting for response...\n");
            break;

        case '2':
            printf("\nRequesting adapter info...\n");
            send_adapter_info_request_as_xbox(adapter_mac);
            printf("✓ Request sent, waiting for response...\n");
            break;

        case '3':
            printf("\nSending beacon...\n");
            send_beacon_as_xbox(adapter_mac);
            printf("✓ Beacon sent\n");
            break;

        case '4':
            interactive_connect_menu();
            break;

        case '5':
            if (discovered_count == 0) {
                printf("\nNo networks discovered yet. Request network list first.\n");
            } else {
                printf("\n========================================\n");
                printf("  DISCOVERED NETWORKS\n");
                printf("========================================\n");
                for (int i = 0; i < 16; i++) {
                    if (discovered_networks[i].valid) {
                        printf("[%2d] %-32s  Signal: %3d  Security: 0x%02x\n",
                               i, discovered_networks[i].ssid,
                               discovered_networks[i].signal_strength,
                               discovered_networks[i].security_type);
                    }
                }
                printf("========================================\n");
            }
            break;

        case 'q':
        case 'Q':
            printf("\nQuitting...\n");
            return 0;

        default:
            printf("\nInvalid option.\n");
            break;
    }

    return 1;
}

/* Main packet processor */

void process_packet(const uint8_t *packet, size_t len) {
    if (len < 26) return;
    uint16_t proto = (packet[12] << 8) | packet[13];
    if (proto != XBOX_PROTOCOL) return;

    const uint8_t *src_mac = packet + 6;
    const uint8_t *dst_mac = packet + 0;
    const uint8_t *body = packet + 14;

    if (memcmp(body, "XBOX", 4) != 0) return;

    uint8_t type = body[7];
    uint16_t nonce = (body[8] << 8) | body[9];
    uint8_t body_dwords = body[6];
    size_t payload_len = (body_dwords * 4 >= 12) ? (body_dwords * 4 - 12) : 0;
    const uint8_t *payload = (payload_len > 0) ? body + 12 : NULL;

    if (capture_log) {
        const char *dir = (memcmp(src_mac, local_mac, 6) == 0) ? "ADAPTER->CONSOLE" : "CONSOLE->ADAPTER";
        log_packet_to_file(packet, len, dir);
    }

    if (operation_mode == MODE_EMULATE_ADAPTER) {
	    switch (type) {
                case PKT_HANDSHAKE_REQUEST:
                    if (payload && payload_len >= 16)
                        /* Pass BOTH src_mac and dst_mac (Xbox's MAC from Ethernet header) */
			handle_handshake_request(payload, payload_len, nonce, src_mac, src_mac);
                    break;
            case PKT_BEACON_REQUEST:
                handle_beacon_request(nonce, src_mac);
                break;

            case PKT_ADAPTER_INFO_REQUEST:
                {
                    uint8_t adapter_info[256] = {0};
                    /* Populate with adapter MAC, capabilities, etc. */
                    memcpy(adapter_info, local_mac, 6);
                    adapter_info[6] = 0x01;  /* Adapter ready */
                    send_packet(PKT_ADAPTER_INFO_RESPONSE, nonce, adapter_info, 256, src_mac, sockfd);
                }
                break;


            case PKT_CONNECT_TO_SSID_REQUEST:
                if (payload && payload_len > 0) {
                    parsed_wifi_config_t config = parse_connect_tlv(payload, payload_len);
                    if (config.valid) {
                      strncpy(xbox_saved_profile.ssid, config.ssid, sizeof(xbox_saved_profile.ssid) - 1);
                      xbox_saved_profile.ssid[sizeof(xbox_saved_profile.ssid) - 1] = '\0';
                        strncpy(xbox_saved_profile.password, config.password, sizeof(xbox_saved_profile.password) - 1);
                        xbox_saved_profile.sec_type = config.security_type;
                        xbox_saved_profile.is_saved = 1;
                        xbox_saved_profile.last_connect_attempt = time(NULL);
                        printf("\n[CONNECT REQUEST]\n");
                        printf("  ✓ Saved profile: %s (security: 0x%02x)\n",
                               config.ssid, config.security_type);
                    }
                    /* Send success response */
                    uint8_t resp[] = {0x00};
                    send_packet(PKT_CONNECT_TO_SSID_RESPONSE, nonce, resp, 1, src_mac, sockfd);
                }
                break;

            case PKT_NETWORKS_LIST_REQUEST:
                handle_networks_list_request(nonce, src_mac);
                break;

        }
    }   else if (operation_mode == MODE_EMULATE_XBOX) {
          switch (type) {
              case PKT_HANDSHAKE_RESPONSE:
                  conn_state = STATE_HANDSHAKE_DONE;
                  if (payload && payload_len >= 256) {
                      parse_handshake_response(payload, payload_len);
                  }
                  break;

              case PKT_BEACON_RESPONSE:
                  beacon_count++;
                  printf("[BEACON #%d] Received beacon response\n", beacon_count);

                  /* Parse beacon payload (4 bytes) */
                  if (payload && payload_len >= 4) {
                      printf("  Beacon data: %02x %02x %02x %02x\n",
                             payload[0], payload[1], payload[2], payload[3]);
                      if (payload[0] == 0x02) {
                          printf("  Link status: Active\n");
                      }
                  }

                  if (beacon_count >= 3 && conn_state == STATE_HANDSHAKE_DONE) {
                      conn_state = STATE_LINKED;
                      printf("✓ Link fully established\n");
                  }
                  break;

              case PKT_NETWORKS_LIST_RESPONSE:
                  printf("\n╔═══════════════════════════════════╗\n");
                  printf("║  ✓ NETWORK LIST RECEIVED!         ║\n");
                  printf("╚═══════════════════════════════════╝\n");
                  if (payload && payload_len > 0) {
                      parse_networks_response(payload, payload_len);
                      printf("\n→ You can now connect to a network (press 4)\n");
                  }
                  break;

              case PKT_ADAPTER_INFO_RESPONSE:
                  printf("\n╔═══════════════════════════════════╗\n");
                  printf("║  ✓ ADAPTER INFO RECEIVED!         ║\n");
                  printf("╚═══════════════════════════════════╝\n");
                  if (payload && payload_len > 0) {
                      printf("\nAdapter Details:\n");
                      if (payload_len >= 6) {
												printf("  MAC: ");
												print_mac(payload);
												printf("\n");
                      }
                      if (payload_len > 10) {
                          printf("  Status: 0x%02x (%s)\n",
                                 payload[10],
                                 payload[10] ? "Connected" : "Disconnected");
                      }

                      /* Try to parse current SSID if connected */
                      if (payload_len > 26) {
                          uint8_t ssid_len = payload[26];
                          if (ssid_len > 0 && ssid_len <= 32 && payload_len >= 27 + ssid_len) {
                              char current_ssid[33] = {0};
                              memcpy(current_ssid, payload + 27, ssid_len);
                              printf("  Current SSID: %s\n", current_ssid);
                          }
                      }
                  }
                  break;

              case PKT_CONNECT_TO_SSID_RESPONSE:
                  printf("\n╔═══════════════════════════════════╗\n");
                  printf("║  ✓ CONNECT RESPONSE RECEIVED!     ║\n");
                  printf("╚═══════════════════════════════════╝\n");
                  if (payload && payload_len > 0) {
                      if (payload[0] == 0x00) {
                          printf("\n✓✓✓ CONNECTION SUCCESS! ✓✓✓\n");
                          printf("Network configuration accepted by adapter.\n");
                          printf("The adapter should now be connecting to the network...\n");
                      } else {
                          printf("\n✗✗✗ CONNECTION FAILED! ✗✗✗\n");
                          printf("Status code: 0x%02x\n", payload[0]);
                      }
                  } else {
                      printf("\n✓ Connection request acknowledged (empty response)\n");
                  }
                  break;

              default:
                  printf("[XBOX MODE] Received unknown packet type 0x%02x\n", type);
                  break;
          }
      }
    }

/* Main function */

int main(int argc, char *argv[]) {
    printf("========================================\n");
    printf("  Xbox Wireless Protocol Tool\n");
    printf("  v7 - Multi-Mode Edition\n");
    printf("========================================\n\n");

    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    /* Parse arguments */
    const char *hex_file = NULL;
    const char *capture_file = NULL;
    const char *replay_file = NULL;
    const char *bridge_iface = NULL;
    int target_packet = -1;
    int listen_mode = 0;

    for (int i = 1; i < argc; i++) {
        if (i == 1) continue;  /* skip interface name */
        if (strcmp(argv[i], "--mode") == 0 && i + 1 < argc) {
            if (strcmp(argv[i + 1], "xbox") == 0) {
                operation_mode = MODE_EMULATE_XBOX;
            }
            i++;
        } else if (strcmp(argv[i], "--target") == 0 && i + 1 < argc) {
            parse_mac(argv[i + 1], adapter_mac);
            i++;
        } else if (strcmp(argv[i], "--send") == 0 && i + 1 < argc) {
            operation_mode = MODE_SEND_HEX;
            hex_file = argv[i + 1];
            i++;
        } else if (strcmp(argv[i], "--bridge") == 0 && i + 1 < argc) {
            operation_mode = MODE_BRIDGE;
            bridge_iface = argv[i + 1];
            i++;
        } else if (strcmp(argv[i], "--replay") == 0 && i + 1 < argc) {
            operation_mode = MODE_REPLAY;
            replay_file = argv[i + 1];
            i++;
        } else if (strcmp(argv[i], "--capture") == 0 && i + 1 < argc) {
            capture_file = argv[i + 1];
            i++;
        } else if (strcmp(argv[i], "--packet") == 0 && i + 1 < argc) {
            target_packet = atoi(argv[i + 1]);
            i++;
        } else if (strcmp(argv[i], "--listen") == 0) {
            listen_mode = 1;
        }
    }

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* Open capture log if requested */
    if (capture_file) {
        capture_log = fopen(capture_file, "w");
        if (capture_log) {
            time_t now = time(NULL);
            printf("CAPTURE: Logging to %s\n", capture_file);
            fprintf(capture_log, "Xbox Wireless Protocol Capture\n");
            fprintf(capture_log, "Started: %s", ctime(&now));
            fprintf(capture_log, "========================================\n\n");
        } else {
            fprintf(stderr, "Warning: Cannot open capture file\n");
        }
    }

    /* ========== MODE 1: SEND HEX FILE ========== */
    if (operation_mode == MODE_SEND_HEX) {
        printf("MODE: Send Hex File\n\n");

        if (!hex_file || adapter_mac[0] == 0) {
            fprintf(stderr, "Error: --send requires filename and --target MAC\n");
            return 1;
        }

        if (load_secrets() < 0) return 1;
        if (init_socket(argv[1], &sockfd, &if_index, local_mac) < 0) return 1;

        uint8_t frame[BUFFER_SIZE];
        size_t frame_len = 0;

        if (load_hex_file(hex_file, frame, &frame_len) < 0) return 1;

				printf("Sending %zu bytes to ", frame_len);
				print_mac(adapter_mac);
				printf("...\n");

        send_raw_frame(frame, frame_len, adapter_mac, sockfd);
        printf("✓ Packet sent\n");

        close(sockfd);
        if (capture_log) fclose(capture_log);
        return 0;
    }

    /* ========== MODE 2: BRIDGE MODE (MITM) ========== */
    if (operation_mode == MODE_BRIDGE) {
        printf("MODE: Bridge (Man-in-the-Middle)\n\n");

        if (!bridge_iface) {
            fprintf(stderr, "Error: --bridge requires second interface\n");
            return 1;
        }

        if (load_secrets() < 0) return 1;

        /* Initialize both interfaces */
        if (init_socket(argv[1], &sockfd, &if_index, local_mac) < 0) return 1;

        uint8_t mac2[6];
        if (init_socket(bridge_iface, &sockfd2, &if_index2, mac2) < 0) return 1;

        strncpy(interface_name, argv[1], IFNAMSIZ - 1);
        strncpy(interface_name2, bridge_iface, IFNAMSIZ - 1);

        /* Learn device MACs on first packet */
        uint8_t xbox_learned_mac[6] = {0};
        uint8_t adapter_learned_mac[6] = {0};
        int xbox_mac_learned = 0;
        int adapter_mac_learned = 0;

        printf("========================================\n");
        printf("  BRIDGE MODE ACTIVE\n");
        printf("========================================\n");
				printf("Interface 1 (Xbox side):    %s (", interface_name);
				print_mac(local_mac);
				printf(")\n");
				printf("Interface 2 (Adapter side): %s (", interface_name2);
				print_mac(mac2);
				printf(")\n");
        printf("\nLearning device MACs from first packets...\n");
        printf("Forwarding packets between devices...\n");
        printf("Press Ctrl+C to stop\n\n");

        uint8_t buffer[BUFFER_SIZE];
        int packet_num = 0;

        while (running) {
            fd_set fds;
            FD_ZERO(&fds);
            FD_SET(sockfd, &fds);
            FD_SET(sockfd2, &fds);
            int max_fd = (sockfd > sockfd2) ? sockfd : sockfd2;

            struct timeval tv = {.tv_sec = 1, .tv_usec = 0};
            int ret = select(max_fd + 1, &fds, NULL, NULL, &tv);

            if (ret > 0) {
                /* Packet from Interface 1 (Xbox side) */
                if (FD_ISSET(sockfd, &fds)) {
                    ssize_t len = recvfrom(sockfd, buffer, sizeof(buffer), 0, NULL, NULL);
                    if (len > 0 && len >= 14) {
                        uint16_t proto = (buffer[12] << 8) | buffer[13];

                        if (proto == XBOX_PROTOCOL) {
                            packet_num++;

                            /* Learn Xbox MAC from source address on first packet */
                            if (!xbox_mac_learned) {
                                memcpy(xbox_learned_mac, buffer + 6, 6);  /* Source MAC */
                                xbox_mac_learned = 1;
																printf("✓ Learned Xbox MAC: ");
																print_mac(xbox_learned_mac);
																printf("\n");
                            }

                            printf("\n[BRIDGE #%d] XBOX → ADAPTER (%zd bytes)\n", packet_num, len);

                            /* Parse packet info */
                            if (len >= 26) {
                                const uint8_t *body = buffer + 14;
                                if (memcmp(body, "XBOX", 4) == 0) {
                                    uint8_t type = body[7];
                                    uint16_t nonce = (body[8] << 8) | body[9];
                                    const char *type_name = get_packet_type_name(type);
                                    printf("  Type: 0x%02x (%s), Nonce: 0x%04x\n",
                                           type, type_name, nonce);

                                    if (type == PKT_CONNECT_TO_SSID_REQUEST) {
                                        parse_and_display_connect_request(body, len - 14);
                                    }

                                    if (capture_log) {
                                        log_packet_to_file(buffer, len, "XBOX→ADAPTER");
                                    }
                                }
                            }

                            /* CRITICAL FIX: Forward packet UNCHANGED - pure transparent bridge */
                            /* Don't modify any MACs - just forward as-is */
                            const uint8_t *original_dest = buffer + 0;  /* Keep original destination */

														printf("  → Forwarding unchanged to adapter (dest: ");
														print_mac(buffer + 0);
														printf(", src: ");
														print_mac(buffer + 6);
														printf(")\n");

                            send_raw_frame(buffer, len, original_dest, sockfd2);
                            printf("  ✓ Forwarded to adapter interface\n");
                        }
                    }
                }

                /* Packet from Interface 2 (Adapter side) */
                if (FD_ISSET(sockfd2, &fds)) {
                    ssize_t len = recvfrom(sockfd2, buffer, sizeof(buffer), 0, NULL, NULL);
                    if (len > 0 && len >= 14) {
                        uint16_t proto = (buffer[12] << 8) | buffer[13];

                        if (proto == XBOX_PROTOCOL) {
                            packet_num++;

                            /* Learn adapter MAC from source address on first response */
                            if (!adapter_mac_learned) {
                                memcpy(adapter_learned_mac, buffer + 6, 6);  /* Source MAC */
                                adapter_mac_learned = 1;
																printf("✓ Learned Adapter MAC: ");
																print_mac(adapter_learned_mac);
																printf("\n");
                                if (xbox_mac_learned) {
                                    printf("\n✓✓✓ Both MACs learned - bridge fully operational! ✓✓✓\n\n");
                                }
                            }

                            printf("\n[BRIDGE #%d] ADAPTER → XBOX (%zd bytes)\n", packet_num, len);

                            /* Parse packet info */
                            if (len >= 26) {
                                const uint8_t *body = buffer + 14;
                                if (memcmp(body, "XBOX", 4) == 0) {
                                    uint8_t type = body[7];
                                    uint16_t nonce = (body[8] << 8) | body[9];
                                    uint8_t body_dwords = body[6];
                                    const char *type_name = get_packet_type_name(type);
                                    printf("  Type: 0x%02x (%s), Nonce: 0x%04x, Body: %d dwords\n",
                                           type, type_name, nonce, body_dwords);

                                    if (type == PKT_NETWORKS_LIST_RESPONSE) {
                                        parse_and_display_network_list(body, len - 14);
                                    } else if (type == PKT_HANDSHAKE_RESPONSE) {
                                        printf("  → Handshake response with HMAC and adapter info\n");
                                    } else if (type == PKT_CONNECT_TO_SSID_RESPONSE) {
                                        size_t payload_len = (body_dwords * 4) - 12;
                                        if (payload_len > 0) {
                                            const uint8_t *payload = body + 12;
                                            printf("  → Status: 0x%02x (%s)\n",
                                                   payload[0],
                                                   payload[0] == 0 ? "SUCCESS" : "FAILURE");
                                        }
                                    }

                                    if (capture_log) {
                                        log_packet_to_file(buffer, len, "ADAPTER→XBOX");
                                    }
                                }
                            }

                            /* CRITICAL FIX: Forward to Xbox's learned MAC */
                            if (xbox_mac_learned) {
                                /* Change destination to Xbox's MAC */
                                memcpy(buffer, xbox_learned_mac, 6);
																printf("  → Forwarding to Xbox MAC: ");
																print_mac(xbox_learned_mac);
																printf("\n");
                            } else {
                                /* Shouldn't happen, but use broadcast as fallback*/
                                memset(buffer, 0xff, 6);
                                printf("  → Broadcasting (Xbox MAC not learned)\n");
                            }

                            /* Change source to interface 1's MAC */
                            memcpy(buffer + 6, local_mac, 6);

                            send_raw_frame(buffer, len, buffer, sockfd);  /* dst_mac is buffer[0-5] */
                            printf("  ✓ Forwarded to Xbox interface\n");
                        }
                    }
                }
            }
        }

        printf("\n========================================\n");
        printf("Bridge Statistics:\n");
        printf("  Total packets: %d\n", packet_num);
				printf("  Xbox MAC: ");
				print_mac(xbox_learned_mac);
				printf("\n");
				printf("  Adapter MAC: ");
				print_mac(adapter_learned_mac);
				printf("\n");
        printf("========================================\n");

        close(sockfd);
        close(sockfd2);
        if (capture_log) fclose(capture_log);
        return 0;
    }

    /* ========== MODE 3: XBOX EMULATION (send to real adapter) ========== */
    if (operation_mode == MODE_EMULATE_XBOX) {
        printf("MODE: Xbox Console Emulation (Interactive)\n\n");

        /* Check if MAC was actually set */
        int mac_is_zero = 1;
        for (int i = 0; i < 6; i++) {
            if (adapter_mac[i] != 0) {
                mac_is_zero = 0;
                break;
            }
        }

        if (mac_is_zero) {
            fprintf(stderr, "Error: Xbox mode requires --target MAC\n");
            fprintf(stderr, "Example: --mode xbox --target aa:bb:cc:dd:ee:ff\n");
            return 1;
        }

        if (load_secrets() < 0) return 1;
        if (init_socket(argv[1], &sockfd, &if_index, local_mac) < 0) return 1;

        printf("Emulating Xbox console...\n");
				printf("Local MAC:  ");
				print_mac(local_mac);
				printf("\n");

				printf("Target MAC: ");
				print_mac(adapter_mac);
				printf("\n");

        printf("\n========================================\n");
        printf("Sending handshake requests every 2 seconds\n");
        printf("until adapter responds...\n");
        printf("========================================\n\n");

        uint8_t buffer[BUFFER_SIZE];
        time_t last_handshake = 0;
        int handshake_attempts = 0;

        /* Initial handshake */
        send_handshake_as_xbox(adapter_mac);
        last_handshake = time(NULL);
        handshake_attempts = 1;
        printf("[Attempt #%d] Handshake sent, waiting for response...\n", handshake_attempts);

        while (running) {
            fd_set fds;
            struct timeval tv = {.tv_sec = 0, .tv_usec = 100000};
            FD_ZERO(&fds);
            FD_SET(sockfd, &fds);

            if (select(sockfd + 1, &fds, NULL, NULL, &tv) > 0) {
                ssize_t len = recvfrom(sockfd, buffer, sizeof(buffer), 0, NULL, NULL);
                if (len > 0) {
                    process_packet(buffer, (size_t)len);

                    /* Break out to interactive menu once handshake completes */
                    if (conn_state == STATE_HANDSHAKE_DONE) {
                        printf("\n✓✓✓ Authentication successful! ✓✓✓\n");
                        break;
                    }
                }
            }

            /* Retry handshake every 2 seconds if no response */
            if (conn_state == STATE_DISCONNECTED && time(NULL) - last_handshake >= 2) {
                handshake_attempts++;
                printf("[Attempt #%d] Retrying handshake...\n", handshake_attempts);
                send_handshake_as_xbox(adapter_mac);
                last_handshake = time(NULL);
            }
        }

        /* If we got here and still disconnected, exit */
        if (conn_state == STATE_DISCONNECTED) {
            printf("\nNo response from adapter. Exiting.\n");
            close(sockfd);
            return 1;
        }

        /* ========== INTERACTIVE MENU MODE ========== */
        printf("\n========================================\n");
        printf("  ENTERING INTERACTIVE MENU MODE\n");
        printf("========================================\n");

        /* Show initial menu */
        show_xbox_menu();

        /* Main interactive loop */
        char input[256];
        while (running) {
            /* Check for incoming packets (non-blocking) */
            fd_set fds;
            struct timeval tv = {.tv_sec = 0, .tv_usec = 10000};
            FD_ZERO(&fds);
            FD_SET(sockfd, &fds);

            if (select(sockfd + 1, &fds, NULL, NULL, &tv) > 0) {
                ssize_t len = recvfrom(sockfd, buffer, sizeof(buffer), 0, NULL, NULL);
                if (len > 0) {
                    process_packet(buffer, (size_t)len);
                }
            }

            /* Check for user input (blocking with timeout) */
            fd_set input_fds;
            struct timeval input_tv = {.tv_sec = 0, .tv_usec = 100000};
            FD_ZERO(&input_fds);
            FD_SET(STDIN_FILENO, &input_fds);

            if (select(STDIN_FILENO + 1, &input_fds, NULL, NULL, &input_tv) > 0) {
                if (fgets(input, sizeof(input), stdin)) {
                    if (!handle_xbox_menu_input(input[0])) {
                        break;  /* User quit */
                    }

                    /* Show menu again after action */
                    printf("\n");
                    show_xbox_menu();
                }
            }
        }

        printf("\n========================================\n");
        printf("Xbox Emulation Statistics:\n");
        printf("  Handshake attempts: %d\n", handshake_attempts);
        printf("  State: %s\n",
               conn_state == STATE_LINKED ? "LINKED" :
               conn_state == STATE_HANDSHAKE_DONE ? "HANDSHAKE_DONE" :
               "DISCONNECTED");
        printf("  Beacons: %d\n", beacon_count);
        printf("  Networks discovered: %d\n", discovered_count);
        printf("========================================\n");

        close(sockfd);
        if (capture_log) fclose(capture_log);
        return 0;
    }

    /* ========== MODE 4: ADAPTER EMULATION (default - respond to Xbox) ========== */
    printf("MODE: Adapter Emulation (Default)\n\n");

    if (load_secrets() < 0) {
        fprintf(stderr, "Failed to load secrets from ./secrets/\n");
        return 1;
    }

    if (init_socket(argv[1], &sockfd, &if_index, local_mac) < 0) {
        return 1;
    }

    strncpy(interface_name, argv[1], IFNAMSIZ - 1);
		printf("Interface: %s (", interface_name);
		print_mac(local_mac);
		printf(")\n");

    if (listen_mode) {
         printf("\n========================================\n");
         printf("  LISTEN MODE: Passive Capture\n");
         printf("========================================\n");
         printf("Capturing Xbox protocol packets (0x886f)\n");
         printf("Interface: %s\n", interface_name);
         printf("Press Ctrl+C to stop\n\n");
    } else {
         printf("\n========================================\n");
         printf("  ADAPTER EMULATION MODE\n");
         printf("========================================\n");
         printf("Waiting for Xbox handshake on %s...\n", interface_name);
         printf("Make sure Xbox can see this interface!\n");
         printf("Press Ctrl+C to stop\n\n");
    }

    uint8_t buffer[BUFFER_SIZE];
        int captured_packets = 0;
        int total_packets_seen = 0;  /* Track ALL packets, not just Xbox protocol */

        while (running) {
           ssize_t len = recvfrom(sockfd, buffer, sizeof(buffer), 0, NULL, NULL);
					 /* ===== DEBUG BLOCK START ===== */
			     if (len > 14) {
			         uint16_t proto = (buffer[12]<<8) | buffer[13];
			         printf(">>> RAW: len=%zd proto=0x%04x [14-21]=%02x%02x%02x%02x %02x%02x%02x%02x\n",
			                len, proto,
			                buffer[14],buffer[15],buffer[16],buffer[17],
			                buffer[18],buffer[19],buffer[20],buffer[21]);
			     }

           if (len > 0) {
                 total_packets_seen++;

                 if (len >= 14) {
             /* Check if this is an Xbox protocol packet */
             uint16_t proto = (buffer[12] << 8) | buffer[13];

             if (proto == XBOX_PROTOCOL) {
                 captured_packets++;

                 if (listen_mode) {
                     /* Extract MACs */
                     const uint8_t *dst_mac = buffer + 0;
                     const uint8_t *src_mac = buffer + 6;

                     printf("\n[PACKET #%d] (%zd bytes)\n", captured_packets, len);
										 printf("  Dst MAC: ");
										 print_mac(dst_mac);
										 printf("\n");
										 printf("  Src MAC: ");
										 print_mac(src_mac);
										 printf("\n");

                     /* Try to parse Xbox packet header */
                     if (len >= 26) {
                         const uint8_t *body = buffer + 14;
                         if (memcmp(body, "XBOX", 4) == 0) {
                             uint8_t type = body[7];
                             uint16_t nonce = (body[8] << 8) | body[9];
                             uint8_t body_dwords = body[6];

                             const char *type_name = get_packet_type_name(type);
                             const char *direction = "UNKNOWN";

                             /* Determine direction */
                             if (memcmp(dst_mac, "\xff\xff\xff\xff\xff\xff", 6) == 0) {
                                 direction = "XBOX→BROADCAST";
                             } else if (type == PKT_HANDSHAKE_REQUEST ||
                                        type == PKT_NETWORKS_LIST_REQUEST ||
                                        type == PKT_ADAPTER_INFO_REQUEST ||
                                        type == PKT_CONNECT_TO_SSID_REQUEST ||
                                        type == PKT_BEACON_REQUEST) {
                                 direction = "XBOX→ADAPTER";
                             } else if (type == PKT_HANDSHAKE_RESPONSE ||
                                        type == PKT_NETWORKS_LIST_RESPONSE ||
                                        type == PKT_ADAPTER_INFO_RESPONSE ||
                                        type == PKT_CONNECT_TO_SSID_RESPONSE ||
                                        type == PKT_BEACON_RESPONSE) {
                                 direction = "ADAPTER→XBOX";
                             }

                             printf("  Type: 0x%02x (%s)\n", type, type_name);
                             printf("  Nonce: 0x%04x\n", nonce);
                             printf("  Body: %d dwords (%d bytes)\n",
                                    body_dwords, body_dwords * 4);
                             printf("  Direction: %s\n", direction);
                         } else {
                             printf("  (Invalid Xbox packet - missing 'XBOX' header)\n");
                         }
                     }

                     /* Log to file if capture enabled */
                     if (capture_log) {
                         const char *dir = (memcmp(src_mac, local_mac, 6) == 0) ?
                                           "LOCAL→REMOTE" : "REMOTE→LOCAL";
                         log_packet_to_file(buffer, (size_t)len, dir);
                     }

                     /* Optional: show hex dump for first 64 bytes */
                     printf("  Hex (first 64 bytes):\n   ");
                     size_t show_len = (len < 64) ? len : 64;
                     for (size_t i = 0; i < show_len; i++) {
                         printf("%02x ", buffer[i]);
                         if ((i + 1) % 16 == 0) printf("\n   ");
                     }
                     if (show_len % 16 != 0) printf("\n");

                 } else {
                     /* Normal mode - process packet */
                     process_packet(buffer, (size_t)len);
										 continue;
                 }
             } else if (!listen_mode && (total_packets_seen % 100 == 0)) {
                 /* In normal mode, periodically show we're receiving OTHER traffic */
                 printf("  [Debug] Received %d total packets, %d Xbox protocol...\n",
                        total_packets_seen, captured_packets);
             }
         }
    }

    printf("\n========================================\n");
        if (listen_mode) {
             printf("Capture Statistics:\n");
             printf("  Total packets captured: %d\n", captured_packets);
             printf("  Total packets seen: %d\n", total_packets_seen);
        } else {
             printf("Session Statistics:\n");
             printf("  Xbox packets: %d\n", packet_count);
             printf("  Total packets seen: %d\n", total_packets_seen);
             printf("  Beacons: %d\n", beacon_count);
             printf("  State: %s\n",
            conn_state == STATE_LINKED ? "LINKED" :
            conn_state == STATE_HANDSHAKE_DONE ? "HANDSHAKE_DONE" :
            "DISCONNECTED");
         if (xbox_saved_profile.is_saved) {
             printf("  Profile: %s\n", xbox_saved_profile.ssid);
         }
     }
    printf("========================================\n");

    if (capture_log) fclose(capture_log);
    close(sockfd);
    return 0;
  }
}

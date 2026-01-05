/*
 * packets.h - Xbox MN-740 Wireless Protocol Packet Structures
 * 
 * Complete type-safe definitions for all Xbox protocol packets.
 * Based on firmware reverse engineering (mn740_handshake_structure.md)
 * 
 * Copyright (C) 2026
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef XBOX_PACKETS_H
#define XBOX_PACKETS_H

#include <stdint.h>
#include <stddef.h>

/* ============================================================================
 * PROTOCOL CONSTANTS
 * ============================================================================
 */

/* EtherType and Network */
#define XBOX_PROTOCOL           0x886f
#define XBOX_UDP_PORT           2002
#define BUFFER_SIZE             8192

/* Packet Types */
#define PKT_ECHO                        0x00
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
#define PKT_DISCOVERY                   0x0d
#define PKT_DISCOVERY_RESPONSE          0x0e

/* Frame Sizes */
#define ETHERNET_HEADER_SIZE    14
#define XBOX_BODY_HEADER_SIZE   12
#define XBOX_MAGIC_SIZE         4       /* "XBOX" */
#define MAC_ADDRESS_SIZE        6

/* Handshake Packet Sizes */
#define HANDSHAKE_CHALLENGE_SIZE            16
#define HANDSHAKE_RESPONSE_PAYLOAD_SIZE     256
#define HANDSHAKE_RESPONSE_TOTAL_SIZE       282  /* 12 + 256 + 14 Ethernet */
#define HANDSHAKE_RESPONSE_DWORDS           67   /* 0x43 */

/* Handshake Response Field Offsets (within 256-byte payload) */
#define HANDSHAKE_RESPONSE_HMAC_OFFSET          0
#define HANDSHAKE_RESPONSE_HMAC_SIZE            20
#define HANDSHAKE_RESPONSE_COPYRIGHT_OFFSET     20
#define HANDSHAKE_RESPONSE_COPYRIGHT_SIZE       84
#define HANDSHAKE_RESPONSE_NAME_OFFSET          104
#define HANDSHAKE_RESPONSE_NAME_SIZE            32
#define HANDSHAKE_RESPONSE_FIRMWARE_OFFSET      136
#define HANDSHAKE_RESPONSE_FIRMWARE_SIZE        32

/* Wireless Stats Offsets - THE HOLY GRAIL (bytes 168-218) */
#define HANDSHAKE_RESPONSE_CAPS_OFFSET          168
#define HANDSHAKE_RESPONSE_UNKNOWN_FLAG_OFFSET  169
#define HANDSHAKE_RESPONSE_UNKNOWN_DATA_OFFSET  170
#define HANDSHAKE_RESPONSE_BSSID_OFFSET         174  /* 0xAE */
#define HANDSHAKE_RESPONSE_SIGNAL_OFFSET        180  /* 0xB4 */
#define HANDSHAKE_RESPONSE_LINK_QUALITY_OFFSET  181  /* 0xB5 */
#define HANDSHAKE_RESPONSE_IP_OFFSET            182  /* 0xB6 */
#define HANDSHAKE_RESPONSE_WIRELESS_MODE_OFFSET 218  /* 0xDA */

/* Connection Status Offsets */
#define HANDSHAKE_RESPONSE_HEADER_OFFSET        214
#define HANDSHAKE_RESPONSE_SSID_LEN_OFFSET      219  /* 0xDB */
#define HANDSHAKE_RESPONSE_SSID_OFFSET          220  /* 0xDC */
#define HANDSHAKE_RESPONSE_SSID_SIZE            32
#define HANDSHAKE_RESPONSE_STATUS_OFFSET        252  /* 0xFC */

/* Additional Metadata */
#define HANDSHAKE_RESPONSE_CHANNEL_OFFSET       261  /* 0x105 */

/* Network List Constants */
#define NETWORK_SLOT_SIZE               64
#define NETWORK_BSSID_OFFSET            0
#define NETWORK_SSID_TAG_OFFSET         6
#define NETWORK_SSID_LEN_OFFSET         7
#define NETWORK_SSID_DATA_OFFSET        8
#define NETWORK_SSID_DATA_SIZE          32
#define NETWORK_SECURITY_TAG_OFFSET     40
#define NETWORK_SECURITY_LEN_OFFSET     41
#define NETWORK_SECURITY_TYPE_OFFSET    42
#define NETWORK_SIGNAL_TAG_OFFSET       43
#define NETWORK_SIGNAL_OFFSET           44
#define NETWORK_RATES_OFFSET            45
#define NETWORK_RATES_SIZE              12
#define MAX_NETWORKS                    16

/* Beacon Response Field Offsets */
#define BEACON_RESPONSE_ASSOCIATION_OFFSET  0
#define BEACON_RESPONSE_ENCRYPTION_OFFSET   1
#define BEACON_RESPONSE_AUTH_MODE_OFFSET    2
#define BEACON_RESPONSE_RESERVED_OFFSET     3

/* Minimum Padding */
#define MIN_PADDED_PAYLOAD      34

/* TLV Tags */
#define TLV_TAG_SSID            0x01
#define TLV_TAG_PASSWORD        0x02
#define TLV_TAG_SECURITY        0x03
#define TLV_TAG_SECURITY_ALT    0x05
#define TLV_TAG_SIGNAL          0x06
#define TLV_TAG_MODE            0x09
#define TLV_TAG_PASSWORD_ALT    0x0a

/* Security Types */
#define SECURITY_NONE           0x00
#define SECURITY_WEP            0x01
#define SECURITY_OPEN           0x02
#define SECURITY_WPA_WPA2       0x04
#define SECURITY_WPA2           0x08

/* Wireless Modes (802.11) */
#define WIRELESS_MODE_11B       0x01
#define WIRELESS_MODE_11G       0x02
#define WIRELESS_MODE_11N       0x03
#define WIRELESS_MODE_11AC      0x05

/* Connection Status Values */
#define STATUS_DISCONNECTED     0x00
#define STATUS_CONNECTED        0x01

/* Association Status (Beacon Response) */
#define ASSOC_NOT_ASSOCIATED    0x00
#define ASSOC_ASSOCIATING       0x01
#define ASSOC_ASSOCIATED        0x02
#define ASSOC_FAILED            0x03

/* Encryption Types (Beacon Response) */
#define ENCRYPTION_NONE         0x00
#define ENCRYPTION_WPA_TKIP     0x40
#define ENCRYPTION_WPA2_AES     0x80

/* Auth Modes (Beacon Response) */
#define AUTH_OPEN               0x00
#define AUTH_WPA_PSK            0x02
#define AUTH_WPA2_PSK           0x03

/* ============================================================================
 * PACKET STRUCTURES
 * ============================================================================
 */

/**
 * @brief Common Xbox Protocol Header (12 bytes)
 * 
 * Present at the start of every Xbox protocol packet.
 * All multi-byte values are BIG-ENDIAN.
 */
typedef struct __attribute__((packed)) {
    uint8_t  magic[XBOX_MAGIC_SIZE];    /* "XBOX" (0x58 0x42 0x4f 0x58) */
    uint8_t  version;                   /* Protocol version (0x01) */
    uint8_t  sub_version;               /* Protocol sub-version (0x01) */
    uint8_t  body_size_dwords;          /* Payload length / 4 */
    uint8_t  packet_type;               /* PKT_* constant */
    uint16_t nonce;                     /* Transaction ID (big-endian) */
    uint16_t checksum;                  /* RFC 1071 one's complement */
} xbox_header_t;

/**
 * @brief Type 0x01 - Handshake Request (28 bytes total)
 * 
 * Direction: Xbox → Adapter
 * Purpose: Initiate authentication with random challenge
 */
typedef struct __attribute__((packed)) {
    xbox_header_t header;
    uint8_t challenge[HANDSHAKE_CHALLENGE_SIZE];  /* Random 16 bytes */
} handshake_request_t;

/**
 * @brief Type 0x02 - Handshake Response (282 bytes total)
 * 
 * Direction: Adapter → Xbox
 * Purpose: Authenticate adapter + provide wireless status
 * 
 * CRITICAL: Offsets documented in mn740_handshake_structure.md
 * Wire format: [Ethernet 14][Xbox Header 12][Payload 256] = 282 bytes
 */
typedef struct __attribute__((packed)) {
    xbox_header_t header;
    
    /* Authentication Section (92 bytes) */
    uint8_t hmac_signature[HANDSHAKE_RESPONSE_HMAC_SIZE];      /* Offset 12 */
    uint8_t copyright[HANDSHAKE_RESPONSE_COPYRIGHT_SIZE];      /* Offset 32 */
    
    /* Device Information (64 bytes) */
    char adapter_name[HANDSHAKE_RESPONSE_NAME_SIZE];           /* Offset 104 */
    char firmware[HANDSHAKE_RESPONSE_FIRMWARE_SIZE];           /* Offset 136 */
    
    /* Wireless Stats - THE HOLY GRAIL (51 bytes) */
    uint8_t capability_flags;                                  /* Offset 168 */
    uint8_t unknown_flag;                                      /* Offset 169 */
    uint8_t unknown_data[4];                                   /* Offset 170 */
    uint8_t bssid[MAC_ADDRESS_SIZE];                           /* Offset 174 (0xAE) */
    uint8_t signal_strength;                                   /* Offset 180 (0xB4) */
    uint8_t link_quality;                                      /* Offset 181 (0xB5) */
    uint32_t ip_address;                                       /* Offset 182 (0xB6) BE */
    uint8_t unknown_padding[30];                               /* Offset 186 */
    uint8_t wireless_mode;                                     /* Offset 218 (0xDA) */
    
    /* Connection Status (37 bytes) */
    uint8_t ssid_length;                                       /* Offset 219 (0xDB) */
    char ssid[HANDSHAKE_RESPONSE_SSID_SIZE];                   /* Offset 220 (0xDC) */
    uint8_t status_flags[4];                                   /* Offset 252 (0xFC) */
    
    /* Additional Metadata (26 bytes) */
    uint8_t unknown_metadata[5];                               /* Offset 256 (0x100) */
    uint8_t wifi_channel;                                      /* Offset 261 (0x105) */
    uint8_t reserved[20];                                      /* Offset 262 */
} handshake_response_t;

/**
 * @brief Network Slot (64 bytes)
 * 
 * Used in Type 0x04 (NETWORKS_LIST_RESPONSE)
 * Each discovered network occupies exactly 64 bytes
 */
typedef struct __attribute__((packed)) {
    uint8_t bssid[MAC_ADDRESS_SIZE];                /* AP MAC address */
    uint8_t ssid_tag;                               /* TLV tag (0x01) */
    uint8_t ssid_length;                            /* SSID length (0-32) */
    char ssid[NETWORK_SSID_DATA_SIZE];              /* SSID data, null-padded */
    uint8_t security_tag;                           /* TLV tag (0x02) */
    uint8_t security_length;                        /* Length (1 byte) */
    uint8_t security_type;                          /* SECURITY_* constant */
    uint8_t signal_tag;                             /* TLV tag (0x06) */
    uint8_t signal_strength;                        /* 0-255 scale */
    uint8_t rates[NETWORK_RATES_SIZE];              /* Supported rates */
    uint8_t padding[7];                             /* Zero padding */
} network_slot_t;

/**
 * @brief Type 0x03 - Networks List Request
 * 
 * Direction: Xbox → Adapter
 * Purpose: Request WiFi scan results
 */
typedef struct __attribute__((packed)) {
    xbox_header_t header;
    uint8_t padding[MIN_PADDED_PAYLOAD];  /* Usually zeros */
} networks_list_request_t;

/**
 * @brief Type 0x04 - Networks List Response (Variable size)
 * 
 * Direction: Adapter → Xbox
 * Purpose: Provide discovered networks
 * 
 * Wire format: [Header 12][Count 1][Slots N*64]
 * Common size: 980 bytes (1 + 15*64 + 19 partial)
 */
typedef struct __attribute__((packed)) {
    xbox_header_t header;
    uint8_t network_count;                /* Number of networks (up to 16) */
    network_slot_t networks[];            /* Variable-length array */
} networks_list_response_t;

/**
 * @brief Type 0x05 - Adapter Info Request
 * 
 * Direction: Xbox → Adapter
 * Purpose: Query adapter status
 * 
 * Note: If payload > 12 bytes, triggers long-form anti-clone response
 */
typedef struct __attribute__((packed)) {
    xbox_header_t header;
    uint8_t challenge_nonce[2];           /* Optional: triggers long response */
} adapter_info_request_t;

/**
 * @brief Type 0x06 - Adapter Info Response (Short Format, 16 bytes)
 * 
 * Direction: Adapter → Xbox
 * Purpose: Quick status heartbeat
 */
typedef struct __attribute__((packed)) {
    xbox_header_t header;
    uint8_t connection_status;            /* 0x00=disconnected, 0x01=connected */
    uint8_t link_speed;                   /* 802.11 rate */
    uint8_t signal_quality;               /* 0-255 */
    uint8_t reserved_flags;               /* Usually 0x00 */
} adapter_info_response_short_t;

/**
 * @brief Type 0x06 - Adapter Info Response (Long Format, 52 bytes)
 * 
 * Direction: Adapter → Xbox
 * Purpose: Anti-clone certificate verification
 * 
 * CRITICAL: Used to prove genuine MN-740 adapter
 * HMAC must be correct or Xbox shows "Adapter not supported"
 */
typedef struct __attribute__((packed)) {
    xbox_header_t header;
    uint8_t hmac_signature[20];           /* HMAC-SHA1 over header */
    uint16_t status;                      /* 0x00 0x01 = Ready */
    uint16_t ethernet_mode;               /* 0x00 0x00 = Wireless active */
    uint8_t reserved[4];                  /* Padding */
} adapter_info_response_long_t;

/**
 * @brief Type 0x07 - Connect to SSID Request (Variable size)
 * 
 * Direction: Xbox → Adapter
 * Purpose: Configure WiFi connection
 * 
 * Wire format: [Header 12][TLV Payload N][HMAC 20]
 */
typedef struct __attribute__((packed)) {
    xbox_header_t header;
    uint8_t tlv_payload[];                /* TLV-encoded config + HMAC */
} connect_request_t;

/**
 * @brief Type 0x08 - Connect to SSID Response (33 bytes)
 * 
 * Direction: Adapter → Xbox
 * Purpose: Confirm connection request
 */
typedef struct __attribute__((packed)) {
    xbox_header_t header;
    uint8_t result;                       /* 0x00=success, non-zero=error */
    uint8_t reserved[19];                 /* Padding */
    uint8_t hmac_signature[20];           /* HMAC-SHA1 authentication */
} connect_response_t;

/**
 * @brief Type 0x09 - Beacon Request (36 bytes)
 * 
 * Direction: Xbox → Adapter
 * Purpose: Keepalive heartbeat (every 1 second)
 */
typedef struct __attribute__((packed)) {
    xbox_header_t header;
    uint8_t payload[4];                   /* Usually 0x00 0x00 0x00 0x00 */
    uint8_t hmac_signature[20];           /* HMAC-SHA1 authentication */
} beacon_request_t;

/**
 * @brief Type 0x0a - Beacon Response (16 bytes)
 * 
 * Direction: Adapter → Xbox
 * Purpose: Real-time security status
 */
typedef struct __attribute__((packed)) {
    xbox_header_t header;
    uint8_t association_status;           /* ASSOC_* constant */
    uint8_t encryption_type;              /* ENCRYPTION_* constant */
    uint8_t auth_mode;                    /* AUTH_* constant */
    uint8_t reserved;                     /* 0x00 */
} beacon_response_t;

/**
 * @brief Type 0x0d - Discovery Request (12 bytes)
 * 
 * Direction: Xbox → Broadcast (UDP 255.255.255.255:2002)
 * Purpose: Find all adapters on network
 */
typedef struct __attribute__((packed)) {
    xbox_header_t header;
    /* No payload */
} discovery_request_t;

/**
 * @brief Type 0x0e - Discovery Response (40 bytes)
 * 
 * Direction: Adapter → Xbox (UDP unicast)
 * Purpose: Provide adapter identity for pairing
 */
typedef struct __attribute__((packed)) {
    xbox_header_t header;
    uint8_t adapter_mac[MAC_ADDRESS_SIZE];    /* MN-740 MAC */
    uint8_t reserved_status[4];               /* 0x00 0x00 0x00 0x00 */
    uint8_t associated_xbox_mac[MAC_ADDRESS_SIZE];  /* Paired Xbox MAC */
    uint8_t reserved_padding[12];             /* Zero padding */
} discovery_response_t;

/**
 * @brief Type 0x00 - Echo Request/Response (Variable size)
 * 
 * Direction: Bidirectional (UDP port 2002)
 * Purpose: Loopback test for latency measurement
 */
typedef struct __attribute__((packed)) {
    xbox_header_t header;
    uint8_t payload[];                    /* Arbitrary data to echo back */
} echo_packet_t;

/* ============================================================================
 * HELPER MACROS
 * ============================================================================
 */

/* Validate structure sizes at compile time */
_Static_assert(sizeof(xbox_header_t) == 12, "xbox_header_t must be 12 bytes");
_Static_assert(sizeof(handshake_request_t) == 28, "handshake_request_t must be 28 bytes");
_Static_assert(sizeof(handshake_response_t) == 268, "handshake_response_t must be 268 bytes");
_Static_assert(sizeof(network_slot_t) == 64, "network_slot_t must be 64 bytes");
_Static_assert(sizeof(beacon_response_t) == 16, "beacon_response_t must be 16 bytes");

/* Get packet type from raw buffer */
#define PACKET_TYPE(buf) ((buf)[7])

/* Get payload pointer (skip header) */
#define PACKET_PAYLOAD(buf) ((buf) + XBOX_BODY_HEADER_SIZE)

/* Calculate body size in DWORDs from payload length */
#define PAYLOAD_TO_DWORDS(len) (((len) + XBOX_BODY_HEADER_SIZE + 3) / 4)

/* Extract nonce from header (big-endian) */
#define HEADER_NONCE(hdr) (((uint16_t)(hdr)->nonce))

#endif /* XBOX_PACKETS_H */

# Xbox MN-740 Wireless XPP over NLB (Xbox Peripheral Protocol) - Complete Specification v48

**Status**: Complete

**Protocol information**: Xbox Peripheral Protocol (XPP) over NLB
The MN-740 is an Ethernet-to-Wireless bridge, but at its core, it is a managed peripheral. Unlike a standard "dumb" bridge, the Xbox console needs to control the radio (to scan for networks, set WEP keys, etc.).

Microsoft used the existing Ethernet port and created a "Virtual Serial Bus" by wrapping management commands in Fake NLB Heartbeats. This allowed the Xbox to configure the adapter without needing a complex TCP/IP stack.

The configuration payload structure resembles Wi-Fi Protected Setup (WPS) TLV encoding but has been modified to be lightweight.

The main problem with the MN740 wireless adapter has been the lack of WPA and newer protocols, the adapter is actually hampered at a firmware level to WEP128 when the adapter actually supports WPA, there is a breakdown of what is required to patch in WPA support in the MN-740 later on in this document

It was the assumption that the Xbox UI is not capable of WPA and long passwords this thinking is wrong, the Xbox has a gated adapter capability function to enable new UI options, WEP64 and WEP128 options are actually gated also, the handshake possesses two hard coded values that state the encryption and cipher suite the adapter is capable of back to the dash.
The Xbox dash is aware of ciphers and encryption support all the way up to WPA/WPA2 with the latest dash files.
The Xbox supports PMK formatted hex and ASCII passwords up to 63 characters as per the WPA/WPA2 standard.

---

## Table of Contents

### Packet Reference (Linear)
1. [Packet Transport Types](#1-packet-transport-types)
   - [1.1 NLB (EtherType 0x886f)](#11-transport-nlb-ethertype-0x886f)
   - [1.2 EAPOL (EtherType 0x888e)](#13-transport-eapol-ethertype-0x888e)
2. [NLB Type 0x00 - ECHO](#2-type-0x00---echo)
3. [NLB Type 0x01 - HANDSHAKE_REQUEST](#3-type-0x01---handshake_request)
4. [NLB Type 0x02 - HANDSHAKE_RESPONSE](#4-type-0x02---handshake_response)
5. [NLB Type 0x03 - NETWORKS_LIST_REQUEST](#5-type-0x03---networks_list_request)
6. [NLB Type 0x04 - NETWORKS_LIST_RESPONSE](#6-type-0x04---networks_list_response)
7. [NLB Type 0x05 - ADAPTER_INFO_REQUEST](#7-type-0x05---adapter_info_request)
8. [NLB Type 0x06 - ADAPTER_INFO_RESPONSE](#8-type-0x06---adapter_info_response)
9. [NLB Type 0x07 - CONNECT_TO_SSID_REQUEST](#9-type-0x07---connect_to_ssid_request)
10. [NLB Type 0x08 - CONNECT_TO_SSID_RESPONSE](#10-type-0x08---connect_to_ssid_response)
11. [NLB Type 0x09 - BEACON_REQUEST](#12-type-0x09---beacon_request)
12. [NLB Type 0x0a - BEACON_RESPONSE](#13-type-0x0a---beacon_response)
13. [NLB Type 0x0b - SILENTLY_DROPPED](#14-type-0x0b---silently_dropped)
14. [NLB Type 0x0c - SILENTLY_DROPPED](#15-type-0x0c---silently_dropped)
15. [NLB Type 0x0f - SILENTLY_DROPPED](#18-type-0x0f---silently_dropped)
16. [EAPOL Type 0x11 - WPA_ASSOC / WPA_EXCHANGE](#19-type-0x11---wpa_assoc--wpa_exchange)

### Supporting Information
- [Connection Workflows](#connection-workflows)
- [Security Types Reference](#security-types-reference)
- [Signal Strength Conversion](#signal-strength-conversion)
- [Firmware Function Map](#firmware-function-map)
- [Implementation Checklist](#implementation-checklist)
- [WPA/WPA2 Implementation](#wpa-wpa2-implementation)
- [Troubleshooting Guide](#troubleshooting-guide)
- [Packet Flow Timing Diagram](#packet-flow-timing-diagram)
- [MSBNUpdate.exe Firmware Update Tool](#msbnupdateexe-firmware-update-tool)
- [BBN Device Discovery Protocol](#bbn-device-discovery-protocol)

---

### 1. Packet Transport Types

Two distinct transports are used across all packet types. Each has a different frame structure. The transport used by each packet type is listed in the **Transport** field at the top of its section.

```
Transport         | EtherType | Used by
------------------|-----------|----------------------------------------------------------
NLB (XPP)         | 0x886f    | Types 0x01–0x09, 0x0A, 0x0B, 0x0C, 0x0F (management)
EAPOL (802.1X)    | 0x888e    | Type 0x11 only (WPA authentication)
```

```
EtherType | Protocol            | Firmware Handler
----------|---------------------|------------------------------------------
0x0806    | ARP                 | ARP_Process_Incoming_Packet
0x886f    | NLB (XPP)           | XPP_TYPE_02_payload_construct
0x888e    | EAPOL (IEEE 802.1X) | wlan_eapol_frame_dispatcher
```
---

### 1.1 Transport: NLB (EtherType 0x886f)

The primary XPP management transport. Used by the majority of packet types.

```
Total size:   (14 Ethernet + 12 XPP Header + Payload + IEEE Padding) = N Bytes
Body Size:    (12 XPP Header + Payload) / 4 = N DWORDs
Checksum:     RFC 1071 over (Body Size * 4) bytes from XPP header start (checksum field = 0x0000)

Size         | Segment            | Description
-------------|--------------------|-------------------------------------------------
14 bytes     | Ethernet header    | dst MAC, src MAC, EtherType 0x886f
12 bytes     | XPP Header         | Magic, version, body size, type, nonce, checksum
Variable     | Payload            | Packet-specific data (see individual packet types)
0-3 bytes    | DWORD padding      | Zeros to align payload to 4-byte boundary
Variable     | IEEE 802.3 padding | Zeros to reach 60-byte minimum frame size (if needed)
```

#### Ethernet Header (14 bytes)
```
Offset | Size | Field           | Value
-------|------|-----------------|------------------
0      | 6    | Destination MAC | Target device MAC (broadcast FF:FF:FF:FF:FF:FF for HANDSHAKE_REQ)
6      | 6    | Source MAC      | Sender MAC
12     | 2    | EtherType       | 0x886f (NLB)
```

### Xbox Peripheral Protocol Header (XPP header) (12 bytes)
```
Offset | Size | Field              | Value
-------|------|--------------------|--------------------------------------------------
0      | 4    | Magic Signature    | "XBOX" (0x58424f58)
4      | 1    | Version byte 1     | 0x01 (static)
5      | 1    | Version byte 2     | 0x01 (static)
6      | 1    | Body Size (DWORDs) | (12 + Payload + padding) / 4
7      | 1    | Packet Type        | Command ID (e.g. 0x01=HANDSHAKE_REQ, 0x09=BEACON)
8      | 2    | XID (Nonce)        | Transaction ID — matched between request and response
10     | 2    | Checksum           | RFC 1071 (calculated with this field = 0x0000)
```

Body Size counts from the start of the XPP header and covers header + payload + DWORD padding. It never counts IEEE 802.3 padding.

```
Examples:
  Type 0x01: 16-byte payload  → (12 + 16) / 4  =  7 DWORDs = 0x07
  Type 0x02: 256-byte payload → (12 + 256) / 4 = 67 DWORDs = 0x43
  Type 0x09: 0-byte payload   → (12 + 0) / 4   =  3 DWORDs = 0x03
```

#### Payload Notes

Payload structure varies by type. Only Type 0x02 (HANDSHAKE_RESPONSE) includes a 20-byte HMAC-SHA1 prepended at offset 0 before all other payload data. All other types carry their data directly with no HMAC.

**Build order:**
1. Pack payload data
2. For Type 0x02 only: prepend 20-byte HMAC at offset 0
3. Pad to 4-byte boundary with 0x00
4. Calculate Body Size: `(12 + padded_payload) / 4`
5. Write XPP header fields (magic, type, XID, body size)
6. Calculate RFC 1071 checksum over `body_size * 4` bytes and write to offset 10
7. Pad entire frame to 60-byte minimum with 0x00 (IEEE 802.3, not checksummed)

---

### 1.2 Transport: EAPOL (EtherType 0x888e)

Used exclusively by Type 0x11 (WPA_ASSOC / WPA_EXCHANGE). IEEE 802.1X EAPOL is the standard 802.11 WPA key exchange transport — the adapter's firmware routes it through `wlan_eapol_frame_dispatcher` rather than the XPP management handler.

**This frame has no XPP magic signature, no Body Size DWORD count, and no RFC 1071 checksum.**

```
Size         | Field            | Value
-------------|------------------|-----------------------------------------------
6  bytes     | Destination MAC  | FF:FF:FF:FF:FF:FF (broadcast) or AP MAC (retry)
6  bytes     | Source MAC       | Console MAC
2  bytes     | EtherType        | 0x888e
2  bytes     | Frame type word  | 0x6388 or 0x123c (WPA sub-protocol selector)
1  byte      | Type marker      | 0x11 (constant)
1  byte      | Sub-type         | Direction/state byte (0x09, 0x19, 0x01–0x04, 0x09)
2  bytes     | Reserved         | 0x0000
2  bytes     | Length           | Big-endian payload length
2  bytes     | Reserved         | 0x0000
Variable     | Payload          | Sub-TLVs: [tag:1][len:1][data:len]
```

The Xbox kernel function `net_dispatch_arp` is used to allocate the frame buffer. The `NETI`/`NETK` values passed to it are `ExAllocatePoolWithTag` pool debug tags — they identify the memory owner for kernel debugging and have no meaning on the wire.

**See [Section 17](#17-type-0x11---wpa_assoc--wpa_exchange) for the full Type 0x11 packet specification.**


### Related Information
- [Checksum Calculation](#15-Checksum Calculation)
- [HMAC Authentication](#16-hmac-sha1-authentication)

----

### 15. Checksum Calculation (RFC 1071)
**Purpose**:  The checksum ensures that integrity of the data contained within the XPP payload

**Note**:
1. If the integrity check fails, the MN-740 does not usually send a response and silently drops processing the packet.
2. When calculating the checksum, the checksum field itself must be treated as 0x0000 during the calculation

**Used in packets**: Types 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A

----

### 16. HMAC-SHA1 Authentication

HMAC-SHA1 (RFC 2104)
**Discovery Source**: Function `XPP_calculate_hmac_sha1` at address `0x8009b274`

**key**    = g_XPP_HMAC_Key
**input**  = 16-byte challenge + 6-byte g_ROUTER_MAC_ADDRESS + 117-byte g_XPP_HMAC_MASTER_KEY

**Static Key**: : ``cb275ff238ab61dc8799fa01ad17745e``
  Believed to decode to `"From isolation / Deliver me o Xbox, for I am the MN-740"` The method to decode this string remains unidentified.

**Memory Address**: `0x800bf520` (ROM/Static Data section in firmware)

**g_XPP_HMAC_MASTER_KEY**: `"From isolation / Deliver me o Xbox - / Through the ethernet
                 Copyright (c) Microsoft Corporation. All Rights Reserved."`
**Memory Address**: `0x800bc364` (ROM/Static Data section in firmware)

**SEC_AUTH_COPYRIGHT_POEM**: `"Device is Xbox Compatible. Copyright (c) Microsoft Corporation. All Rights Reserved."`
**Memory Address**: `0x800bc3dc` (ROM/Static Data section in firmware)


**Purpose**: g_XPP_HMAC_MASTER_KEY is a static ROM string used as part of the HMAC input message. Combined with the Xbox's random nonce and the paired router MAC, it ensures only genuine MN-740 firmware — which has this string hardcoded in ROM — can produce a valid HMAC digest. G_XPP_HMAC_Key is the actual HMAC signing key.

### Xbox Dashboard HMAC Verification (Xbox-side)
**Discovery Source**: `XPP_calculate_handshake_hmac` decompiled from xonlinedash_xbe.c

The decompiled code fully resolves the dashboard HMAC verification:

```c
undefined1 XPP_calculate_handshake_hmac(int param_1, int *param_2, undefined4 *param_3)
{
  // Build HMAC input buffer on stack:
  // [0..15]   = 16-byte nonce copied from frame at param_1+0x2c
  // [16..21]  = 6-byte adapter MAC from param_3 (source_mac from Ethernet frame)
  // [22..138] = 117-byte master key string (indices 22..138, 117 bytes)
  //   = "From isolation / Deliver me o Xbox - / Through the ethernet\n
  //      Copyright (c) Microsoft Corporation. All Rights Reserved."

  // HMAC key (16 bytes, hardcoded):
  local_18..local_9 = { 0xcb, 0x27, 0x5f, 0xf2, 0x38, 0xab, 0x61, 0xdc,
                         0x87, 0x99, 0xfa, 0x01, 0xad, 0x17, 0x74, 0x5e };

  XcHMAC(&local_18, 0x10,    // key = 16-byte static key (same as g_XPP_HMAC_Key)
         &local_b8, 0x8b,    // input = 0x8b = 139 bytes total: 16 nonce + 6 MAC + 117 master key bytes
         0, 0,               // no extra data
         local_2c);          // output = 20-byte SHA1 digest into local_2c[5]

  // Compare first 20 bytes (5 DWORDs) of digest against frame payload:
  for (iVar3 = 5; iVar3 != 0; iVar3--) {
    if (*piVar5 != *param_2) return 0;  // mismatch
  }
  return 1;  // all 5 DWORDs match
}
```

**Key findings confirmed by decompile:**
- The HMAC key is **identical** to `g_XPP_HMAC_Key` — `cb275ff238ab61dc8799fa01ad17745e` — the same static ROM key used by the adapter.
- The input is **139 bytes**: 16-byte nonce + 6-byte adapter source MAC + 117-byte master key string. This matches the adapter firmware exactly.
- The comparison is **20 bytes** (5 DWORDs loop)
- `XcHMAC` is an Xbox kernel crypto primitive (`xboxkrnl.exe` import).

----

## 2. Type 0x00 - ECHO
**Direction**: Xbox → Adapter  
**Transport**: NLB (EtherType 0x886f)  
**HMAC Required**: No

### Brief Description
Latency probe. The Xbox sends an XPP frame with type 0x00 over EtherType 0x886f and measures how long the response takes.

### Firmware-Verified Response Mechanism

The zero-frame response is **not a designed echo reply**. It is a **fall-through artefact** of `xpp_TYPE_02_payload_construct`, the EtherType 0x886f handler, confirmed directly from `NML_bin.c`:

**Step by step for an incoming type 0x00 frame:**
1. Frame arrives at `xpp_TYPE_02_payload_construct` via the EtherType 0x886f demux path
2. XPP magic signature (`XBOX`) and RFC 1071 checksum are verified
3. A response buffer of 0x5ee bytes is allocated and **completely zero-filled**
4. The type switch has **no case for 0x00** — no handler runs, `iVar3` stays 0
5. The `if (iVar3 == 0)` transmit block fires — the zero buffer is sent back
6. A 60-byte all-zeros EtherType 0x886f frame is on the wire within ~5ms

**The zero-frame is an accidental ACK, not a designed reflect.** Type 0x00 is simply
an unhandled type that triggers the default success-transmit path with a blank buffer.

### Packet Format (Xbox → Adapter)
```
Size     | Segment         | Description
---------|-----------------|---------------------------------------------------
14 bytes | Ethernet header | dst=adapter MAC, src=Xbox MAC, EtherType=0x886f
12 bytes | XPP Header      | Magic=XBOX, ver=0x0101, type=0x00, body=0x03 DWORDs
```

Payload is empty; body size = 0x03 (12 bytes / 4 = minimum XPP header only).

### Response Format (Adapter → Xbox, wire-verified)
```
Size     | Segment         | Description
---------|-----------------|---------------------------------------------------
14 bytes | Ethernet header | dst=Xbox MAC, src=adapter MAC, EtherType=0x886f
46 bytes | Zeros           | Zero-filled to meet 60-byte minimum frame size
```
No XPP `XBOX` magic. No checksum. All bytes after the Ethernet header are 0x00.
RTT typically 1–5ms from captures.

### Implementation Notes
An emulator receiving type 0x00 should respond with a 60-byte all-zeros Ethernet frame (EtherType 0x886f, src=adapter MAC, dst=Xbox MAC, all remaining bytes 0x00). **Do not** include the XPP magic or any XPP structure in the response.

Note: type 0x00 also has handlers in the ICMP path (`XPP_Send_Type00_Reply` via `ip_protocol_demuxer` when IP proto=0x01) and in `XPP_Ethernet_Dispatcher`. In both those paths type 0x00 is queued to the firmware's internal ping-receive queue and no response is generated. Only the EtherType 0x886f NLB path produces the zero-frame via the fall-through described above.

----

## 3. Type 0x01 - HANDSHAKE_REQUEST
**Direction**: Xbox → Adapter  
**Transport**: Ethernet 0x886f  
**HMAC Required**: No

### Brief Description
Initiates authentication session with random challenge.

### Packet Format
```
Total size: (14 Ethernet + 12 XPP Header + 16 Payload) =42 bytes
Body Size:  (12 XPP header +16 Payload) / 4 = 0x07 DWORDs

Size | Segment          | Description
-------------|------------------|--------------------------------
14 bytes     | Ethernet header  | Standard header
12 bytes     | XPP Header       | Type 0x01, body size = 0x07 DWORDs
16 bytes     | Payload          | Randomly generated 128-bit challenge nonce
```

### Example
```
58 42 4f 58 01 01 07 01 ed c6 66 9a  <-- 12-byte Header ( Type: 0x01 Body Size: 0x07)
12 34 56 78 9a bc de f0 11 22 33 44  <-- 16-byte Challenge Start
55 66 77 88                          <-- 16-byte Challenge End
```

### Related Information
- [Type 0x02 Response](#4-type-0x02---handshake_response)

----

## 4. Type 0x02 - HANDSHAKE_RESPONSE
**Direction**: Adapter → Xbox  
**Transport**: Ethernet 0x886f  
**HMAC Required**: Yes challenge reply

### Brief Description
Authenticates adapter and provides current wireless status (BSSID, SSID, IP, connection state)

### Packet Format
```
Total size: (14 Ethernet + 12 XPP Header + 252 fixed Payload + 4 trailer payload) = 282 bytes
Body Size:  (12 XPP + 252 Payload + 4 trailer payload) / 4 = 0x43 DWORDs

Size         | segment          | Description
-------------|------------------|--------------------------------
14 bytes     | Ethernet         | Standard Ethernet frame header
12 bytes     | XPP Header       | Type 0x02, body size = 0x43 DWORDs
252 bytes    | Fixed payload    | fixed buffer
4 bytes      | Trailer payload  | Trailer OpMode + LinkState + 00 00
```
### Fixed Payload Structure (256 bytes)
```
Offset | Size     | Firmware source                        | Field Name / Description / Logic
-------|----------|----------------------------------------|--------------------------------------------------
0      | 20 bytes | XPP_calculate_hmac_sha1()              | HMAC-SHA1 (RFC 2104) key = g_XPP_HMAC_Key
                                                           | input = 16-byte challenge + 6-byte g_ROUTER_MAC_ADDRESS
                                                           | + 117-byte g_XPP_HMAC_MASTER_KEY (139 bytes total)
20     | 84 bytes | util_strncpy(SEC_AUTH_COPYRIGHT_POEM)  | "Device is Xbox Compatible. Copyright (c)
       |          |                                        |  Microsoft Corporation. All Rights Reserved."
104    | 32 bytes | util_strncpy(s_Xbox_Adapter_MN740_Name)| "Xbox Wireless Adapter (MN-740)" null-padded
136    | 32 bytes | util_strncpy(DAT_Firmware_Build_Date)  | "1.0.2.26 Boot: 1.3.0.06" null-padded
168    | 6 bytes  | get_wireless_bssid_ptr() or memset 0   | BSSID of connected AP, or 00:00:00:00:00:00
174    | 1 byte   | get_WPA_security_capability_STUB()     | ⚠ HARDCODED STUB — always 0x06 see byte 174 below
175    | 1 byte   | get_WPA_cipher_capability_STUB()       | ⚠ HARDCODED STUB — always 0x07 see byte 175 below
176    | 4 bytes  | TX RATE INDEX BITMASK                  | ⚠ HARDCODED STUB — always 0x00000FFE see byte 176 below
180    | 28 bytes | CHANNEL ALLOWLIST BITMASK              | ⚠ HARDCODED STUB — always null filled see byte 176 below
208    | 1 byte   | XPP_Get_Link_Status_Summary_STUB()     | ⚠ HARDCODED STUB — always 0x05 see byte 208 below
209    | 1 byte   | g_NET_InterfaceStatus / DHCP state     | State of upstream DHCP
210    | 4 bytes  | memcpy(&CFG_Device_IP)                 | Current IP address (big-endian). Stored to AutoClass1+0xd94.
       |          |                                        | If non-zero, dashboard triggers net_validate_ip_for_dhcp() (IP validity check).
214    | 1 byte   | wlan_is_radio_active()                 | Radio active flag: 0x00=radio off, 0x01=radio on.
215    | 1 byte   | XPP_Check_Auth_Status()                | Auth/association status.
       |          |                                        | 0x02=open/idle, 0x03=WEP association in progress.
216    | 1 byte   | wlan_is_infra_or_adhoc()               | Network mode: 0x01=infrastructure, 0x00=ad-hoc.
217    | 1 byte   | XPP_Get_Channel_Or_Fallback()          | Channel number (1–14)
218    | 1 byte   | wlan_get_encryption_type()             | WEP enabled: 0x00=open, 0x02=WEP active.
219    | 1 byte   | get_current_ssid_length()              | SSID length. 0x21 (max 32). Used to bound FUN_000a3dad() SSID copy.
220    | 32 bytes | hw_get_ssid_string()                   | Raw SSID string, null-padded to 32 bytes.
252    | 1 byte   | hw_ver_major                           | Hardware version major byte. Stored to AutoClass1+0xe2e via FUN_000a34c8().
253    | 1 byte   | hw_ver_minor                           | Hardware version minor byte. Also consumed by FUN_000a34c8().
254    | 2 bytes  | (unwritten)                            | Padding/reserved, always 0x00 0x00.
```

### Bytes 174–175 WPA Capability Byte Decoding ()
**Source**: `my_handle_nlb_handshake_response` / `FUN_000a2a24` decompiled from xonlinedash_xbe.c

The adapter firmware produces stub constants here (0x06, 0x07), but the dashboard decodes them as WPA capability bitfields. The MN-740 hardware is pre-WPA2, and the constant values indicate which cipher suites the hardware supports in principle.

### Byte 174 adapter capability
This byte is used to inform the Xbox what wireless security ciphers is supports (adapter capability)
```
  Bit | Mask | AutoClass1 field | Wire value | Meaning
  ----|------|-----------------|------------|------------------------------
  1   | 0x02 | 0xd68           | SET (0x06) | WPA_TKIP cipher supported
  2   | 0x04 | 0xd6c           | SET (0x06) | WPA_CCMP/AES cipher supported
  4   | 0x10 | 0xd70           | CLEAR      | WPA2/RSNA capable (not supported by MN-740)
  5   | 0x20 | 0xd74           | CLEAR      | WPA2 enterprise capable (not supported)
```

### Byte 175 adapter sub capability
This byte is used to inform the Xbox what wireless security sub ciphers is supports (sub adapter capability)
```
  Bit | Mask | AutoClass1 field | Wire value | Meaning
  ----|------|-----------------|------------|------------------------------
  0   | 0x01 | 0xd78           | SET (0x07) | NONE/open cipher mode
  1   | 0x02 | 0xd7c           | SET (0x07) | WEP/TKIP cipher mode
  2   | 0x04 | 0xd80           | SET (0x07) | TKIP cipher mode (used by FUN_000a2a24 as WPA_TKIP flag)
  3   | 0x08 | 0xd84           | CLEAR      | CCMP/AES cipher mode
  4   | 0x10 | 0xd88           | CLEAR      | WPA2 TKIP
  5   | 0x20 | 0xd8c           | CLEAR      | WPA2 CCMP/AES
```

**FUN_000a2a24** uses `AutoClass1+0xd70` (byte174 bit4 = WPA2 capable) and `AutoClass1+0xd80` (byte175 bit2 = TKIP) together with wire auth/channel bytes to compute the final `AutoClass1+0xe2e` (resolved security mode). For the MN-740, WPA2 is always 0 so this path falls to the WEP/open code.

### Byte 176 TX RATE INDEX BITMASK
This byte is used to inform the xbox what wireless TX rate codes it supports
```
Bit | Rate (Mbps) | Standard  | Notes
----|-------------|-----------|-------
1   | 1 Mbps      | 802.11b   | Legacy compatibility
2   | 2 Mbps      | 802.11b   | Legacy compatibility
3   | 5.5 Mbps    | 802.11b   |
4   | 6 Mbps      | 802.11g   | Basic rate
5   | 9 Mbps      | 802.11g   |
6   | 11 Mbps     | 802.11b   | Maximum 802.11b rate
7   | 12 Mbps     | 802.11g   |
8   | 18 Mbps     | 802.11g   |
9   | 24 Mbps     | 802.11g   |
10  | 36 Mbps     | 802.11g   |
11  | 48 Mbps     | 802.11g   |
12  | 54 Mbps     | 802.11g   | Maximum 802.11g rate
```

Rejection rule: bit 0 set OR bit >14 set → entire HS_RESP rejected.

### Byte 180-207 Channel Allowlist Bitmask
28 bytes used as a regulatory bitmask. Each bit from 1–200 represents a channel: **0=enabled, 1=disabled**. Bits above 200 are discarded by firmware. For 2.4 GHz operation only channels 1–14 are meaningful; the MN-740 hardware cannot use channels above 14.
```
Bit | Channel | Notes
----|---------|------
1   | 1       | 2.4 GHz
2   | 2       | 2.4 GHz
...                  
11  | 11      | 2.4 GHz (FCC max)
13  | 13      | 2.4 GHz (ETSI max)
14  | 14      | Japan only
15+ | (n/a)   | Not used by MN-740 hardware
```
⚠ Wire-verified: real MN-740 firmware sends all zeros here (all channels enabled). The channel ceiling is enforced separately by CTAG 0x84 (Max Channel write tag), not by this bitmask.

### Byte 208 Radio Mode Capability Bitmask
**Source**: `my_handle_nlb_handshake_response` decompiled from xonlinedash_xbe.c

```
Bit | Mask | AutoClass1 field | Wire value | Meaning
----|------|------------------|------------|------------------------------
0   | 0x01 | 0xd60            | SET (0x05) | 802.11b capable
1   | 0x02 | 0xd5c            | CLEAR      | 802.11g capable (MN-740 is b/g but firmware stub clears this)
2   | 0x04 | 0xd64            | SET (0x05) | Ad-hoc mode capable
3-7 | 0xf8 | (validation)     | 0x00       | Must be zero — dashboard rejects packet if any high bit set
```
Wire constant 0x05 (bits 0+2): confirmed in all captures including ad-hoc logs.
Note: Even the b-only mode captures (lysten_wep*_ch9_b.log) show 0x05, not 0x01.
This is a fixed firmware stub — the adapter does not dynamically set the 11g bit.

### Byte 209 DHCP state
This byte indicates the state of the upstream DHCPDISCOVER.
```
Result | Meaning
-------|--------
0x00   | no DHCP/searching,
0x01   | DHCP acquired,
0x02   | interface manually enabled.
```
Interface Descriptor Struct (0x800ceba0, stride 0x0C per interface)
Discovered via `DHCP_Client_Start` assembly. The DHCP init loop walks this struct:

```
Offset | Address    | Symbol                 | Size   | Purpose
-------|------------|------------------------|--------|------------------------------------------
+0x00  | 0x800ceba0 | g_NET_InterfaceStatus  | 1 byte | DHCP skipped for this interface if non-zero
+0x01  | 0x800ceba1 | g_Interface_Has_Target | 1 byte | DHCP skipped for this interface if non-zero.
+0x02  | 0x800ceba2 | g_ROUTER_MAC_ADDRESS   | 6 bytes| Associated AP MAC address
+0x08  | 0x800ceba8 | DHCP_Config_Word       | 4 bytes| Copied to DHCP state table on init
```
Only one interface (index 0) is used at boot — the loop runs once (`s0 < 1`).

### Byte 216 wlan_radio_is_up
```
Tag 0x04 val | WLAN_Set_Operating_Mode() sets | G_WLAN_OpMode | Radio Active?
-------------|-------------------------------|---------------|---------------
0x00         | G_WLAN_OpMode = 8             | 8             | No (disabled)
0x01         | G_WLAN_OpMode = 2             | 2             | Yes
other        | G_WLAN_OpMode = 2             | 2             | Yes (error return but mode set)
```

### Byte 217 - XPP_Get_Channel_Or_Fallback()
returns live radio channel (1–14) via wlan_freq_to_channel_number() when authenticated (auth_status == 0)
returns g_CFG_Max_Channel (saved configured channel) when not authenticated

### Byte 218 Encryption type (Tag 0x11 in ADAPTER_INFO_RESP)

Populated by `wlan_get_encryption_type()`. Two paths depending on radio state:

**PATH 1 — Radio live** (`wlan_get_connection_readiness() == 0`):
Reads `WLAN_Get_Radio_Substate()` from the Marvell 88W8310 HAL hardware context byte at `driver_ctx+0x29`.
This byte is written exclusively by the Marvell HAL below the firmware abstraction layer — not by any
firmware function Ghidra resolves. Source is a precompiled HAL binary blob; offset meaning is proprietary.
```
Substate | wlan_get_encryption_type() returns | Tag 0x11 value
---------|------------------------------------|----------------
0        | 1                                  | 0x01  ← never seen on wire; HAL substate origin unknown
1        | 2                                  | 0x02  ← wire-verified (WEP active)
2        | 0                                  | 0x00  ← wire-verified (open)
3        | 2                                  | 0x02
>3       | raw substate value                 | varies
```

**PATH 2 — Radio not connected** (NVRAM path):
Reads `g_XPP_Auth_Mode_Enabled` (address `0x800ceb9d`, inside NVRAM struct, persists across power cycles).
```
g_XPP_Auth_Mode_Enabled | wlan_get_encryption_type() returns | Tag 0x11 value
-------------------------|------------------------------------|-----------------
0                        | 0                                  | 0x00  (no encryption)
1                        | 2                                  | 0x02  (encryption active)
2                        | 1                                  | 0x01  ← UNREACHABLE (see note)
other                    | 2                                  | 0x02
```

**`g_XPP_Auth_Mode_Enabled` write sources** (confirmed from XREF analysis — only 3 writers):
- `CFG_Set_XPP_Auth_Mode(0x00)` → writes `0` (Tag 0x11=0x00 in CONNECT_REQ)
- `CFG_Set_XPP_Auth_Mode(0x02)` → writes `1` (Tag 0x11=0x02 in CONNECT_REQ)
- Any other value passed to `CFG_Set_XPP_Auth_Mode()` → **silently ignored, no write**
- `Flash_Commit_Settings()` → hardcodes `1` as factory default

**Value `g_XPP_Auth_Mode_Enabled = 2` is dead code** — no code path ever writes it.
Tag 0x11 = `0x01` via PATH 2 is therefore unreachable. It can only appear via PATH 1 (Marvell HAL
substate = 0), which has never been observed on wire across any captured session.

**Wire-verified values**: only `0x00` and `0x02` have ever been observed in ADAPTER_INFO_RESP Tag 0x11.

### Trailer Payload Structure
```
Offset | Size     | Firmware source                     | Description
-------|----------|-------------------------------------|----------------------------------
0      | 1 byte  | XPP_Get_Link_State_Bitmask()        | 0x02=WEP disabled / link idle, 0x04=WEP enabled / link active
1      | 1 byte  | XPP_Tag_09_Handler_Get_Link_State() | 0x01=no link, 0x02=infra linked, 0x04=ad-hoc linked
2      | 1 byte  | (static)                            | Always 0x00
3      | 1 byte  | (static)                            | Always 0x00
```

### Payload Example
```
[Offset 0x00] HMAC-SHA1:   b9 f0 d1 96 c3 3c 1f 34 f7 b9 e9 85 1c 45 f0 77 11 85 9d a0
[Offset 0x14] Copyright:   "Device is Xbox Compatible. Copyright (c) Microsoft..."
[Offset 0x68] Model:       "Xbox Wireless Adapter (MN-740)"
[Offset 0x88] Firmware:    "1.0.2.26 Boot: 1.3.0.06"
[Offset 0xD0] Config block: 01 02 01 0b 02 06 68 69 64 64 65 6e
              → conn=0x01, auth=0x02, opmode=0x01, arbiter=0x0b, enc=0x02, ssid_len=0x06, ssid="hidden"
```

---

### ⚠️ CRITICAL: WPA Capability Stubs Control the Dashboard UI — WPA is Gated by Adapter Response

This is the most important consequence of the HANDSHAKE_RESP capability byte stubs.

**The dashboard does NOT show a WPA PSK option unless the adapter reports WPA capability.**

The complete unlock chain is:


## HANDSHAKE_RESP byte 174
```
Bit  | Meaning
-----|---------
0x10 |  "WPA1/RSN capable" flag
0x20 |  "WPA2 enterprise capable" flag
```

## HANDSHAKE_RESP byte 175
```
bit  | Meaning
-----|----------------------------
0x01 | "no security" menu option gating
0x02 | "WEP-64" menu option gating
0x04 | "WEP-128" menu option gating
```
**With stock firmware stub values:**
- Byte 174 = `0x06` → bits 0x10 and 0x20 are CLEAR → `0xd70 = 0`, `0xd74 = 0` → WPA PSK option **never shown**
- Byte 175 = `0x07` → bits 0x01, 0x02, 0x04 SET → No Security, WEP-64, WEP-128 options **all shown**

**To enable the WPA PSK menu option** without modifying the Xbox, the adapter must report
byte 174 with bit `0x10` set (i.e., `0x16` instead of `0x06`) OR bit `0x20` set.

**field_0xf5c** (operating mode: `0x01` = infrastructure, `0x00` = ad-hoc) controls which WPA
capability field is checked: infrastructure mode checks `0xd70`, ad-hoc mode checks `0xd74`.

**Ad-hoc channel picker limit (assembly-verified):**

The ad-hoc channel creation picker shows channels 1–12. This is a **hardcoded list in
`xonlinedash.xbe`**, completely independent of the `channel_list` populated from HS_RESP bytes
180–207. Proof: the real MN-740 sends all zeros in bytes 180–207 (empty `channel_list`) yet the
dashboard still shows 1–12 — therefore the picker does not read `channel_list`.

The picker is located near the call sites of `XPP_cap_downgrade_wpa_if_no_wpa2`
(addresses `0x0007877a` and `0x00078801`). To extend to 1–14: find a `CMP reg, 0x0c` / `JLE`
sequence near those addresses in Ghidra and change `0x0c` → `0x0e`.

**Joining existing ad-hoc networks is NOT limited to 1–12:**

When joining (not creating) an ad-hoc network, the channel comes from the SCAN_RESP entry,
not from the picker. Wire-verified: ad-hoc CONN_REQ Tag 0x05 carries whatever channel was in
the scan result. An unpatched Xbox can join an ad-hoc network on ch36 if:
1. The emulator has `max_channel=0` (default — empty channel list, no filter)
2. The Wi-Fi adapter hardware supports 5GHz scanning
The XBE channel patch is only needed for the **creating** Xbox.

---

### Security Type Enum (AutoClass1+0xf5e)

The dashboard tracks the current security selection in a single byte at `AutoClass1+0xf5e`.
This is set by user selection and also used by `FUN_000a364e` to decide which tags to emit.

```
Value | Function                        | Security Mode       | Tag(s) Emitted by FUN_000a364e
------|---------------------------------|---------------------|--------------------------------
0x01  | AutoClass1_set_security_open()  | No security / Open  | None (no key tags)
0x02  | AutoClass1_set_security_wep64() | WEP-64              | Tags 0x0a–0x0d (WEP-40 key slots)
0x03  | AutoClass1_set_security_wep128()| WEP-128             | Tag 0x0f (WEP-128 ASCII) or 0x0f + 0x14 (hex)
0x04  | AutoClass1_set_security_wpa()   | WPA-PSK             | Tag 0x10 (PMK) or Tag 0x12 (passphrase)
```

Additionally `field_0xf5e == 0x04` has a guard: `FUN_000a2f0f()` will **downgrade WPA to open**
if WPA2 enterprise capability is absent (`field_0xd74 == 0`). This is called when the
operating mode is set to ad-hoc.

**Ad-hoc WPA XBE patch** (assembly-verified from full function decode):

The function `XPP_cap_downgrade_wpa_if_no_wpa2` at `0x000a2f0f` has two independent parts:

**Part 1 — WPA downgrade** (lines `2f11`–`2f23`):
```
if (enc_type == WPA && cap_wpa1_rsn == 0)
    AutoClass1_set_security_open()   ← the downgrade
```

**Part 2 sets the flags that `FUN_000a364e` (CONN_REQ builder) reads to emit WPA key tags. Patching Part 2 would break ad-hoc WPA CONN_REQ entirely.

 Address      | Current | Patch | Meaning
--------------|---------|-------|---------
 `0x000a2f18` | `75`    | `EB`  | `JNZ` → `JMP` (unconditional skip of downgrade)

Find sequence: `8B D1  80 BA 5E 0F 00 00 04  75 0E  83 BA 74 0D 00 00 00`
Change byte at offset +9 from `75` → `EB`. The `0e` displacement byte stays unchanged.

To enable ad-hoc WPA via `wpa_sec_cap`, set bit 5 (`0x20`) in byte 174: use `wpa_sec_cap=0x36` in the emulator INI. This sets `field_0xd74` non-zero, so the downgrade condition is false even without the patch. **The XBE patch at `0x000a2f18` is still required** — without it the downgrade fires regardless of `field_0xd74` for ad-hoc paths where the check is bypassed.

---

### WPA Connection State Machine (SubStates 0x11–0x15)

When the user selects WPA PSK security, the connection sub-state machine enters a dedicated WPA authentication flow separate from the
WEP/open path. The full state sequence confirmed from `XPP_fsm_state_dispatch` disassembly:

```
State | Function Called                    | Action
------|------------------------------------|-------------------------------------------------------------
0x11  | XPP_build_wpa_assoc_request()      | Send WPA_ASSOC_REQ — first attempt, SSID sub-TLV to broadcast
0x12  | XPP_build_wpa_assoc_request()      | Retry path — same builder, falls through from 0x11 case
0x13  | XPP_fsm_wpa_credential_exchange()  | Send IP negotiation sub-TLV set (frame_type 0x21c0)
0x14  | XPP_fsm_retransmit()               | Retransmit last credential-exchange packet
0x15  | XPP_fsm_wpa_credential_exchange()  | Second credential exchange pass (frame_type 0x2180)
0x16  | XPP_fsm_reset_cleanup()            | WPA failure terminal — resets all state
```

**State 0x11 vs 0x12**: The check at entry to 0x11 `if (wpa_assoc_retry == 0 && ++retry_count > retry_limit)` causes
state 0x11 to call `XPP_fsm_fatal_error(0xc0000000)` on retry exhaustion. State 0x12 retries
unconditionally (no retry guard). The retry limit is `AutoClass1+0x25`.

**Critical**: The FSM does **not** advance from 0x11/0x12 based on a response packet.
There is no response packet for WPA_ASSOC_REQ. The adapter is expected to silently begin
802.11 association and then drive the console forward by sending type 0x11 frames
of its own. The console advances to 0x13 only when `XPP_wpa_inbound_frame_handler` receives a valid
sub-type 0x01 frame from the adapter with `local_10[0] != 0` (active negotiation flag set).

---

## 5. Type 0x03 - NETWORKS_LIST_REQUEST
**Direction**: Xbox → Adapter  
**Transport**: Ethernet 0x886f  
**HMAC Required**: No

### Brief Description
Triggers the adapter to perform a site survey (Wi-Fi Scan). This is a "blind" request with no parameters; the adapter scans all available channels and prepares the results for the subsequent Type 0x04 response.

**Note**:
If a scan is already in progress, any requests during a scan are silently dropped and no response is sent.

### Packet Format
```
Total size: (14 Ethernet + 12 Header) = 26 bytes
Body size:  (12 XPP header) / 4 = 0x03 DWORDs

Size | Segment          | Description
-------------|------------------|--------------------------------
14 bytes     | Ethernet header  | Standard header
12 bytes     | XPP Header       | Type 0x03, body size = 0x03 DWORDs
```
### Behavior
- Adapter triggers async Wi-Fi scan
- Scan takes 50-900ms depending on channel count
- Response sent when scan completes

### Tags
None (payload ignored)

### Related Information
- [Type 0x04 Response](#6-type-0x04---networks_list_response)

----

## 6. Type 0x04 - NETWORKS_LIST_RESPONSE
**Direction**: Adapter → Xbox  
**Transport**: Ethernet 0x886f  
**HMAC Required**: No

### Brief Description
Returns discovered Wi-Fi networks in a big payload.

**Network slot sizes**:
Each the network slots is a string of 53 bytes of sequential meaningful data with padding at
the end of each slot to make a stride of 61 bytes from the start of one slot to the next.

### How to Invoke
**Triggered by**: Type 0x03

### Packet Format
```
Total size: (14 Ethernet + 12 Header + 1 Count + N×61 Slots + Padding) = N Bytes
Body size:  (12 header + 1 network count  + (NC * 61) + Padding) / 4 = N DWORDs

Size         | Segment            | Description
-------------|--------------------|--------------------------------
14 bytes     | Ethernet header    | Standard header
12 bytes     | XPP Header         | Type 0x04, body size = variable DWORDs
1 byte       | Network count (NC) | Number of SSIDs found
N × 61 bytes | Network slots      | Fixed-width blocks containing SSID and Signal
0-3 bytes    | Alignment Padding  | Nulls to ensure the total body is DWORD aligned
```

### Payload Structure example:
```
Offset | Size  | Field
-------|-------|-------
0      | 61    | Network slot 1
61     | 61    | Network slot 2
------------------------------
info omitted  for slots 3-14
-----------------------------
915    | 61    | network slot 15
931    | 61    | network slot 16
```

### Network Slot Structure (61 bytes each)
```
Offset | Size | Field              | Description
-------|------|--------------------|------------------
0      | 6    | BSSID              | The AP's MAC Address.
6      | 1    | Privacy flags      | 0x01 means the AP has the 802.11 Privacy bit set (WEP/WPA), 0x00 means open.
7      | 1    | SSID Length        | 0-32 bytes.
8      | 32   | SSID String        | The network name, null-padded.
40     | 1    | Security Type      | Enum Open WEP WPA / WPA2. See security type
41     | 1    | Network mode       | 0x01=Infrastructure, 0x06=Ad-Hoc, 0x09=Infrastructure (observed on some APs — exact distinction from 0x01 unknown)
42     | 1    | Security Status    | bitmask of cipher info (TKIP/AES). See security status
43     | 1    | Channel            | Ap Channel
44     | 1    | Signal/RSSI        | Raw signal strength scale.
45     | 12   | Supported Rates    | Handshake rates (6, 9, 12, 18, 24, 36, 48, 54 Mbps).
53     | 4    | Alignment          | Zeros to pad the slot to the stride of 61-bytes.
```
**Note**: byte 44 signal RSSI has custom scaling see [Signal strength / link quality scaling)](Signal strength / link quality scaling)

**Factory Reset Default Network**:
When a factory reset is performed the adapter defaults to SSID "mshome", channel 1, infrastructure mode, IP 192.168.2.252/24, rate capability 0x0B (11 Mbps), no security, with all WEP keys cleared.

**⚠ Stale cache behaviour**: If the current scan returns zero networks, the adapter falls back to the previous scan's results and returns those instead. The adapter never sends an empty network list — it always returns the last successful scan.

```
1024 - 14 (Ethernet Header) - 4 (FCS Checksum) = 1006 bytes of available payload.
(1006 - 27) / 61 = 16 Slots
```

**note**: 16 network limit in the firmware of the adapter.
```
1500 - 12 - 1 = 1487 bytes/ 61 = 25 Slots
```

### Security type enumerated field (Byte 40)
```
⚠ Wire-verified: This byte is ALWAYS 0x02 in every adapter response regardless of network type
(open, WEP, WPA, WPA2, infrastructure, ad-hoc). The firmware writes 0x02 unconditionally.
.

 Value (Hex) | Wire observation
-------------|--------------------------------------------------
 0x02        | Always — firmware hardcodes this value for all network types
```

### Security status Bitfield (Byte 42)
```
⚠ Wire-verified across all real adapter logs (lysten_* captures):

 Value | Wire observation                       | Known networks with this value
-------|----------------------------------------|-------------------------------
 0x02  | 802.11 Privacy bit NOT set in beacon   | All open networks (OpenWrt*), WEP-open auth networks
 0x04  | 802.11 Privacy bit SET in beacon       | WPA, WPA2, WEP shared-key auth networks
```
**Important**: The adapter faithfully copies the 802.11 Privacy bit from the AP beacon into this byte.
It does NOT make a higher-level judgement about the security protocol in use.
- WEP open-auth networks may report 0x02 if the AP beacon has Privacy=0 (AP-dependent).
- OWE (Opportunistic Wireless Encryption) networks report 0x04 despite being open-auth.
- Use this byte only to determine if the AP beacon advertises encryption — not what kind.

**Privacy byte (Byte 6) is unreliable**: Wire captures show 0x01 on virtually all networks
including genuinely open ones. Do not use Byte 6 as a security indicator.
```
 Bit | Hex  | Original Ghidra Label | Description (firmware constant names are inferred)
-----|------|-----------------------|------------------------------------------------------
 0   | 0x01 | WLAN_FLAG_PRIVACY     | (unreliable — set on almost all networks including open)
 1   | 0x02 | WLAN_FLAG_OPEN        | 802.11 Privacy bit not set in beacon
 2   | 0x04 | WLAN_FLAG_TKIP        | 802.11 Privacy bit set in beacon (WEP/WPA/WPA2)
 3   | 0x08 | WLAN_FLAG_AES         | Reserved/Unused (not seen on wire)
 4-7 | ---- | WLAN_FLAG_RSVD        | Reserved/Unused bits
```

### Hidden SSID Handling
**Mechanism**: There is no specific "hidden flag" byte in the packet.
**Firmware Logic**: The adapter sets **SSID Length = 0** if the broadcast bit is disabled in the AP's beacon.
**Xbox Behaviour**:

- On first discovery, Xbox ignores hidden networks (length 0)
- When user manually enters SSID in Dashboard, Xbox sends Type 0x03 probe for that specific string
- Once adapter returns BSSID for that SSID, Xbox "pins" them together in RAM
- Dashboard displays "[Hidden Network]" for length 0 entries

### Real Example
```
[Network Slot 0 - Kids2.4g] - 61 bytes total

Offset | Hex Data                                   | Field
-------|--------------------------------------------|-------
0-5    | b6 b0 24 59 b8 0a                          | BSSID
6      | 01                                         | Privacy flags
7      | 08                                         | SSID length (8)
8-15   | 4b 69 64 73 32 2e 34 67                    | "Kids2.4g"
16-39  | 00 00 00 00 00 00 00 00 00 00 00 00 00 00  | SSID padding
       | 00 00 00 00 00 00 00 00 00 00              |
40     | 02                                         | Security type Open (0x02)
41     | 01                                         | network mode Infrastructure (Access Point)
42     | 02                                         | Security Flags: Basic/No Encryption
43     | 01                                         | channel 01
44     | d9                                         | Signal: 0xd9 (217 = 85%)
45-52  | 0c 12 18 24 30 48 60 6c                    | handshake Rates: 6,9,12,18,24,36,48,54 Mbps
53-60  | 00 00 00 00 00 00 00 00                    | Reserved/Padding

Total: 61 bytes (0x3D)
```

### Related Information
- [Type 0x03 Request](#5-type-0x03---networks_list_request)
- [Security Types Reference](#security-types-reference)
- [Signal Strength Conversion](#signal-strength-conversion)

----

## 7. Type 0x05 - ADAPTER_INFO_REQUEST
**Direction**: Xbox → Adapter  
**Transport**: Ethernet 0x886f  
**HMAC Required**: No


### Brief Description
Requests a variable array of tags. This operation reads TLV-formatted data from the MN-740.

#### - ADAPTER_INFO_REQUEST
```
Total size: (14 Ethernet + XPP header + 1 tag count + tag payload + Padding) = N Bytes
Body size:  (12 XPP Header + 1 tag count + tag payload + padding) / 4 = N DWORDs

 Size | Segment            | Description
--------------|--------------------|--------------------------------
14 bytes      | Ethernet header    | Standard header
12 bytes      | XPP Header         | Type: 0x05 , body size variable
1  byte       | TLV tag count      | Number of [Tag][Length Hint] pairs in the following tag block
Variable      | tag payload        | Array of [Tag][Length Hint] pairs — see Table A TLV Tags
Variable      | NULL Padding       | Zeros to ensure the body is DWORD aligned
```

### Tag Encoding Format
TLV tags are encoded as sequential byte strings in an array, aligned to a 4-byte boundary with padding.

All TLV tags use: `[1 byte Tag] [1 byte Length Hint]`

**Length Hint**: Advisory field designed to tell the adapter how many bytes to reserve for the tag response.
The MN-740 firmware reads but ignores the value entirely — all response lengths are hardcoded internally.
The hint values sent by Xbox do match the actual response sizes for fixed-width tags, suggesting this was an intended pre-allocation mechanism that was never implemented.
This results in alignment between request and response payload structures when they could have omitted this field entirely in the request.

### How to perform a bulk tag request
To query multiple TLV tags simultaneously, the host can send a Type 0x05 request.
The request starts with a numerical value representing the number of TLV [Tag][Length Hint] pairs requested in the payload.
The payload is a dense array of [Tag][Length Hint] pairs one after the other.
The adapter parses this array sequentially and generates a Type 0x06 response containing the full TLV data for every valid ID found in the request array.
Null bytes (0x00) are used only as trailing padding to maintain 32-bit alignment and are ignored by the adapter's parser."

### Example Payload Structure
Ask for tags 0x01 0x04 and 0x11
```
03 01 04 04 01 11 01 00
|  ↑  ↑  ↑  ↑  ↑  ↑  ↑  
|  |  |  |  |  |  |  └─── alignment padding to next 4 Byte boundary (1 byte)
|  |  |  |  |  |  └─  third requested length hint  (1 byte)
|  |  |  |  |  └────  third requested tag 0x11 (encryption type)
|  |  |  |  └─ second requested length hint (1 byte)
|  |  |  └──── second requested tag 0x04 (wireless mode), (1 byte)
|  |  └─── first requested length hint (4 bytes)
|  └────── first requested tag 0x01 (IP address)
└────── Number of [tag] [tag hint] pairs (3)
```

**Note**:
If you request a really large array of tags that exceeds the buffer length it will trigger a malloc_error
and silently drop the packet issuing a NUK NUK error response in the serial console.

### Table A TLV Tags
**Note**: See type 0x06 Table A TLV Tags for a list of tags and responses.


### Related Information
- [Type 0x06 adapter Info Response](#8-type-0x06---adapter_info_response)

---

## 8. Type 0x06 - ADAPTER_INFO_RESPONSE
**Direction**: Adapter → Xbox  
**Transport**: Ethernet 0x886f  
**HMAC Required**: No

### Brief Description
response to a type 0x05 request to read TLV formatted tags from the MN-740.

**Triggered by**: Type 0x05 request

**DYNAMIC TLV TAG POSITIONING**. Tags are only included if they have valid data. You **MUST** parse as a TLV stream, NOT fixed offsets!
**Example**: If adapter has no IP assigned, Tag 0x01 is skipped entirely from the response

### Packet Format (Tag Response)
```
Total bytes: (14 Ethernet + 12 XPP Header + 2 artifact + Payload + padding) = N bytes
Body size:   (12 XPP header + 2 artifact + payload + padding) / 4 = N DWORDs

Size | Segment           | Description
-------------|-------------------|--------------------------------
14 bytes     | Ethernet header   | Standard Header
12 bytes     | XPP Header        | Type 0x06, body size = variable
1  Byte      | Firmware artifact | Always 0x00 side effect of firmware DWORD zero write at XPP+12, skip before parsing TLV stream
1 Byte       | request count     | Echo of the Type 0x05 request count byte (e.g., 0x09 if 9 tags were requested)
variable     | Payload           | Array of [Tag][Length] pairs
0 - 3 bytes  | Null/Padding      | padding to align to 4 byte boundary
```


### Tag Encoding Format
TLV tags are encoded as sequential byte strings in an array, aligned to a 4-byte boundary with padding.

All TLV tags use: `[1 byte Tag] [1 byte Length] [N bytes Value]`

### Example Response Payload Structure
Response for tags 0x01 0x04 and 0x11 from prior request example in type 0x05 section
```
00 00 04       04 01 00 11 01 01
↑  ↑  ↑  ↑  ↑  ↑  ↑  ↑  ↑  ↑  ↑  
|  |  |  |  |  |  |  |  |  |  └──second response data (1 byte, value 0x01)
|  |  |  |  |  |  |  |  |  └─────second response length (1 byte)
|  |  |  |  |  |  |  |  └─────── second response tag 0x11 (radio mode), (1 byte)
|  |  |  |  |  |  |  └─ first response data (1 byte, value 0x00)
|  |  |  |  |  |  └──── first response length (1 byte)
|  |  |  |  |  └─────── first response tag 0x04 (wireless mode), (1 byte)
|  |  |  |  └─── first requested tag expected data (4 bytes) MISSING !!
|  |  |  └─── expected first requested tag length (4 bytes) MISSING !!
|  |  └────── expected first requested tag 0x01 (IP address) MISSING !!!
|  └────── echo of tag count from type 0x05
└────── Firmware artifact
```
**Example feature**:
If you look in the response example in type 0x05 adapter it requested for tags 0x01 0x04 and 0x11.
This response is totally void of the first requested tag IP address!!!
This response shows the adaptive nature of the TLV tag system and the sliding tags.
In this response example does not have an IP address at the time of the tag request so the data was skipped and the second tag filled it place.

### Table A TLV Tags
**Note**: This table lists tags available in Type 0x05 for request and type 0x06 for response.
```
 Tag  | Name                  | Size  | Condition       | Description
------|-----------------------|-------|-----------------|-------------
0x01  | IP Address            |  4    |   IP assigned   | Current adapter IP (Big-Endian)
0x02  | Connection State      |  1    |   Always        | 0x00=no DHCP yet, 0x01=DHCP acquired (state 0x52), 0x02=interface manually enabled. See Tag 0x02 detail below.
0x03  | Admin Identity        |  Var  |   Always        | Read-back of `g_NVRAM_User_Settings.Legacy_Padding` (`admin_id`) — the XPP admin identity password (max 16 bytes + NUL). Write counterpart is Table B Tag 0x03. This same string is used as HMAC input for TFTP RRQ auth on port 16932.
0x04  | Radio Active Flag     |  1    |   Always        | wlan_is_radio_active(): 0x00=radio off, 0x01=radio on/b-only, 0x02=radio on/b+g.
                                                        | 0x01 means radio active in 802.11b mode, not merely "on". (Write path via Tag 0x04 in Type | 0x07 sets operatingmode
0x05  | radio channel         |  1    |   Always        | XPP_Get_Channel_Or_Fallback(): returns live radio channel (1–14) via wlan_freq_to_channel_number() when authenticated, or
                                                        | g_CFG_Max_Channel (saved configured channel) when not authenticated. Wire-verified: channel 3 = 0x03 observed in
                                                        | lysten_open_connect_with_wan_ch_3_new.log.
0x06  | BSSID                 |  6    |   If connected  | MAC address of the current AP (BSSID). Returns 00:00:00:00:00:00 when not associated with any AP (e.g. Router is off, adapter
                                                        | is scanning, or profile configured but not yet connected). Wire-verified: c4:4b:d1:00:47:4e (DrayTek Vigor 2762 router,
                                                        | actively connected) in open captures; 00:00:00:00:00:00 (no AP present) in lysten_setmac_host_ppoe_and_connect_to_live.log
                                                        | where router was powered off.
0x07  | SSID                  |  Var  |   If associated | Byte 0: length; Byte 1: SSID string
0x08  | Auth Type (response)  |  1    |   Always        | In ADAPTER_INFO_RESP: negotiated auth/encryption type. 0x02=open network, 0x04=WEP active. ⚠ Do NOT confuse with Tag 0x08 in
                                                        | CONNECT_REQ (Type 0x07) which writes to CFG_Set_WEP_Enabled().
0x09  | Link state            |  1    |   Always        | 0x01=no link, 0x02=infra linked, 0x04=ad-hoc linked
0x0A  | WEP Key Slot 0        |  —    |   WRITE-ONLY    | ⚠ NO READ HANDLER. Falls to LAB_8009a918 (silent response corruption). Write counterpart: Table B Tag 0x0A → Wi-Fi_Set_Security_Key(src, 0).
0x0B  | WEP Key Slot 1        |  —    |   WRITE-ONLY    | ⚠ NO READ HANDLER. Falls to LAB_8009a918. Write counterpart: Table B Tag 0x0B → Wi-Fi_Set_Security_Key(src, 1).
0x0C  | WEP Key Slot 2        |  —    |   WRITE-ONLY    | ⚠ NO READ HANDLER. Falls to LAB_8009a918. Write counterpart: Table B Tag 0x0C → Wi-Fi_Set_Security_Key(src, 2).
0x0D  | WEP Key Slot 3        |  —    |   WRITE-ONLY    | ⚠ NO READ HANDLER. Falls to LAB_8009a918. Write counterpart: Table B Tag 0x0D → Wi-Fi_Set_Security_Key(src, 3).
0x0E  | Current Channel       |  1    |   radio active  | Channel 1–14. Returns live channel via `wlan_freq_to_channel_number()`. Read-only — write counterpart is Table B Tag 0x0E (`CFG_Set_WiFi_Channel()`). Stored to AutoClass1+0xe41.
0x0F  | WEP-128 Key           |  —    |   WRITE-ONLY    | ⚠ NO READ HANDLER. Falls to LAB_8009a918. Write counterpart: Table B Tag 0x0F → CFG_Set_WEP128_Key_Slot() all 4 slots (13-byte key).
0x10  | WPA PMK               |  —    |   WRITE-ONLY    | ⚠ NO READ HANDLER. Falls to LAB_8009a918. Write counterpart: Table B Tag 0x10 → 32-byte PMK stub (src = pbVar4 + 0x22, discards data — not stored to hardware).
0x11  | Encryption Type       |  1    |   Always        |  `wlan_get_encryption_type()`: 0x00=no encryption, 0x01=unreachable (dead code), 0x02=WEP/encryption active. Wire-verified: only 0x00 and 0x02 observed. See §Byte 218 in Type 0x02 for full firmware path.
0x81  | adapter MAC           |  6    |   Always        | Adapter LAN-side MAC address. Source: `g_NVRAM_Router_MAC` — the adapter's
      |                       |       |                 | own Ethernet interface MAC, initialised from `G_XBOX_MAC_ADDR` at boot via
      |                       |       |                 | `eth_brecis_msp_init()`. ⚠ Despite the variable name containing "Router",
      |                       |       |                 | this is the adapter's own MAC, not the paired console MAC.
0x83  | Net Reset Param       |  1    |   Always        | g_CFG_Reconnect_Mode — current reconnect mode value (read-back of Tag 0x83 write).
0x82  | regulatory domain     |  1    |   Always        | this is the regulatory domain code burned into the AR5 hardware EEPROM
0x84  | Max Channel           |  1    |   Always        | g_CFG_Max_Channel — configured channel ceiling (read-back of Tag 0x84 write). Clamped to hardware regulatory channel range.
0x85  | TX Rate Code          |  1    |   If associated | Current PHY speed in MBps  see Rate code whitelist
0x86  | AR5212 EEPROM Block 0 |  512  |   If radio off  | AR5212 EEPROM offset 0x000-0x1FF (board config, TX power tables) ⚠ PC wizard only — never requested by xonlinedash.xbe
0x87  | AR5212 EEPROM Block 1 |  512  |   If radio off  | AR5212 EEPROM offset 0x200-0x3FF (noise floor, channel corrections) ⚠ PC wizard only
0x88  | AR5212 EEPROM Block 2 |  512  |   If radio off  | AR5212 EEPROM offset 0x400-0x5FF (extended calibration, often 0 on b/g hardware) ⚠ PC wizard only
0x89  | AR5212 EEPROM Block 3 |  512  |   If radio off  | AR5212 EEPROM offset 0x600-0x7FF (extended calibration, often 0 on b/g hardware) ⚠ PC wizard only
```
**⚠ LAB_8009a918 — Write-only tag corruption behaviour**: Tags 0x0A–0x0D, 0x0F, 0x10 have no read handler. All fall to `LAB_8009a918` which executes `*(pPayload+2) -= 1` — it decrements whatever byte happens to be at the data position (leftover from the previous tag's response), then falls through without advancing the response write pointer. The result is a response entry with the correct tag byte but a corrupted length field and no data. The loop counter still advances so subsequent tags in the same request are processed normally. Do not include these tags in ADAPTER_INFO_REQ.

## Tag 0x02 Connection State
```
Return | Condition                                                        | Meaning
-------|------------------------------------------------------------------|----------------------------
0x00   | g_NET_InterfaceStatus=0, g_DHCP_Interface_States ≠ 0x52          | Interface up, no DHCP yet
0x01   | g_NET_InterfaceStatus=0, g_DHCP_Interface_States == 0x52         | DHCP acquired (fully connected)
0x02   | g_NET_InterfaceStatus=1                                          | Static IP / manual mode
⚠ UNDEF| g_NET_InterfaceStatus any other value                           | local_res5 never assigned — raw stack byte sent
```
**Edge case**: If `g_NET_InterfaceStatus` holds any value other than `0` or `1` (corrupted state), the firmware never assigns `local_res5` before `memcpy()` — an uninitialised stack byte is transmitted. This is a firmware bug.

The WEP64 Packet #98 returned `0x00` (not `0x01`) for Tag 0x02 **despite having IP 192.168.1.181**. This means `g_DHCP_Interface_States` had not yet reached state `0x52` at the time of the query — the adapter had an IP but DHCP wasn't fully finalised in the state machine. This is a timing issue, not an error.

### Tag 0x08 Auth Type (response)
Tag 0x08 Auth Type (response) in Type 0x02 trailer byte 0 returns XPP_Get_Link_State_Bitmask() which reads g_WLAN_LinkState_Bit directly:

g_WLAN_LinkState_Bit = 0 → returns 0x02
g_WLAN_LinkState_Bit = 1 → returns 0x04

g_WLAN_LinkState_Bit is set by CFG_Set_WEP_Enabled() which is called internally by XPP_Set_Link_State() (Tag 0x09). Value 0x04 means an active link state was committed via Tag 0x09 — it does NOT indicate ad-hoc mode. Use XPP_Tag_09_Handler_Get_Link_State() (Tag 0x09 response) to determine actual link state reliably.

### Tag 0x09 Link State Return Values
```
Return | g_WLAN_LinkActive | g_WLAN_LinkState_Bitmask | Meaning
-------|-------------------|--------------------------|---------------------
0x01   | 0                 | (any)                    | No link / idle
0x01   | 1                 | not 0x05 or 0x0d         | No link (fallback)
0x02   | 1                 | 0x05                     | Infrastructure linked ✓
0x04   | 1                 | 0x0d                     | Ad-Hoc linked ✓
```

### Tag 0x82 regulatory country channels
```
Value | Meaning   | range
------|-----------|------------------------------------------------
0x10  | USA       | ch 1–11 (default)
0x20  | Canada    | ch 1–11 (default)
0x30  | ETSI      | ch 1–13
0x31  | Spain     | ch 10–11
0x32  | France    | ch 10–13
0x40  | Japan     | ch 14 only
0x41  | Japan all | ch 1–14
other | unknown   | ch 1–11 (default)
```

### Tag 0x85 - Rate code Whitelist
**Note**: The "Index" column below is the Xbox-side sequential index inferred from firmware bounds checking — it is not a value transmitted on the wire. The "Hex" column is the actual PHY rate code transmitted on the wire. These PHY rate codes (0x02, 0x0B, 0x16, 0x6C, etc.) are the same values returned in Type 0x0A BEACON_RESPONSE byte 2 (`tx_rate_code`). See also the [Type 0x0A payload structure](#12-type-0x0a---beacon_response) — `drvr_get_tx_rate_code()` returns these same codes.
```
 Index | Rate (Mbps) | Standard  | Notes
-------|-------------|-----------|-------
 0x00  | Auto-select | -         | Automatic rate negotiation
 0x01  | 1 Mbps      | 802.11b   | Legacy compatibility
 0x02  | 2 Mbps      | 802.11b   | Legacy compatibility
 0x03  | 5.5 Mbps    | 802.11b   |
 0x04  | 6 Mbps      | 802.11g   | Basic rate
 0x05  | 9 Mbps      | 802.11g   |
 0x06  | 11 Mbps     | 802.11b   | Maximum 802.11b rate
 0x07  | 12 Mbps     | 802.11g   |
 0x08  | 18 Mbps     | 802.11g   |
 0x09  | 24 Mbps     | 802.11g   |
 0x0A  | 36 Mbps     | 802.11g   |
 0x0B  | 48 Mbps     | 802.11g   |
 0x0C  | 54 Mbps     | 802.11g   | Maximum 802.11g rate
```
**Note**: The index column is inferred based on bounds checking in the firmware. There is no explicit index-to-rate mapping table in firmware — the Xbox performs this conversion client-side.

### (Tags 0x86-0x89) AR5212 EEPROM Dump

**Origin**: These tags have never been observed in any Xbox dashboard capture (`lysten_*` logs
or any other XPP capture). They sit in the same provisioning tag range as 0x81–0x85 which the
spec confirms are never sent by `xonlinedash.xbe`. The most likely origin is the **Windows
MN-740 Setup Wizard** — the PC-side configuration utility that shipped on CD with the adapter.
The wizard would use these tags to read the EEPROM before a firmware upgrade (so calibration
data can be preserved across flash operations) and possibly to display regional compliance
information. An emulator implementing these tags should do so for completeness and tool use,
but should not expect the Xbox dashboard to ever request them during normal operation.

**What is being read**: These tags return the contents of the Atheros AR5212 radio chip's
onboard serial EEPROM — **not** the adapter's firmware flash. The EEPROM is a separate 2KB
chip on the AR5001X MAC/baseband board that holds factory-calibrated radio data burned at
manufacture time. The adapter firmware itself lives in a larger SPI flash and is accessed
via TFTP (see §TFTP Firmware Upgrade), not via these tags.

**EEPROM contents** (2048 bytes total, four 512-byte blocks):
```
Offset       | Contents
-------------|---------------------------------------------------------------
0x000-0x07F  | AR5212 magic word (0x5aa5 at word 0x3D), board configuration,
             | regulatory domain code, factory MAC address (hardware-burned,
             | distinct from the provisioned NVRAM MAC)
0x080-0x1FF  | Per-channel TX power calibration tables (2.4GHz channels 1-14)
0x200-0x3FF  | Noise floor calibration, additional per-channel corrections
0x400-0x7FF  | Extended calibration (often sparse/zeroed on b/g-only hardware)
```

**Why does the Xbox request this?**

Two purposes:

1. **Radio HAL initialisation** — The Atheros HAL requires the EEPROM data
   to configure TX power levels, noise floor thresholds, and regulatory channel limits
   for each country. A physical MN-740 reads its own EEPROM at boot via the AR5212 SPI
   bus.

2. **Soft authenticity check** — The EEPROM contains the factory-burned hardware MAC
   address at a known offset. The dashboard could in theory cross-check this against the MAC
   presented in the HANDSHAKE_RESP for aditional adaptor verification.

**⚠ Partial Read Limitation**: `XPP_flash_read_wrapper()` reads only `0x400` bytes (1KB)
into an `0x800`-byte buffer. On failure the buffer is filled with `0xFF` via `memset`.
Each tag copies a 512-byte (`0x200`) block at offset `(tag - 0x86) * 0x200`:
```
Tag  | Block offset | Contents                        | Reliable?
-----|--------------|----------------------------------|--------------------------
0x86 | 0x000-0x1FF  | Board config, TX power tables   | ✓ Yes — within 0x400 read
0x87 | 0x200-0x3FF  | Noise floor, channel corrections| ✓ Yes — within 0x400 read
0x88 | 0x400-0x5FF  | Extended calibration (often 0)  | ✓ Yes — real hardware returns valid data
0x89 | 0x600-0x7FF  | Extended calibration (often 0)  | ✓ Yes — real hardware returns valid data
```
**Note**: Wire-verified capture from a real MN-740 confirms all
four blocks return valid data — blocks 2 and 3 are mostly zeros because the MN-740 is a
2.4GHz-only b/g adapter and does not use the extended 5GHz calibration tables that would
occupy that space. The all-zero content is correct and expected, not a read failure.

**Transfer mechanism**: The EEPROM is memory-mapped through the Atheros wireless chip.
`XPP_flash_read_wrapper()` calls `net_interface_read_word()` repeatedly, pulling 16 bits
at a time into a local RAM shadow buffer. Once complete, each 512-byte block is moved into
the XPP transmission buffer as a single TLV response.

**Special notes**:
- The TLV Length Byte in the response is `0xFF` — a protocol signal indicating an
  "Extended Data Block" of 512 bytes follows, since 512 > 255 (the normal 1-byte length
  maximum).
- The radio must be inactive (tag 0x04 = 0x00) for the EEPROM read to succeed. Querying
  these tags while the radio is associated will return 0xFF-filled blocks.

### Wire-Verified ADAPTER_INFO_RESP Example (Open Network, Channel 3, WAN Connected)
Captured from `lysten_open_connect_with_wan_ch_3_new.log` Packet #16.
Xbox requested tags: 0x09, 0x01, 0x04, 0x02, 0x01, 0x04, 0x01, 0x05, 0x01, 0x06, 0x06, 0x07, 0x20, 0x08, 0x01, 0x09, 0x01, 0x11, 0x01 (9 tags total).

#### ⚠Response Payload Structure
The ADAPTER_INFO_RESP payload does **not** begin with a plain TLV stream. It has a fixed preamble payload header:
```
Byte(s)        | Description
---------------|------------------------------------------------------------
0x00           | Firmware artifact (always 0x00, present only when IP assigned)
0x09           | number [Tag][Len][Val] triplets sent in this payload
TLV stream     | Remaining tags as standard [Tag][Len][Val] triplets
```
The IP field is only present when the `link_state` byte indicates a connected state. This structure
was confirmed by comparing open network, WEP-64, and WEP-128 wire captures.

```
Raw bytes (payload only, after XPP header):
00 09 | 01 04 c0 a8 01 96 | 02 01 00 | 04 01 01 | 05 01 03 | 06 06 c4 4b d1 00 47 4e | 07 04 6f 70 65 6e | 08 01 02 | 09 01 01 | 11 01 02

Decoded:
 Byte(s)                 | Value           | Meaning
-------------------------|-----------------|--------------------------------------------------
 00                      | 0x00            | Firmware byte alignment artifact (always 0x00)
 09                      | 0x09            | number of tags in the following payload
 01 04 c0 a8 01 96       | Tag 0x01 len 4  | IP Address: 192.168.1.150 (raw field, not TLV)
 02 01 00                | Tag 0x02 len 1  | DHCP state: 0x00 (g_DHCP_Interface_States not yet 0x52)
 04 01 01                | Tag 0x04 len 1  | Radio active: 0x01 (radio on)
 05 01 03                | Tag 0x05 len 1  | Channel: 3 (wire-confirms channel 3 = 0x03) ✅
 06 06 c4 4b d1 00 47 4e | Tag 0x06 len 6  | BSSID: c4:4b:d1:00:47:4e (DrayTek Vigor 2762 router)
 07 04 6f 70 65 6e       | Tag 0x07 len 4  | SSID: "open" (4 bytes)
 08 01 02                | Tag 0x08 len 1  | Auth type: 0x02 (open network — no WEP encryption)
 09 01 01                | Tag 0x09 len 1  | link_state: 0x01 (no link — ADAPTER_INFO_REQ is sent before CONNECT_REQ)
 11 01 02                | Tag 0x11 len 1  | Encryption type: 0x02 (pre-set by CFG_Set_XPP_Auth_Mode)
```
**Note**: Tag 0x09 = `0x01` (no link) is the expected state during the ADAPTER_INFO query phase —
the dashboard queries current state BEFORE sending CONNECT_REQ, so the adapter is not yet
associated at this point. Tag 0x02 = `0x00` confirms DHCP is not active. Both are consistent
with the normal session flow, not error conditions. The Tag 0x11 = `0x02` (WEP) appears
because `CFG_Set_XPP_Auth_Mode(0x02)` was previously called (Tag 0x11 in a Type 0x07 connect packet).

#### Tag 0x08 in ADAPTER_INFO_RESP — Auth Type
⚠ In ADAPTER_INFO_RESP (Type 0x06), Tag 0x08 reports the **negotiated authentication/encryption type**,
not the link state bitmask. This is different from Tag 0x08 in CONNECT_REQ (Type 0x07) where it is the
security mode flag written to `CFG_Set_WEP_Enabled()`.
```
Value | Meaning
------|-------------------------------------------------------------------
0x02  | Open network (no WEP encryption) — wire-verified
0x04  | WEP encryption active (64-bit or 128-bit) — wire-verified
```
Wire evidence: open network (`ssid=open`) returns `0x02`; both WEP-128 ASCII (`ssid=wpa_128`) and
WEP-64 ASCII (`ssid=wpa_64`) return `0x04` in their respective ADAPTER_INFO_RESP Tag 0x08 fields.

### Wire-Verified ADAPTER_INFO_RESP Examples (WEP Connections)
Captured from `lysten_wep_secured_128_bit_ascii.log` Packet #111 and `lysten_wep_secured_64_bit_ascii.log` Packet #98.
New router (BSSID prefix `02:1d:aa`), channel 11, IP 192.168.1.181.
```
--- WEP 128-bit ASCII (ssid=wpa_128) ---
Raw payload preamble + TLV stream:
00 09 01 04 | c0 a8 01 b5 | 02 01 00 | 04 01 01 | 05 01 0b | 06 06 02 1d aa 64 c6 50 | 07 07 77 70 61 5f 31 32 38 | 08 01 04 | 09 01 04 | 11 01 02

 Byte(s)                          | Meaning
----------------------------------|---------------------------------------------------
 00                               | Firmware artifact byte (always 0x00, present when IP is assigned)
 09                               | 9 tags in the following payload
 01 04 c0 a8 01 b5                | IP Address: 192.168.1.181 (raw field)
 02 01 00                         | DHCP state: 0x00 (timing lag, IP assigned but state not 0x52 yet)
 04 01 01                         | Radio active: 0x01
 05 01 0b                         | Channel: 11 (0x0b) — new router on channel 11
 06 06 02 1d aa 64 c6 50          | BSSID: 02:1d:aa:64:c6:50 (new router, locally administered MAC)
 07 07 77 70 61 5f 31 32 38       | SSID: "wpa_128" (7 bytes — test network name, not WPA protocol)
 08 01 04                         | Auth type: 0x04 ✅ WEP active
 09 01 04                         | link_state: 0x04 (ad-hoc state code — exact meaning TBD)
 11 01 02                         | Encryption type: 0x02

--- WEP 64-bit ASCII (ssid=wpa_64) ---
Raw payload preamble + TLV stream:
00 09 01 04 | c0 a8 01 b5 | 02 01 00 | 04 01 01 | 05 01 0b | 06 06 02 1d aa 54 c6 50 | 07 06 77 70 61 5f 36 34 | 08 01 04 | 09 01 02 | 11 01 02

 Byte(s)                          | Meaning
----------------------------------|---------------------------------------------------
 00                               | Firmware artifact byte (always 0x00, present when IP is assigned)
 09                               | 9 tags in the following payload
 01 04 c0 a8 01 b5                | IP Address: 192.168.1.181 (raw field)
 02 01 00                         | DHCP state: 0x00 (timing lag)
 04 01 01                         | Radio active: 0x01
 05 01 0b                         | Channel: 11 (0x0b)
 06 06 02 1d aa 54 c6 50          | BSSID: 02:1d:aa:54:c6:50 (note different from 128-bit session)
 07 06 77 70 61 5f 36 34          | SSID: "wpa_64" (6 bytes — test network name, not WPA protocol)
 08 01 04                         | Auth type: 0x04 ✅ WEP active
 09 01 02                         | link_state: 0x02 (infrastructure linked)
 11 01 02                         | Encryption type: 0x02
```
**Notes**:
- Both WEP sessions confirm `Tag 0x08 = 0x04` as the wire indicator of WEP encryption.
- The SSIDs `wpa_128` and `wpa_64` are test network names — the actual protocol is WEP in both cases, confirmed by the key tags sent in CONNECT_REQ and by Tag 0x08 = 0x04 in the response.
- Tag 0x02 = `0x00` is the expected value during the ADAPTER_INFO query phase — the dashboard queries state before sending CONNECT_REQ, before DHCP has been established for the new connection.
- The WEP 128-bit session shows `Tag 0x09 = 0x04` (ad-hoc code) while WEP 64-bit shows `0x02` (infrastructure). Both connections are infrastructure — the `0x04` value here may be a transient state; further capture needed.

### Related Information
- [Type 0x05 Request](#7-type-0x05---adapter_info_request)

----

## 9. Type 0x07 - CONNECT_TO_SSID_REQUEST
**Direction**: Xbox → Adapter  
**Transport**: Ethernet 0x886f  
**HMAC Required**: No

### Brief Description
Configures network connection with TLV-encoded parameters
configure and save the adapter settings to the EEPROM.

### Packet Format
```
Total size: (14 Ethernet + 12 Header + Payload + padding) = N bytes
Body size:  (12 XPP header + payload + padding) / 4 = N DWORDs

Size | Segment          | Description
-------------|------------------|--------------------------------
14 bytes     | Ethernet header  | Standard Header
12 bytes     | XPP Header       | Type 0x07, body size = variable
1  byte      | TLV Count        | Number of TLV tags that follow in this payload
variable     | TLV Stream       | stream of TLV tags [Tag][Length][Value]
0 - 3 bytes  | Empty/Padding    | padding to align to 4 byte boundary
```

### Tag Encoding Format
TLV tags are encoded as sequential byte strings in an array, aligned to a 4-byte boundary with padding.

All TLV tags use: `[1 byte Tag] [1 byte Length] [N bytes Value]`

### Table B - Type 0x07 TLV Tag Table
**Source**: Confirmed directly from firmware function `XPP_Parse_Entry()` in NML_bin.c.

**Note**: These tags are handled exclusively by `XPP_Parse_Entry()`. Do **not** confuse with Table A tags (Types 0x05/0x06) which share some tag numbers but have completely different meanings.

```
 Tag | Name                    | Size | Firmware Function Called              | Description
-----|-------------------------|------|---------------------------------------|--------------------------------------------------------
0x00 | CFG Save & Reboot       | 0    | Flash_Commit_Settings()               | Save current config to flash and triggers system reboot
     |                         |      | + CFG_Save_To_Flash()                 |
     |                         |      | + hw_trigger_reboot_sequence()        |
0x01 | IP Address              | 4    | memcpy → CFG_Device_IP                | Static IP address configuration (big-endian)
0x02 | Connection State        | 1    | g_NET_InterfaceStatus = (*src == 2)   | 0x02=enable (true), any other value=disable (false)
0x03 | XPP Admin Password /    | 0-16 | memcpy → g_NVRAM_User_Settings.Legacy_Padding (admin_id) | Console pairing lock: prevents unauthorised consoles from reconfiguring
     | Pairing Lock            |      |                                       | the adapter. Factory default "admin". Also serves as HTTP/TFTP admin
     |                         |      |                                       | username. Len=0 clears the password. Wire-verified in lysten_password.log.
0x04 | Operating Mode          | 1    | WLAN_Set_Operating_Mode()             | Wireless operating mode configuration.
0x05 | allowed channel range   | 1    | CFG_Set_Max_Channel()                 | sets the allowed Wi-Fi channel range
0x06 | Target Xbox MAC         | 6    | CFG_Set_Paired_Xbox_MAC()             | 6-byte MAC address of paired Xbox console.
0x07 | Target SSID             | 1-32 | CFG_Set_Target_SSID ()                | Network SSID to connect to.
0x08 | Security mode           | 1    | CFG_Set_WEP_Enabled()                 | Sets the WEP/security flag.
0x09 | link State              | 1    | XPP_Set_Link_State()                  | Wireless link state update.
0x0A | WEP Key Slot 0          | 5    | Wi-Fi_Set_Security_Key(src, 0)        | WEP-40 key slot 0 (5-byte key).
0x0B | WEP Key Slot 1          | 5    | Wi-Fi_Set_Security_Key(src, 1)        | WEP-40 key slot 1 (5-byte key).
0x0C | WEP Key Slot 2          | 5    | Wi-Fi_Set_Security_Key(src, 2)        | WEP-40 key slot 2 (5-byte key).
0x0D | WEP Key Slot 3          | 5    | Wi-Fi_Set_Security_Key(src, 3)        | WEP-40 key slot 3 (5-byte key).
0x0E | Radio Channel Index     | 1    | CFG_Set_Wi-Fi_Channel ()              | Selects the active Wi-Fi channel.
0x0F | WEP-128 Advanced        | 13   | CFG_Set_WEP128_Key_Slot()             | Writes 13-byte WEP-128 key into all 4 slots of G_CFG_WEP128_Key_Table.
0x10 | WPA PMK                 | 32   | src = pbVar4 + 0x22 (stub — discards) | 32-byte WPA Pairwise Master Key. Dashboard hex-decodes user's 64-char
                                                                              | hex input to 32 raw bytes and sends
                                                                              | here. STUB — firmware advances pointer 0x22 bytes from tag byte
                                                                              | (tag+len+32) and silently discards. Not
                                                                              | stored, not passed to hardware key engine. See §Tag 0x10 below.
0x11 | Auth mode Flag          | 1    | CFG_Set_XPP_Auth_Mode()               | Flag to indicate saved network was encrypted if it is not connected to
                                                                              | indicate via state
0x12 | WPA Passphrase          | 8-63 | NOT HANDLED — falls to got_unknown_%d | Raw ASCII WPA passphrase (8–63 chars). Dashboard sends when user
                                                                              | enters a text passphrase (not pre-computed
                                                                              | PMK). Stock firmware has NO case for 0x12: parser logs got_unknown_%d
                                                                              | and exits the TLV loop immediately.
                                                                              | Tags after 0x12 in the same packet are NEVER processed. See §Tag 0x12
                                                                              | below.
0x14 | MAC Address Clone       | 6    | see mac address cloning / spoofing    | 6-byte MAC address to spoof. Historically logged and documented; wire
                                                                              | capture lost. Not emitted by
                                                                              | `xonlinedash.xbe` — originates from the network settings XBE
                                                                              | (multi-XBE dash architecture). No `case 0x14`
                                                                              | in firmware v1.0.2.26 parser. See §Tag 0x14 below.
0x81 | Session MAC Init        | 6    | XPP_Establish_Secure_Identity_Link()  | 6-byte MAC → copies to session buffer then initialises session
0x82 | Interface Reset/Reinit  | 1    | NET_Interface_Reset_And_Reconnect()   | Value=0x00: skip disconnect, go straight to MAC reinit.
                                                                              | Value≠0x00: call disconnect_interface_handle(0,
                                                                              | value) first, then reinit. Internally calls what Ghidra labels
                                                                              | NET_Is_Link_Active — this is a misnomer, the
                                                                              | function is actually NET_Reinit_Interface_With_MAC.
0x83 | Net Reset Param         | 1    | g_CFG_Reconnect_Mode = val            | Parameter passed to NET_Interface_Reset_And_Reconnect(). **Valid
                                                                              | values**: 0, 1, 2 only. Defaults to 1 if invalid. Factory default = 1.
0x84 | Max Channel             | 1    | g_CFG_Max_Channel = val               | Sets the Wi-Fi regulatory channel ceiling. Input clamped to hardware
                                                                              | range via determine_hw_channel_range(). Defaults to channel 11 if out | of range.
0x85 | TX Rate Code            | 1    | g_CFG_TX_Rate_Index = val             | 802.11 rate code — validated against whitelist. If not in whitelist,
                                                                              | value is **silently dropped** (not stored). No clamping occurs.
```
### Tag 0x04 Operating mode
```
Hex  | Description
-----|-------------
0x00 | Disable radio
0x01 | Enable radio
```

### Tag 0x08 op mode mask
Tag 0x08 (OpMode Mask) in Type 0x02 trailer byte 0 returns `XPP_Get_Link_State_Bitmask()` which reads `g_WLAN_LinkState_Bit` directly:
```
g_WLAN_LinkState_Bit = 0 → returns 0x02
g_WLAN_LinkState_Bit = 1 → returns 0x04
```
`g_WLAN_LinkState_Bit` is set by `CFG_Set_WEP_Enabled()` which is called internally by `XPP_Set_Link_State()` (Tag 0x09). Both infrastructure and ad-hoc connect set `g_WLAN_LinkState_Bit = 1`, so trailer byte 0 returns `0x04` for both — it only indicates WEP is active, not the network topology. Use `XPP_Tag_09_Handler_Get_Link_State()` to determine actual link type reliably.

---

### Tag 0x09 (XPP_Set_Link_State)
**This tag controls `g_WLAN_LinkActive`, `g_WLAN_LinkState_Bitmask`, and `g_WLAN_LinkState_Bit` (via `CFG_Set_WEP_Enabled()`).**

```
Val  | g_WLAN_LinkActive | g_WLAN_LinkState_Bitmask | g_WLAN_LinkState_Bit | Meaning
-----|-------------------|--------------------------|----------------------|------------------------
0x01 | 0 (link down)     | unchanged                | 0 (WEP disabled)     | Disassociate / go idle
0x02 | 1 (link up)       | 0x05                     | 1 (WEP enabled)      | Infrastructure connect
0x04 | 1 (link up)       | 0x0d                     | 1 (WEP enabled)      | Ad-Hoc connect
```

`XPP_Tag_09_Handler_Get_Link_State()` reads `g_WLAN_LinkActive` and `g_WLAN_LinkState_Bitmask` to determine the link state returned in Type 0x06 Tag 0x09.

`XPP_Get_Link_State_Bitmask()` reads `g_WLAN_LinkState_Bit` to return the opmode mask in Type 0x02 trailer byte 0. Both infrastructure and ad-hoc connect set `g_WLAN_LinkState_Bit = 1`, so trailer byte 0 returns `0x04` for both — it only indicates WEP is active, not the network topology. Use `XPP_Tag_09_Handler_Get_Link_State()` to determine actual link type.

## Tags 0x81–0x85 — Provisioning / Management Tags (Not sent by Dashboard)

**Important**: Tags 0x81–0x85 are **never sent by the Xbox dashboard** (`xonlinedash.xbe`). A thorough search of `FUN_000a364e` (the CONNECT_REQ builder) and all related functions confirms no code path emits these tag values. They are only processable by the adapter firmware.

**Likely origin**: These tags were intended for a PC-side provisioning utility (the Windows MN-740 Setup Wizard), a factory test jig, or a future firmware update mechanism. The Xbox dashboard communicates exclusively via tags 0x00–0x12.

| Tag  | Name                      | Size | Firmware Handler                        | Purpose |
|------|---------------------------|------|-----------------------------------------|---------|
| 0x81 | Session MAC Init          | 6    | `XPP_Establish_Secure_Identity_Link()`  | Register Xbox's MAC as trusted peer; generate session ID |
| 0x82 | Interface Reset / Reinit  | 1    | `NET_Interface_Reset_And_Reconnect()`   | Force disconnect + WLAN interface reinit (see below) |
| 0x83 | Reconnect Mode            | 1    | `g_CFG_Reconnect_Mode = val`            | Auto-reconnect behaviour (0=off, 1=auto, 2=manual) |
| 0x84 | Max Channel               | 1    | `g_CFG_Max_Channel = val`               | Set regulatory channel ceiling (range-validated) |
| 0x85 | TX Rate Code              | 1    | `g_CFG_TX_Rate_Index = val`             | Force TX rate (validated against whitelist; silent drop if invalid) |

### Tag 0x81 — Session MAC Init
**Function**: `XPP_Establish_Secure_Identity_Link(p_mac_addr)`:
1. Calls `Net_Init_Socket_Logic(p_mac_addr, 6)` to validate/register the MAC.
2. If successful: calls `NET_Register_Peer_MAC(p_mac_addr)` to store the Xbox MAC as the trusted peer.
3. Sets `g_XPP_Current_Session_ID = XPP_Get_Identity_Token()` to start a new authenticated session.

This is the **pairing step** — it binds a specific Xbox console MAC to the adapter. The HMAC-SHA1 session authentication in HANDSHAKE derives from this peer MAC.

## Tag 0x82 — Interface Reset/Reinit
```
Value  | Meaning
-------|----------------------------------
= 0x00 | Skip disconnect_interface_handle(), go straight to MAC reinit
≠ 0x00 | First call disconnect_interface_handle(0, value) (tear down with that reason code), then reinit
```
**Note**: After the conditional disconnect, the firmware calls `NET_Reinit_Interface_With_MAC()` which reinitializes the WLAN interface using the hardware MAC from `ath_hal_get_hw_info()`. If that returns an all-zero MAC (hardware failure), the reinit step is silently skipped. This is one mechanism for **undoing MAC address spoofing** — reinit restores the hardware MAC.

### Tag 0x84 channel range table
**Note**: `determine_hw_channel_range()` reads the regulatory domain code burned into the AR5 hardware EEPROM and returns the permitted min/max channel for that region. Tag 0x84 write values outside this range are clamped to channel 11.
```
Reg Domain | Min Channel | Max Channel | Default if invalid
-----------|-------------|-------------|-------------------
0x30       | 1           | 13          | 11
0x31       | 10          | 11          | 11
0x32       | 10          | 13          | 11
0x40       | 14          | 14          | 11
0x41       | 14          | 14          | 11
other      | 1           | 11          | 11
```
### Tag 0x85 - Rate Whitelist/ Tag 0x84 rate Index
**Note**: The "index" column is the Xbox-side sequential index inferred from firmware bounds checking in the Tag 0x84 chip revision table above. The "Hex" column is the actual PHY rate code written to `g_CFG_TX_Rate_Validated` and transmitted on the wire. These PHY rate codes are the same values returned in Type 0x0A BEACON_RESPONSE byte 2 (`tx_rate_code` via `drvr_get_tx_rate_code()`). The two tables are describing the same rate-code enumeration — one from the write path (Type 0x07), one from the read/status path (Type 0x0A).
```
 index    |Hex   | Rate (Mbps) | Standard  | Notes
----------|------|-------------|-----------|--------
          | 0x00 | Auto-select | -         | Automatic rate negotiation
 0x01     | 0x02 | 1 Mbps      | 802.11b   | Legacy compatibility
 0x02     | 0x04 | 2 Mbps      | 802.11b   | Legacy compatibility
 0x04     | 0x0B | 5.5 Mbps    | 802.11b   |
 0x0B     | 0x16 | 11 Mbps     | 802.11b   | Maximum 802.11b rate
 0x0C     | 0x0C | 6 Mbps      | 802.11g   | Basic rate
 0x12     | 0x12 | 9 Mbps      | 802.11g   |
 0x18     | 0x18 | 12 Mbps     | 802.11g   |
 0x24     | 0x24 | 18 Mbps     | 802.11g   |
 0x30     | 0x30 | 24 Mbps     | 802.11g   |
 0x48     | 0x48 | 36 Mbps     | 802.11g   |
 0x60     | 0x60 | 48 Mbps     | 802.11g   |
 0x6C     | 0x6C | 54 Mbps     | 802.11g   | Maximum 802.11g rate
```
**Note**: .5 Mbps is the firmware clamp/ fall-back value set if an invalid rate code is received.
And the index column is speculative / inferred as there is no index in the firmware with mapping.

### Wire-Verified Examples

All examples below are decoded directly from captured log files using `XPP_Type02_0x07_FlashConfig()` parser offsets: XPP header at byte 14, TLV count at byte 26 (`iVar3+0x0c`), first TLV at byte 27 (`iVar3+0x0d`).

**Open network** (`lysten_open_ch9_b.log` Pkt#19):
```
Raw (60 bytes):
  0000: 00 12 5a 33 fa 31 00 0d 3a 50 22 73 88 6f 58 42
  0010: 4f 58 01 01 09 07 bf dc 87 0a 04 07 0b 6f 70 65
  0020: 6e 5f 63 68 39 5f 62 67 08 01 00 09 01 01 11 01
  0030: 00 00 00 00 00 00 00 00 00 00 00 00

XPP: type=0x07  body_dwords=9  nonce=0xbfdc
TLV count: 4
  [1] Tag 0x07 SSID         len=11  "open_ch9_bg"
  [2] Tag 0x08 Sec_Mode     len= 1  0x00  (open)
  [3] Tag 0x09 Link_State   len= 1  0x01  (disassociate/idle)
  [4] Tag 0x11 Auth_Mode    len= 1  0x00  (no encryption)
  Padding: 00 00 00 00 00 00 00 00 00 00 00 00
```

**WEP-128 ASCII single-key** (`lysten_wep128_ch9_b.log` Pkt#15):
```
Raw (60 bytes):
  0000: 00 12 5a 33 fa 31 00 0d 3a 50 22 73 88 6f 58 42
  0010: 4f 58 01 01 0b 07 fe 05 51 ae 02 07 0d 77 70 61
  0020: 5f 31 32 38 5f 63 68 39 5f 62 0f 0d 61 62 63 64
  0030: 65 61 62 63 64 65 61 62 63 00 00 00

XPP: type=0x07  body_dwords=11  nonce=0xfe05
TLV count: 2
  [1] Tag 0x07 SSID         len=13  "wpa_128_ch9_b"
  [2] Tag 0x0f WEP128_Key   len=13  61 62 63 64 65 61 62 63 64 65 61 62 63  ("abcdeabcdeabc")
  Padding: 00 00 00
```

**WEP-64 ASCII 4-key** (`lysten_wep64_ch9_b.log` Pkt#15):
```
Raw (78 bytes):
  0000: 00 12 5a 33 fa 31 00 0d 3a 50 22 73 88 6f 58 42
  0010: 4f 58 01 01 10 07 db 02 46 01 08 07 0c 77 70 61
  0020: 5f 36 34 5f 63 68 39 5f 62 08 01 00 09 01 02 0e
  0030: 01 01 0a 05 61 62 63 64 65 0b 05 61 62 63 64 65
  0040: 0c 05 61 62 63 64 65 0d 05 61 62 63 64 65

XPP: type=0x07  body_dwords=16  nonce=0xdb02
TLV count: 8
  [1] Tag 0x07 SSID         len=12  "wpa_64_ch9_b"
  [2] Tag 0x08 Sec_Mode     len= 1  0x00  (open/WEP mode selector)
  [3] Tag 0x09 Link_State   len= 1  0x02  (infrastructure connect)
  [4] Tag 0x0e Radio_Ch     len= 1  0x01  (channel index 1)
  [5] Tag 0x0a WEP_K0       len= 5  61 62 63 64 65  ("abcde")
  [6] Tag 0x0b WEP_K1       len= 5  61 62 63 64 65
  [7] Tag 0x0c WEP_K2       len= 5  61 62 63 64 65
  [8] Tag 0x0d WEP_K3       len= 5  61 62 63 64 65
```

**WEP-128 hex-encoded key** (`lysten_wep128hex_ch9_b.log` Pkt#11):
```
Raw (66 bytes):
  0000: 00 12 5a 33 fa 31 00 0d 3a 50 22 73 88 6f 58 42
  0010: 4f 58 01 01 0d 07 b6 d4 1a 2b 03 07 10 77 70 61
  0020: 5f 31 32 38 68 65 78 5f 63 68 39 5f 62 0f 0d 11
  0030: 11 11 11 11 11 11 11 11 11 11 11 11 11 01 00 00
  0040: 00 00

XPP: type=0x07  body_dwords=13  nonce=0xb6d4
TLV count: 3
  [1] Tag 0x07 SSID         len=16  "wpa_128hex_ch9_b"
  [2] Tag 0x0f WEP128_Key   len=13  11 11 11 11 11 11 11 11 11 11 11 11 11  (13× 0x11)
  [3] Tag 0x01 (?)          len= 0  (zero-length — see note)
  Padding: 00 00
```

**⚠️ Note on TLV[3] "Tag 0x01, len=0"**: The third TLV (`01 00`) appears only in the b-band-only variant of this capture (`_b`, not `_bg`). It is **not present** in `lysten_wep128hex_ch9_bg.log` or `lysten_wep128_ch9_b.log`. The hex-input vs ASCII-input code paths call identical firmware functions (`AutoClass1_set_security_wep128` + `FUN_000a2d32`) — neither emits a hex-marker tag. The most likely explanation is that this TLV was carried over from a prior connection state where the IP address flag (`0xff8` bit `0x02`, Tag 0x01) was set and not fully cleared between sessions. With `len=0`, the firmware `case 1:` handler still executes `memcpy(&CFG_Device_IP, src, 4)` (reads 4 bytes regardless of len) then advances `src = pbVar4 + 6` — this is a firmware bug but functionally harmless when the 4 bytes are padding zeros. **There is no "hex WEP marker tag"** — the adapter receives the same binary key bytes regardless of whether the user entered them as ASCII or hex on the dashboard.

**WEP-128 hex-encoded key, b+g band** (`lysten_wep128hex_ch9_bg.log` Pkt#17):
```
Raw (62 bytes):
  0000: 00 12 5a 33 fa 31 00 0d 3a 50 22 73 88 6f 58 42
  0010: 4f 58 01 01 0c 07 aa 2a 25 82 02 07 11 77 70 61
  0020: 5f 31 32 38 68 65 78 5f 63 68 39 5f 62 67 0f 0d
  0030: 11 11 11 11 11 11 11 11 11 11 11 11 11 00

XPP: type=0x07  body_dwords=12  nonce=0xaa2a
TLV count: 2
  [1] Tag 0x07 SSID         len=17  "wpa_128hex_ch9_bg"
  [2] Tag 0x0f WEP128_Key   len=13  11 11 11 11 11 11 11 11 11 11 11 11 11  (13× 0x11)
```
Note: identical binary key to the ASCII case — dashboard decodes hex before sending.

**XPP Admin Password — Set** (`lysten_password.log` Pkt#9):
```
Raw (60 bytes):
  0000: 00 0d 3a 1f 26 09 00 0d 3a 50 22 73 88 6f 58 42
  0010: 4f 58 01 01 07 07 7b c4 d8 a4 01 03 0a 61 61 62
  0020: 62 63 63 64 64 65 65 00 00 00 00 00 00 00 00 00
  0030: 00 00 00 00 00 00 00 00 00 00 00 00

XPP: type=0x07  body_dwords=7  nonce=0x7bc4
TLV count: 1
  [1] Tag 0x03 Admin_Ident  len=10  "aabbccddee"  (XPP admin password / pairing lock)
```
Note: only Tag 0x03 is sent — SSID and security mode are omitted because the adapter already
has a stored profile from a previous session. The user is setting the XPP admin password
that prevents other consoles from reconfiguring this adapter.

**Notes from wire analysis**:
- Tag 0x08 is **absent** from the WEP-128 captures. The firmware infers WEP mode from the key tag (0x0f or 0x0a–0x0d) itself via `CFG_Set_WEP_Enabled()` called from within the key handlers.
- Tag 0x04 (Operating Mode) is **absent** from all these captures — it is only sent when the mode needs to change from the adapter's current state.
- Tag 0x09 (Link State) is present in WEP-64 (`0x02` = infrastructure) but absent from WEP-128 examples. The adapter infers link state from having received key data.
- Tags appear in ascending numerical order as the firmware processes them in a single forward pass with no backtracking.
- The TLV count at `iVar3+0x0c` is a hard limit: the firmware iterates exactly that many TLV entries and stops, regardless of remaining bytes.

**Notes on tag ordering and unknown tags**:
- Tags **must** be packed in ascending numerical order. The firmware processes TLVs in a single forward pass with no backtracking and no random-access. Out-of-order tags are not rejected but the firmware will have already acted on earlier tags before the later ones arrive.
- **Unknown tags abort the entire parse loop** (`got_unknown_%d` + `goto LAB_8009b120`). Do NOT include unrecognised tags. Tag 0x12 triggers this abort in stock firmware — see §Tag 0x12 above.
- Padding bytes at the end of the packet (after all TLVs) are never reached by the parser due to the TLV count hard limit.

Beacons/multicast cap at 2 Mbps
unicast cap at 11 Mbps
ARF steps up to 11 Mbps ceiling
These rates are a hardcoded firmware limitation designed to ensure BSS stability and prevent 'Hidden Node' collisions during System Link play.

## Clock Synchronization:
Ad-Hoc peers rely on TSF (Timing Synchronization Function) found in beacons to keep their hardware clocks in sync. If these were sent at 54 Mbps, a peer at the edge of the range might miss them, causing the Ad-Hoc network to "split."

Because Ad-Hoc networks lack a central Access Point to manage "Hidden Nodes" (where two Xboxes can see the host but not each other). High-speed OFDM (54 Mbps) is very sensitive to collisions. By capping the data at 11 Mbps (DSSS/CCK), the signal is much more "penetrating" and less likely to drop frames during intense System Link play.

### Tag 0x03 - XPP Admin Password / Console Pairing Lock

**Purpose**: The XPP admin password is a security feature that locks the adapter against
configuration changes by an unauthorised console. When set, only a console that presents the
correct password via Tag 0x03 can issue `CONNECT_REQ` commands that modify the adapter's
settings. This prevents another Xbox from hijacking a paired adapter.

**Firmware storage**: `g_NVRAM_User_Settings.Legacy_Padding` (`admin_id`) (max 16 bytes + NUL = 17 bytes total). Copied into `XPP_Identity_t.admin_id` at boot for CLI session authentication.
Factory default is `"admin"` (set by `Flash_Commit_Settings()` via `STR_DEFAULT_CREDENTIAL`).

**What Tag 0x03 changes**: the `Legacy_Padding` (`admin_id`) field only — this is the HTTP Basic Auth **password** and the TFTP RRQ HMAC input. The HTTP Basic Auth **username** (`xpp_identity_username`) is a separate field that Tag 0x03 does not touch and has no XPP write path.

**Setting the password**: Send Tag 0x03 with the new password string (3-16 printable ASCII).\
**Clearing the password**: Send Tag 0x03 with length = 0x00 (empty value).

**Wire-verified** (`lysten_password.log`):

Packet 9 - Setting the admin password to `"aabbccddee"`:
```
Type: 0x07 (CONNECT_REQ)
Payload: 01 | 03 0a 61 61 62 62 63 63 64 64 65 65
              tag=0x03, len=10, val="aabbccddee"
```

Packet 99 - Clearing the admin password (len=0x00):
```
Type: 0x07 (CONNECT_REQ)
Payload: 01 | 03 00
              tag=0x03, len=0, val=(empty - clears password)
```

**Context of the capture**: The adapter already had a saved connection profile (`wpa_128hex`,
seen in HANDSHAKE_RESP). No SSID, no security tags were sent - only Tag 0x03 - because the
adapter profile was unchanged and only the admin password was being set then cleared.
The BEACON_RESP auth byte transitions `0x02 -> 0x03` after Pkt#9 (adapter re-processing
config), then back to `0x02` after Pkt#99 (cleared). A second HANDSHAKE_REQ from a different
console MAC (`00:0d:3a:50:22:73`) appears at Pkt#199.

### CRITICAL: Tag 0x10 — WPA PMK (Firmware Stub — Discards) ⚠️

this field IS the WPA Pairwise Master Key (PMK). The 32-byte value is exactly what the 802.11 4-way handshake requires as input to the PRF function for PTK derivation.

**Why it is called PMK and not something else**: the dashboard's `FUN_00079633` performs PBKDF2-equivalent hex decoding of the user's 64-char hex input to produce a 32-byte value that represents the raw pre-shared key material — this is the standard PMK for WPA-PSK as defined in IEEE 802.11i 8.5.1.2.

**Tag 0x10 Wire Format**:
```
Offset | Size | Field                     | Description
-------|------|---------------------------|------------------
0      | 1    | Tag                       | 0x10
1      | 1    | Length                    | 0x20 (32 bytes follow)
2-33   | 32   | PMK (Pairwise Master Key) | Raw 256-bit pre-shared key
```

**Dashboard Behaviour**: When the user enters a 64-character hex string as the WPA key,
`FUN_00079633()` validates it is valid hex, converts it to 32 raw bytes, calls
`AutoClass1_set_security_wpa()` (sets security mode = 0x04 = WPA), then `AutoClass1_set_wpa_pmk_raw()` which copies
the 32-byte PMK into `AutoClass1+0xf93` and sets `0xff8` bit `0x10000`. The connect
request builder `FUN_000a364e` then emits Tag 0x10 with `puVar9[1]=0x20` (length=32)
and the 32-byte PMK from `0xf93..0xfb2`.

**Stock Firmware Reality** (v1.0.2.26): Tag 0x10 is a dead stub.
The PMK is silently discarded. It is **not** stored and **not** passed to the hardware key engine.

**Pointer advance = 0x22 bytes from the tag byte** = `tag(1) + length(1) + 32 value bytes`.
This is NOT 32 bytes from the tag — it is 34 bytes total. The length field is still consumed.
Emulators must advance exactly 34 bytes from the start of the tag or subsequent tags will desync.

---

### CRITICAL: Tag 0x12 — WPA Passphrase (Fatal Parse Abort) ⚠️

**Tag 0x12 Wire Format**:
```
Offset | Size  | Field      | Description
-------|-------|------------|------------------
0      | 1     | Tag        | 0x12
1      | 1     | Length     | 8–63 (WPA2 passphrase length)
2-N    | 8-63  | Passphrase | Raw ASCII passphrase (0x20–0x7e only)
```

**Dashboard Behaviour**: When the user enters a text passphrase (not a 64-hex PMK),
`AutoClass1_set_wpa_passphrase()` validates it is 8–63 printable ASCII chars, stores it at
`AutoClass1+0xfb3` (max 63 bytes + NUL), sets `0xff8` bit `0x40000`. The connect
request builder `FUN_000a364e` then emits Tag 0x12 with the raw passphrase bytes
(via `strlen` from `0xfb3`, capped at 63).

**Stock Firmware Reality** (v1.0.2.26): Tag 0x12 has **NO case** in `XPP_Type02_0x07_FlashConfig()`.
It falls through to the `default:` branch which logs `got_unknown_%d` and immediately
executes `goto LAB_8009b120` — this exits the TLV parse loop entirely.

```c
// XPP_Type02_0x07_FlashConfig() — default branch reached for tag 0x12
default:
    sprintf(&stack0x00000014, s_got_unknown__d_800bc444, uVar7);
    wlan_log_debug_info(4, &stack0x00000014, ...);
    goto LAB_8009b120;   // exits parse loop — NO further tags processed
```

**Any tags placed after Tag 0x12 in the same packet are never processed.**
This is a hard parse abort, not a skip-and-continue. The firmware stops reading TLVs.

**Emulator note**: To emulate stock behaviour faithfully, on receiving Tag 0x12 stop
processing the TLV stream, log the unknown tag, and send the response as-if parsing
completed. Do not advance to the next tag.

#### WPA/WPA2 Dashboard Key Input Paths

The dashboard has two separate code paths for WPA key input. Which tag is sent depends
entirely on what the user typed at the on-screen keyboard:

 Input Type        | Length Check                  | Dashboard Path | Tag Sent | Firmware Handles?
-------------------|-------------------------------|----------------|----------|-------------------
 64 hex chars      | Exactly 64 hex-digit wchars   | `FUN_00079633` → hex decode → 32-byte PMK → `AutoClass1_set_wpa_pmk_raw` | Tag 0x10 (32-byte PMK) | Stub — silently discards
 8–63 ASCII chars  | 8 ≤ len ≤ 63, all printable   | `FUN_00079633` → raw copy → `AutoClass1_set_wpa_passphrase` | Tag 0x12 (raw passphrase) | Not handled — parse abort
 < 8 or > 63 chars | Rejected                      | Dashboard shows `WIRELESS_SETTINGS_ERR_INVALID_KEY_FOR_TYPE` | Nothing sent | N/A

**Note**: For a 64-hex-char input it sends the pre-computed raw key bytes directly as Tag 0x10 (PMK). For a passphrase it sends the
plaintext as Tag 0x12 and relies on the firmware to derive the PMK — which stock firmware
cannot do. WPA is therefore completely non-functional with stock firmware regardless of
which input path is used.

#### WPA/WPA2 Firmware Patch Paths

Two firmware patch paths exist for enabling WPA/WPA2. Neither requires Xbox modification.
See [WPA/WPA2 Implementation](#wpa-wpa2-implementation) for full details.

| Path | Trigger Tag | Dashboard Action | Firmware Patch Required | Notes |
|------|-------------|------------------|-------------------------|-------|
| Path 1 — Store PMK | Tag 0x10 | User enters 64-hex-char key; dash sends 32-byte PMK | Implement `case 0x10` to store PMK and call `ath_hal_set_key_cache_entry()` | Simpler — Xbox already sends valid PMK data |
| Path 2 — Derive PMK from passphrase | Tag 0x12 | User enters ASCII passphrase; dash sends plaintext | Add `case 0x12` to call `wlan_pbkdf2_pmk_derive()` (already in firmware) | More complex — requires worker task context for 4096-iteration PBKDF2 |

### tag 0x0e Region Code (Tag 0x0E)
**function**: Affects allowed Wi-Fi channels for regulatory purposes
**Note**: Missing region code defaults to USA mode (channels 1-11 only).

```
 Value | Region                  | Allowed Channels (2.4 GHz)
-------|-------------------------|-----------------------
 0x00  | USA / Canada (FCC)      | 1-11
 0x01  | Japan (TELEC)           | 1-14
 0x02  | Europe (ETSI)           | 1-13
 0x03  | Australia / New Zealand | 1-13
 0x04  | Korea                   | 1-13
```

### Tag 0x14 — MAC Address Cloning / Spoofing

**Purpose**: Makes the Xbox + MN-740 adapter appear as a **single device** to the router/AP,
eliminating double-NAT MAC mismatch. The cloned MAC becomes the source identity for all frames
on both the Ethernet side (Xbox→adapter) and the Wi-Fi side (adapter→router).

**Transparent bridge problem (solved by MAC clone):**

The MN-740 is a Layer 2 transparent bridge. Without MAC cloning:
- 802.11 transmitter address = adapter hardware MAC
- DHCP `chaddr` in packet payload = Xbox MAC
- Router sees two different MACs for what appears to be one Wi-Fi client
- Looks like double-NAT; some routers reject or rate-limit this
- Xbox Live reports NAT issues

With MAC clone (Xbox MAC = adapter Wi-Fi MAC = same value):
- Router sees **one consistent device** — clean transparent bridge
- Router's DHCP assigns same IP the PC had; MAC filters pass; Xbox Live open NAT

**No MAC conflict:** The Ethernet segment (Xbox↔adapter) and Wi-Fi segment (adapter↔router)
are electrically isolated. Each segment has only one device using that MAC value.
The adapter bridges between them — same logical identity on both sides is correct bridging behaviour.

**ISP use case (2004):** Cable/DSL with modem in bridge mode (no home router) and
PPPoE-based MAC authentication. Cloning the PC's MAC bypassed ISP MAC-lockout.
With a normal home router the ISP never sees the Xbox MAC — the router's WAN MAC
is what the ISP sees. The MAC clone still benefits router-side DHCP/MAC filtering.

**Common Use Case (2004)**: Cable and DSL ISPs (particularly PPPoE providers) frequently locked
internet access to the MAC address of the first device that connected — typically the user's PC.
When switching to an Xbox, the ISP would reject the new MAC. Cloning the PC's MAC address made
the adapter invisible to the ISP's MAC-auth system.

**Format**: 6-byte MAC address in standard network byte order.

```
Tag  | Len | Value
-----|-----|------
0x14 | 06  | XX XX XX XX XX XX   (MAC to spoof, network byte order)
```

**Wire-verified** (`lysten_setmac_host_ppoe_and_connect_to_live.log`):

The MAC spoofing mechanism has now been directly observed on the wire. The log was captured
with the router/AP **powered off** — the adapter is holding its saved profile (`open_ch9_bg`,
IP=192.168.1.150, b-only mode) but is not associated with any AP. The adapter hardware MAC
is `00:12:5a:33:fa:31`. The clone MAC set for ISP bypass is `aa:bb:cc:dd:aa:ff`.

```
Pkt#1-14:  Normal session
  HANDSHAKE_REQ src MAC = 00:0d:3a:50:22:73  (real Xbox console NIC)
  Adapter MAC            = 00:12:5a:33:fa:31  (MN-740 hardware MAC)
  Saved profile: SSID=open_ch9_bg, IP=192.168.1.150 (not currently connected)

Pkt#15-16: Console re-authenticates (new nonce 0x5c3d), same MAC identity

Pkt#17:    MAC CLONE ACTIVE
  HANDSHAKE_REQ src MAC = aa:bb:cc:dd:aa:ff  <<< SPOOFED
  (broadcast to ff:ff:ff:ff:ff:ff as normal, but sourced from the clone MAC)
```

**Mechanism — how the clone works at Layer 2:**

The MAC spoof operates at the XPP handshake level, not just at the bridge forwarding level.
When the user configures a clone MAC via the settings XBE, the Xbox console's Ethernet NIC
begins broadcasting HANDSHAKE_REQ frames sourced from the cloned MAC entered in the Xbox dash.
Instead of its real hardware MAC. The adapter then:

1. Accepts the HANDSHAKE_REQ from the Xbox with the cloned source MAC
2. Stores this as `g_NVRAM_Router_MAC` (the paired console MAC identity)
3. Re-initialises the WLAN interface with `g_NVRAM_Router_MAC`as the Wi-Fi adapter MAC
   (assembly-verified: `NET_Reinit_Interface_With_MAC()` applies the new MAC to the radio).
   All subsequent 802.11 frames use it as the transmitter address.
   The router/AP sees one consistent device MAC for both association and data frames.

The HMAC computation during the handshake uses the **adapter's own hardware MAC**
(`00:12:5a:33:fa:31`) as its fixed MAC input component regardless of what source MAC
the HANDSHAKE_REQ arrives from. The HMAC is not re-keyed to the clone identity — the
HMAC key relationship remains between the adapter and any console that knows the shared
static key. The clone MAC is purely a Layer 2 forwarding identity, not a cryptographic one.

**Source XBE note**: Tag 0x14 is **not emitted by `xonlinedash.xbe`**. The MAC clone
setting is configured via the network settings XBE (multi-XBE dashboard architecture).
The setting XBE instructs the Xbox NIC driver to use the cloned MAC, which then appears
as the source MAC in all subsequent XPP HANDSHAKE_REQ broadcasts.

**Firmware parser note**: `XPP_Type02_0x07_FlashConfig()` in v1.0.2.26 has no `case 0x14`.
The mechanism observed on wire operates through the XPP HANDSHAKE path (Type 0x01/0x02),
not the FlashConfig path (Type 0x07) — so the absence of `case 0x14` in the Type 0x07
parser is consistent. The clone MAC is implicitly registered when the adapter accepts the
HANDSHAKE_REQ from the new source MAC identity.

**Related**: Tag 0x82 (`NET_Interface_Reset_And_Reconnect`) calls `NET_Reinit_Interface_With_MAC()`
which restores the hardware MAC from `ath_hal_get_hw_info()` — this clears the clone and restores
the real identity.

### WPA/WPA2 Hardware Support

**The MN-740 is fully capable of WPA (TKIP) and WPA2 (AES-CCMP) in hardware.** The limitation is
purely firmware. The hardware was designed for WPA/WPA2 from the start but the firmware was never
finished.

**Hardware**: The Marvell Libertas 88W8310 security engine is a dedicated hardware block with
silicon-level AES-Rijndael at 54Mbps, TKIP MIC generation, and a full hardware key cache.
All of this is confirmed accessible from firmware via `ath_hal_set_key_cache_entry()`,
`ath_hal_ccmp_aes_encrypt()`, and `wlan_ccmp_decrypt_verify()`.

**Firmware status**: The crypto engine is complete. The EAPOL state machine is present and
functional. The PBKDF2 derivation function exists as dead code. Two stubs block the full path:

```
 Gap   | Location                      | What is Missing
-------|-------------------------------|-----------------
 Gap 1 | `XPP_Parse_Entry()` case 0x10 | PMK received from Xbox but discarded
 Gap 2 | `eapol_handle_key_exchange()` | Logs "EAP Failure" and returns immediately. ANonce/SNonce exchange, PTK derivation, MIC verification, and GTK install are all absent.
 ```

See [WPA/WPA2 Implementation](#wpa-wpa2-implementation) for the full patch analysis.

### Related Information
- [Type 0x08 Response](#10-type-0x08---connect_to_ssid_response)

---

## 10. Type 0x08 - CONNECT_TO_SSID_RESPONSE
**Direction**: Adapter → Xbox  
**Transport**: Ethernet 0x886f  
**HMAC Required**: No

### Brief Description
Confirms connection request result.

### Packet Format
```
Total size: (14 Ethernet + 12 XPP Header + 4 payload + padding) = 30 bytes
Body size:  (12 XPP header + 4 payload + padding) / 4 = 4 DWORDs

Size | Segment          | Description
-------------|------------------|--------------------------------
14 bytes     | Ethernet header  | Standard Header
12 bytes     | XPP Header       | Type 0x08, , body size = 0x04 DWORDs
1 byte      | Payload          | response payload
3 bytes      | Null/Padding     | Zeros to pad the payload to match body size
```

### Result Codes
⚠ Only `0x00` (success) is wire-verified from real adapter captures. The remaining codes are inferred from firmware structure and XBE handler analysis. See also [Error Code Flags](#error-code-flags) for the dashboard's interpretation of these wire bytes.
```
Result code | Wire-verified? | Description / Value
------------|----------------|---------------------
0x00        | ✓ Yes          | Success — connection accepted and config committed
0x01        | Inferred       | Rejection / error (dashboard sets error_code=0x80000003)
0x02        | Inferred       | Retry requested (dashboard retries after ~8 seconds)
0x03        | Inferred       | Rejection / error (dashboard sets error_code=0x80000003)
0x04        | Inferred       | Error (Type 0x08 connect-specific rejection)
0x05        | Unconfirmed    | Timed Out
0xFF        | Unconfirmed    | General error
```

---

## TFTP Firmware Upgrade
> **Note**: TFTP is a supporting feature, not a packet type in the XPP management protocol. This section describes the adapter's built-in firmware upgrade mechanism accessed independently of XPP.

**Transport**: UDP ports 69 and 16932 — two distinct TFTP listening ports (see below)
**State Requirement**: UDP sockets open at boot, but transfers are gated by a prior XPP handshake.

### Two TFTP Ports — Firmware Confirmed
The adapter listens for TFTP on **two separate UDP ports**, both registered at boot by
`xpp_check_firmware_update_status()` via the same `xpp_udp_packet_dispatcher` callback.
They serve different purposes and have different auth behaviours.

```
Port      | Hex    | Registered by              | Path name   | Auth handler
----------|--------|----------------------------|-------------|-----------------------------
69        | 0x0045 | xpp_sync_radio_state()     | Unpaired    | g_XPP_Active_Frequency
16932     | 0x4224 | xpp_sync_connection_status()| Paired      | XPP_Secure_Config_Update
```

The dispatcher uses sentinel values to distinguish which port received the packet:
- `0xffffff9d` → port 69 → `TFTP_Process_New_Request(..., param_4=0)`
- `0xffffff9c` → port 16932 → `TFTP_Process_New_Request(..., param_4=1)`

**Session handle gate**: Both ports check `g_XPP_Session_Handle == -1` before
allowing any transfer. If the handle is not set (i.e. no XPP handshake has occurred),
the adapter responds with `"Transfers currently disabled"` on either port. The
`g_XPP_Session_Handle` is set to `0xffffffff` (-1) by `TFTP_Session_Enable()` during the XPP
handshake flow, and cleared to `0` by `TFTP_Session_Disable()`. **A prior XPP
handshake is therefore required before TFTP transfers are accepted on either port.**

**Data transfer port**: After auth passes, the session's port field is zeroed and
`hal_mailbox_query()` allocates a dynamic ephemeral port for the actual data transfer.
The adapter sends DATA blocks and ACKs from this ephemeral source port. The client
must direct subsequent DATA/ACK packets to this ephemeral port — standard TFTP
behaviour per RFC 1350.

### How TFTP Becomes Available
`net_main_task()` calls `XPP_check_firmware_update_status()` as a fixed step
during boot, before DHCP, before any Xbox connection exists:

    net_main_task()
      └─ XPP_check_firmware_update_status()
           ├─ xpp_sync_connection_status()   ← opens port 16932, registers paired auth callbacks
           └─ xpp_sync_radio_state()
                └─ UDP_Socket_Open(port 69, xpp_udp_packet_dispatcher)
                   UDP_Socket_Open(port 16932, xpp_udp_packet_dispatcher)

Both UDP sockets open at power-on. **Transfers are blocked until a valid XPP
handshake sets `g_XPP_Session_Handle = -1`.**

### TFTP Upgrade Sequence
1. Establish XPP session first — HANDSHAKE_REQ (Type 0x01) → HANDSHAKE_RESP (Type 0x02). This sets `g_XPP_Session_Handle = -1` enabling TFTP transfers.
2. Send TFTP WRQ to port **69** for firmware upload, or port **16932** for config/virtual files.
3. Send WRQ with filename `"image"` (or `"boot.bin"` for MSBNUpdate.exe) in `"octet"` mode.
4. Transfer firmware blocks (512 bytes each, RFC 1350).
5. Adapter buffers all blocks in `g_HTTP_UPLOAD_BUFFER` via `xpp_vfs_write_payload()`.
6. On final block (< 512 bytes), `xpp_flash_write_manager()` is called with the total byte count.
7. **Firmware image must be exactly `0x100000` (1 MB).** If the total received bytes do not equal `0x100000`, the flash write is silently skipped and no reboot occurs. Any other size is treated as a config partition write or ignored entirely.
8. Automatic reboot with new firmware.

**⚠ Third upload path — HTTP POST**: The adapter also has a built-in HTTP web server with a multipart form upload endpoint (`http_handle_post_upload`) that writes to the same `g_HTTP_UPLOAD_BUFFER`. This is a third firmware flash path alongside the two TFTP ports. It shares the same 1MB buffer and the same size/validation constraints.

### TFTP Protocol Details
- **Block Size**: 512 bytes (0x200) — firmware constant `TFTP_Block_size`
- **Transfer modes accepted**: `"image"`, `"octet"` (binary), `"netascii"` (text)
- **Auth header**: Non-standard 58-byte prefix before the TFTP payload (see below)
- **WRQ auth**: None — the firmware upload path performs no credential check on either port
- **RRQ auth**: MAC check + HMAC-SHA1 (port 16932 paired path only). MAC checked against `g_NET_Interface_MAC_Table` (adapter hardware MAC when unpaired, Xbox console MAC when paired).
- **Concurrent sessions**: Only one TFTP session is permitted at a time (`g_TFTP_Session_Active_Flag` ref-count). A second request while a session is active is logged and rejected.
- **XPP session prerequisite**: `g_XPP_Session_Handle` must be `-1` (set by successful XPP handshake) or any request on either port gets `"Transfers currently disabled"`.
- **Data transfer port**: After auth passes, the adapter opens a new ephemeral UDP port for the actual DATA/ACK exchange. Ephemeral ports start at 1200 (0x4b0), allocated by `UDP_Allocate_Dynamic_Port()` seeded from uptime ticks. The client must send subsequent packets to this ephemeral port, not to 69 or 16932.
- **Retransmit backoff**: Exponential — starts at 5 ticks, doubles on each retry, capped at 150 ticks. Minimum interval 10 ticks. Retry limit is set at session creation; exhaustion → ERROR `"Retry limit exceeded"`.
- **RTT-adaptive interval**: On each successful ACK, `xpp_calculate_link_latency()` adjusts the retry interval based on measured round-trip time. The interval converges toward `RTT + smoothed_RTT + 1`, clamped to [10, 150].
- **Filename length limit**: Filenames must be shorter than 80 characters (0x51). Longer names are silently ignored by `xpp_vfs_open()`.

**Port selection by use case:**
```
Use case                    | Port  | Notes
----------------------------|-------|------------------------------------------
Firmware flash (WRQ)        | 69    | Standard path, no auth, any client
Firmware flash (WRQ)        | 16932 | Also works — WRQ has no auth on either port
Read config files (RRQ)     | 16932 | Requires MAC + HMAC auth (adapter MAC if unpaired, Xbox MAC if paired)
Read debug log (RRQ)        | 16932 | Requires MAC + HMAC auth (adapter MAC if unpaired, Xbox MAC if paired)
Virtual file writes (WRQ)   | 16932 | No auth on WRQ, but payload has embedded tokens
```

---

### ⚠️ CORRECTED: XPP TFTP Auth Header — Exact Wire Format

**Wire-verified** from live captures (`tftpx.pcap`, `trialupdate.pcapng`) + firmware decompile of `XPP_Secure_Config_Update`.

⚠️ **FURTHER CORRECTION from `trialupdate.pcapng`**: The description below (originally from `tftpx.pcap`) presents the auth material as a header prepended before the TFTP opcode. The `trialupdate.pcapng` capture shows that MSBNUpdate.exe instead **embeds the 58 auth bytes inside the TFTP filename field**: the packet begins with opcode `0x0002` (WRQ), then the 58 auth bytes follow as binary filename data, then a null terminator, then `"octet"` mode. The firmware reads auth bytes at fixed UDP payload offsets (`+0x00` for MAC, `+0x26` for HMAC) which happen to land inside the filename field due to the 2-byte opcode prefix. **See the "Wire-Verified Correction: WRQ Auth Material Embedded in Filename Field" subsection in the MSBNUpdate section for the full corrected wire format.** The layout described below applies to RRQ packets from `tftpx.pcap` and may reflect a different tool or firmware revision.

The entire UDP payload for TFTP on **port 16932** is structured as a **58-byte auth header** immediately followed by the standard RFC 1350 TFTP packet. There is no gap or alignment between them.

```
Offset | Size     | Description
-------|----------|------------------------------------------
+0x00  | 6 bytes  | Source MAC address of sender
+0x06  | 32 bytes | Zero-filled padding — firmware reads but ignores
+0x26  | 20 bytes | HMAC-SHA1 token (RRQ auth only — all zeros for WRQ)
+0x3a  | variable | Standard RFC 1350 TFTP packet (opcode at +0x3a)
```
Total auth header: **58 bytes (0x3a)** — wire-confirmed ✅

**Wire-verified packet example (RRQ for `"image"` in `"octet"` mode):**
```
Offset | Hex                                               | Field
-------|---------------------------------------------------|-------
+0x00  | 94 de 80 b9 b1 2c                                 | src_mac (6 bytes)
+0x06  | 00 00 00 00 ... (32 zero bytes)                   | padding (zeros)
+0x26  | 82 2f 85 b7 ca 0c f6 fa ad 5f                     | HMAC-SHA1
       | 3c 26 04 30 62 6d 1b 08 3e c8                     | (20 bytes total)
+0x3a  | 00 01                                             | TFTP opcode: RRQ (1)
+0x3c  | 69 6d 61 67 65 00                                 | filename: "image\0"
+0x42  | 6f 63 74 65 74 00                                 | mode: "octet\0"
```

---

### ⚠️ CORRECTED: Auth Logic — Port 16932 RRQ MAC Check

**Firmware function**: `XPP_Secure_Config_Update()` — decompiled from `NML_bin.c`.

The firmware source code contains a **critical difference** from earlier versions of this spec:

```c
void XPP_Secure_Config_Update(undefined4 param_1, char *param_2, uint tftp_op_mode)
{
    // param_2 = raw UDP payload pointer (the 58-byte auth header start)

    if ((tftp_op_mode & 0xffff) == 2) {
        // WRQ — log "tftpd_put" and return immediately (NO checks)
        wlan_log_debug_info(4, s_tftp_update, s_tftpd_put);
    }
    else if ((tftp_op_mode & 0xffff) == 1) {
        // RRQ — perform two auth checks:
        wlan_log_debug_info(4, s_tftp_update, s_tftpd_get);

        // CHECK 1: MAC match
        iVar1 = wlan_mac_addr_equal(param_2, &g_NET_Interface_MAC_Table, 6);
        if (iVar1 == 0) {
            // MAC matched — proceed to HMAC check

            // CHECK 2: HMAC verification
            strcpy(&DAT_800cdb6c, g_NVRAM_User_Settings.Legacy_Padding);  // admin_id (XPP admin identity password)
            sVar2 = strlen(g_NVRAM_User_Settings.Legacy_Padding);
            xpp_calculate_hmac_sha1((SHA_CTX *)&DAT_800cdb6c, sVar2, -0x7ff32014, 0x14);
            iVar1 = wlan_mac_addr_equal(param_2 + 0x26, &DAT_800cdfec, 0x14);
            if (iVar1 == 0) {
                // Both checks passed — allow RRQ
                wlan_log_debug_info(4, s_tftp_update, s_filename_ok);
            }
            else {
                wlan_log_debug_info(4, s_tftp_update, s_password_error1);  // HMAC mismatch
            }
        }
        else {
            wlan_log_debug_info(4, s_tftp_update, s_mac_error);  // MAC mismatch
        }
    }
}
```

**Key correction — the MAC being checked is `g_NET_Interface_MAC_Table`, which is dual-use.**

`g_NET_Interface_MAC_Table` is the same global written in two different places depending on adapter state:

- **At boot / unpaired**: populated from the adapter hardware MAC by `eth_brecis_msp_init()`. This is what appears in the BBN discovery response at `+0x60`.
- **After pairing**: overwritten with the paired Xbox console MAC by `CFG_Set_Paired_Xbox_MAC()`.

The previous version of this spec incorrectly stated `g_NVRAM_Router_MAC` was used, and also incorrectly stated the field always contains the Xbox console MAC. On an **unpaired** adapter (the MSBNUpdate firmware-update scenario), this field contains the **adapter hardware MAC**, not a console MAC.

Full corrected auth rules for port 16932:

```
Check       | What is compared                                         | Failure result
------------|----------------------------------------------------------|---------------------
MAC check   | param_2[0..5] vs g_NET_Interface_MAC_Table:
            |   UNPAIRED adapter → adapter hardware MAC                | log "mac_error", refuse
            |   PAIRED adapter   → paired Xbox console MAC             |
HMAC check  | param_2[0x26..0x39] vs HMAC-SHA1(key=g_XPP_HMAC_Key,
            |   input=g_NVRAM_User_Settings.Legacy_Padding (admin_id)) | log "password_error1", refuse
```

**Implications for emulator TFTP RRQ:**
1. The source MAC in the auth header (`param_2[0..5]`) must match the current value of `g_NET_Interface_MAC_Table`: the **adapter hardware MAC** on an unpaired adapter, or the **Xbox console MAC** on a paired adapter. MSBNUpdate always sends the adapter hardware MAC — correct for its unpaired firmware-update use case.
2. For an **unpaired** adapter at factory reset, `g_NET_Interface_MAC_Table` holds the **adapter hardware MAC** (populated at boot by `eth_brecis_msp_init()`), not all-zeros as previously stated.
3. The HMAC at offset `+0x26` is computed as: `HMAC-SHA1(key=g_XPP_HMAC_Key (16 bytes), input=admin_id_string)`.
4. For default config, `admin_id = "admin"` and the key is the static ROM value `cb275ff238ab61dc8799fa01ad17745e`. Both are fixed constants — the correct HMAC is fully offline-computable.

**WRQ has no access control on either port.** `XPP_Secure_Config_Update` logs `"tftpd_put"` and returns immediately without any check. Any host that has established an XPP session can flash new firmware via WRQ on port 69 or 16932.

---

### ⚠️ CORRECTED: WRQ Initial ACK — Block 0 Sent Before DATA

**From `TFTP_Process_New_Request()` decompile:**

For a WRQ (write request), the adapter sends **ACK block 0 immediately** upon accepting the request — before receiving any DATA:

```c
// WRQ path (opcode == 2):
*(undefined2 *)&p_tftp_session_desc->field_0x2c = 0;       // block number = 0
net_tftp_send_acknowledgment(p_tftp_session_desc, ...);     // send ACK 0
*(undefined2 *)&p_tftp_session_desc->field_0x2c = 1;       // next expected = 1
*(undefined4 *)&p_tftp_session_desc->field_0x38 = 1;       // state = RECV
```

This is standard RFC 1350 WRQ behaviour — the server sends ACK 0 to signal readiness, client then sends DATA block 1. Your emulator **must** send ACK block 0 in response to WRQ before the client will begin sending data. Failure to send ACK 0 causes the client to time out waiting.

**For RRQ (read request):**

The block number starts at 1 — the adapter opens the file and begins sending DATA block 1 immediately:

```c
// RRQ path (opcode == 1):
*(undefined4 *)&p_tftp_session_desc->field_0x38 = 6;       // state = SEND
*(undefined2 *)&p_tftp_session_desc->field_0x2c = 1;       // next block = 1
*(undefined4 *)&p_tftp_session_desc->field_0x28 = 0x200;   // block size = 512
```

No ACK 0 is sent for RRQ — the adapter sends DATA 1 directly.

---


### Standard TFTP Packet (at +0x3a on port 16932, at +0x00 on port 69)
```
WRQ/RRQ:  [opcode:2][filename\0][mode\0]
DATA:      [opcode:2][block:2][data:≤512]
ACK:       [opcode:2][block:2]
ERROR:     [opcode:2][error_code:2][message\0]
```
Opcodes: 1=RRQ, 2=WRQ, 3=DATA, 4=ACK, 5=ERROR

### WRQ Filename
The standard firmware upgrade filename is `"image"`. MSBNUpdate.exe uses `"boot.bin"` as its WRQ filename. Both are accepted by the firmware — the completion callback (`xpp_tftp_commit_config`) does not validate the filename at all; it flashes whatever data was received into `g_HTTP_UPLOAD_BUFFER` regardless of what the file was named. Any filename triggers the same flash-and-reboot path.

### Auth Logic — Port 69 vs Port 16932 (Corrected)

Firmware function: `TFTP_Process_New_Request()`, branching on `param_4` (0=port 69, 1=port 16932).

Both ports first check `g_XPP_Session_Handle == -1`. If not set, transfer is refused on both.

**Port 69 — unpaired path (param_4 = 0):**
- Auth handler: `g_XPP_Active_Frequency` (called if non-null)
- WRQ: auth handler called with value `1` — in practice returns success (no real check)
- RRQ: auth handler called with value `2` — lighter credential check
- Completion callback: `g_XPP_Link_Quality`
- Error on failure: `"Transfer refused"` (ERROR code 0)

**Port 16932 — paired path (param_4 = 1):**
- Auth handler: `g_XPP_Link_State` = `XPP_Secure_Config_Update()`
- WRQ: `XPP_Secure_Config_Update` logs `"tftpd_put"` and **returns immediately — no checks**.
- RRQ: performs two checks in sequence:
  1. `wlan_mac_addr_equal(param_2+0x00, &g_NET_Interface_MAC_Table, 6)` — source MAC must match `g_NET_Interface_MAC_Table`. This is the **adapter hardware MAC** on an unpaired adapter, or the **paired Xbox console MAC** on a paired adapter. Mismatch = `"mac_error"`, transfer refused. ⚠️ **NOTE: This is `g_NET_Interface_MAC_Table`, NOT `g_NVRAM_Router_MAC`.**
  2. HMAC-SHA1 of `g_NVRAM_User_Settings.Legacy_Padding` (`admin_id`, the XPP admin identity password, default `"admin"`) using `g_XPP_HMAC_Key`, compared against 20 bytes at `param_2+0x26`. Mismatch = `"password_error1"`, transfer refused.
- Return values from auth handler: `0` = allowed, `-1` = Access violation (ERROR code 2), `-2` = silent drop
- Completion callback: `g_XPP_Security_State`

**Both ports — WRQ has no access control.** Any host with a valid XPP session can flash
new firmware on either port. Port 69 WRQ has no auth handler at all. Port 16932 WRQ calls
`XPP_Secure_Config_Update` which immediately returns after logging `"tftpd_put"` without
checking anything.

**Note on dispatch paths**: The firmware also checks `if (param_4 == 0) OR (g_XPP_Link_State == NULL)` — if port 16932 is used but `g_XPP_Link_State` was never registered, it falls through to the port 69 auth path as a fallback.

---

### TFTP Credentials
The adapter has two separate credentials stored in NVRAM, both defaulting to `"admin"` at factory reset:

**HTTP username / XPP device identity**: `xpp_identity_username` (default `"admin"`).
Populated into `XPP_Identity_t.password` at boot. Used as the HTTP Basic Auth username.
**No XPP TLV tag writes this field** — it can only be changed via the HTTP web config page.

**HTTP password / TFTP HMAC input / CLI admin_id**: `g_NVRAM_User_Settings.Legacy_Padding` — the XPP admin identity password (max 16 chars + NUL = 17 bytes total).
This is the credential used by `XPP_Secure_Config_Update` as the HMAC input for TFTP RRQ authentication on port 16932. It is also used as the HTTP Basic Auth password and copied to `XPP_Identity_t.admin_id` at boot for CLI session auth.
**Written by Tag 0x03 in Type 0x07 CONNECT_REQ.** Also changeable via HTTP web UI.

⚠ **Naming note**: this field is called `Legacy_Padding` by Ghidra (the decompiler artifact name). In the firmware's runtime struct `XPP_Identity_t` it is `admin_id`. There is no field called `wifi_key` anywhere in the firmware — that name was an error in earlier versions of this spec.

Both default to `"admin"` at factory reset giving HTTP credentials of `admin:admin`.
Tag 0x03 changes only the password/HMAC side (`Legacy_Padding` / `admin_id`), not the username side (`xpp_identity_username`).
Factory reset restores both via `Flash_Commit_Settings()` → `strcpy(STR_DEFAULT_CREDENTIAL)`.

---

### TFTP — Emulator Implementation Checklist

This section documents the most likely causes of TFTP failure in an emulator, ordered by probability:

```
Priority | Issue                                                   | Fix
---------|---------------------------------------------------------|---------------------------------------------
1 (HIGH) | Not sending ACK block 0 after WRQ is accepted           | Send ACK opcode 4, block number 0, immediately
         |                                                         | on WRQ receipt — before client sends DATA 1
2 (HIGH) | Sending DATA to wrong port after session starts         | Client must re-address packets to the EPHEMERAL
         |                                                         | port the adapter allocated, not port 69/16932
3 (HIGH) | XPP session handle not set before TFTP                  | Must complete a full Type 0x01/0x02 handshake
         |                                                         | before TFTP port accepts any request
4 (MED)  | RRQ MAC check failing — using wrong MAC                 | Auth header src_mac[0..5] must equal
         |                                                         | g_NET_Interface_MAC_Table: adapter hardware
         |                                                         | MAC if unpaired, Xbox console MAC if paired.
         |                                                         | MSBNUpdate uses adapter MAC — get it from
         |                                                         | the BBN discovery response at offset +0x60.
5 (MED)  | HMAC at wrong offset in auth header                     | HMAC is at payload offset +0x26 (38 decimal),
         |                                                         | not at +0x06. Offsets 0x06–0x25 are zero padding.
6 (LOW)  | APIPA routing — no route back to 169.254.x.x adapter    | Add a host IP in the 169.254.0.0/16 range on the
         |                                                         | NIC connected to the adapter before attempting TFTP
7 (LOW)  | Final zero-length DATA packet not handled               | Adapter may not ACK final zero-length block;
         |                                                         | handle ACK timeout on final block gracefully
```

**Step-by-step WRQ flow (emulator must implement exactly):**

```
Client → Adapter  UDP dst=69   [WRQ opcode=2] [filename\0] [mode\0]
Adapter → Client  UDP dst=client-src-port (ephemeral port) [ACK opcode=4] [block=0]
Client → Adapter  UDP dst=ephemeral-port  [DATA opcode=3] [block=1] [512 bytes payload]
Adapter → Client  UDP dst=client-src-port [ACK opcode=4] [block=1]
...
Client → Adapter  UDP dst=ephemeral-port  [DATA opcode=3] [block=N] [<512 bytes — final block]
Adapter → Client  UDP dst=client-src-port [ACK opcode=4] [block=N]
   (adapter calls xpp_tftp_commit_config → xpp_flash_write_manager → reboot if size == 0x100000)
```

**Step-by-step RRQ flow (port 16932 with auth):**

```
Client → Adapter  UDP dst=16932  [src_mac:6][zeros:32][HMAC-SHA1:20][RRQ opcode=1][filename\0][mode\0]
   (adapter checks src_mac vs g_NET_Interface_MAC_Table — adapter hardware MAC if unpaired, Xbox MAC if paired)
Adapter → Client  UDP dst=client-src-port (ephemeral port) [DATA opcode=3] [block=1] [512 bytes]
Client → Adapter  UDP dst=ephemeral-port  [ACK opcode=4] [block=1]
...
Adapter → Client  UDP dst=client-src-port [DATA opcode=3] [block=N] [<512 bytes — final block]
Client → Adapter  UDP dst=ephemeral-port  [ACK opcode=4] [block=N]
```

---

### Security Notes
**WRQ has no access control on either port.** Any host that has established an XPP session can flash new firmware. Port 69 WRQ has no auth handler at all. Port 16932 WRQ calls `XPP_Secure_Config_Update` which immediately returns after logging `"tftpd_put"` without checking anything.

**RRQ auth is a fixed credential (port 16932 only).** The HMAC at `+0x26` is `HMAC-SHA1(key=g_XPP_HMAC_Key, input=admin_id_string)`. For default config, `admin_id = "admin"` and the key is the static ROM value. Both are fixed constants — the correct HMAC is fully offline-computable once the key is extracted.

**Unpaired vs paired adapter behaviour (port 16932 RRQ only):**
- Unpaired adapter: `g_NET_Interface_MAC_Table` holds the **adapter hardware MAC** (populated at boot, not all-zeros). The RRQ src_mac must match this adapter hardware MAC. MSBNUpdate obtains this MAC from the BBN discovery response at `+0x60` before attempting TFTP.
- Paired adapter: source MAC in the auth header must exactly match the stored paired Xbox console MAC (`g_NET_Interface_MAC_Table`) before HMAC is even attempted.

---

### Network Requirements for TFTP (APIPA Adapters)

When the MN-740 is connected directly to a PC with no router or switch, it
self-assigns an APIPA address (`169.254.x.x/16`) because no DHCP server is
present. TFTP is standard UDP and requires the **client PC to have an address
on the same `/16` subnet**; without one the UDP reply from the adapter has no
route back and every RRQ times out with `WSA 10060`.

**Confirmed from live testing with adapter at `169.254.250.49`:**

The adapter IP is learned from `HANDSHAKE_RESP` offset 210 (the `ip_address`
field). If that field is zero the adapter hasn't obtained an address yet; wait
for APIPA self-assignment (~15–30 s after power-on) and re-run the handshake.

**To add a temporary host address on Windows (run as Administrator):**
```
netsh interface ip add address "Ethernet" 169.254.1.1 255.255.0.0
```
Replace `"Ethernet"` with the actual NIC name from `ipconfig /all`.
Remove after TFTP completes:
```
netsh interface ip delete address "Ethernet" 169.254.1.1
```

**Route add does NOT work for 169.254.x.x.** The Windows IP stack enforces
that APIPA destinations are only reachable via an interface that already has an
address in the `169.254.0.0/16` range. A `route add` command without a local
address on that range is silently ignored by the routing table.

---

### Virtual File System — Complete File Catalogue
The firmware implements a virtual filesystem rooted in `g_HTTP_UPLOAD_BUFFER` (1 MB RAM).
All filenames are matched by `strcmp()` — there is no real filesystem on the adapter.

**RRQ — Files readable from the adapter** (all require RRQ auth to pass):

```
Filename       | Size   | Contents / Source
---------------|--------|-----------------------------------------------------------
"dbgout.txt"   | 32768  | Debug log ring buffer from RAM (0x807f8000). Contains
               |        | recent firmware serial console output.
"ar5maco.dat"  | ~32    | AR5212 hardware MAC address as formatted ASCII string:
               |        | "0x XXXX XX:XX:XX:XX:XX:XX" — reads from ath_hal_get_hw_info()
"ar5eepo.dat"  | 2048   | AR5212 EEPROM dump (0x800 bytes). Reads via
               |        | xpp_flash_read_wrapper(0, 0, 0x400). If read fails,
               |        | buffer is 0xFF-filled.
```

**WRQ — Files writable to the adapter** (no auth required for any WRQ):

All WRQ uploads buffer into `g_HTTP_UPLOAD_BUFFER` (1 MB max). Validation and effect
are applied in the completion callback after the full transfer completes. Each virtual
file write has an embedded credential in the file payload itself that the firmware
checks before acting — these are separate from the TFTP auth header HMAC.

```
Filename          | Payload size | Effect on success
------------------|--------------|----------------------------------------------------
"image"           | any          | Flash firmware: xpp_flash_write_manager() → reboot
"boot.bin"        | any          | Same as "image" — both accepted (MSBNUpdate specific)
"resdef.dat"      | 39 bytes     | Flash_Commit_Settings() + CFG_Save_To_Flash() +
                  |              | NET_Reload_Config() — restores factory config
"mac.dat"         | any          | xpp_finalize_console_pairing() → reboot.
                  |              | Writes Xbox pairing MAC. On unpaired adapter, MAC
                  |              | check trivially passes (adapter MAC matches itself).
"ar5maci.dat"     | any          | AR5212 MAC address import via config_helper().
                  |              | Payload embeds a 4-byte auth token checked against
                  |              | MAC_DAT_DESCRIPTOR_BLOCK.magic_header[0..3].
"ar5eepi.dat"     | any          | EEPROM refresh via nvram_flash_read_to_buffer().
                  |              | Payload embeds 4-byte auth token vs magic_header[4..7].
"tx_rate.dat"     | any          | Sets G_PENDING_TX_Rate_Code and reboots.
                  |              | 7-byte auth token embedded in payload.
"ee_ar531x.dat"   | 4096 bytes   | Writes full AR5212 EEPROM block via
                  |              | sys_flash_write_block(). Requires payload size ==
                  |              | 0x1004 and XOR checksum validation. 4-byte auth token.
```

⚠ The virtual file write tokens (embedded credentials) are derived from `MAC_DAT_DESCRIPTOR_BLOCK.metadata[]` and related ROM constants. Their exact values are hardware-specific and not documented here — they are not related to the TFTP auth header HMAC. These files are PC wizard / factory tool targets and are never requested by `xonlinedash.xbe`.

### Related Information
- [Type 0x07 Request](#9-type-0x07---connect_to_ssid_request)
- [MSBNUpdate.exe Firmware Update Tool](#msbnupdateexe-firmware-update-tool)

---

## MSBNUpdate.exe Firmware Update Tool

**Source**: String analysis of `MSBNUpdate.exe` (Microsoft Broadband Networking
Update Utility, build path `d:\Net2\src\DINGO\exe\MSBNUpdate\Release`).
This is the official Microsoft PC-side tool used to upgrade MN-740 firmware.

**Driver**: Uses `ISW32N50.dll` — a PCANDIS/ISLNDIS raw-packet wrapper that
provides `W32N_PacketSend` and related calls over EtherType 0x886F. Functionally
identical to what our Npcap layer does. Does **not** use UDP port 2002.

### Two-Stage Firmware Update Flow

The update sends **boot firmware first, then runtime firmware**, verifying each
stage before proceeding. The two internal SKU identifiers confirm the ordering:

```
Stage | SKU identifier        | Description
------|-----------------------|------------------------------------------
1     | SKU_MN-740_BOOT_FW    | Boot firmware image (sent first)
2     | SKU_MN-740_RUNTIME_FW | Runtime firmware image (sent second)
```

**Full update sequence (string-verified):**
```
1.  Discover MN-740 via XPP (EtherType 0x886F — same as our tool)
2.  Query firmware versions:
      "Bridge firmware runtime version:"
      "Bridge firmware get runtime version:"
      "Bridge firmware boot version:"
      "Bridge firmware get boot version string:"
3.  Check minimum version floor — "Firmware is too old to update"
4.  Validate admin password — "MN740 Connect, bad password"
    (sent via XPP CONNECT_REQ Tag 0x03 before TFTP begins)
5.  Log: "Updating firmware for MN740 MAC: '%S' IP: '%S'"
    (confirms TFTP target is adapter's actual IP, not broadcast)
6.  TFTP WRQ → "boot.bin" in "octet" mode to adapter IP:69
7.  Transfer boot firmware blocks (512 bytes each, RFC 1350)
8.  "sent last zero data packet, host timed out, but OK"
    (zero-length final DATA packet; ACK timeout expected and harmless)
9.  Wait for bridge reboot: "Waiting for Bridge reboot, mac: '%S' try: %d * 15 seconds"
10. Verify boot stage: "Verifying boot fw update...."
      "Current boot firmware did not match update file" (error)
      "Looking for bridge fw version to verify boot, cnt: %d"
11. TFTP WRQ → "boot.bin" in "octet" mode — runtime firmware
12. Transfer runtime firmware blocks
13. Wait for reboot again (same 15-second poll)
14. Verify runtime stage: "Verifying runtime fw update...."
      "Current runtime firmware did not match update file" (error)
      "Updating bridge firmware was a success"
```

### Key String Findings (MSBNUpdate.exe)

```
String                                          | Significance
------------------------------------------------|--------------------------------------
"Updating firmware for MN740 MAC: '%S' IP: '%S'"| TFTP goes to adapter's actual IP
"boot.bin"                                      | WRQ filename (not "image")
"octet"                                         | TFTP mode string (binary)
"sent last zero data packet, host timed out, but OK" | Final zero-length packet expected
"MN740 Connect, bad password"                   | Password validated before TFTP
"SKU_MN-740_BOOT_FW"                            | Boot firmware SKU identifier
"SKU_MN-740_RUNTIME_FW"                         | Runtime firmware SKU identifier
"Waiting for Bridge reboot, mac: '%S' try: %d * 15 seconds" | 15-second reboot poll
"Bridge did not reboot"                         | Reboot detection failure
" Runtime firmware version: %d.%d.%d.%d"       | Version string format (note leading space)
" Boot firmware version: %d.%d.%d.%d"          | Boot version string format
"TFTP, negotiating ports with MN740..."         | Separate MN-740 TFTP function
"TFTP send MN740 file"                          | Distinct from gateway TFTP
"No MN740 Bridge attached"                      | Discovery failure message
```

**⚠ WRQ filename is `"boot.bin"`, not `"image"`.** The firmware dump RRQ uses
`"image"` (firmware source: `XPP_flash_read_wrapper`). The official update WRQ
uses `"boot.bin"`. These are two different TFTP code paths.

### BOOT_ME Signal — Gateway Only

The `BOOT_ME` signal (`"Wait for BOOT_ME, recvd: %d"` / `"Received BOOT_ME"`)
appears only in the **gateway update path** (MN-700 base station, BCM94710AP
chipset). The MN-740 wireless bridge update does **not** use `BOOT_ME`. The
bridge reboot is detected by polling XPP handshake responses, not a broadcast
beacon signal.

### Final Zero-Length DATA Packet

`"sent last zero data packet, host timed out, but OK"` confirms that
MSBNUpdate.exe deliberately sends a zero-length DATA packet as the final
transfer step. The adapter's TFTP server may not ACK this packet (it has
already received and processed the full image), so the ACK timeout is expected
and is not treated as an error. Implementors should handle a missing ACK on the
final block gracefully.

### Password Validation Flow

`"MN740 Connect, bad password"` appears in the TFTP code area, not the XPP
discovery code. The password is validated before the TFTP session opens.
Internally this is done via the XPP channel (CONNECT_REQ Tag 0x03) — the
same `g_NVRAM_User_Settings.Legacy_Padding` (`admin_id`) credential described in the TFTP credentials section above.
If the password is wrong the TFTP session is never attempted.

---

### BBN Device Discovery Protocol
**Sources**: `trialupdate.pcapng` (wire), `NML_bin.c` + `BBN_Handle_Discovery_Task` assembler (firmware-verified)

Before any TFTP transfer begins, MSBNUpdate.exe runs a proprietary device-discovery exchange using the firmware's **BBN** (Broadband Networking) subsystem. This is entirely separate from the XPP (EtherType `0x886f`) management protocol — it operates over standard UDP/IP on port **42424** (`0xa5b8`) and is used by the PC wizard to locate adapters on the local subnet, retrieve their IP and version information, and obtain a session nonce before opening TFTP.

**Session participants (wire-verified):**
```
PC (MSBNUpdate.exe): 169.254.250.55, MAC 00:15:5d:01:0a:1b
Adapter (MN-740):    169.254.38.9,   MAC 00:0d:3a:1f:26:09
```

#### Transport

The firmware opens **two separate UDP sockets** at boot via `BBN_Init_Sockets()`:

- **RX socket** (`g_BBN_Socket_RX`): bound to port **42424** — receives incoming queries
- **TX socket** (`g_BBN_Socket_TX`): unbound ephemeral port — sends responses to broadcast `255.255.255.255:42424`

Responses are broadcast (not unicast) so multiple PC listeners on the subnet can receive them simultaneously. The adapter's fixed response source port observed on the wire is **1204**.

The BBN task runs in `WLAN_Discovery_Manager_Task`, which polls `BBN_Handle_Discovery_Task` in a 1ms sleep loop as long as `g_NET_MASTER_STATE` is non-zero (network stack running).

#### Discovery Query Packet (PC → broadcast:42424)

**Firmware-verified**: `BBN_Handle_Discovery_Task` at `8009b854` checks that the received byte count equals exactly `0x14` (20 bytes), then at `8009b884–8009b8e0` validates that bytes `[0..3]` of the incoming buffer equal `50 00 00 00`. Any other size or first byte causes the packet to be rejected with `"bbn: not a discovery request"`.

```
Offset | Size | Value             | Description
-------|------|-------------------|----------------------------------------------------
0      | 1    | 0x50              | Query type marker — REQUIRED, firmware validates this
1      | 3    | 0x00 0x00 0x00    | Padding zeros (part of the 4-byte match)
4      | 4    | variable          | Flags/version field — firmware does not validate
8      | 8    | zeros             | Reserved — firmware does not read these bytes
16     | 4    | random            | Session nonce — echoed verbatim at response offset +0x66
Total  | 20   |
```

Wire examples (both observed in the same session — only the 20-byte form passes the firmware length check):
```
20-byte form: 50 00 00 00 01 00 00 00 00 00 00 00 00 00 00 00 59 3f 80 3e  ← ACCEPTED
17-byte form: 50 00 00 00 01 00 00 00 00 00 00 00 00 59 3f 80 3e           ← REJECTED (wrong length)
```

#### Discovery Response Packet (Adapter → broadcast:42424, 126 bytes)

**Firmware-verified**: complete field layout derived from `BBN_Handle_Discovery_Task` assembler (`8009b918–8009bbe0`). The buffer is zero-filled with `memset(0, 0x7e)` then each field is written by an explicit `memcpy` or `sh` instruction. Fields marked *(zero-filled gap)* have **no firmware write** — they remain `0x00` from the memset.

The "trailing capabilities TLV block" previously described as having unknown field definitions is now fully decoded: it is the byte-swapped firmware and hardware version fields written as individual halfwords.

```
Offset  | Size | Firmware source                     | Wire value            | Description
--------|------|-------------------------------------|-----------------------|---------------------------------------------
+0x00   |  4   | 0x51 byte-reversed → 0x51000000     | 51 00 00 00           | Response type marker
+0x04   |  4   | G_BBN_PROTO_VERSION                 | 00 00 00 01           | Protocol version = 1 (big-endian)
+0x08   |  4   | nvram_check_default_state() result  | 01 00 00 00           | 0x01000000 = factory defaults active, 0x00000000 = customised
+0x0c   | 32   | str_BBN_Device_Name                 | "MN-740 Bridge\0..."  | Long device name, null-padded to 32 bytes
+0x2c   | 32   | str_BBN_Model_Info                  | "MN-740\0..."         | Short model name, null-padded to 32 bytes
+0x4c   |  4   | CFG_Device_IP                       | a9 fe 26 09           | Device IP address (big-endian). 0.0.0.0 if unassigned.
+0x50   |  4   | (zero-filled gap — no firmware write)| 00 00 00 00          | Unused. Always 0x00000000.
+0x54   |  4   | G_NET_ActiveSubnetMask              | ff ff 00 00           | Subnet mask. 0xffff0000 (255.255.0.0) on APIPA /16.
+0x58   |  4   | (zero-filled gap — no firmware write)| 00 00 00 00          | Unused. Always 0x00000000.
+0x5c   |  4   | G_NET_PrimaryDNS                    | 00 00 00 01           | Primary DNS. May retain stale value from prior DHCP lease on APIPA adapter.
+0x60   |  6   | g_NET_Interface_MAC_Table           | 00:0d:3a:1f:26:09     | Adapter MAC address (see note on g_NET_Interface_MAC_Table below).
+0x66   |  4   | buf_BBN_Incoming_Request + 0x10     | 59 3f 80 3e           | ⚠ NONCE ECHO — bytes [16..19] of the incoming query, copied verbatim.
+0x6a   |  4   | s1=0x04000740 byte-reversed         | 40 07 00 04           | Hardcoded capability flags (firmware constant).
+0x6e   |  2   | G_FW_MajorVersion byte-swapped      | 01 00                 | Firmware major version = 1
+0x70   |  2   | G_FW_MinorVersion byte-swapped      | 03 00                 | Firmware minor version = 3
+0x72   |  2   | G_FW_Revision byte-swapped          | 00 00                 | Firmware revision = 0
+0x74   |  2   | G_FW_Build byte-swapped             | 05 00                 | Firmware build = 5
+0x76   |  2   | G_HW_MajorVersion byte-swapped      | 01 00                 | Hardware major version = 1
+0x78   |  2   | G_HW_MinorVersion byte-swapped      | 00 00                 | Hardware minor version = 0
+0x7a   |  2   | G_HW_FeatureFlags byte-swapped      | 02 00                 | Hardware feature flags = 2
+0x7c   |  2   | G_HW_RegionID byte-swapped          | 15 00                 | Hardware region ID = 0x15 = 21
```

**Version byte-swap encoding**: each 16-bit version field is stored in native MIPS big-endian order but written to the response buffer via a byte-reversal sequence (`sra/sll/or` pattern at `8009bac4–8009bbe0`). The wire value is the byte-reversed form of the stored value. To decode: swap the two bytes. Wire `01 00` → stored `0x0001` = 1. Wire `15 00` → stored `0x0015` = 21.

**Firmware version cross-reference**: the BBN response reports firmware 1.3.0.5 and hardware 1.0. Cross-referencing against the HANDSHAKE_RESP build string `"1.0.2.26 Boot: 1.3.0.06"` suggests the BBN fields encode the **boot firmware** version (1.3.x.x) separately from the runtime firmware (1.0.2.26). The hardware region ID 21 (`0x15`) corresponds to the regulatory domain code.

**Wire-verified response hex (126 bytes):**
```
51 00 00 00 00 00 00 01 01 00 00 00
4d 4e 2d 37 34 30 20 42 72 69 64 67 65 00 ...  ← "MN-740 Bridge" (+0x0c)
4d 4e 2d 37 34 30 00 00 00 00 00 00 00 00 ...  ← "MN-740" (+0x2c)
a9 fe 26 09                                    ← CFG_Device_IP (+0x4c)
00 00 00 00                                    ← zero-filled gap (+0x50)
ff ff 00 00                                    ← G_NET_ActiveSubnetMask (+0x54)
00 00 00 00                                    ← zero-filled gap (+0x58)
00 00 00 01                                    ← G_NET_PrimaryDNS (+0x5c)
00 0d 3a 1f 26 09                              ← adapter MAC (+0x60)
59 3f 80 3e                                    ← nonce echo (+0x66)
40 07 00 04                                    ← capability flags (+0x6a)
01 00 03 00 00 00 05 00                        ← FW major/minor/revision/build (+0x6e)
01 00 00 00 02 00 15 00                        ← HW major/minor/flags/regionID (+0x76)
```

**Note on G_NET_PrimaryDNS at +0x5c**: the wire value `0x00000001` on this APIPA adapter is a stale value retained from a prior partial DHCP lease. A factory-reset adapter with no prior DHCP history shows `0x00000000` here.

#### Nonce Echo — Firmware-Verified Mechanism

The nonce echo was previously labelled `G_NET_SecondaryDNS` based on Ghidra's address resolution. The assembler proves this was wrong. At `8009ba60`:

```asm
addiu v1, s2, 0x10    ; s2 = buf_BBN_Incoming_Request; v1 = incoming + 0x10
addiu param_1, s0, 0x66 ; s0 = buf_BBN_Outgoing_Response; dest = response + 0x66
or    param_2, v1, zero  ; source = incoming_request + 0x10
ori   param_3, zero, 0x4 ; size = 4 bytes
jal   memcpy
```

Bytes `[16..19]` of the 20-byte query (the session nonce) are copied verbatim to response offset `+0x66`. `G_NET_SecondaryDNS` is never written anywhere in this function — that label was a Ghidra artefact from incorrect pointer resolution.

#### Discovery Timing
```
PC broadcasts query          → adapter responds within ~77ms (first seen response)
PC repeats query periodically → multiple discovery rounds before TFTP begins
Query interval: ~300–1300ms  → adapter responds to each independently
```

MSBNUpdate runs several discovery rounds while waiting for the adapter to become reachable (e.g. while it finishes APIPA address assignment). The session nonce changes each round; the adapter echoes back whatever nonce it received in the most recent valid query.

---

### ⚠️ WIRE-VERIFIED CORRECTION: WRQ Auth Material Embedded in Filename Field
**Source**: `trialupdate.pcapng` — Packet #32, wire-verified

The existing spec documented the 58-byte auth header as a separate block *prepended before* the TFTP opcode, giving the structure `[58-byte header][TFTP opcode][filename]`. **This is incorrect.** The actual wire shows MSBNUpdate.exe packs the 58 bytes of auth material directly **inside the TFTP filename field**, using binary data as the filename string. The firmware's TFTP parser reads the auth bytes out of the filename before acting on them.

#### Corrected WRQ Wire Format (port 16932)

```
Offset | Size | Field            | Wire value / Description
-------|------|------------------|------------------------------------------------------
0      | 2    | TFTP opcode      | 0x0002 = WRQ
2      | 6    | auth.src_mac     | Adapter MAC address (e.g. 00:0d:3a:1f:26:09)
8      | 32   | auth.padding     | 32 bytes (non-zero data from MSBNUpdate)
40     | 20   | auth.HMAC-SHA1   | 20-byte HMAC (non-zero for WRQ in MSBNUpdate)
60     | 1    | filename end     | 0x00 (null terminator — ends the filename field)
61     | 5    | mode string      | "octet" (0x6f 0x63 0x74 0x65 0x74)
66     | 1    | mode end         | 0x00 (null terminator — ends the mode field)
```

Total WRQ packet length: **67 bytes**

**Wire-verified WRQ hex (frame 32, UDP payload):**
```
00 02  ← TFTP opcode: WRQ
00 0d 3a 1f 26 09  ← auth.src_mac (adapter MAC)
d1 d0 de c1 2a 5d e5 5d f8 38 02 ed ba 6c 56 b8
cd 15 8e 23 25 52 16 08 2a b4 a2 04 fe 5f 6d 6b  ← auth.padding (32 bytes)
89 d3 e1 6d 31 54 09 6e 1c 89 f6 b5 94 af b6 f7
2a c2 49 80  ← auth.HMAC-SHA1 (20 bytes, non-zero)
00  ← null terminator (end of filename field)
6f 63 74 65 74  ← "octet"
00  ← null terminator (end of mode field)
```

**Key differences from previous spec description:**

The previous spec stated: `[58-byte auth header][TFTP WRQ packet]` where the TFTP opcode appeared after the header at offset `+0x3a`. This is wrong on the wire. The correct structure is a single standard TFTP WRQ where the filename field happens to contain 58 bytes of binary auth material.

The firmware's TFTP receiver on port 16932 calls `XPP_Secure_Config_Update(param_2, ...)` where `param_2` points to the start of the UDP payload. For a WRQ this function reads `param_2[0:6]` as src_mac and `param_2[0x26:0x3a]` as the HMAC regardless of TFTP framing. Because the opcode `0x0002` occupies bytes `[0:2]` of the payload and the filename starts at byte `[2]`, the firmware's fixed-offset reads into the filename body correctly extract the auth material at the expected positions:

```
UDP payload offset | TFTP field context    | Auth field read
-------------------|-----------------------|------------------
+0x00 (bytes 0-1)  | TFTP opcode (0x0002)  | (not auth — opcode)
+0x02 (bytes 2-7)  | Filename bytes 0-5    | auth.src_mac
+0x08 (bytes 8-39) | Filename bytes 6-37   | auth.padding
+0x26 (bytes 38-57)| Filename bytes 36-55  | auth.HMAC-SHA1
+0x3a (byte 58-59) | Filename bytes 56-57  | (last 2 bytes of filename)
+0x3c (byte 60)    | Filename null term    | (end of filename)
+0x3d (bytes 61-65)| Mode field "octet"    | (not auth)
```

⚠️ **The firmware reads auth material at fixed UDP payload offsets `+0x00` (MAC) and `+0x26` (HMAC), which land inside the TFTP filename field** because of the 2-byte TFTP opcode prefix. This is not a coincidence — MSBNUpdate was written to produce exactly this layout.

#### src_mac field in WRQ auth

For the RRQ auth (described elsewhere in this spec), `src_mac` must match `g_NET_Interface_MAC_Table` — the **adapter hardware MAC** on an unpaired adapter, or the **paired Xbox console MAC** on a paired adapter. For WRQ, `XPP_Secure_Config_Update` returns immediately without checking anything — so the src_mac value in WRQ auth is irrelevant to whether the transfer succeeds. MSBNUpdate puts the **adapter's own MAC** (`00:0d:3a:1f:26:09`) in the WRQ src_mac field, which is also correct for the RRQ case on an unpaired adapter.

#### HMAC field in WRQ

MSBNUpdate sends a **non-zero HMAC** in WRQ packets (unlike the all-zeros value the spec previously suggested for writes). Since the firmware ignores the WRQ auth entirely, the HMAC value is functionally irrelevant for firmware uploads. An emulator or custom tool implementing WRQ on port 16932 may send any value (including all-zeros) in the HMAC field without affecting transfer success.

---

### ⚠️ WIRE-VERIFIED: TFTP ACK 0 and Ephemeral Port
**Source**: `trialupdate.pcapng` — Packets #33 and #34

```
Frame 32: PC → adapter:16932     WRQ (67 bytes, filename contains auth material)
Frame 33: adapter:1205 → PC:1118 ACK block 0 (4 bytes: 00 04 00 00)  ← RTT ~10ms
Frame 34: PC:1118 → adapter:1205 DATA block 1 (516 bytes)
Frame 35: adapter:1205 → PC:1118 ACK block 1 (4 bytes: 00 04 00 01)
...
```

The adapter allocates ephemeral port **1205** for the data transfer. All subsequent DATA and ACK exchanges use `adapter:1205 ↔ PC:1118` (the PC's original WRQ source port). This confirms the ephemeral port behaviour described in the TFTP section.

ACK 0 wire (4 bytes): `00 04 00 00`
ACK 1 wire (4 bytes): `00 04 00 01`

---

### Wire-Verified Firmware Block 1 Content
**Source**: `trialupdate.pcapng` — Frame 34, DATA block 1

The first 512-byte firmware block transferred contains the following human-readable strings, which identify it as the **boot stage** firmware (stage 1 of MSBNUpdate's two-stage update):

```
String                              | Significance
------------------------------------|------------------------------------------
"GL2454AP-LT1-M80     -0000.00.00" | Hardware board identifier (GL2454AP chipset)
"Sat, 06 Sep 2003    "              | Firmware build date
"MN-740 Bootrom"                    | Firmware stage: boot ROM
00:11:22:33:44:55                   | Placeholder/test MAC in firmware image
```

This confirms that MSBNUpdate stages the boot firmware first, consistent with the `SKU_MN-740_BOOT_FW` → `SKU_MN-740_RUNTIME_FW` ordering documented from string analysis. The build date of 6 September 2003 places boot ROM development approximately 12–18 months before the retail launch.

---

### Wire-Verified DHCP Behaviour (Adapter, No Server Present)
**Source**: `trialupdate.pcapng` — Frames 1 and 7824

When no DHCP server responds, the adapter falls back to APIPA (`169.254.x.x`) and continues sending DHCP DISCOVER broadcasts indefinitely with exponential backoff. The vendor class and hostname fields are wire-verified:

```
DHCP Option 12 (Hostname):            "MN-740"
DHCP Option 60 (Vendor class):        "MSFT 98"
DHCP Option 50 (Requested IP):        192.168.1.181 (retained from previous session)
DHCP Option 61 (Client ID hw type):   0x01 (Ethernet)
DHCP Option 55 (Param request list):  Subnet Mask, Router, DNS, Domain Name
DHCP Transaction ID pattern:          0x22334468, 0x22334469, ... (incrementing)
DHCP seconds elapsed:                 291 (first), increments per retry
Retry interval (observed):            ~2s, ~4s, ~8s (doubling)
```

The adapter retains the last-used DHCP IP (192.168.1.181) in NVRAM and requests it on every subsequent DISCOVER, consistent with the `g_NET_InterfaceStatus` / `CFG_Device_IP` save behaviour described in the HANDSHAKE_RESP section.

### IPHlpSvr.exe

`IPHlpSvr.exe` (Microsoft Broadband Networking IPHlpAPI Server Application)
is a Windows 9x/Me helper shim. It provides IP Helper API calls via window
messages to processes that cannot call `GetAdaptersInfo()` directly on those
platforms. It communicates via `SendMessageTimeout` to a hidden window
(`"Could not find IPHlpSvr window."`). It has no involvement in TFTP or XPP
protocol traffic and is irrelevant on Windows XP and later.

### Related Information
- [TFTP Firmware Upgrade](#tftp-firmware-upgrade)
- [TFTP Credentials](#tftp-credentials)

---

## 11. Type 0x09 - BEACON_REQUEST
**Direction**: Xbox → Adapter  
**Transport**: Ethernet 0x886f  
**HMAC Required**: no

### Brief Description
Keepalive heartbeat sent every 1 second.

### Packet Format
```
Total size: (14 Ethernet + 12 XPP Header) = 26 bytes
Body size:  (12 XPP header) / 4 = 3 DWORDs

Size         | Segment          | Description
-------------|------------------|--------------------------------
14 bytes     | Ethernet header  | Standard Header
12 bytes     | XPP Header       | Type 0x09, body size = 0x03 DWORDs
```

### Timing
- **Interval**: Every 1 second while connected
- **Timeout**: 5 seconds without response → adapter disconnected
- **Recovery**: Requires full handshake restart (Type 0x01)

### 30-Second Watchdog System ⚠️ CRITICAL

**Firmware Function**: `NET_Interface_Watchdog` at `0x8000a10c`

The adapter doesn't just wait for Type 0x09 beacons. It monitors **ANY valid Ethernet frame** from the paired Xbox MAC address.

**If no traffic seen for 30 seconds**:
1. Calls `net_set_error_state`
2. Shuts down Wi-Fi radio
3. Enters low-power mode
4. Requires full re-authentication (Type 0x01 handshake)

**Emulator Impact**: You must maintain an "active heartbeat" by either:
- Sending Type 0x09 beacons every 1 second (normal mode)
- OR sending any valid Xbox protocol packet within 30 seconds
- OR simulating ARP/ping traffic to reset watchdog

**Failure Mode**:
```
Adapter logs: "Watchdog timeout - Xbox MAC aa:bb:cc:dd:ee:ff inactive"
Adapter action: Radio shutdown, connection state = ERROR
Xbox UI: "Connection lost - adapter not responding"
Recovery: Full Type 0x01 → 0x02 handshake restart required
```

### Tags
None (fixed structure)

### ⚠️ Wire Observation — `09 01` bytes in ADAPTER_INFO_REQ are NOT beacon-related
When inspecting captures (e.g. Packet #112 in `lysten_open_connect_with_wan_ch_3_a.log`), the byte sequence
`09 01` appears inside the **Type 0x05 ADAPTER_INFO_REQ** payload. This is **not** related to the Type 0x09 BEACON_REQUEST.

The Type 0x05 payload is a counted array of `[Tag][Length Hint]` pairs. The `09 01` there decodes as:
- `0x09` = Table A Tag ID for **Link State**
- `0x01` = Length hint (1 byte response expected)

The Xbox routinely requests 9 tags in one Type 0x05 call (tag count = `0x09`), with Tag `0x09` (link state)
being the 8th entry in the array. The coincidence of the tag count (`0x09`) and the tag ID (`0x09`) in
the same payload can make the stream appear ambiguous on first inspection.

**The Type 0x09 BEACON_REQUEST itself carries zero payload** — it is exactly 26 bytes: 14-byte Ethernet
header + 12-byte XPP header with no data following. Any `09 01` bytes observed are always within a
Type 0x05/0x06 TLV stream, never inside a beacon packet.

**Wire-verified**: Packet #112 ADAPTER_INFO_REQ full TLV request array:
```
Payload:00 09 | 01 04 | 02 01 | 04 01 | 05 01 | 06 06 | 07 20 | 08 01 | 09 01 | 11 01 | 00 00 00
        ↑  ↑    ↑       ↑       ↑       ↑       ↑       ↑       ↑       ↑       ↑       ↑
        |  |    Tag01   Tag02   Tag04   Tag05   Tag06   Tag07   Tag08  [Tag09] Tag11   padding
        |  Tag count=9                                                   ↑
        Firmware Artifact
                                                         Link State tag — this is the "09 01"
```

### Related Information
- [Type 0x0a Response](#13-type-0x0a---beacon_response)

---

## 12. Type 0x0A - BEACON_RESPONSE

**Direction**: Adapter → Xbox  
**Transport**: Ethernet 0x886f  
**HMAC Required**: No

### Brief Description
Response to Type 0x09 keepalive. Returns current authentication status, smoothed signal strength,
and a raw hardware TX state byte. Sent within ~100ms of receiving a Type 0x09.

**Triggered by**: Type 0x09

### Packet Format
```
Total size: (14 Ethernet + 12 XPP Header + 4 Payload + 16 Padding) = 46 bytes
Body size:  (12 XPP Header + 4 Payload) / 4 = 0x04 DWORDs

Size         | Segment          | Description
-------------|------------------|--------------------------------
14 bytes     | Ethernet header  | Standard header
12 bytes     | XPP Header       | Type 0x0A, body size = 0x04 DWORDs
4  bytes     | Payload          | auth_status, smoothed_rssi, hal_tx_state, reserved
16 bytes     | Firmware padding | ⚠ Never written — uninitialised memory (firmware bug)
```

### Payload Structure (4 bytes)
```
 Offset | Size | Firmware Source               | Field Name/ Description
--------|------|-------------------------------|-----------------------------
 0      | 1    | `XPP_Check_Auth_Status()`     | auth_status   authentication Status
 1      | 1    | `drvr_get_smoothed_rssi()`    | smoothed_rssi  Smoothed rssi value
 2      | 1    | `drvr_get_tx_rate_code()`     | tx_rate_code   Raw 802.11 rate code masked `& 0x7f` (basic-rate bit stripped)
 3      | 1    | hardcoded                     | reserved       Always `0x00`
```
### ⚠ Firmware Bug — 16-byte Uninitialised Padding
Bytes 4–19 are a zero-filled pre-allocation artifact. The packet buffer is cleared to
`0x00` by `memset(0, 0x5ee)` before the builder runs. The body size field correctly
covers only the 4-byte payload (`0x04 DWORDs`). Implementations should tolerate and
ignore this trailing data.

**note**: The body size is calculated dynamically but the payload is always 4 bytes, so the body size will always be 0x04 DWORDs.

### Auth State (Byte 0)
```
Return | Name                            | Condition
-------|---------------------------------|------------------------------------------------------
0x00   | Authenticated                   | wlan_get_connection_readiness() == 0 AND CRYPTO_Get_Hardware_ID() matches g_ROUTER_MAC_ADDRESS
       |                                 | ⚠ Also seen transiently mid-association on open networks (wire-verified)
0x01   | Associating                     | wlan_get_connection_readiness() == 1
0x02   | Idle / Open-linked              | Default (not connected, past boot, not in TLV parse)
       |                                 | ⚠ Also observed on fully connected open networks — not exclusively idle
0x03   |802.11 association in progress   | TLV parser active, OR early boot (< 400 uptime ticks)
       |                                 | transitions from 0x02→0x03 after WEP CONNECT_REQ committed
       |                                 |   (lysten_wep_secured_128_bit_ascii.log Pkt#14, lysten_wep_secured_64_bit_ascii.log Pkt#14)
```

### Smoothed_rssi (Byte 1)

```
return      | Description / Value
------------|---------------------
0x80        | pre seed buffer state (-128)
0xBA        | seed value (-70)
other       | smoothed RSSI value

```
**Note**: byte 44 signal RSSI has custom scaling see [Signal strength / link quality scaling)](Signal strength / link quality scaling)
**Note**: Signed byte = 10-sample rolling average when authenticated.
Seed value `0xba` (-70) written explicitly when not authenticated
Value `0x80` (-128) is pre-association default; `g_RSSI_Smoothed_Output` is an
uninitialised global — `0x80` is not written by firmware, it reflects BSS/memory state.

### Raw 802.11 rate code masked `& 0x7f` (basic-rate bit stripped) (Byte 2)
```
Result code | Description/ value
------------|---------------------
0x00        | Not associated / no data frame sent
0x02        | 1 Mbps (802.11b)
0x04        | 2 Mbps (802.11b)
0x0B        | 5.5 Mbps (802.11b)
0x16        | 11 Mbps (802.11b)
0x0C        | 6  Mbps (802.11g)
0x12        | 9  Mbps (802.11g)
0x18        | 12 Mbps (802.11g)
0x24        | 18 Mbps (802.11g)
0x30        | 24 Mbps (802.11g)
0x48        | 36 Mbps (802.11g)
0x60        | 48 Mbps (802.11g)
0x6C        | 54 Mbps (802.11g)
```

### reserved (Byte 3)
```
Result code | Description/ value
------------|---------------------
  0x00      | hardcoded reserved
```

### ⚠ Rate limit Cap (Firmware-Verified)
The firmware enforces a hardware rate cap in ad-hoc mode:
- **Not Linked**:     tx_rate_code = `0x16` (11 Mbps) — returned as the pre-association / not-yet-linked default rate
- **Infrastructure**: tx_rate_code = `0x6C` (54 Mbps) — No Rate limit
- **Ad-hoc**:         tx_rate_code = `0x16` (11 Mbps) — hardcoded ceiling
This is a deliberate firmware design decision for BSS stability and Hidden Node collision avoidance. See Tag 0x07 section for full explanation.

### Wire-Verified Payload Examples
```
[Packets #4,#6,#8 - Before CONNECT_REQ (lysten_wep_secured_128_bit_ascii.log)]
02 80 60 00  →  auth=0x02(open/idle), rssi=0x80(-128 pre-seed), rate=0x60(48Mbps), reserved=0x00

[Packets #14+ - After WEP CONNECT_REQ committed (lysten_wep_secured_128_bit_ascii.log)]
03 80 60 00  →  auth=0x03(802.11 association in progress), rssi=0x80(-128 pre-seed), rate=0x60(48Mbps), reserved=0x00

[Packets #4,#6,#8 - Before CONNECT_REQ (lysten_wep_secured_64_bit_ascii.log)]
02 80 16 00  →  auth=0x02(open/idle), rssi=0x80(-128 pre-seed), rate=0x16(11Mbps), reserved=0x00

[Packets #14+ - After WEP CONNECT_REQ committed (lysten_wep_secured_64_bit_ascii.log)]
03 80 16 00  →  auth=0x03(802.11 association in progress), rssi=0x80(-128 pre-seed), rate=0x16(11Mbps), reserved=0x00

[Packet #138 - After ad-hoc reconnect (lysten_adhoc.log)]
02 80 16 00  →  auth=0x02(open/idle), rssi=0x80(-128 disconnected), rate=0x16(11Mbps cap), reserved=0x00

[Packets #2–#10 - Open network CH3 WAN connected (lysten_open_connect_with_wan_ch_3_new.log)]
02 80 6c 00  →  auth=0x02(open network connected), rssi=0x80(-128 pre-seed), rate=0x6C(54Mbps), reserved=0x00
⚠ NOTE: auth=0x02 on a fully-connected open network confirms 0x02 is NOT exclusively "idle" —
it is the steady-state auth byte for open/unencrypted connections. Only WEP transitions to 0x03.

[Packet #12 - Status change event during connection (lysten_open_connect_with_wan_ch_3_new.log)]
d5 82 00 d7  →  auth=0xd5(?), rssi=0x82, rate=0x00(not assoc), reserved=0xd7
⚠ NOTE: This transient packet appears once during link-up negotiation — fields are in flux.

[Packet #36/38 - After reconnect, BSSID acquired (lysten_open_connect_with_wan_ch_3_new2.log)]
08 e8 00 d7  →  auth=0x08(?), rssi=0xe8, rate=0x00(not associated), reserved=0xd7
⚠ NOTE: These transient values appear briefly during re-association. The reserved byte (Byte 3)
is NOT always 0x00 in these transitional states — the firmware memset may not cover this region.

[Packet #14 - WEP-128 hex mid-association (lysten_wep128hex_ch9_b2.log)]
a2 b2 00 e8  →  auth=0xa2(out-of-range), rssi=0xb2, rate=0x00, reserved=0xe8
⚠ NOTE: auth=0xa2 exceeds the dashboard validation threshold (>0x03 rejected).
  This packet is silently discarded by the dashboard. Confirms the firmware does
  not gate transient values before writing the BEACON_RESP buffer.
```

**Rate code **: new logs confirm rate=`0x6c` (54 Mbps) is the infrastructure value once the
radio associates. `0x16` is only for ad-hoc mode and the pre-association default.

### Dashboard Handler — `my_handle_beacon_response` (Assembler-Verified)

**Source**: `xonlinedash_xbe.c` @ `0x000a3563`, called from `my_fetch_wireless_adapter_data_p`.

#### Validation (fail → return 0)
```
[ESI+0x07] == 0x0a          ← XPP type must be BEACON_RESP
[ESI+0x06] << 2 == 0x10     ← body_dwords must == 0x04 (fixed 4-byte payload)
body byte[0] <= 0x03         ← CMP AL,0x03 / JA error — values > 0x03 rejected
```

#### Pre-switch call
Before the state switch, `FUN_000a2af6(byte[0], byte[1])` is called for all valid packets.
Its return value is discarded. Purpose: likely RSSI smoothing or beacon statistics — assembler
for `FUN_000a2af6` needed to confirm.

#### State Switch on body byte[0] → AutoClass1 fields (ECX = AutoClass1)

| body[0] | Condition | ECX+0x3c | ECX+0x48 | ECX+0x49 |
|---------|-----------|----------|----------|----------|
| 0x01    | —         | 0x01     | 0x80     | body[1]  |
| 0x02    | —         | 0x02     | 0x80     | body[1]  |
| 0x03    | —         | 0x03     | 0x80     | body[1]  |
| 0x00    | body[1] < 0xa6 | 0x02 | 0x80    | body[1]  |
| 0x00    | body[1] ≥ 0xa6 | 0x00 | body[1] | body[2]  |

**Note on case 0x00 / body[1] ≥ 0xa6**: DL is zero (zeroed by `XOR EDX,EDX` before the
pre-switch call, never reloaded). So `ECX+0x3c = 0x00`, not body[1]. Body[1] goes to
`ECX+0x48` (raw RSSI), body[2] goes to `ECX+0x49`.

#### Post-switch writes (all cases)
```
[ECX+0x40] = 0x00000000               ← always zero (EDX never changed from XOR EDX,EDX)
[ECX+0x44] = ([ECX+0x3c] != 0x03)     ← SETNZ: 1=infrastructure/scanning, 0=ad-hoc
return 1 (success)
```

#### AutoClass1 Field Map (from this function)
> **AutoClass1** is the Xbox dashboard's central wireless state object instantiated in `xonlinedash.xbe`. All offsets are relative to its base pointer (`ECX` in the assembler). Understanding these fields is useful for debugging but not required for adapter implementation.
```
 Offset | Size    | Name | Values
--------|---------|------------==-------|--------
 +0x3c  | 1 byte  | `XPP_link_state`    | 0x00=state0, 0x01=pre-assoc, 0x02=associated ✓, 0x03=ad-hoc |
 +0x40  | 4 bytes | (cleared) `         | Always written 0x00000000 |
 +0x44  | 4 bytes | `is_infrastructure` | 1 = not ad-hoc, 0 = ad-hoc (SETNZ on state≠0x03) |
 +0x48  | 1 byte  | `rssi_upper`        | 0x80 sentinel (cases 1/2/3), raw body[1] (case 0/≥0xa6) |
 +0x49  | 1 byte  | `rssi_lower`        | body[1] (cases 1/2/3), body[2] (case 0/≥0xa6) |
```

#### Wire cross-check
```
Body '02 80 6c 00' → CASE 0x02 → XPP_link_state=0x02, rssi_upper=0x80, rssi_lower=0x80
                                  is_infrastructure=1  ← normal connected state ✓
Body '03 80 60 00' → CASE 0x03 → XPP_link_state=0x03, rssi_upper=0x80, rssi_lower=0x80
                                  is_infrastructure=0  ← ad-hoc ✓
Body '01 80 16 00' → CASE 0x01 → XPP_link_state=0x01, rssi_upper=0x80, rssi_lower=0x80
                                  is_infrastructure=1  ← pre-association ✓
```

### Related Information
- [Type 0x09 Request](#11-type-0x09---beacon_request)
- [Connection Workflows](#connection-workflows)

---

## 13. Type 0x0B - SILENTLY_DROPPED
**Direction**: Any → Adapter  
**Transport**: Ethernet 0x886f  
**HMAC Required**: N/A

### Brief Description
**Firmware-verified**: The dispatcher silently drops any Type 0x0B packet and increments an internal counter g_CNT_XPP_TYPE_0B @ `800ce0f8`.
 No response is sent. This type is undocumented — it is an unused slot possibly for future expansion.

---

## 14. Type 0x0C - SILENTLY_DROPPED
**Direction**: Any → Adapter  
**Transport**: Ethernet 0x886f  
**HMAC Required**: N/A

### Brief Description
**Firmware-verified**: The dispatcher silently drops any Type 0x0C packet and increments an internal counter at g_CNT_XPP_TYPE_0C @ `800ce0fc`.
No response is sent. This type is undocumented — it is an unused slot possibly for future expansion.

---

## 15. Type 0x0F - SILENTLY_DROPPED
**Direction**: Any → Adapter  
**Transport**: Ethernet 0x886f  
**HMAC Required**: N/A

### Brief Description
**Firmware-verified**: The dispatcher silently drops any Type 0x0F packet. No response is sent, no counter is incremented, and nothing is logged — completely silent. This type is undocumented.

---

## 16. Type 0x11 - WPA_ASSOC / WPA_EXCHANGE

**Direction**: Bidirectional (Console→Adapter and Adapter→Console)  
**Transport**: EtherType 0x888e (EAPOL / IEEE 802.1X)  
**HMAC Required**: No

⚠️ **This is NOT a standard XPP management packet.** Type 0x11 has its own frame structure — no XPP magic signature, no Body Size DWORD count, no RFC 1071 checksum. It is a fully bidirectional sub-protocol used exclusively for WPA authentication. Xbox kernel pool tags `NETI` (0x4954454e) outbound and `NETK` (0x4b54454e) reply are internal memory debug tags only and have no meaning on the wire.

### Brief Description

Type 0x11 carries the WPA association and credential exchange between console and adapter. The console sends a `WPA_ASSOC_REQ` to begin WPA association. The adapter must then send type 0x11 frames back to drive the console FSM through IP negotiation, ANonce delivery, and final IP configuration. Without adapter-originated type 0x11 frames the console FSM stalls in state 0x11/0x12 until timeout.

---

### Quick Reference — Complete WPA Exchange Sequence

> This is the most implementation-critical section. Full FSM internals are documented below in [Appendix: Xbox FSM Internals](#appendix-xbox-fsm-internals).

```
Step | Direction       | Sub-type | frame_type | Sub-TLVs required                     | Console FSM Effect
-----|-----------------|----------|------------|---------------------------------------|---------------------------------------
1    | Adapter→Console | 0x01     | 0x21c0     | tag=0x03/4/0x23c0 (challenge token)   | Console replies with 0x23c2 response
     |                 |          |            | tag=0x05/6/<nonce> (DHCP cookie)      | and NOT(nonce) in reply frame
2    | Adapter→Console | 0x01     | 0x21c0     | tag=0x01/4/<IP> (proposed IP)         | FSM: advances to credential exchange
     |                 |          |            | tag=0x05/6/<nonce>                    |
3    | Adapter→Console | 0x09     | 0x21c0     | payload[8..] = ANonce bytes           | Console sends SNonce via state 0x13
     |                 |          |            | (requires console +0xa38 == 0x04)     | XPP_fsm_wpa_credential_exchange()
4    | Adapter→Console | 0x01     | 0x2180     | tag=0x03/6/<gateway IP>               | Console processes IP config
     |                 |          |            | tag=0x81/6/<DNS1 IP>                  | local_10[0]: 0x02→0x04
     |                 |          |            | tag=0x83/6/<DNS2 IP>                  | triggers state setup 0x14/0x15
5    | —               | —        | —          | —                                     | FSM exits WPA → state 0x0c
     |                 |          |            |                                       | IP ready signal to Xbox IP stack
```

**Sub-TLV format**: `[tag: 1 byte][len: 1 byte][data: len bytes]` (all sub-TLVs in type 0x11 frames use this format)

**Frame type word selects the sub-protocol**:
```
Frame Type Word | Sub-Protocol                          | When sent
----------------|---------------------------------------|------------------
0x21c0          | IP negotiation + WPA challenge        | Steps 1, 2, 3
0x23c0          | 4-way ANonce/SNonce retransmit        | State 0x14 retransmit
0x2180          | Post-auth IP configuration delivery   | Step 4
```

---

### Packet Format

```
Total size: variable (26-byte combined header + payload)

Size         | Segment              | Description
-------------|----------------------|---------------------------------------------
6  bytes     | Destination MAC      | Broadcast (FF:FF:FF:FF:FF:FF) or unicast AP MAC
6  bytes     | Source MAC           | Console MAC (field_0x1b0[+0x30..+0x35])
2  bytes     | Frame type word      | 0x6388 normal; 0x123c if fsm_state_flags&0x80 or first of double-send
1  byte      | Type marker [+0x0e]  | 0x11 (constant)
1  byte      | Sub-type  [+0x0f]    | Direction/state indicator (see Sub-type table)
2  bytes     | Reserved  [+0x10]    | 0x0000
2  bytes     | Length    [+0x12]    | Big-endian total payload length
2  bytes     | Reserved  [+0x14]    | 0x0000
variable     | Payload              | Sub-TLVs (format: [tag:1][len:1][data:len])
```

**Frame type word `0x6388` vs `0x123c` — source-verified selection logic:**
When `wpa_assoc_retry != 0` in state 0x11, the function sends the packet **twice** in one call (`local_c` starts at 2, loops down to 0). The selector per iteration is:
 ```c
if ((fsm_state_flags & 0x80) || local_c == 2) uVar8 = 0x123c; else uVar8 = 0x6388;
```
The **first** packet (local_c == 2) always uses `0x123c`; the **second** (local_c == 1) uses `0x6388` unless `fsm_state_flags & 0x80` forces `0x123c` on both. On a normal single-send (local_c starts at 1) with `fsm_state_flags & 0x80` clear, `0x6388` is always used.

**Console → Adapter sub-types (sent by Xbox)**
```
Sub-type | FSM State | Meaning
---------|-----------|------------------------------------------
0x09     | 0x11      | WPA_ASSOC_REQ — first attempt (broadcast to FF:FF:FF:FF:FF:FF)
0x19     | 0x12      | WPA_ASSOC_REQ — retry (unicast to AP MAC, carries ANonce material)
0x01     | 0x13,0x15 | Credential/IP exchange reply (always 0x01 — source-verified)
```

**Adapter → Console sub-types (sent by emulator/adapter)**
```
Sub-type      | frame_type | Meaning
--------------|------------|------------------------------------------
0x01          | 0x21c0     | IP negotiation: challenge token + DHCP cookie (steps 1, 2)
0x09          | 0x21c0     | ANonce delivery (step 3 — requires console +0xa38 == 0x04)
0x01          | 0x2180     | Post-auth IP config: gateway, DNS1, DNS2 (step 4)
0x01–0x04     | any        | IP/DHCP negotiation variants (0x02–0x04 less common)
```

⚠️ **NEVER send sub-types 0x05, 0x07, or 0x08** — these are hardcoded to call `XPP_fsm_fatal_error` on the console, immediately aborting the WPA session. This is NOT a silent drop.

> **Sub-type byte derivation (source-verified):**
> `XPP_build_wpa_assoc_request` computes the sub-type as `(!bVar15 - 1U & 0xF0) + 0x19` where `bVar15 = (fsm_state == 0x11)`.
> - State 0x11 (bVar15=true): `(0 - 1) & 0xF0 = 0xF0`, `0xF0 + 0x19 = 0x109` → **byte truncates to `0x09`**
> - State 0x12 (bVar15=false): `(1 - 1) & 0xF0 = 0x00`, `0x00 + 0x19` = **`0x19`**
>
> The value `0xF9` is **mathematically impossible** from this expression for any bool input. Verified identically in both the XPP and XNET namespace copies of the function.

### Frame Type Word (Sub-Protocol Selector)

The **frame type word** in the payload selects which sub-protocol is active. Three sub-protocols exist within type 0x11:

```
Frame Type Word | Sub-Protocol                          | FSM States
----------------|---------------------------------------|------------------
0x21c0          | DHCP/IP negotiation + WPA challenge   | 0x13
0x23c0          | WPA 4-way ANonce/SNonce exchange      | 0x14 (retransmit)
0x2180          | Post-auth IP configuration delivery   | 0x15
```

---

### Console→Adapter: WPA_ASSOC_REQ (FSM States 0x11 / 0x12)

**Source function**: `XPP_build_wpa_assoc_request`  
**Transport magic**: `0x4954454e` ("NETI")

#### Packet Format — First Attempt (State 0x11)

```
Size         | Field                | Value / Source
-------------|----------------------|--------------------------------------------------------------
6  bytes     | Destination MAC      | FF:FF:FF:FF:FF:FF (broadcast)
6  bytes     | Source MAC           | field_0x1b0[+0x30..+0x35]
2  bytes     | Frame type word      | 0x6388
1  byte      | Type marker          | 0x11
1  byte      | Sub-type             | 0x09  (state 0x11 first attempt)
2  bytes     | Reserved             | 0x0000
2  bytes     | Length               | Big-endian: (SSID_len + 8) << 8
2  bytes     | Reserved             | 0x0000
```

#### Payload — First Attempt (State 0x11)

```
Offset   | Size    | Field        | Value / Source
---------|---------|--------------|--------------------------------------------------------------
+0x00    | 2 bytes | Sub-tag      | 0x0101 — SSID sub-record type
+0x02    | 2 bytes | Length       | Big-endian SSID length
+0x04    | N bytes | SSID data    | Raw bytes from AutoClass1+0xa0a (wpa_assoc_ssid, max 40B)
+0x04+N  | 2 bytes | Sub-tag      | 0x0301 — state counter sub-record type
+0x06+N  | 2 bytes | Length       | 0x0400 (length = 4)
+0x08+N  | 4 bytes | Counter      | AutoClass1+0xa78 (state_change_counter / dhcp_flags_a)
```

#### Payload — Retry (State 0x12, wpa_anonce_ptr != null)

The SSID sub-TLV is replaced by ANonce material. Destination MAC changes to unicast AP MAC.

```
Offset   | Size    | Field        | Value / Source
---------|---------|--------------|--------------------------------------------------------------
+0x00    | 2 bytes | Sub-tag      | 0x0101 — same tag, different data
+0x02    | 4 bytes | Length       | *wpa_anonce_ptr (first dword = ANonce byte count)
+0x06    | N bytes | ANonce data  | wpa_anonce_ptr[1..] (the ANonce bytes)
+0x06+N  | 2 bytes | Sub-tag      | 0x0301 — state counter (unchanged)
+0x08+N  | 2 bytes | Length       | 0x0400
+0x0A+N  | 4 bytes | Counter      | AutoClass1+0xa78
```

**Note**: `wpa_assoc_ssid` at `AutoClass1+0xa0a` is populated by `XPP_credential_block_copy` from profile offset `+0x3c`. Maximum 40 bytes, NUL-terminated.

---

### Adapter→Console: WPA Exchange Frames (FSM States 0x13–0x15)

**Inbound handler**: `XPP_wpa_inbound_frame_handler`
**Sub-TLV parser**: `XPP_wpa_subtlv_parser`

#### Acceptance Guards

The console **discards** any inbound type 0x11 frame if any of the following are true:

```
Guard | Condition                                               | Result
------|---------------------------------------------------------|--------
1     | Payload length word [EDI+4] < 4                         | Discard
2     | Byte-swapped length does not fit within declared length | Discard
3     | AutoClass1+0x8c8 (FSM state) < 0x13                     | Discard
4     | Sub-type byte is 0x05, 0x07, or 0x08                    | Fatal error — calls `XPP_fsm_fatal_error` (connection abort)
```

⚠️ Frames arriving while the console is in states 0x11 or 0x12 are silently dropped — the console is not yet ready to receive adapter frames at that point.

#### Sub-type Routing

```
Sub-type  | Requirement                                  | Console Action
----------|----------------------------------------------|--------------------------------------------------
0x09      | frame_type==0x21c0, len≥8, +0xa38==0x04      | ANonce delivery → reply via XPP_wpa_outbound_frame_builder (tag=0x0a)
0x01–0x04 | —                                            | IP/DHCP negotiation:
          |                                              |   1. Read pass: parse sub-TLVs via XPP_wpa_subtlv_parser
          |                                              |   2. If sub-type==0x01 and FSM==0x14: call XPP_fsm_wpa_state_setup(0x13)
          |                                              |   3. Set bit 0x04 in AutoClass1+0xa7a
          |                                              |   4. Write pass: generate reply sub-TLVs
          |                                              |   5. Send reply frame via XPP_wpa_outbound_frame_builder (sub-type=0x01)
          |                                              |   6. If local_10[0]==0x02→0x04: call XPP_fsm_wpa_state_setup(0x14/0x15)
0x05,0x07,0x08 | —                                       | Hard-coded **fatal error**: calls `XPP_fsm_fatal_error(this, 0xa0000000)` — aborts WPA session, NOT a silent drop. An adapter emulator must never send these sub-types.
```

**Progress counter pointer (`local_10`) — source-verified:**
Inside `XPP_wpa_inbound_frame_handler`, `local_10` points to the in-progress state byte:
- `frame_type == 0x21c0` → `local_10 = this + 0xa38` (`wpa_handshake_flags[0]`)
- all other frame types → `local_10 = this + 0xa3d` (`wpa_handshake_flags[5]`)
This byte tracks negotiation progress through values `0x01`→`0x02`→`0x03`→`0x04`. Value `0x04` means that exchange is complete and `local_10` changes stop being applied. The two separate counters allow simultaneous tracking of 0x21c0-path and 0x2180-path progress.


#### Sub-TLV Tags — frame_type 0x21c0 (IP Negotiation / WPA Challenge)

Sub-TLV format: `[tag:1 byte][len:1 byte][data:len bytes]`

```
Tag  | Len | Direction  | Field                | Console Action / Storage
-----|-----|------------|----------------------|------------------------------------------------------
0x01 | 4   | A→C        | Proposed IP address  | dir=1: confirmed IP → AutoClass1+0xa40
     |     |            |                      | dir≠1: proposed IP → +0xa3e, or error bit 0x02 @ +0xa39
0x05 | 6   | A→C        | DHCP transaction     | dir=1 + matches +0xa44: reply NOT(value) → return 2
     |     |            | nonce                | dir≠1: generate nonce via net_prng() → store to +0xa44
0x03 | ≥4  | A→C        | Challenge/response   | len=4 + value=0x23c0 → challenge match
     |     |            | token                | len=5 + value=0x23c2 + byte[4]=0x05 → response match
     |     |            |                      | match + write mode: reply [0x23c2, 0x05] → return 2
     |     |            |                      | else: set bits 0x04/0x08 into +0xa39
```

#### Sub-TLV Tags — frame_type 0x23c0 (WPA 4-Way Exchange)

Same tag dispatch as 0x21c0. Used during state 0x14 retransmit of credential buffers.

```
Tag  | Len | Field               | Console Action
-----|-----|---------------------|-----------------------------------------------
0x01 | 4   | Timing/beacon value | Byte-swapped word from [param+2]
0x05 | 6   | DHCP nonce          | Same logic as frame_type 0x21c0
0x03 | ≥4  | Challenge/response  | Same logic as frame_type 0x21c0
```

#### Sub-TLV Tags — frame_type 0x2180 (Post-Auth IP Config)

```
Tag  | Len | Field      | Console Action / Storage
-----|-----|------------|-------------------------------------------------------
0x03 | 6   | Gateway IP | Validated via net_validate_unicast_ip → AutoClass1+0x8f0
0x81 | 6   | DNS1 IP    | Validated via net_validate_unicast_ip → AutoClass1+0x8f8
0x83 | 6   | DNS2 IP    | Validated via net_validate_unicast_ip → AutoClass1+0x8fc
```

Invalid IPs set error flags rather than storing. All three tags must be valid unicast addresses.

---

### Console→Adapter: Credential Exchange Replies (FSM States 0x13 / 0x15)

**Source function**: `XPP_fsm_wpa_credential_exchange`  
**Transport magic**: `0x4b54454e` ("NETK") via `XPP_wpa_outbound_frame_builder` (`FUN_0013d64e`)  
Both states set `fsm_timer_region[0x15] |= 0x40` before sending.

> **Outbound sub-type is always `0x01`** (source-verified: `FUN_0013d64e(self, uVar3, 1, ...)` — the third argument is the sub-type byte, hardcoded to `1` in both state 0x13 and state 0x15 paths).

#### Payload Structure — State 0x13 (frame_type 0x21c0)

Tags are included conditionally based on `wpa_handshake_flags[1]`:

```
Tag  | Len | Include when              | Data Source
-----|-----|---------------------------|----------------------------------------------
0x01 | 4   | flags & 0x02 clear        | AutoClass1+0xa3e (proposed IP)
     |     |                           | + word from wpa_handshake_flags[6..7]
0x05 | 6   | flags & 0x01 clear        | AutoClass1+0xa44 (DHCP nonce)
     |     |                           | + 4 bytes from wpa_ptk_region[+0x00]
```

#### Payload Structure — State 0x15 (frame_type 0x2180)

```
Tag  | Len | Include when              | Data Source
-----|-----|---------------------------|----------------------------------------------
0x03 | 6   | flags & 0x10 clear        | AutoClass1 dhcp_wpa_state[+0x00] (gateway IP)
0x81 | 6   | flags & 0x20 clear        | AutoClass1 dhcp_wpa_state[+0x08] (DNS1 IP)
0x83 | 6   | flags & 0x40 clear        | AutoClass1 dhcp_wpa_state[+0x0c] (DNS2 IP)
```

#### State 0x14 — Retransmit (XPP_fsm_retransmit)

Retransmits the credential buffers with frame_type `0x23c0`:

```
Buffer         | AutoClass1 Offset | Size    | Content
---------------|-------------------|---------|---------------------------
wpa_cred_buf0  | +0x962            | 64 bytes| ANonce/SNonce material
wpa_cred_buf1  | +0x9a2            | 64 bytes| ANonce/SNonce material
```

`wpa_handshake_flags[2]` counter incremented on each retransmit. Guard: `flags[1] & 0x08` must be clear.

---

### Complete WPA Exchange Sequence (Emulator Reference)

The full sequence of type 0x11 frames required to drive the console from state 0x11 to connected:

```
Step | Direction       | Sub-type | frame_type | Sub-TLVs                              | Console FSM Effect
-----|-----------------|----------|------------|---------------------------------------|---------------------------------------
1    | Adapter→Console | 0x01     | 0x21c0     | tag=0x03/4/0x23c0 (challenge)         | Console replies with 0x23c2 response
     |                 |          |            | tag=0x05/6/<nonce> (DHCP cookie)      | and NOT(nonce) in reply frame
2    | Adapter→Console | 0x01     | 0x21c0     | tag=0x01/4/<IP> (proposed IP)         | FSM: 0x14 → XPP_fsm_wpa_state_setup(0x13)
     |                 |          |            | tag=0x05/6/<nonce>                    | Enters credential exchange entry
3    | Adapter→Console | 0x09     | 0x21c0     | payload[8..] = ANonce bytes           | Console sends SNonce via state 0x13
     |                 |          |            | (requires +0xa38 == 0x04)             | XPP_fsm_wpa_credential_exchange()
4    | Adapter→Console | 0x01     | 0x2180     | tag=0x03/6/<gateway IP>               | local_10[0]: 0x02→0x04
     |                 |          |            | tag=0x81/6/<DNS1 IP>                  | triggers XPP_fsm_wpa_state_setup(0x14/0x15)
     |                 |          |            | tag=0x83/6/<DNS2 IP>                  |
5    | —               | —        | —          | —                                     | FSM exits WPA sub-states → state 0x0c
     |                 |          |            |                                       | KeSetEvent(+0xaf8) — IP ready signal
```

### Related Information
- [WPA Connection State Machine](#wpa-connection-state-machine-substates-0x11-0x15)
- [Type 0x07 CONNECT_TO_SSID_REQUEST](#9-type-0x07---connect_to_ssid_request) — delivers PMK (Tag 0x10) or passphrase (Tag 0x12) before this flow begins


---

## Appendix: Xbox FSM Internals

> The following sections document the Xbox dashboard's internal state machine (`xonlinedash.xbe`). This information is useful for understanding exactly what the console expects at each step, but is **not required** to implement the adapter side. Implementors should start with the [Quick Reference — Complete WPA Exchange Sequence](#quick-reference--complete-wpa-exchange-sequence) above.

### Dashboard Connection State Machine (xonlinedash.xbe — Decompile Confirmed)

**Source**: `AutoClass1::my_fetch_wireless_adapter_data_probably` — the main polling loop

The dashboard's internal state (`AutoClass1+0x0c`) drives which packet type is expected and dispatched:

```
State | Sends Packet Type          | Awaits Response Type    | Timeout
------|----------------------------|-------------------------|--------
0x00  | (idle — no pending op)     | —                       | —
0x01  | Type 0x01 HANDSHAKE_REQ    | Type 0x02 HANDSHAKE_RESP| 2000ms, 1 retry
0x02  | Type 0x03 NETWORKS_LIST_REQ| Type 0x04 NETWORKS_RESP | 10000ms, 1 retry
0x03  | Type 0x05 ADAPTER_INFO_REQ | Type 0x06 ADAPTER_INFO  | 3000ms, 2 retries
0x04  | Type 0x07 CONNECT_TO_SSID  | Type 0x08 CONNECT_RESP  | 10000ms, varies
0x05  | Type 0x09 BEACON_REQ (1/s) | Type 0x0a BEACON_RESP   | 3000ms/20000ms
```

Timeout behaviour: if `AutoClass1+0x24` (retry count) reaches 0 with no valid response, `error_code` is set to `0x80000001` and state returns to `0x00`.

State 0x05 (keepalive) differs — beacons are sent every 1000ms and the keepalive timer (`AutoClass1+0x1c`) drives a secondary timeout independent of the retry counter.

---

### XPP_fsm_state_dispatch — Full Decompile Analysis

**Source**: `XPP_fsm_state_dispatch` @ `0x0013d97f`
**callee**: `XPP_build_and_send_dhcp_message` @ `0x0013cef8` (state 0x09 retry abort — not previously in spec).

**Switch 1 (switchD_0013d9f2) — confirmed action dispatch:**

```
 State                  | Action
------------------------|---------------
 0x00, 0x05, 0x16, 0x1b | `XPP_fsm_reset_cleanup()`
 0x02, 0x07, 0x0b       | `net_dispatch_arp()`
 0x03                   | `my_send_networks_list_request()`
 0x09                   | Retry guard: `if +0x8c9 != 0 OR ++retry_count >= 0x18` → `XPP_build_and_send_dhcp_message()`
 0x0c                   | `KeSetEvent(+0xaf8)` — IP ready signal to dashboard IP stack
 0x12                   | `XPP_build_wpa_assoc_request()`
 0x14                   | `XPP_fsm_wpa_credential_exchange()`
 0x18                   | RFC 3927 link-local: `169.254.[MAC_even_xor].[MAC_odd_xor]`
```

**XPP_build_and_send_dhcp_message (0x0013cef8) — assembly-decoded:**

Builds and transmits a DHCP packet via pool tag `NETj` (`0x6a54454e`). Called from `XPP_fsm_state_dispatch` on retry-exceeded states. Sends DHCP message type determined by current FSM state:
```
 FSM State | DHCP Type    | Option 53 | Notes
-----------|--------------|-----------|-------
 0x04      | DHCPRELEASE  | 0x08      | Includes gateway IP. OR `+0xa7a` with 0x01
 0x09      | DHCPDISCOVER | 0x01      | OR `+0xa79` with 0x10
 0x0f      | DHCPREQUEST  | 0x04      | OR `+0xa7a` with 0x04
 others    | DHCPDECLINE  | 0x03      | OR `+0xa79` with 0x40
```
Always includes:
- Option 12 (Hostname): SSID string from `AutoClass1+0x93a` (if non-empty)
- Option 61 (Client ID): hardware type 0x01 + MAC from `AutoClass1+0x1e0`
- Option 60 (Vendor Class): `"XBOX 1.0"` — Xbox identity string (states ≠ 0x0f)
- Option 0x37 (Param Request List): subnet mask + router
- Option 0x32 (Requested IP): `AutoClass1+0x8f0` gateway (states 8/9/10/15)
- Option 0x36 (Server ID): `AutoClass1+0x930` (states 10/15)
- Option 0xff (End)

Frame header words: `0x4400` / `0x4300`. Sent via `FUN_001378dd`.

**XPP_fsm_handle_response_received (0x0013de56) — state transition table:**

```
From        | To   | Trigger
------------|------|---------
0x02        | 0x00 | HANDSHAKE_RESP received
0x03        | 0x04 | NETWORKS_RESP, networks found
0x03        | 0x05 | NETWORKS_RESP, no networks
0x07        | 0x09 | CONNECT_RESP success
0x0b        | 0x0f | ADAPTER_INFO_RESP received
0x18/0x19   | 0x1a | Link-local ARP probe complete
```
Increments `state_change_counter` (`+0xa7c`) on each transition.

This is the central FSM. Every state transition passes through here. The function has **two switch blocks**:
1. **Action switch** (`switchD_0013d9f2`) — executes the work for the new state
2. **Timeout scheduler** (`switchD_0013dbbc`) — sets the deadline for the next FSM tick

#### Entry Sequence (always runs)

```c
// 1. Update state byte and increment change counter if state changed
old_state = AutoClass1+0x8c8;
AutoClass1+0x8c8 = param_1 (new state);
AutoClass1+0xa7c += (param_1 != old_state);   // replay-protection counter

// 2. Manage retry sub-counter
if (param_2 == 0) AutoClass1+0x8c9 = 0;       // reset on fresh entry
else if (AutoClass1+0x8c9 != 0xFF) ++AutoClass1+0x8c9;  // saturate at 255

// 3. ARP dispatch (runs every tick regardless of state)
net_dispatch_arp(this, 0, 0, 0);
```

#### Switch 1 — Action Dispatch (`switchD_0013d9f2`)

```
State(s)        | Action
----------------|--------------------------------------------------------------
0x00, 0x05,     | XPP_fsm_reset_cleanup() — flush ARP, snapshot saved pkt ptrs
0x16, 0x1b      |
0x02, 0x07,     | uVar11=0; dispatch ARP with iVar6=iVar10=this+0x8f0
0x0b            |
0x03            | uVar11=0; dispatch ARP with iVar6=this+0x908, iVar10=this+0x8f0
0x04,0x08,0x0a, | → (falls into abort path, see below)
0x0d,0x0e,0x0f  |
0x09            | RETRY GUARD: if 8c9≠0 OR (++8ca ≥ this+0x18) → abort_retry_exceeded
                | ELSE if bit2 of this+0x05 == 0:
                |   OR this+0xa78 with 0xc0000000; goto state 0x00 (WPA reset path)
                | ELSE: goto state 0x17 (re-send CONNECT_REQ / handshake)
0x0c            | if bit3 of this+0xa79 is CLEAR:
                |   SET bit3 of this+0x8cc (IP_ready flag)
                |   KeSetEvent(this+0xaf8, 1, 0) if pointer non-null
                | [FALLS THROUGH to reset cleanup]
0x11            | RETRY GUARD: if 8c9==0 AND (++8ca > this+0x25):
                |   XPP_fsm_fatal_error(0xc0000000); return
                | [FALLS THROUGH to state 0x12]
0x12            | XPP_build_wpa_assoc_request()
0x13, 0x15      | XPP_fsm_retransmit()
0x14            | XPP_fsm_wpa_credential_exchange()
0x18            | (see nonce generation below)
0x19            | uVar11=1; dispatch ARP with iVar6=iVar10=this+0x8f0
```

##### State 0x18 — Link-Local IP Address Generation (RFC 3927)

State 0x18 generates a 169.254.x.x link-local IP candidate address stored in `AutoClass1+0x8f0` as 4 bytes. This is used as a fallback/probe IP for DHCP-less operation.

```
RETRY GUARD: if 8c9≠0 OR (++8ca ≥ this+0x2d):
    SET bit7 of this+0xa7b; goto state 0x00   ← nonce retries exhausted

If bVar7 == 1 (FIRST attempt, 8ca just became 1):
    this+0x8f0 = 0xa9        (169)
    this+0x8f1 = 0xfe        (254)   ← 169.254.x.x = RFC 3927 link-local range
    this+0x8f2 = (MAC[4] ^ MAC[2] ^ MAC[0]) % 0xfe + 1   ← 3rd octet from MAC
    this+0x8f3 = (MAC[5] ^ MAC[3] ^ MAC[1]) % 0xfe + 1   ← 4th octet from MAC

If bVar7 > 1 (RETRY — address was rejected, try a new random one):
    this+0x8f0 = 0xa9, this+0x8f1 = 0xfe   ← prefix always 169.254
    this+0x8f2 = net_prng(this) % 0xfe + 1  ← random 3rd octet (1-254)
    this+0x8f3 = net_prng(this) % 0xfe + 1  ← random 4th octet (1-254)

Both attempts: net_dispatch_arp(this, 0, this+0x8f0, 1) — sends ARP probe for 169.254.x.x
```

**MAC addresses used** (`AutoClass1+0x1e0` = adapter_mac[6]):
- MAC[0]=`+0x1e0`, MAC[1]=`+0x1e1`, MAC[2]=`+0x1e2`, MAC[3]=`+0x1e3`, MAC[4]=`+0x1e4`, MAC[5]=`+0x1e5`

#### Switch 2 — Timeout Scheduler (`switchD_0013dbbc`)

All timeouts are relative to `AutoClass1+0x1d8` (current tick counter) and set a deadline in `AutoClass1+0xa68` via `FUN_001337c5` (`XPP_fsm_set_timer`). The floor guard prevents scheduling in the past: `if (deadline < current) deadline = current`.

Timer units: the tick rate appears to be 200ms (5 ticks/second). Timeout values stored in bytes are multiplied by 5 before adding to the current tick.

```
State(s)                  | Timeout computation
--------------------------|-------------------------------------------------------------
0x01, 0x06, 0x10, 0x17    | deadline = this+0x1d8 (fire immediately / use stored absolute)
0x02, 0x03, 0x07, 0x0b,   | deadline = (this+0x12 * 5) + this+0x1d8
0x19                      |
0x04, 0x08, 0x09, 0x0a    | deadline = (this+0x1d * 5) + this+0x1d8
0x0c                      | deadline = (this+0x924 * 5) + this+0x920  ← AP-count weighted
0x0d                      | Binary-approach to this+0x928 slot (see below)
0x0e                      | Binary-approach to this+0x92c slot (see below)
0x0f                      | deadline = (this+0x24 * 5) + this+0x1d8
0x11–0x15                 | deadline = (this+0x2a * 5) + this+0x1d8
0x18                      | deadline = this+0x2f + this+0x1d8  (÷5 is compiler artifact)
0x1a                      | deadline = this+0x30 + this+0x1d8
default (all others)      | deadline unchanged (uVar5=0xffffffff, floor guard fires)
```

##### States 0x0d / 0x0e — Binary-Approach Adaptive Scheduler

States 0x0d and 0x0e use a **binary-approach** algorithm to converge on an AP beacon slot boundary without overshooting:

```c
slot_target = slot_ticks * 5 + this+0x920;   // slot_ticks = this+0x928 (0x0d) or this+0x92c (0x0e)
current = this+0x1d8;
if (current < slot_target) {
    step = (slot_target - current) >> 1;          // halve remaining distance
    min_step = this+0x1f * 5;
    step = max(step, min_step);                   // enforce minimum advance
    deadline = min(current + step, slot_target);  // never overshoot
} else {
    deadline = current;   // already past slot — fire immediately
}
```

This is a standard convergence algorithm: each invocation advances halfway to the target, floored by a minimum step (`AutoClass1+0x1f`). Used for AP beacon slot synchronisation during scan states 0x0d/0x0e.

#### State Transition Handler (XPP_fsm_handle_response_received — Response Received)

Called on receipt of a valid XPP response. Advances the FSM to the next state:

```
Received in State | Action                                       | Next State
------------------|----------------------------------------------|------------
0x02              | OR this+0xa78 with 0x80000800; clear state   | → 0x00
0x03              | derive state from 8cc>>6 bit OR 4            | → 0x04 or 0x05
0x07              | clear bit4 of 8cc; zero 8f0 and 930          | → 0x09
0x0b              | decrement a7c; OR a7b with 0x20              | → 0x0f
0x18–0x19         | zero 8f0                                     | → 0x1a
other (<0x18)     | return (no transition)                       | —
```

#### XPP_fsm_fatal_error — Assembly-Verified Full Logic

> **Assembly-verified** (`XPP_fsm_fatal_error` @ `0x0013e542`):

```
0013e545: MOV DL, [ESI+0x8c8]        ; current FSM state
0013e54b: CMP DL, 0x5  → JZ  timer_tick_reset
0013e550: CMP DL, 0xc  → JZ  timer_tick_reset
0013e555: CMP DL, 0xe  → JZ  timer_tick_reset
0013e55a: CMP DL, 0x16 → JZ  timer_tick_reset
         ; all other states fall through:
0013e563: OR [ESI+0xa78], param_2    ; OR error code into flags
0013e56b: CMP DL, 0x14              ; WPA handshake state?
0013e572:   → OR [ESI+0xa78], 0x80010000  ; (state 0x14 only) add WPA abort marker
0013e583: PUSH 0 / PUSH 0
0013e589: CALL XPP_fsm_state_dispatch  ; force re-dispatch → cleanup

timer_tick_reset:
0013e57e: CALL XPP_fsm_timer_tick    ; full state machine reset (zeroes all FSM state)
         ; then returns (no state_dispatch)
```

**Behaviour by caller state:**

```
Caller FSM state | XPP_fsm_fatal_error behaviour
-----------------|-----------------------------------------------------------------
0x05, 0x0c,      | Calls XPP_fsm_timer_tick (FULL RESET — zeroes entire FSM block,
0x0e, 0x16       |   wpa_anonce_ptr freed, all fields zeroed). No state_dispatch.
                 |   These are "safe abort" states — clean reset is appropriate.
0x14 (WPA HS)    | OR a78 with (param_2 | 0x80010000). Calls XPP_fsm_state_dispatch.
                 |   The extra 0x80010000 signals WPA handshake failure specifically.
All other states | OR a78 with param_2. Calls XPP_fsm_state_dispatch(0, 0).
                 |   State dispatch handles cleanup based on updated error flags.
```

**For the WPA emulator**: The console never sends sub-types `0x05`/`0x07`/`0x08`. If the adapter emulator sends any of these, the console calls `XPP_fsm_fatal_error(this, 0xa0000000)` from the Type 0x11 inbound handler — which is NOT a bypass state, so it takes the `OR + state_dispatch` path, tearing down the WPA session.

#### New AutoClass1 Fields Confirmed from FSM Decompile

```
Offset  | Type   | Name                    | Description
--------|--------|-------------------------|----------------------------------------------------------
+0x0005 | byte   | connection_mode_flags   | bit2: 0=WPA path, 1=CONNECT_REQ/state-0x17 path
                                           | Set from network profile before FSM start.
                                           | Other bits used elsewhere (bit3 seen at +0x48103)
+0x0012 | byte   | timeout_ticks_short     | Timeout for states 2,3,7,0xb,0x19 (×5 ticks)
+0x001d | byte   | timeout_ticks_connect   | Timeout for states 4,8,9,0xa (×5 ticks)
+0x001f | byte   | scan_min_step_ticks     | Minimum advance step for 0x0d/0x0e adaptive scheduler
+0x0023 | byte   | scan_interval_multi     | Used in scan time estimate: val × 0x15180 ticks
+0x0024 | byte   | timeout_ticks_0f        | Timeout for state 0x0f (×5 ticks)
+0x0025 | byte   | wpa_retry_limit         | Max retries before fatal error in state 0x11
+0x002a | byte   | timeout_ticks_wpa       | Timeout for WPA states 0x11–0x15 (×5 ticks)
+0x002d | byte   | nonce_retry_limit       | Max link-local IP probes before state 0x18 aborts
+0x002f | byte   | timeout_ticks_0x18      | Timeout per probe in state 0x18 (direct ticks, not ×5)
+0x0030 | byte   | timeout_ticks_0x1a      | Timeout in state 0x1a (direct ticks, not ×5)
+0x01d8 | uint32 | current_tick            | Current FSM tick counter (absolute timer baseline)
+0x0268 | uint32 | saved_nonce_subnet      | Copy of 8f0 saved on reset (subnet for ARP removal)
+0x026c | uint32 | saved_nonce_mask        | Copy of 8f4 saved on reset (mask for ARP removal)
+0x0920 | uint32 | scan_base_ticks         | Tick baseline for scan slot calculations. Written as this+0x1d8 at scan start.
+0x0924 | uint32 | scan_ap_weight          | 50% of scan interval (uVar4 >> 1). State 0x0c timeout = (val × 5) + scan_base.
+0x0928 | uint32 | scan_slot_0d_ticks      | 87.5% of scan interval (uVar4 * 7 >> 3). Target for state 0x0d binary-approach.
+0x092c | uint32 | scan_slot_0e_ticks      | 100% of scan interval (uVar4). Target for state 0x0e binary-approach.
+0x0930 | uint32 | scan_reset_flag         | Cleared when entering state 0x07 (on response)
+0x0a68 | uint32 | fsm_timer_target        | Output: next scheduled tick deadline (set by timer fn)
+0x0a60 | uint32 | connection_start_tick   | Tick timestamp written when WPA credentials loaded (this+0x1d8 snapshot).
+0x0a4c | uint32 | wpa_ap_ip[4]            | AP IP address from profile (param_2+0x194).
+0x0a50 | uint16 | wpa_ap_port             | AP port from profile (param_2+0x198).
+0x0af8 | uint32 | ip_ready_event_ptr      | KeSetEvent target — signalled when IP_ready (0x0c)
+0x0918 | uint32 | scan_profile_ip[4]      | IP candidate from scan profile (iVar5+0x18c).
+0x091c | uint16 | scan_profile_port       | Port from scan profile (iVar5+0x190).
+0x091e | uint16 | scan_profile_port_swap  | Byte-swapped port (iVar5+0x192 big-endian swap).
+0x0962 | byte[64]| wpa_cred_buf0          | WPA credential buffer 0 (from profile+0x84, 64 bytes).
+0x09a2 | byte[64]| wpa_cred_buf1          | WPA credential buffer 1 (from profile+0xc4, 64 bytes).
+0x09e2 | byte[40]| wpa_cred_buf2          | WPA credential buffer 2 (from profile+0x104, 40 bytes).
+0x093a | byte[40]| ssid_scan_buf          | SSID scan buffer (from profile+0x5c, 40 bytes; non-infra path).
```

---

### XPP_fsm_start_connection — Profile Loader

**Source**: `XPP_fsm_start_connection` (`xonlinedash_xbe.c` @ `0x0013dfa0`)

This function is called to **initiate a connection** from a saved network profile. It transfers all connection parameters from the profile struct (`param_2`) into `AutoClass1` fields, then calls `XPP_fsm_state_dispatch` to start the FSM.

#### param_3 Initialization Bitmask

```
param_3 bit0 (0x1): → SET AutoClass1+0x8cc bit0 (WEP key present flag)
param_3 bit1 (0x2): → SET AutoClass1+0x8cc bit1 (hex-encoded WEP key flag)
param_3 bit2 (0x4): → allocate WPA scan-result ANonce buffer at AutoClass1+0xa34:
                       size = (AutoClass1+0x26 * 0x18c) + 4 bytes
                       pool tag 'NETJ' (0x4a54454e) via net_alloc_zeroed
                       +0x26 = AP slot count byte (number of scan result slots)
                       0x18c = 396 bytes per AP slot
                       +4 = 4-byte header (stores total slot count)
                       SET AutoClass1+0x8cc bit2 if allocation succeeded (WPA mode active)
                       If allocation FAILS: ESI = 0x2747, calls XPP_fsm_state_dispatch(0,0) — abort
```

> **Assembly-verified** (`XPP_fsm_start_connection` @ `0x0013dfa0`):
> ```
> 0013dffc: TEST [EBP+_tmp_p1_], 0x4      ; bit2 = WPA?
> 0013e002: MOVZX EAX, [EBX+0x26]          ; slot count
> 0013e006: IMUL EAX, EAX, 0x18c           ; * 396 bytes/slot
> 0013e00c: PUSH 0x4a54454e                 ; pool tag 'NETJ'
> 0013e011: ADD EAX, 4                      ; + 4-byte header
> 0013e014: PUSH EAX                        ; size arg
> 0013e017: CALL net_alloc_zeroed               ; allocate
> 0013e01e: MOV [EBX+0xa34], EAX            ; store → wpa_anonce_ptr
> 0013e02d: OR [EBX+0x8cc], 0x4             ; set WPA mode flag
> ```

#### Profile Struct (param_2) Field Map

The profile struct passed as `param_2` has the following confirmed offsets:

```
param_2 offset | AutoClass1 dest | Content
---------------|-----------------|----------------------------------------------
+0x040 (bits)  | (dispatch)      | Capability/path selector bitmask
                                 | bit0: DHCP/IP config present
                                 | bit1: WPA credentials present → copy to +0x962/+0x9a2/+0x9e2/+0xa0a
                                 | bit2: Infrastructure mode (go to state 0x17 path → bit2 of AutoClass1+0x05)
                                 | bit3: IP addresses present (2 entries at +0x54)
+0x048         | +0x8f0          | IP address candidate (when bit2&bit3 set)
+0x04c         | +0x8f4          | Subnet mask / netmask
+0x050         | +0x908          | Gateway / router IP
+0x054[0..1]   | +0x8f8/+0x8fc   | Additional IP candidates (when bit3 set)
+0x05c[40B]    | +0x93a          | SSID scan buf (non-infrastructure path)
+0x084[64B]    | +0x962          | WPA credential buf 0 (when bit1 set)
+0x0c4[64B]    | +0x9a2          | WPA credential buf 1
+0x104[40B]    | +0x9e2          | WPA credential buf 2
+0x12c[40B]    | +0xa0a          | WPA passphrase / SSID for WPA_ASSOC_REQ
+0x154/158     | (time check)    | 64-bit timestamp (FILETIME) for lease expiry
+0x15c         | +0x924,928,92c  | Scan interval ticks uVar4:
                                 |  +0x924 = uVar4 >> 1 (50%)
                                 |  +0x928 = uVar4 * 7 >> 3 (87.5%)
                                 |  +0x92c = uVar4 (100%)
+0x160         | +0x8f0/+0x930   | IP (validated by FUN_0013410f)
+0x164         | +0x8f4          | Netmask (validated — must be contiguous ones)
+0x168         | +0x930          | Scan profile copy target
+0x16c[4]      | +0x908..+0x914  | IP list (4 entries)
+0x17c[4]      | +0x8f8..+0x904  | Additional IP list (4 entries, when 8cc&0x40 clear)
+0x18c[4]      | +0x918          | Scan result IPs
+0x192         | +0x91e          | Byte-swapped port
+0x194[6B]     | +0xa4c/+0xa50   | AP MAC address
+0x198         | +0xa50          | AP port
+0x19a         | +0xa52          | AP port (alternate)
```

#### AutoClass1+0x05 connection_mode_flags — Assembly-Verified

> **Assembly-verified** (`XPP_fsm_start_connection` @ `0x0013e2d6`):
> ```
> 0013e2d6: TEST [EBX+0x5], 0x2    ; read AutoClass1+0x05 bit1
> 0013e2dc: JZ   LAB_0013e2e4      ; if bit1 clear → WPA SSID copy path
> 0013e2de: PUSH 0x0
> 0013e2e0: PUSH 0x17              ; else → dispatch to state 0x17 (re-send CONNECT_REQ)
> ```

The FSM reads `AutoClass1+0x05` but only **bit1 (0x02)** is checked here — not bit2. The field semantics:
- **bit1 (0x02)**: if SET → skip WPA SSID copy, go directly to state 0x17 (re-use existing CONNECT_REQ). If CLEAR → copy SSID from profile into `+0x93a` via `FUN_0013c9db` (40 bytes), then dispatch to state 0x06.
- **bit2 (0x04)**: read at state 0x09 branch — if SET → state 0x17 path; if CLEAR → WPA abort path (OR `+0xa78` with `0xc0000000`, goto state 0x00). **Write site not in this function.**

The **WPA mode flag** written by this function is `AutoClass1+0x8cc bit2` (set at `0x0013e02d` when ANonce buffer allocation succeeds) — this is distinct from `AutoClass1+0x05 bit2`.

**Note**: The write site for `AutoClass1+0x05` bits remains unidentified within the analysed functions. It is set by the caller before `XPP_fsm_start_connection` is invoked. Callers: `XPP_start_connection_checked:0x00130a1c` and `XnInit:0x00130db0`.

### Related Information
- [Type 0x01 Request](#3-type-0x01---handshake_request)
- [Signal Strength Conversion](#signal-strength-conversion)
- [Firmware Function Map](#firmware-function-map)

---

### FUN_0013ee56 — XPP_wpa_anonce_handler (Assembly-Verified)

> **Assembly-verified** (`FUN_0013ee56` @ `0x0013ee56`). Only caller: `FUN_0013f3a1:0x0013fa8e`.

This function handles inbound **0x23c2 challenge/response** frames from the adapter during WPA credential exchange. It validates the frame, assembles the response using `wpa_cred_buf0` and `wpa_cred_buf1`, and sends via `XPP_wpa_outbound_frame_builder`.

#### Entry Guards
```
1. Outer length (param_1[4]) < 4                → OR +0xa7a with 0x2; return
2. Inner length word (EBX[2] byte-swapped) < 4  → same
3. Inner length > outer length                  → same
4. FSM state < 0x14                             → OR +0xa7a with 0x2; return (too early)
5. FSM state == 0x14: check +0xa39 bit3 == 0    → else return (already processed)
6. Param_2 (frame_type) == 0x23c0: SETZ AL      →
      compare +0xa39 bit2 == AL                  → mismatch → return
```

#### Routing by inbound sub-type byte (EBX[0])
```
Sub-type | Condition       | Action
---------|-----------------|----------------------------------------------------------
0x01     | param_1 >= 5,   | Decrypt/hash: FUN_001433b7 (init), FUN_001433f5 (update)
         | param_1 >= 5+   |   with wpa_cred_buf0 (+0x962) and optionally wpa_cred_buf1
         | EBX[4] len      |   and EBX[5..] challenge data. Then calls
         |                 |   XPP_wpa_outbound_frame_builder(frame_type=0x23c2, sub-type=0x2,
         |                 |   inner_len=strlen(+0x962), payload=+0x962[...], ...)
0x02     | FSM == 0x14     | → XPP_fsm_wpa_state_setup(0x15)  (advance to IP exchange)
0x03     | FSM == 0x14     | → XPP_fsm_wpa_state_setup(0x15)  (same)
0x03     | —               | → XPP_fsm_fatal_error(0x80010000)
0x04     | —               | → XPP_fsm_fatal_error(0x80010000)
other    |                 | → return (no action)
```

#### Credential Buffer Usage
```
AutoClass1+0x962 (wpa_cred_buf0, 64B): Fed to MD5_Update as first input block
AutoClass1+0x9a2 (wpa_cred_buf1, 64B): Fed to MD5_Update as second input block (if non-empty)
EBX[5..]                              : Challenge data from inbound 0x23c2 frame, also fed to MD5_Update
MD5_Init    = FUN_001433b7            : Initialises 92-byte MD5 context (see below)
MD5_Update  = FUN_001433f5            : Appends data to MD5 context
MD5_Final   = FUN_00143523            : Produces 16-byte digest
```

#### MD5 Context Layout (assembly-verified, `FUN_001433b7`)

```
Offset | Size | Content
-------|------|-----------------------------------------------------
+0x00  | 4B   | Type tag: 0x2035444d (ASCII 'MD5 ', little-endian)
+0x04  | 64B  | Message block buffer (16 × DWORD, zeroed on init)
+0x44  | 4B   | State word A = 0x67452301  (RFC 1321 initial value)
+0x48  | 4B   | State word B = 0xefcdab89
+0x4c  | 4B   | State word C = 0x98badcfe
+0x50  | 4B   | State word D = 0x10325476
+0x54  | 4B   | Bit count low  (zeroed on init)
+0x58  | 4B   | Bit count high (zeroed on init)
Total context size: 0x5c = 92 bytes
```

> **Algorithm confirmed: standard MD5 (RFC 1321).** All four initialisation constants match exactly. The `XPP_wpa_anonce_handler` computes `MD5(wpa_cred_buf0 ‖ wpa_cred_buf1 ‖ challenge_data)` and sends the 16-byte digest as the `0x23c2` challenge response payload.

### Signing vs Verification
**Xbox → Adapter (Type 0x01 — CHALLENGE):**
- Sends 16-byte random nonce only. No secret. No HMAC.

**Adapter → Xbox (Type 0x02 — SIGNED RESPONSE):**
- Adapter proves authenticity by computing HMAC-SHA1 over the nonce.
- Dashboard verifies the digest — only a genuine MN-740 with the correct
  ROM key and salt can produce the right answer.

**Adapter firmware: No HMAC verification code exists**
- Evidence: Zero `memcmp()` calls in entire firmware
- The adapter only validates RFC 1071 header checksum on received packets
- It does not need to verify anything — it only needs to sign

### Authentication Flow
```
Xbox Dashboard                         MN-740 Adapter
      |                                      |
      |--- Type 0x01: [16-byte nonce] ------>|
      |                                      | HMAC-SHA1(
      |                                      |   key   = g_XPP_HMAC_Key (16 bytes),
      |                                      |   input = nonce(16)
      |                                      |         + g_ROUTER_MAC_ADDRESS(6)
      |                                      |         + g_XPP_HMAC_MASTER_KEY(117)
      |                                      | ) = 20-byte digest
      |<-- Type 0x02: [20-byte digest + payload] ----|
      |                                      |
      | XPP_calculate_handshake_hmac():       |
      |   SAME key = g_XPP_HMAC_Key          |
      |   SAME input layout:                 |
      |     nonce(16) from AutoClass1+0x2c   |
      |     + Ethernet src_mac(6)            |
      |     + g_XPP_HMAC_MASTER_KEY(117)     |
      |   Compare ALL 20 bytes of digest.    |
      | Only genuine MN-740 firmware         |
      | (with correct ROM key+string)        |
      | can produce a matching digest.       |
```

### Dashboard Digest Verification (Xbox-side — xonlinedash.xbe)
**Source**: `XPP_calculate_handshake_hmac` — fully decompiled from `xonlinedash_xbe.c`

Both sides use **identical algorithm, key, and input layout**:

```c
// Key: identical 16-byte constant hardcoded in the XBE binary
key[16] = { 0xcb, 0x27, 0x5f, 0xf2, 0x38, 0xab, 0x61, 0xdc,
             0x87, 0x99, 0xfa, 0x01, 0xad, 0x17, 0x74, 0x5e };

// Input: 139 bytes total
input[0..15]   = nonce (from AutoClass1+0x2c, received in Type 0x01)
input[16..21]  = adapter_source_mac (from Ethernet frame src_mac field)
input[22..138] = g_XPP_HMAC_MASTER_KEY (117-byte ROM string)

// Compute and compare full 20-byte digest
XcHMAC(key, 16, input, 139, 0, 0, digest_out);
compare digest_out[0..19] == Type_0x02_payload[0..19]
```

The `adapter_source_mac` used by the dashboard (Ethernet `src_mac`) matches `g_ROUTER_MAC_ADDRESS` used by the adapter — both refer to the adapter's own MAC address. The binding to a specific adapter is inherent in the MAC being part of the HMAC input.

✅ **Confirmed and closed**: No dynamic key derivation. The v17 speculation about `console_ip + adapter_mac` key construction and 16-byte truncation was incorrect and is fully retracted.

### Security Implications
**Actual Security Relies On:**
1. HMAC-SHA1 challenge-response — proves adapter has genuine ROM key and ROM string
2. `g_ROUTER_MAC_ADDRESS` / Ethernet `src_mac` binds the HMAC to a specific adapter MAC
3. Nonce randomness — each session uses a fresh 16-byte random nonce (via `XNetRandom`)
4. Physical LAN isolation (no WAN routing)

**Note**: MAC address pairing (`mac.dat`) and the 30-second watchdog are
secondary mechanisms — the primary authentication is the HMAC challenge-response.

----
### Supporting Information

---

## Connection Workflows

### Infrastructure Mode Connection

1. Xbox → Adapter:  HANDSHAKE_REQUEST (Type 0x01)
   - 16-byte random challenge

2. Adapter → Xbox:  HANDSHAKE_RESPONSE (Type 0x02)
   - 256 bytes with HMAC signature
   - Current SSID, BSSID, signal, channel, IP
   ✅ Authentication complete
   ✅ Xbox dashboard shows adapter info

3. Xbox → Adapter:  BEACON_REQUEST (Type 0x09)
4. Adapter → Xbox:  BEACON_RESPONSE (Type 0x0a)
   - Security status (02 80 03 00 = WPA2)
   [Repeat 3-4 at least 3 times]
   ✅ Link established

   **Note on beacon value**: `02 80 XX 00` = auth=0x02 (open/idle or open-connected), rssi=0x80 (pre-seed RSSI, wire default before association), rate=TX rate code. Value `0x03` in byte 0 indicates WEP association in progress. See Type 0x0A payload structure for full decode.

   [ONLY if user opens network list in dashboard]
5. Xbox → Adapter:  NETWORKS_LIST_REQUEST (Type 0x03)
6. Adapter → Xbox:  NETWORKS_LIST_RESPONSE (Type 0x04)
   - Array of 61-byte network slots
   ✅ User sees available networks

   [If user selects a network and enters password]
7. Xbox → Adapter:  CONNECT_TO_SSID_REQUEST (Type 0x07)
   - TLV: SSID + password + security type
8. Adapter → Xbox:  CONNECT_TO_SSID_RESPONSE (Type 0x08)
   - Result code (0x00 = success)
   ✅ Connection initiated

   [CONTINUOUS - Every 1 second while connected]
9. Xbox → Adapter:  BEACON_REQUEST (Type 0x09)
10. Adapter → Xbox: BEACON_RESPONSE (Type 0x0a)
    ✅ Keepalive maintained

   [PERIODIC - Every 5-10 seconds for status updates]
11. Xbox → Adapter:  ADAPTER_INFO_REQUEST (Type 0x05)
12. Adapter → Xbox: ADAPTER_INFO_RESPONSE (Type 0x06)
    - 4-byte status update
    ✅ Dashboard refreshes signal bars

----

### Ad-hoc Mode Connection

1-4. [Same handshake and beacon sequence as infrastructure]

5. Xbox → Adapter:  CONNECT_TO_SSID_REQUEST (Type 0x07)
   - Tag 0x07: SSID
   - Tag 0x0e: Radio Channel (MANDATORY for ad-hoc - e.g., 0x06 for channel 6)
   - Tag 0x09: 0x01 (Enable radio)
   - Tag 0x0A-0x0E: WEP keys and index (if encrypted)

6. Adapter → Xbox:  CONNECT_TO_SSID_RESPONSE (Type 0x08)
   - Result code 0x00
   ✅ Ad-hoc network created

7. [Adapter begins beaconing on specified channel]
8. [Other Xbox consoles can discover and join]
9. [Continue beacon keepalive as in infrastructure mode]

**Key Difference**: Ad-hoc **requires** Tag 0x02 (channel), infrastructure auto-selects.

---

### Wire-Verified: Open Network with WAN Connection (Channel 3)
**Source**: `lysten_open_connect_with_wan_ch_3_new.log` and `lysten_open_connect_with_wan_ch_3_new2.log`

This log captures the adapter connecting to an open (unencrypted) 802.11g network on channel 3
(SSID "open", BSSID c4:4b:d1:00:47:4e, DrayTek Vigor 2762 router) with a real WAN internet connection active.

**Key observations from the log:**

1. BEACON_RESP (Type 0x0a) payload consistently: `02 80 6c 00`
   - auth=0x02 (idle), rssi=0x80 (pre-seed), rate=0x6c (54 Mbps infrastructure) ✅

2. ADAPTER_INFO_RESP (Type 0x06) shows:
   - Tag 0x01 (IP): 192.168.1.150 — real DHCP address from router
   - Tag 0x05 (channel): 0x03 — wire-confirms channel 3 reported correctly ✅
   - Tag 0x06 (BSSID): c4:4b:d1:00:47:4e — DrayTek Vigor 2762 router MAC
   - Tag 0x07 (SSID): "open" (4 bytes)
   - Tag 0x08: 0x02 (WEP inactive — correct for open network)
   - Tag 0x09: 0x01 (no link — DHCP state machine not at 0x52 yet)
   - Tag 0x02: 0x00 (same reason as Tag 0x09)

3. The Xbox queries Type 0x05 / 0x06 every ~3-5 beacons while connected.

4. Transient beacon anomalies during re-association (packets like `d5 82 00 d7` and `08 e8 00 d7`)
   appear briefly — Byte 3 (reserved) is **not** always 0x00 during these transitional states.
   These are short-lived and the adapter returns to stable `02 80 6c 00` quickly.

5. The Xbox sends ADAPTER_INFO_REQ without first sending a NETWORKS_LIST_REQ or CONNECT_REQ
   in this capture — the adapter was already configured from a previous session stored in NVRAM.

**Confirmed working configuration (for emulator implementors)**:
- Type 0x0a rate=`0x6c` (54 Mbps) is correct for infrastructure when radio associates
- Type 0x06 Tag 0x05 returns the raw channel number (e.g. Channel 3 = `0x03`) ✅
- Tag 0x09 = `0x01` (no link) is the normal state during ADAPTER_INFO query, before CONNECT_REQ is issued. It can coexist with a saved IP in Tag 0x01 since Tag 0x01 returns the stored static/last-used IP regardless of current link state.

---

### Tag 0x11 - CFG_Set_XPP_Auth_Mode
**Firmware Function**: `CFG_Set_XPP_Auth_Mode()`  
**Purpose**: Sets `g_XPP_Auth_Mode_Enabled` (NVRAM, persists across power cycles) so the adapter can
report the correct encryption state in ADAPTER_INFO_RESP Tag 0x11 before a live radio association exists.

**Accepted values** (only `0x00` and `0x02` are processed — all others silently ignored):
- `0x00` — sets `g_XPP_Auth_Mode_Enabled = 0` → ADAPTER_INFO_RESP Tag 0x11 reports `0x00` (no encryption)
- `0x02` — sets `g_XPP_Auth_Mode_Enabled = 1` → ADAPTER_INFO_RESP Tag 0x11 reports `0x02` (encryption active)

**Wire-verified**: `0x02` is sent in CONNECT_REQ for all WEP connections. `0x00` is sent for open networks.
`0x01` in CONNECT_REQ Tag 0x11 would be silently ignored (not in accepted values whitelist).

**Dashboard 802.11 auth mode field** (`AutoClass1+0xf5f`): This is a **separate** field from the Tag 0x11 firmware value. The dash field controls the 802.11 authentication algorithm used for association:
```
field_0xf5f value | Set by function   | 802.11 auth algorithm
------------------|-------------------|----------------------------
0x00              | FUN_000a2ea3()    | Open System authentication
0x01              | FUN_000a2e8a()    | Shared Key authentication (WEP-only)
0x02              | FUN_000a2ebc()    | WPA/WPA2 authentication
```
This dash-side value is stored and used by the sub-state machine but does NOT map directly to the Tag 0x11 wire value (which uses only 0x00 / 0x02 as described above).

---

## Signal strength / link quality scaling
### Firmware-verified facts

**BEACON_RESP (Type 0x0a) smoothed_rssi (Byte 1)**
- Source: `drvr_get_smoothed_rssi()` — firmware-confirmed
- Formula: `raw = driver_ctx[0x273] − 0x5f` (signed byte)
- Averaging: 10-sample rolling average stored in `g_RSSI_Smoothed_Output`
- Seed value `0xba` (-70) — written when `XPP_Check_Auth_Status() != 0` (not authenticated)
- Value `0x80` (-128) — wire-observed pre-association default; `g_RSSI_Smoothed_Output` is an uninitialised global (BSS), wire captures consistently show `0x80` before association

**Type 0x04 NETWORKS_LIST_RESPONSE (Byte 44 per slot)**
- Source: `wlan_map_rssi_to_quality()` via lookup table — firmware-confirmed
- Scale: 0–255 linear (confirmed from function structure)
- The Xbox Dashboard displays signal bar labels from this value — exact dBm breakpoints confirmed from `XPP_rssi_to_signal_bars` decompile. See Signal Bar Conversion Table below.

**Type 0x02 HANDSHAKE_RESPONSE capability fields (Bytes 174–175)**
- Both are HARDCODED STUBS from the adapter firmware
- The dashboard decodes them as WPA cipher suite capability bitmasks
- Byte 174 (0x06): bits &2 and &4 set = WPA-TKIP and WPA-CCMP supported
- Byte 175 (0x07): bits &1, &2, &4 set = open/WEP/TKIP cipher modes available
- See the WPA Capability Byte Decoding table under Type 0x02 for full bit definitions

### Dashboard Signal Bar Thresholds — Source Verified
**Source**: `XPP_rssi_to_signal_bars` (`FUN_000a2fea`, `xonlinedash_xbe.c` @ `0x000a2fea`)

Function reads `AutoClass1+0x48` (smoothed RSSI signed byte from BEACON_RESP).
Guards before thresholds: `AutoClass1+0x0d == 0x01` AND `AutoClass1+0x40 != 0x80000001` AND `rssi > -0x5b`.
If any guard fails: returns 0 bars.

```c
// Decompiled logic (signed byte cVar1 = AutoClass1+0x48):
if (cVar1 <= -0x5b) return 0;   // no signal / disconnected
if (cVar1 <= -0x52) return 1;
if (cVar1 <= -0x48) return 2;
if (cVar1 <= -0x44) return 3;
if (cVar1 <= -0x3a) return 4;
return 5;                        // (-0x3a < rssi)
```

### Signal Bar Conversion Table

| Bars | RSSI threshold     | approx dBm | visual          |
|------|--------------------|------------|-----------------|
| 0    | rssi ≤ -0x5b (-91) | ≤ -91 dBm  | ░░░░░ no signal |
| 1    | rssi ≤ -0x52 (-82) | ≤ -82 dBm  | █░░░░           |
| 2    | rssi ≤ -0x48 (-72) | ≤ -72 dBm  | ██░░░           |
| 3    | rssi ≤ -0x44 (-68) | ≤ -68 dBm  | ███░░           |
| 4    | rssi ≤ -0x3a (-58) | ≤ -58 dBm  | ████░           |
| 5    | rssi  > -0x3a (-58)| > -58 dBm  | █████ excellent |

**Note**: dBm values are approximate. The smoothed_rssi byte is already offset by the firmware
formula `raw = driver_ctx[0x273] − 0x5f`, so these threshold bytes map directly to the
smoothed_rssi value in BEACON_RESP byte 1

---

## Error code flags

Two distinct error code systems exist: **XPP wire result bytes** (in packet payloads) and **Dashboard internal status codes** (in `AutoClass1.error_code`).

### XPP Wire Result Bytes (payload byte at offset 0x00 in Type 0x06 and 0x08 responses)

**Source**: `my_handle_adapter_info_response` and `my_handle_connect_to_ssid_response` decompiled from `xonlinedash_xbe.c`

```
Wire Byte | Meaning                     | Dashboard sets error_code to
----------|-----------------------------|------------------------------
0x00      | Success — TLV data follows  | 0x00000000 (cleared)
0x01      | Error / rejected            | 0x80000003 (hard error)
0x02      | Retry requested             | 0x80000002 (retry), retries after ~8 seconds
0x03      | Error / rejected            | 0x80000003 (hard error)
0x04      | Error (connect only)        | 0x80000003 (hard error, Type 0x08 only)
```

### Dashboard Internal Status Codes (AutoClass1.error_code field, 4 bytes)

**Source**: assignments across all response handler functions in `xonlinedash_xbe.c`

```
Code        | Meaning
------------|-----------------------------------------------------------------------
0x00000000  | Idle / cleared — no pending operation
0x0000FFFF  | Pending / in-progress — request has been sent, awaiting response
0x80000001  | Timeout — retry counter exhausted, no valid response received
0x80000002  | Retry — adapter requested retry (wire code 0x02); dashboard re-sends
0x80000003  | Hard error — adapter rejected request (wire code 0x01/0x03/0x04)
0x80000004  | Handshake validated — Type 0x02 HMAC and payload checks all passed
```

These status codes are written into `AutoClass1+0x40` (`error_code` field) by the response handlers and polled by the dashboard UI state machine. Code `0x80000001` is the most-checked in the codebase — dashboard screens test for it to detect adapter loss.

**Firmware-side error constants** (adapter `NML_bin.h`, negative values, never sent on wire):
`XPP_ERR_FATAL_ABORT (0xFFFFFFFE)`, `XPP_ERR_REMOTE_REJECT (0xFFFFFFFD)`,
`XPP_ERR_FILE_IO (0xFFFFFFFC)`, `XPP_ERR_MALLOC_FAIL (0xFFFFFFEB)`.

### 6.2 MAC.DAT Pairing File Format

**Firmware-verified** (`NML_bin.h`, `NML_bin.c`):

```c
struct XPP_VirtualFileDescriptor {
    char filename[8];      // e.g. "mac.dat"
    char magic_header[8];  // "AMACAEPM"
    byte metadata[16];     // Pairing/flags data — internal layout below
};
```

`MAC_DAT_DESCRIPTOR_BLOCK` is a real global (confirmed at `NML_bin.c` line 43).
The `metadata[16]` blob is accessed at offsets `[0]–[3]`, `[4]–[9]`, and `[0xc]–[0xf]`
by `XPP_finalize_console_pairing()` and the TFTP RRQ handler — but as raw bytes with
no named fields in the decompiled source.


**What is confirmed**:
- `AMACAEPM` magic string is real
- `metadata[0–3]` and `metadata[4–9]` and `metadata[0xc–0xf]` are used in pairing/auth logic
- `g_XPP_Paired_Flag` is set by `CFG_Set_Paired_Xbox_MAC()` (0=unpaired, 1=paired)
- Factory reset clears paired state


---

## WPA/WPA2 Implementation

### Background

Full WPA/WPA2 support involves **three separate gaps** that must all be closed:

**Gap 1 — Adapter does not advertise WPA capability (HANDSHAKE_RESP)**
The adapter's HANDSHAKE_RESP byte 174 stub value of `0x06` never sets bit 0x10 (`field_0xd70`).
The dashboard checks this bit before showing the WPA PSK option in the security type UI.
With stock firmware, the user **cannot even select WPA** — the menu option is hidden.

**Gap 2 — Dashboard sends WPA key but firmware discards it; adapter does not drive handshake**
Once WPA is selected and a key entered, the dashboard:
- Sends Tag 0x10 (32-byte PMK, from 64-hex input) via CONNECT_REQ (Type 0x07), OR
- Sends Tag 0x12 (ASCII passphrase) via CONNECT_REQ (Type 0x07), OR
- Sends a Type 0x11 WPA_ASSOC_REQ packet (`XPP_build_wpa_assoc_request`) with SSID from `AutoClass1+0xa0a`

After sending WPA_ASSOC_REQ, the console **waits for the adapter to send type 0x11 frames back**
to drive the IP negotiation and ANonce exchange (sub-types 0x01 and 0x09). Without these
adapter-initiated frames, the console FSM stays in state 0x11/0x12 until timeout.

The adapter's Tag 0x10 handler stubs the PMK. The adapter sends no type 0x11 response frames.

**Gap 3 — 4-way handshake is stubbed (eapol_handle_key_exchange)**
Even if the PMK is stored, `eapol_handle_key_exchange()` logs an immediate failure and returns.
ANonce/SNonce exchange, PTK derivation, MIC verification, and GTK installation are all absent.

The Xbox was **designed** to offload PMK calculation to the adapter. The Dashboard sends the
pre-calculated PMK via Tag 0x10 so the adapter does not need to run the expensive PBKDF2
locally. The adapter was then supposed to complete the 4-way handshake and install PTK/GTK
into the hardware key cache. All three parts of this were stubbed or omitted before shipping.

**Summary: For a WPA-capable emulator or patched firmware, ALL THREE GAPS must be addressed:**
1. Report WPA capability in HANDSHAKE_RESP byte 174 bit 0x10 (send `0x16` instead of `0x06`)
2. Handle the key material (Tag 0x10 PMK, Tag 0x12 passphrase, or Type 0x11 ASSOC_REQ SSID)
3. Implement the full bidirectional type 0x11 sub-protocol (IP negotiation → ANonce → IP config)
4. Implement `eapol_handle_key_exchange()` body (4-way handshake with AP)

### What Is Already In Firmware
```
 Component            | Function                                                                            | Status
----------------------|-------------------------------------------------------------------------------------|--------
 AES crypto engine    | `AES_Key_Expansion_Routine`, `aes_hw_encrypt`, `aes_init_tboxes`                    | Complete
 CCMP encrypt/decrypt | `wlan_ccmp_encrypt`, `wlan_ccmp_decrypt_verify`, `ath_hal_ccmp_aes_encrypt`         | Complete
 Hardware key cache   | `ath_hal_set_key_cache_entry`, `ath_hal_install_hw_key`, `ath_hal_program_key_slot` | Complete
 TKIP MIC             | `ath_hal_is_tkip_mic_enabled`, `wpa_handle_mic_failure`                             | Complete
 WPA security init    | `WLAN_WPA_Security_Init`                                                            | Complete
 WPA/RSN IE handling  | `wlan_wpa_ie_generator`, `wlan_pack_wpa_ie_tlv`, `wlan_parse_wpa_rsn_ies`           | Complete
 EAPOL state machine  | `eapol_pae_state_machine`, `wlan_eapol_frame_dispatcher`                            | Complete
 PBKDF2 derivation    | `XPP_PBKDF2_F_Block` (FUN_8004113c)                                              | Dead code - never called
 Tag 0x10 receive     | `XPP_Parse_Entry` case 0x10                                                    | Stub - discards PMK
 4-way handshake      | `eapol_handle_key_exchange`                                                         | Stub - logs failure and returns
```
### The Two Patch Paths

#### Path 1 - Xbox Sends PMK (Original Design Intent)

The Xbox Dashboard already calculates and sends the PMK in Tag 0x10. No Xbox modification
is needed. The patch is purely on the firmware side.

**Call chain after patch**:
```
XPP_Parse_Entry() case 0x10
    PATCH: extract 32-byte PMK from pbVar4+2
    store to new global: G_WPA_PMK[32]
    set flag: G_WPA_PMK_READY = 1
        |
        v
eapol_pae_state_machine()          <- already intact
        |
        v
eapol_handle_key_exchange()        <- PATCH: implement body
    retrieve G_WPA_PMK
    receive ANonce from AP msg 1
    generate SNonce
    derive PTK = PRF-512(PMK, ANonce, SNonce, MACs)
    verify MIC on msg 3
    install PTK via ath_hal_set_key_cache_entry()
    extract GTK from msg 3 (wrapped)
    install GTK via ath_hal_install_hw_key()
    send msg 4 (confirm)
        |
        v
Hardware AES/CCMP engine           <- already intact
```

**NVRAM changes required**: New 32-byte global `G_WPA_PMK` and 1-byte flag `G_WPA_PMK_READY`.
These do not need to be persisted to flash - they are session-only values.

**Passphrase limitation**: None. The Xbox provides the PMK directly so the firmware never
sees the passphrase. Any WPA2-compatible AP password works.

---

#### Path 2 - Receive Passphrase via Type 0x11 WPA_ASSOC_REQ

The dashboard sends a WPA_ASSOC_REQ packet (Type 0x11) carrying the SSID from
`AutoClass1+0xa0a`. This fires from state 0x11/0x12 in the sub-state machine via
`XPP_build_wpa_assoc_request`. The SSID is embedded as sub-tag 0x0101 with its length.

**Important**: The Type 0x11 WPA_ASSOC_REQ carries the **SSID**, not the passphrase directly.
The passphrase material arrives via Tag 0x10 (PMK) or Tag 0x12 (passphrase) in the earlier
CONNECT_REQ. The Type 0x11 packet signals the start of 802.11 association for the specific SSID.

After receiving WPA_ASSOC_REQ, the adapter must:
1. Begin 802.11 association with the AP for the specified SSID
2. Send type 0x11 sub-type 0x01 frames (frame_type=0x21c0) to initiate IP negotiation
3. Exchange challenge tokens with the console (tag=0x03 token 0x23c0/0x23c2)
4. Send sub-type 0x09 (ANonce) once 802.11 association and initial EAPOL completes
5. Complete 4-way handshake with AP using stored PMK
6. Send type 0x11 frame_type=0x2180 with IP config (gateway, DNS) to console
7. Console exits WPA sub-states and signals IP ready via KeSetEvent(+0xaf8)

**Worker task requirement**: 4-way handshake must not block the network mutex.
Must run in the existing `wireless_worker_task` context.

---

#### Path 3 - Firmware Calculates PMK Locally (via Tag 0x12)

**Note**: Previous spec versions documented this as "Path 2 via repurposed Tag 0x10". This
was incorrect. The correct tag for passphrase-in-CONNECT_REQ is Tag 0x12 (not Tag 0x10).

When the user enters an 8–63 char ASCII passphrase, the dashboard sends Tag 0x12 (raw
passphrase) in a Type 0x07 CONNECT_REQ. Stock firmware has no `case 0x12` — it aborts
parsing. A patch adds `case 0x12` to call `wlan_pbkdf2_pmk_derive()`.

See Tag 0x12 for full details of this path.

---

### Comparison
```
| Consideration      | Path 1: Tag 0x10 PMK | Path 2: Type 0x11 ASSOC_REQ | Path 3: Tag 0x12 passphrase
|--------------------|----------------------|-----------------------------|---------------------------------
| Xbox key input     | 64-char hex string   | 8–63 ASCII passphrase       | 8–63 ASCII passphrase
| Protocol packet    | CONNECT_REQ (0x07)   | WPA_ASSOC_REQ (0x11)        | CONNECT_REQ (0x07)
| Firmware side      | Patch case 0x10      | Add Type 0x11 handler       | Add case 0x12
| PMK computation    | Xbox pre-computes    | Firmware runs PBKDF2        | Firmware runs PBKDF2
| Worker task needed | No                   | Yes (PBKDF2 ~100–200ms)     | Yes (PBKDF2 ~100–200ms)
| Capability unlock  | Byte 174 bit 0x10    | Byte 174 bit 0x10           | Byte 174 bit 0x10
| Complexity         | Lower                | Medium                      | Medium
```

**Recommendation**: Path 1 is the simplest for a patched firmware or emulator. The Xbox
already sends a valid 32-byte PMK for 64-hex input. Path 2 is preferable for normal user
experience (most users enter ASCII passphrases, not 64-hex PMKs). Both require setting
HANDSHAKE_RESP byte 174 bit 0x10 to unlock the WPA PSK menu option.

### Additional Change Required (Both Paths)

`wlan_get_encryption_type()` currently only returns `0x00` (none), `0x01` (WEP), `0x02`
(WPA/WPA2 generic). Two new constants must be defined for the XPP Tag 0x11 handler so the
adapter correctly reports its active cipher mode:

```c
XPP_SEC_TKIP = 0x03   // WPA-TKIP
XPP_SEC_CCMP = 0x04   // WPA2-AES-CCMP
```

---

## Implementation Checklist
### Phase 1: Core Infrastructure ✅
- [ ] Raw Ethernet socket (EtherType 0x886f)
- [ ] RFC 1071 checksum implementation
- [ ] HMAC-SHA1 authentication
- [ ] Packet parser for XPP Headers
- [ ] Load secrets (hmac_key.bin, hmac_salt.bin, auth_copyright.bin)

### Phase 2: Discovery & Authentication ✅
- [ ] Type 0x01 handshake request handler
- [ ] Type 0x02 handshake response builder
- [ ] HMAC signature for Type 0x02

### Phase 3: Network Operations ✅
- [ ] Type 0x03 networks list request handler
- [ ] Wi-Fi scan integration (iw/nmcli/wpa_cli)
- [ ] Type 0x04 networks list response builder
- [ ] 61-byte network slot encoding
- [ ] Signal strength conversion (dBm 0-255)

### Phase 4: Connection Management ✅
- [ ] Type 0x07 TLV parser
  - [ ] Tag 0x01/0x04 (SSID)
  - [ ] Tag 0x02 (Channel for ad-hoc)
  - [ ] Tag 0x09 (Network mode)
  - [ ] Tag 0x0A (Password/WEP key)
  - [ ] Tag 0x0B-0x0E (WEP multi-key)
- [ ] Type 0x08 connect response
- [ ] Wi-Fi connection integration (wpa_supplicant)
- [ ] SavedProfile structure (flash simulation)

### Phase 5: Keepalive & Monitoring ✅
- [ ] Type 0x09 beacon request handler
- [ ] Type 0x0a beacon response builder
- [ ] 5-second beacon timeout detection
- [ ] Connection state machine
- [ ] Type 0x05/0x06 periodic status updates

### Phase 6: Advanced Features (Optional)
- [ ] MAC address pairing (mac.dat)
- [ ] Region code support (Tag 0x12)
- [ ] Static IP configuration (Tags 0x06-0x08)
- [ ] WEP-128 support (Tag 0x0F)
- [ ] Multi-adapter support

### Phase 7: WPA/WPA2 (Firmware Patch)
**Choose one path - see [WPA/WPA2 Implementation](#wpa-wpa2-implementation)**

**Path 1 - Xbox sends PMK (Recommended)**:
- [ ] Patch `XPP_Parse_Entry()` case 0x10 to store 32-byte PMK to `G_WPA_PMK`
- [ ] Implement `eapol_handle_key_exchange()` body:
  - [ ] ANonce/SNonce exchange
  - [ ] PTK derivation via PRF-512(PMK, ANonce, SNonce, MACs)
  - [ ] MIC verification on handshake msg 3
  - [ ] PTK install via `ath_hal_set_key_cache_entry()`
  - [ ] GTK unwrap and install via `ath_hal_install_hw_key()`
  - [ ] Send handshake msg 4 confirmation
- [ ] Add `XPP_SEC_TKIP = 0x03` and `XPP_SEC_CCMP = 0x04` to `wlan_get_encryption_type()`

**Path 2 - Firmware calculates PMK (Alternative)**:
- [ ] Allocate `G_WPA_Passphrase[64]` in NVRAM
- [ ] Patch `XPP_Parse_Entry()` case 0x10 to store raw passphrase
- [ ] Wire `XPP_PBKDF2_F_Block()` into `wireless_worker_task()` async signal
- [ ] All items from Path 1 `eapol_handle_key_exchange()` above
- [ ] Add `XPP_SEC_TKIP = 0x03` and `XPP_SEC_CCMP = 0x04` to `wlan_get_encryption_type()`

---

## Packet Flow Timing Diagrams

### Initial Connection Sequence
```
Time  Xbox                    Adapter                   State
─────────────────────────────────────────────────────────────────
0.0s  Type 0x01 ────────>                              DISCONNECTED
      (Challenge)           
                            Compute HMAC
                            Build status
0.1s                  <──────── Type 0x02              HANDSHAKE_DONE
                                (HMAC + Wi-Fi Status)

1.0s  Type 0x09 ────────>                              
      (Beacon #1)           Verify signature
1.1s                  <──────── Type 0x0a
                                (Security: 02 80 03 00)

2.0s  Type 0x09 ────────>                              
      (Beacon #2)           Check association
2.1s                  <──────── Type 0x0a
                                (Security: 02 80 03 00)

3.0s  Type 0x09 ────────>                              
      (Beacon #3)           Link confirmed
3.1s                  <──────── Type 0x0a              LINKED ✓
                                (Security: 02 80 03 00)
─────────────────────────────────────────────────────────────────
```

### Ongoing Operation (Connected State)

```
Time  Xbox                    Adapter                   Notes
─────────────────────────────────────────────────────────────────
0s    Type 0x09 ────────>                              Keepalive
      (Beacon)
0.1s                  <──────── Type 0x0a              Status OK

2s    Type 0x05 ────────>                              Status query
      (STATUS variant)      Read Wi-Fi stats
2.1s                  <──────── Type 0x06        Dashboard update
                                (Signal: 75%, Chan: 6)

4s    Type 0x09 ────────>                              Keepalive
4.1s                  <──────── Type 0x0a              Status OK

6s    Type 0x05 ────────>                              Status query
6.1s                  <──────── Type 0x06       Dashboard update

... (Repeat every 1-2 seconds) ...
─────────────────────────────────────────────────────────────────
```

### Network Discovery Flow

```
Time  Xbox                    Adapter                   Action
─────────────────────────────────────────────────────────────────
0s    [User opens Network List in Dashboard]

0.1s  Type 0x03 ────────>                              Scan request
      (Network List Req)    
                            Start Wi-Fi scan
                            Scan channels 1-11
                            Collect beacons
                            (Takes 50-900ms)

0.8s                  <──────── Type 0x04              Results ready
                                (16 networks × 61 bytes) //Max limit


      [Dashboard displays network list]
─────────────────────────────────────────────────────────────────
```

### Connection to New Network

```
Time  Xbox                    Adapter                   Action
─────────────────────────────────────────────────────────────────
0s    [User selects "MyNetwork" and enters password]

0.1s  Type 0x07 ────────>                              Connect request
      (TLV: SSID, Pwd,      Parse TLV
       Security, Region)
                            Extract config
0.2s                  <──────── Type 0x08              Confirm
                                (Result: 0x00 = OK)

                            [Adapter starts connecting...]
                            Associate to AP
                            WPA handshake
                            DHCP request
                            (Takes 2-5 seconds)

      [Connection established - return to beacon cycle]
─────────────────────────────────────────────────────────────────
```

### Watchdog Timeout Scenario

```
Time  Xbox                    Adapter                   State
─────────────────────────────────────────────────────────────────
0s    Type 0x09 ────────>                              LINKED
      (Last beacon)
0.1s                  <──────── Type 0x0a

      [Xbox crashes / network cable unplugged]

5s                            5s beacon timeout         STANDBY
                            Radio stays on
                            Stop routing packets

30s                           30s watchdog timeout      ERROR
                            Call net_set_error_state
                            Shutdown Wi-Fi radio
                            Enter low-power mode

      [Xbox reboots]

60s   Type 0x01 ────────>                              Recovery
      (Handshake)           Full re-auth required
─────────────────────────────────────────────────────────────────
```

---

## 5. DHCP Implementation & XPP Interaction

### 5.1 Overview
The MN-740 operates as a **Layer 2 Transparent Bridge**. While it does not act as a DHCP client itself for its primary function, it performs **Passive DHCP Snooping** to maintain its internal state. The adapter "listens" to the DHCP handshake between the Xbox console and the network Gateway to populate its internal status registers.

### 5.2 DHCP Snooping Mechanic
When the Xbox Console initiates a DHCP transaction, the adapter’s firmware intercepts specific UDP packets on **Ports 67 (Server)** and **68 (Client)**.

1. **Intercept**: The firmware monitors traffic for the **DHCP Magic Cookie**: `0x63 0x82 0x53 0x63`.
2. **Filter**: It specifically looks for **Option 53 (Message Type)** with a value of `0x05` (**DHCP ACK**).
3. **Extraction**: Upon detecting an ACK, the firmware extracts the `yiaddr` (Your IP Address) and **Option 54 (Server Identifier)**.


### 5.3 Relationship to Type 0x02 (Status Response)
The IP address captured during snooping is mirrored in the **XPP Type 0x02** handshake response. This allows the Xbox Dashboard to verify that the wireless bridge has successfully bridged the console onto the local subnet.
```
Field     | Offset | Size    | Description
----------|--------|---------|----------------
Current IP| 0x12   | 4 Bytes | The IP address extracted from the last seen DHCP ACK.
Server ID | N/A    | 4 Bytes | Internal only; used to detect Gateway changes/roaming.
```

###DHCP Info
```
 Component           | Value      | Role
---------------------|------------|-----------------------
 **DHCP Port (Src)** | 68         | Xbox Console (Client)
 **DHCP Port (Dst)** | 67         | Router/Gateway (Server)
 **Option 53**       | 0x05       | DHCP ACK (Triggers IP Cache Update)
 **Option 54**       | IP Address | Server Identifier (Gateway IP)
 **Option 51**       | 4 Bytes    | Lease Time (Used for internal timeout logic)
```
### DHCP Sequence
**1. DHCP DISCOVER**
```
Adapter → Broadcast (255.255.255.255:67)
Source Port: 68
Contains: Client MAC, requested IP (if cached)
```

**2. DHCP OFFER**
```
Server → Broadcast (255.255.255.255:68)
Contains: Offered IP, subnet mask, gateway, DNS, lease time
```

**3. DHCP REQUEST**
```
Adapter → Broadcast (255.255.255.255:67)
Contains: Requested IP, server identifier (Option 54)
```

**4. DHCP ACK**
```
Server → Adapter (unicast or broadcast)
Contains: Confirmed IP configuration
```

> **NOTE on Static IP Behavior:** If the Xbox is configured with a Static IP, no DHCP ACK will traverse the bridge. In this scenario, the `0x12` field in the Type 0x02 response will remain `0.0.0.0` unless the Xbox explicitly pushes the configuration to the adapter using **XPP Tag 0x04**.

### Session Lifecycle

**1. Session Creation (Type 0x01 Handshake)**
```
Xbox → Type 0x01 (Challenge)
Adapter generates:
  - New session ID (incremented from previous)
  - Session handle (pointer to session context)
  - Security state = PENDING
  - Link state = DISCONNECTED
```

**2. Session Authentication (Type 0x02 Response)**
```
Adapter → Type 0x02 (HMAC signature valid)
Update states:
  - Security state = AUTHENTICATED
  - Link state = LINKED (after 3 beacons)
```

**3. Session Active (Beacon Exchange)**
```
Continuous Type 0x09/0x0a exchange
Security state = AUTHENTICATED
Link state = ACTIVE
Session ID remains constant
```

**4. Session Timeout (30-second watchdog)**
```
No traffic from Xbox MAC for 30 seconds:
  - Security state = TIMEOUT
  - Link state = ERROR
  - Session handle invalidated
Requires new Type 0x01 handshake
```

### Security State vs Link State
**Security State** (Authentication):
- `PENDING`: Challenge sent, awaiting response
- `AUTHENTICATED`: Valid HMAC received
- `TIMEOUT`: No activity timeout
- `REJECTED`: Invalid HMAC or malformed packet

**Link State** (Connection):
- `DISCONNECTED`: No association
- `LINKED`: Handshake complete, beacons starting
- `ACTIVE`: Regular beacon exchange (every 1 second)
- `ERROR`: Watchdog timeout or fatal error

**Independence**: Security can be `AUTHENTICATED` while link is `ERROR` (e.g., beacon timeout)

### Virtual File Descriptor

```c
// Firmware-verified (NML_bin.h)
struct XPP_VirtualFileDescriptor {
    char filename[8];      // "mac.dat"
    char magic_header[8];  // "AMACAEPM"
    byte metadata[16];     // Internal layout NOT decoded — see section 6.2
};
```

### AMACAEPM Magic Header
**Purpose**: Integrity check for paired Xbox configuration — firmware-verified
**Expansion** ("Adapter MAC Address & Endpoint Manager"): NOT firmware-verified, inferred label only

### File Structure
⚠ The previously documented 32-byte field breakdown (Paired Xbox MAC at 16-21, Flags at 22-23,
Timestamp at 24-27, CRC32 at 28-31) and the Pairing Flags bitmask (Bit 0/1/2) are **NOT firmware-verified**
— generated by LLM and removed. The `metadata[16]` blob internal layout is not decoded.

### Pairing Process (firmware-verified behaviour)
**Factory Reset**: `g_XPP_Paired_Flag = 0` (unpaired)

**Pairing**: `CFG_Set_Paired_Xbox_MAC()` copies the Xbox MAC and sets `g_XPP_Paired_Flag = 1`,
then calls `Flash_Commit_Settings()` + `CFG_Save_To_Flash()`

**Subsequent Connections**: adapter checks source MAC against stored paired MAC via
`NET_Register_Peer_MAC()` — only responds to the paired Xbox MAC

### Security Model
**Pairing Lock**: Once paired, adapter only responds to that Xbox MAC (firmware-verified)
**Reset**: Factory reset clears paired state (firmware-verified)


### 5.5 The "IP Mismatch" Logic
If the IP address reported in the Type 0x02 response does not match the IP the Xbox is currently using, the console may initiate a **Type 0x01 (Handshake Request)** to re-sync the adapter. If the adapter continues to report `0.0.0.0`, the Xbox Dashboard will trigger the "Wireless Adapter is connected but has no IP" error message.

---

## Firmware Version Detection

The MN-740 reports firmware version in Type 0x02 handshake response at offset 136 (32 bytes).

### Known Verified Firmware Versions (Not extensive)
```
 Version  | Release    | Notes
----------|------------|-------
 1.0.2.21 | 2004       | Early production firmware
 1.0.2.26 | 2005       | Final production firmware (latest release)
 1.0.2.28 | Unreleased | Debug/development build
```
### Version-Specific Differences

**v1.0.2.21 (Early Production)**:
- Channel 14 (Japan) requires separate region flash update
- DHCP client has retry bug (3 attempts max)
- WEP key cache not implemented (slower reconnects)

**v1.0.2.26 (Final Production)**:
- Region code properly read from EEPROM at `0x800A984E`
- DHCP client improved (10 attempts with exponential backoff)
- WEP key cache added for fast roaming
- Watchdog timeout increased from 20s to 30s
- Bug fix: Hidden SSID length 0 handling

**v1.0.2.28 (Debug Build)**:
- UART debug logging enabled (115200 baud)
- Extra validation checks in TLV parser
- Never released to production
- Occasionally found on developer units
- Apparently leaked in 2020 Xbox giga leak

## Known Limitations
### Hardware Constraints
- MN-740 released 2004 (pre-WPA2 certification)
- 2.4GHz only (no 5GHz support)
- 802.11b/g maximum (no n/ac/ax)
- No WPA3/SAE support
- Single shared HMAC key (no per-device keys)

### Protocol Constraints
- SHA1 considered weak by modern standards
- No certificate-based authentication
- No key rotation mechanism
- Security types are adapter-specific values

---

### Required Files

```
secrets/
  ├── hmac_key.bin          # 16 bytes (extracted from firmware)
  ├── hmac_salt.bin         # 117 bytes (extracted from firmware)
  └── auth_copyright.bin    # 84 bytes (extracted from firmware)
```

---

### Quirky error handler string

The device has a very funny error handling string as a line from the
three stooges that is common on other dlink products:

"Hey Moe, it dont woik. NYUK NYUK NYUK NYUK"

Any unknown TLV tag sent will print this error on the debug serial port.

---

### Packet Type Dispatcher — Both Sides Confirmed Complete (Types 0x01–0x0F)
**Source**: `switchD_00134348` (xonlinedash.xbe)

The Xbox Dashboard packet type switch has a **unique handler for every type `0x01` through `0x0F`** with no fall-throughs. Cross-referencing against the adapter firmware:

```
Type  | Adapter behaviour      | Dash sends? | Notes
------|------------------------|-------------|-----------------------------------------------
0x01  | Handled (HANDSHAKE_REQ)| Yes         | Xbox sends; adapter responds with 0x02
0x02  | Handled (HANDSHAKE_RSP)| No          | Adapter sends; dash receives
0x03  | Handled (SCAN_REQ)     | Yes         |
0x04  | Handled (SCAN_RSP)     | No          | Adapter sends; dash receives
0x05  | Handled (INFO_REQ)     | Yes         |
0x06  | Handled (INFO_RSP)     | No          | Adapter sends; dash receives
0x07  | Handled (CONNECT_REQ)  | Yes         |
0x08  | Handled (CONNECT_RSP)  | No          | Adapter sends; dash receives
0x09  | Handled (BEACON_REQ)   | Yes         |
0x0A  | Handled (BEACON_RSP)   | No          | Adapter sends; dash receives
0x0B  | SILENTLY DROPPED       | Yes         | Adapter discards — confirmed from firmware counter DAT_800ce0f8
0x0C  | SILENTLY DROPPED       | Yes         | Adapter discards — confirmed from firmware counter DAT_800ce0fc
0x0D  | Not present            | N/A         | No handler in firmware v1.0.2.26
0x0E  | Not present            | N/A         | No handler in firmware v1.0.2.26
0x0F  | SILENT DROP (no counter)| Yes        | Adapter discards with no log, no counter
```

This confirms the adapter's silent-drop entries for types `0x04`, `0x05`, `0x0B`, `0x0C`, `0x0F` are **accurate from the adapter side**. The dashboard sends all of them but the adapter discards most. The full type space `0x01–0x0F` is exercised by the dashboard with no unknown types on either side.

---

### Footer
**All reverse engineering was based on the mn740 firmware version v1.0.2.26**
**All supplementary reverse engineering was based on xonlinedash.xbe from dash 5960**
**Captures and initial fuzzing was done using custom tooling**
**Live firmware update capture: trialupdate.pcapng — MSBNUpdate.exe against real MN-740 hardware**
**Disassembly was done using Ghidra v12**
**MSBNUpdate.exe analysis: string extraction from official Microsoft update binary (build path d:\Net2\src\DINGO\exe\MSBNUpdate\Release)**
**BBN discovery protocol: firmware-verified from NML_bin.c decompile + BBN_Handle_Discovery_Task and BBN_Init_Sockets assembler (MIPS)**
**Signed off by Jonathan Brophy — Professor_jonny@hotmail.com**

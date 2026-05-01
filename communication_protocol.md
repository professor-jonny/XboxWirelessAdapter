# Xbox Wireless Adapter — XPP Protocol Specification

**Compatable Hardware**:
Microsoft MN-740 Wireless Bridge
Linksys WGA54G Wireless-G Game Adapter

**Protocol**: Xbox Peripheral Protocol (XPP) over NLB (EtherType 0x886f)  
**Status**: near complete

---

## Overview
This document purpose is to document the XPP wireless protocol as implemented on the original Xbox console and the MN-740/ WGA54g Ethernet-to-Wireless bridge. the software link is unique that is manages the wireless hardware Unlike a standard "dumb" bridge, the Xbox console is able to control and monitor the adaptors wireless radio all from the dashboard UI.

Microsoft used the existing Ethernet port and created a "Virtual Serial Bus" by wrapping management commands in Fake NLB Heartbeats. This allowed the Xbox to configure the adapter without needing a complex TCP/IP stack.

The configuration payload structure resembles Wi-Fi Protected Setup (WPS) TLV encoding but has been modified to be lightweight.

The Main problem with the wireless adapter hardware has been the lack of WPA and newer protocols, this project aims to be a stepping stone to implement an emulator or alternative hardware to enable such connections to modern wireless networks.

The currently available adaptors are actually hampered at a firmware level to WEP128 when the adapters actually support newer security standards, there is a breakdown of what is required to patch in WPA support in the MN-740 and WGA54G later on in this document.

Contuary to belieif The Xbox is capable of more than it seems the adaptor uses the handshake response to tell the Xbox what security is supports and the Xbox dashboard uses this to customize the UI.
upon returning specific values new UI options are available for wireless networks.
The Xbox dash is aware of ciphers and encryption support all the way up to WPA/WPA2 with the latest dash files.
The Xbox supports PMK formatted hex and ASCII passwords up to 63 characters as per the WPA/WPA2 standard.

The adaptors and console supports a set of basic tags but extra tags and features have been implemented and features outside of what the console or adaptors support currently for future purposes that never materialised on both the Xbox and adaptor side.

---

## Table of Contents

- [Packet Transport Types](#packet-transport-types)
  - [NLB (EtherType 0x886f)](#nlb-transport-ethertype-0x886f)
  - [EAPOL (EtherType 0x888e)](#eapol-transport-etherType-0x888)
- [Type 0x00 - ECHO](#type-0x00--echo)
- [Type 0x01 - HANDSHAKE_REQUEST](#type-0x01--handshake_request)
- [Type 0x02 - HANDSHAKE_RESPONSE](#type-0x02--handshake_response)
- [Type 0x03 - NETWORKS_LIST_REQUEST](#type-0x03--networks_list_request)
- [Type 0x04 - NETWORKS_LIST_RESPONSE](#type-0x04--networks_list_response)
- [Type 0x05 - ADAPTER_INFO_REQUEST](#type-0x05--adapter_info_request)
- [Type 0x06 - ADAPTER_INFO_RESPONSE](#type-0x06--adapter_info_response)
- [Type 0x07 - CONNECT_TO_SSID_REQUEST](#type-0x07--connect_to_ssid_request)
- [Type 0x08 - CONNECT_TO_SSID_RESPONSE](#type-0x08--connect_to_ssid_response)
- [Type 0x09 - BEACON_REQUEST](#type-0x09--beacon_request)
- [Type 0x0A - BEACON_RESPONSE](#type-0x0a--beacon_response)
- [Types 0x0B, 0x0C, 0x0F — Silently Dropped](#types-0x0b-0x0c-0x0f--silently-dropped)
- [Type 0x11 - WPA_ASSOC / WPA_EXCHANGE](#type-0x11--wpa_assoc--wpa_exchange)

### Supporting Information
- [HMAC-SHA1 Authentication](#hmac-sha1-authentication)
- [Checksum Calculation](#checksum-calculation)
- [BBN Device Discovery Protocol (MN-740 only)](#bbn-device-discovery-protocol)
- [TFTP Firmware Upgrade (MN-740 only)](#tftp-firmware-upgrade)
- [Virtual File System (MN-740 only)](#Virtual-File-system)
- [MSBNUpdate Firmware Update Tool (MN-740 only)](#msbnupdate-firmware-update-tool)
- [Xbox FSM Internals](#xbox-fsm-internals)
- [Signing vs Verification](#signing-vs-verification)
- [Signal Strength Scaling](#signal-strength-scaling)
- [Error code flags](#error-code-flags)
- [MAC.DAT File Format (MN-740 only)](#mac-dat-pairing-file-format)
- [Connection Workflows](#connection-workflows)
- [Implementation Checklist](#implementation-checklist)
- [DHCP Implementation & XPP Interaction](#dhcp-implementation---xpp-interaction)
- [Packet Flow Timing Diagrams](#packet-flow-timing-diagrams)
- [WPA/WPA2 Implementation](#wpa-wpa2-implementation)
- [Troubleshooting Guide](#troubleshooting-guide)
- [Packet Flow Timing Diagram](#packet-flow-timing-diagram)

---

## Packet Transport Types

Two distinct transports are used. The transport for each packet type is noted at the top of each section.

```
Transport      | EtherType | Used by
---------------|-----------|--------------------------------------------------
NLB (XPP)      | 0x886f    | Types 0x00–0x09, 0x0A, 0x0B, 0x0C, 0x0F
EAPOL (802.1X) | 0x888e    | Type 0x11 only (WPA authentication)
```

**protocol types**
```
EtherType | Protocol            
----------|---------------------------------------------------------------
0x0806    | ARP
0x886f    | NLB (XPP)
0x888e    | EAPOL (IEEE 802.1X)
```

### NLB Transport (EtherType 0x886f)

```
Size         | Segment           | Description
-------------|-------------------|------------------------------------------------
14 bytes     | Ethernet header   | dst MAC, src MAC, EtherType 0x886f
12 bytes     | XPP header        | Magic, version, body size, type, nonce, checksum
Variable     | Payload           | Packet-specific data
0–3 bytes    | DWORD padding     | Zeros to align to 4-byte boundary
Variable     | IEEE 802.3 padding| Zeros to reach 60-byte minimum frame size
```

#### Ethernet Header (14 bytes)

```
Offset | Size | Field           | Value
-------|------|-----------------|----------------------------------------------
0      | 6    | Destination MAC | Target MAC (FF:FF:FF:FF:FF:FF for HANDSHAKE_REQ)
6      | 6    | Source MAC      | Sender MAC
12     | 2    | EtherType       | 0x886f
```

#### XPP Header (12 bytes)

```
Offset | Size | Field              | Value
-------|------|--------------------|--------------------------------------------------
0      | 4    | Magic signature    | "XBOX" (0x58 0x42 0x4f 0x58)
4      | 1    | Version byte 1     | 0x01 (static)
5      | 1    | Version byte 2     | 0x01 (static)
6      | 1    | Body size (DWORDs) | (12 + payload + padding) / 4
7      | 1    | Packet type        | Command ID
8      | 2    | XID (nonce)        | Transaction ID — matched between request and response
10     | 2    | Checksum           | RFC 1071 (calculated with this field = 0x0000)
```

Body size counts from the start of the XPP header and covers header + payload + DWORD padding. IEEE 802.3 padding is never included.

```
Example body size calculation:
Type 0x01: 16-byte payload  → (12 + 16) / 4 =  7 DWORDs = 0x07
Type 0x02: 256-byte payload → (12 + 256) / 4 = 67 DWORDs = 0x43
Type 0x09: 0-byte payload   → (12 + 0) / 4  =  3 DWORDs = 0x03
```

**Build order:**
1. Pack payload data
2. For Type 0x02 only: prepend 20-byte HMAC at offset 0
3. Pad to 4-byte boundary with 0x00
4. Calculate body size: `(12 + padded_payload) / 4`
5. Write XPP header fields
6. Calculate RFC 1071 checksum over `body_size × 4` bytes and write to offset 10
7. Pad entire frame to 60-byte minimum with 0x00 (IEEE 802.3, not checksummed)

---

### EAPOL Transport (EtherType 0x888e)

Used exclusively by Type 0x11. **No XPP magic signature, no body size DWORD count, no RFC 1071 checksum.**

```
Size     | Field           | Value
---------|-----------------|------------------------------------------------
6 bytes  | Destination MAC | FF:FF:FF:FF:FF:FF (broadcast) or AP MAC (retry)
6 bytes  | Source MAC      | Console MAC
2 bytes  | EtherType       | 0x888e
2 bytes  | Frame type word | 0x6388 or 0x123c (WPA sub-protocol selector)
1 byte   | Type marker     | 0x11 (constant)
1 byte   | Sub-type        | Direction/state byte
2 bytes  | Reserved        | 0x0000
2 bytes  | Length          | Big-endian payload length
2 bytes  | Reserved        | 0x0000
Variable | Payload         | Sub-TLVs: [tag:1][len:1][data:len]
```

---

## Type 0x00 — ECHO

**Direction**: Xbox → Adapter  
**Transport**: NLB (EtherType 0x886f)

Latency probe. The adapter has no dedicated echo handler — an incoming type 0x00 frame falls through the type switch with no handler and the firmware transmits the zero-filled response buffer. The response is therefore a 60-byte all-zeros frame, not a structured XPP reply.

### Packet Format Request

```
Size     | Segment         | Description
---------|-----------------|-----------------------------------------------
14 bytes | Ethernet header | dst=adapter MAC, src=Xbox MAC, EtherType=0x886f
12 bytes | XPP header      | type=0x00, body=0x03 DWORDs, no payload
```

### Packet Format Response

```
Size     | Segment         | Description
---------|-----------------|-----------------------------------------------
14 bytes | Ethernet header | dst=Xbox MAC, src=adapter MAC, EtherType=0x886f
46 bytes | Zeros           | Zero-filled to meet 60-byte minimum frame size
```

No XPP magic. No checksum. All bytes after the Ethernet header are 0x00. RTT typically 1–5 ms.

**Emulator note**: Respond with a 60-byte all-zeros Ethernet frame (EtherType 0x886f). Do not include XPP structure in the response.

---

## Type 0x01 — HANDSHAKE_REQUEST

**Direction**: Xbox → Adapter  
**Transport**: NLB (EtherType 0x886f)

Initiates an authentication session with a random challenge nonce.

### Packet Format

```
Total size: 42 bytes (14 Ethernet + 12 XPP + 16 payload)
Body size:  0x07 DWORDs

Size     | Segment         | Description
---------|-----------------|-----------------------------------------------
14 bytes | Ethernet header | dst=FF:FF:FF:FF:FF:FF (broadcast), EtherType=0x886f
12 bytes | XPP header      | type=0x01, body=0x07 DWORDs
16 bytes | Payload         | Randomly generated 128-bit challenge nonce
```

### Example

```
58 42 4f 58 01 01 07 01 ed c6 66 9a   ← XPP header (type=0x01, body=0x07)
12 34 56 78 9a bc de f0 11 22 33 44   ← 16-byte challenge nonce (bytes 0–11)
55 66 77 88                           ← 16-byte challenge nonce (bytes 12–15)
```

---

## Type 0x02 — HANDSHAKE_RESPONSE

**Direction**: Adapter → Xbox  
**Transport**: NLB (EtherType 0x886f)

Authenticates the adapter and reports current wireless status. Contains a 20-byte HMAC-SHA1 at offset 0 of the payload — the only packet type to carry an HMAC.

```
Total size: 282 bytes (14 Ethernet + 12 XPP + 252 payload + 4 trailer)
Body size:  0x43 DWORDs

Size     | Segment         | Description
---------|-----------------|-----------------------------------------------
14 bytes | Ethernet header | Standard
12 bytes | XPP header      | type=0x02, body=0x43 DWORDs
252 bytes| Fixed payload   | See layout below
4 bytes  | Trailer         | OpMode bitmask + LinkState + 0x00 0x00
```

### Fixed Payload (252 bytes)

```
Offset | Size     | Field
-------|----------|------------------------------------------------------------------
0      | 20 bytes | HMAC-SHA1 — see HMAC Authentication section
20     | 84 bytes | "Device is Xbox Compatible. Copyright (c) Microsoft Corporation.
       |          |  All Rights Reserved." null-padded to 84 bytes
104    | 32 bytes | "Xbox Wireless Adapter (MN-740)" null-padded to 32 bytes
136    | 32 bytes | Firmware version string e.g. "1.0.2.26 Boot: 1.3.0.06" null-padded
168    | 6 bytes  | BSSID of connected AP, or 00:00:00:00:00:00 if not connected
174    | 1 byte   | Security capability byte — see WPA Capability Bytes below
175    | 1 byte   | Cipher capability byte — see WPA Capability Bytes below
176    | 4 bytes  | 2.4ghz Channel allow list bitmask — hardcoded 0x00000FFE (channels 1-11)
       |          | Rejection rule: bit 0 set OR bit >14 set → entire response rejected
180    | 28 bytes | Extended Channel allow list bitmask (1=enabled, 0=disabled, per-bit for ch 1–200)
       |          | Stock firmware sends all zeros (all channels disabled)
       |          | Channel allow list overflow,Parsed, hard-rejected by XBE always 0x00 0x00 0x00
208    | 1 byte   | Radio mode capability bitmask — hardcoded 0x05
       |          | Bit 0=802.11b capable, Bit 2=Ad-hoc capable. High bits (0xF8) must be zero
       |          | or the dashboard rejects the packet
209    | 1 byte   | DHCP state: 0x00=no DHCP, 0x01=DHCP acquired, 0x02=static/manual
210    | 4 bytes  | Current IP address (big-endian)
214    | 1 byte   | Radio active: 0x00=radio off, 0x01=radio on
       |          | Tag 0x04 val 0x00 → OpMode=8 (disabled), 0x01 or other → OpMode=2 (active)
215    | 1 byte   | Auth status: 0x02=open/idle, 0x03=WEP association in progress
216    | 1 byte   | Radio active flag: 0x00=radio off, 0x01=radio on.
       |          | Guard: value must be < 2 — sending 0x02 or higher rejects the entire
       |          | handshake response. The 0x02 (b+g active) value is only valid in
       |          | ADAPTER_INFO_RESP Tag 0x04, never in the handshake.
217    | 1 byte   | Current channel (1–14). Returns live radio channel when authenticated,
       |          | or the saved configured channel when not authenticated.
218    | 1 byte   | 802.11 authentication algorithm. Seeds AutoClass1+0xf5f (auth_algorithm)
       |          | via copy_rx_state_to_cfg, which is echoed back as CONNECT_REQ Tag 0x11.
       |          | Guard: value must be < 3 — value 0x03+ rejects the entire handshake.
       |          | 0x00=Open System auth, 0x01=Shared Key auth, 0x02=WPA/EAP auth.
       |          | Only 0x00 and 0x02 are seen on wire from stock firmware.
219    | 1 byte   | SSID length (max 32)
220    | 32 bytes | SSID string, null-padded
252    | 1 byte   | Secondary security capability
       |          | Bit 0x10 SET → WPA1/RSN capable (same as byte 174)
       |          | Bit 0x20 SET → WPA2 enterprise capable (same as byte 174)
       |          | Controls which security type is pre-selected in the UI
253    | 1 byte   | Secondary cipher capability  
       |          | Bit 0x01 SET → Open security option selected by default
       |          | Bit 0x02 SET → WEP-64 selected by default
       |          | Bit 0x04 SET → WEP-128 selected by default
       |          | Controls which security mode is pre-selected in the UI
254    | 2 bytes  | Reserved, always 0x00 0x00
```

### Trailer payload (4 bytes)

```
Offset | Size   | Field       | Values
-------|--------|-------------|-----------------------------------------------
0      | 1 byte | OpMode mask | 0x02=WEP disabled/link idle, 0x04=WEP enabled/link active
1      | 1 byte | Link state  | 0x01=no link, 0x02=infrastructure linked, 0x04=ad-hoc linked
2      | 1 byte | Reserved    | Always 0x00
3      | 1 byte | Reserved    | Always 0x00
```

### WPA Capability Bytes (Offsets 174–175)

These two bytes gate which security options the Xbox dashboard displays. Stock firmware sends hardcoded stubs.
 **To enable the WPA PSK menu option, byte 174 must have bit 0x10 set** (send `0x16` instead of `0x06`).

**Byte 174 — Adapter security capability:**
This byte is used to inform the Xbox what wireless security ciphers it supports
this packet is rejected if a prior security method is not supported ie:

byte174 Setting bit 0x20 without bit 0x10 → rejection

```
Bit  | Mask | Stock value | Meaning
-----|------|-------------|--------------------------------------------
1    | 0x02 | SET         | WPA-TKIP cipher supported
2    | 0x04 | SET         | WPA-CCMP/AES cipher supported
4    | 0x10 | CLEAR       | WPA1/RSN capable — set this to unlock WPA PSK UI
5    | 0x20 | CLEAR       | WPA2 enterprise capable
```

**Byte 175 — Cipher mode capability:**
This byte is used to inform the Xbox what wireless security sub ciphers is supports
this packet is rejected if a prior security method is not supported ie:

byte175 bits 0,1,2 must ALL be set or → rejection

```
Bit  | Mask | Stock value | Meaning
-----|------|-------------|--------------------------------------------
0    | 0x01 | SET         | "No Security" menu option shown
1    | 0x02 | SET         | "WEP-64" menu option shown
2    | 0x04 | SET         | "WEP-128" menu option shown
3    | 0x08 | CLEAR       | CCMP/AES cipher mode
4    | 0x10 | CLEAR       | WPA2 TKIP
5    | 0x20 | CLEAR       | WPA2 CCMP/AES
```
**Stock values**: the adaptor has a function stub indicating the cipher mode the device supports.
byte 174=`0x06`, byte 175=`0x07` → WPA PSK option never shown; No Security, WEP-64, WEP-128 all shown.

### 2.4ghz Channel allow list bitmask (Bytes 176–179)
This bitfield is used as a reglatory bitmask to inform the Xbox what 2.4ghz channels are allowed to be used and display in the Xbox dash.

This list is a fallback list and is second priority to the extended channel allow bitmask (bytes 180-207)

2.4ghz Channel allow list bitmask in the mn-740 this list is dynamically created based off the regon code of the adaptor set with Tag 0x84:
```
For example:

FCC (default): min=1, max=11 → bits 1–11 set → 0x00000FFE
ETSI: min=1, max=13 → bits 1–13 set → 0x00003FFE
Spain: min=10, max=11 → bits 10–11 set → 0x00000C00
Japan: min=14, max=14 → bit 14 set → 0x00004000
```

Rejection rule: bit 0 set OR bit >14 set → entire HS_RESP rejected.

### Extended Channel allow list Bitmask (Bytes 180–207)

This bitfield is used as a regulatory bitmask to inform the Xbox what channels are allowed to be used and display in the Xbox dash.
this list is the primary source if set, if a channel is not set the dash will fallback to the 2.4ghz channel allow bitmask
Total of 28 bytes, Each bit represents a channel 1-200 : **1=enabled, 0=disabled**.
bit 0 has no special handling and maps to channel 0 it will not cause rejection but setting bits above 200 will cause rejection.

```
Bit | Channel | Notes
----|---------|------
1   | 1       | 2.4 GHz
2   | 2       | 2.4 GHz
...
11  | 11      | 2.4 GHz
12  | 12      | 2.4 GHZ (USA Banned )
13  | 13      | 2.4 GHz (USA Banned)
14  | 14      | 2.4 GHZ (Japan only)
15  | 15      | 2.4ghz Not a valid channel under current regs
...
32  | 32      | 5.0ghz 5150–5170mhz U-NII-1
...
196 | 196     | 5.9ghz 5970–5990mhz UK indoor
```

### Radio Mode Capability Bitmask (Byte 208)

These bytes are used to inform the Xbox what radio mode standard it supports.

```
Bit | Mask | Wire value | Meaning
----|------|------------|------------------------------
0   | 0x01 | SET        | 802.11b capable
1   | 0x02 | CLEAR      | 802.11g capable (MN-740 is b/g but firmware stub clears this)
2   | 0x04 | SET        | Ad-hoc mode capable
3-7 | 0xf8 | 0x00       | Must be zero — dashboard rejects packet if any high bit set
```
**Stock values**: the adaptor has function stubs setting constants
byte 208=`0x05` → adaptor supports 802.11b /AD-hoc

### Byte 209 DHCP state
This byte indicates the state of the upstream DHCP DISCOVERY.
```
Result | Meaning
-------|--------
0x00   | no DHCP/searching,
0x01   | DHCP acquired,
0x02   | interface manually enabled.
```

### Byte 216 — Radio Active Flag

This bytes indicates the state of the radio in the adaptor.
The `0x02` (b+g radio active) value reported by Tag 0x04 in ADAPTER_INFO_RESP is not valid here.

```
Result | Meaning
-------|------------------------------------------------------------------
0x00   | Radio off / disabled
0x01   | Radio on
0x02+  | ENTIRE HANDSHAKE REJECTED — do not send in handshake response
```

### Byte 217 - XPP_Get_Channel_Or_Fallback()

returns live radio channel when authenticated
returns saved configured channel when not authenticated

### Byte 218 — 802.11 Authentication Algorithm

This is the **802.11 authentication algorithm** currently active on the radio — not a generic encryption flag. It is distinct from Tag 0x11 in ADAPTER_INFO_RESP, which reports live HAL encryption state.

The value seeds `AutoClass1+0xe2f`, which propagates via `copy_rx_state_to_cfg` to `AutoClass1+0xf5f` (auth_algorithm). That field is then echoed back to the adapter as CONNECT_REQ Tag 0x11, keeping the dash and adapter in sync on the 802.11 auth method in use.

```
Value | Meaning                    | Wire seen
------|----------------------------|-----------
0x00  | Open System authentication | Yes — open and WEP open-auth networks
0x01  | Shared Key authentication  | Not seen on wire from stock firmware
0x02  | WPA/EAP authentication     | Not seen on wire from stock firmware
0x03+ | ENTIRE HANDSHAKE REJECTED — do not send in handshake response
```

Stock firmware only produces `0x00` (Open System) since WPA is not implemented and Shared Key auth is uncommon. For a WPA-patched adapter, send `0x02` when WPA association is active.

### WPA Capability default selection (Offsets 252–253)

**Byte 252 — Adapter security default selection:**
This byte is used to inform the Xbox what wireless security ciphers to select or use by default.

```
Bit  | Mask | Stock value | Meaning
-----|------|-------------|--------------------------------------------
1    | 0x02 | SET         | WPA-TKIP cipher supported
2    | 0x04 | SET         | WPA-CCMP/AES cipher supported
4    | 0x10 | CLEAR       | WPA1/RSN capable — set this to unlock WPA PSK UI
5    | 0x20 | CLEAR       | WPA2 enterprise capable
```

**Byte 253 — Cipher mode default selection:**
This byte is used to inform the Xbox what wireless security sub ciphers to select or use by default.

```
Bit  | Mask | Stock value | Meaning
-----|------|-------------|--------------------------------------------
0    | 0x01 | SET         | "No Security" menu option shown
1    | 0x02 | SET         | "WEP-64" menu option shown
2    | 0x04 | SET         | "WEP-128" menu option shown
3    | 0x08 | CLEAR       | CCMP/AES cipher mode
4    | 0x10 | CLEAR       | WPA2 TKIP
5    | 0x20 | CLEAR       | WPA2 CCMP/AES
```

### Example Payload

```
[0x00] HMAC-SHA1:  b9 f0 d1 96 c3 3c 1f 34 f7 b9 e9 85 1c 45 f0 77 11 85 9d a0
[0x14] Copyright: "Device is Xbox Compatible. Copyright (c) Microsoft Corporation..."
[0x68] Model:     "Xbox Wireless Adapter (MN-740)"
[0x88] Firmware:  "1.0.2.26 Boot: 1.3.0.06"
```

---

## Type 0x03 — NETWORKS_LIST_REQUEST

**Direction**: Xbox → Adapter  
**Transport**: NLB (EtherType 0x886f)

Triggers a Wi-Fi site survey. No payload. If a scan is already in progress the request is silently dropped.

### Packet Format

```
Total size: 26 bytes (14 Ethernet + 12 XPP)
Body size:  0x03 DWORDs

Size     | Segment         | Description
---------|-----------------|-----------------------------
14 bytes | Ethernet header | Standard
12 bytes | XPP header      | type=0x03, body=0x03 DWORDs
```

Scan takes 50–900 ms depending on channel count. Response is sent when scan completes.

---

## Type 0x04 — NETWORKS_LIST_RESPONSE

**Direction**: Adapter → Xbox  
**Transport**: NLB (EtherType 0x886f)

Returns discovered networks. Maximum 16 networks (firmware limit).

**Network slot sizes**:
Each the network slots is a string of 53 bytes of sequential meaningful data with padding at
the end of each slot to make a stride of 61 bytes from the start of one slot to the next.

### Packet Format

```
Total size: Variable (14 Ethernet + 12 Header + 1 Count + N×61 Slots + Padding) = N Bytes
Body size:  Variable (12 + 1 + (Network count × 61) + padding) / 4 DWORDs

Size         | Segment         | Description
-------------|-----------------|-----------------------------------------------
14 bytes     | Ethernet header | Standard
12 bytes     | XPP header      | type=0x04, body=variable DWORDs
1 byte       | Network count   | Number of SSIDs found (max 16)
N × 61 bytes | Network slots   | Fixed-width blocks (see below)
0–3 bytes    | Padding         | Zeros to DWORD-align
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
Offset | Size    | Field           | Description
-------|---------|-----------------|--------------------------------------------------
0      | 6 bytes | BSSID           | AP MAC address
6      | 1 byte  | Privacy flags   | Unreliable — set on almost all networks. Use byte 42.
7      | 1 byte  | SSID length     | 0–32. Length=0 means hidden SSID.
8      | 32 bytes| SSID            | Network name, null-padded
40     | 1 byte  | Network mode    | 0x00=softAP/test, 0x02=infrastructure.
       |         |                 | Ad-hoc value unseen in captures.
41     | 1 byte  | Channel         | AP channel number
42     | 1 byte  | Security status | 0x02=Privacy bit NOT set in beacon (open/WEP-open)
       |         |                 | 0x04=Privacy bit SET in beacon (WEP/WPA/WPA2)
43     | 1 byte  | Rate indicator  | 0x01 when byte 42=0x02, 0x06 when byte 42=0x04.
       |         |                 | Correlates with rate set size
44     | 1 byte  | Signal/RSSI     | 0–255 scaled
45     | 8 bytes | Supported rates | table of supported rate codes
53     | 8 bytes | Padding         | Zeros to reach 61-byte stride
```


**Factory Reset Default Network**:
When a factory reset is performed the adapter defaults to SSID "mshome", channel 1, infrastructure mode, IP 192.168.2.252/24, rate capability 0x0B (11 Mbps), no security, with all WEP keys cleared.

**⚠ Stale cache behaviour**: If the current scan returns zero networks, the adapter falls back to the previous scan's results and returns those instead. The adapter never sends an empty network list — it always returns the last successful scan.

### Network mode field (Byte 40)
```
⚠ Wire-verified across lysten_* captures. Values 0x01/0x06/0x09 do NOT appear at byte 40.

 Value | Meaning
-------|--------------------------------------------------
 0x00  | softAP / test AP (observed on software access points)
 0x02  | Infrastructure BSS (real AP)
 other | Ad-hoc — not observed in captures, expected non-zero
```
Dash validation guard: value must be ≤ 2 or the entire slot entry is rejected.

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

**Note**: byte 44 signal RSSI has custom scaling see [Signal strength / link quality scaling)](Signal strength / link quality scaling)

**Hidden SSID handling**: SSID length=0 indicates a hidden network. The Xbox ignores these on first scan; the user can manually enter the SSID to trigger a directed probe.

### Real Example

```
[Network Slot — "Kids2.4g"] — 61 bytes total
Offset | Hex                                            | Field
-------|------------------------------------------------|-------------------
0–5    | b6 b0 24 59 b8 0a                              | BSSID
6      | 01                                             | Privacy flags (unreliable)
7      | 08                                             | SSID length (8)
8–15   | 4b 69 64 73 32 2e 34 67                        | "Kids2.4g"
16–39  | 00 × 24                                        | SSID padding
40     | 02                                             | Network mode (0x02 = infrastructure)
41     | 01                                             | Channel 1
42     | 02                                             | Security status (Privacy bit not set — open)
43     | 01                                             | Rate indicator
44     | d9                                             | Signal/RSSI (0xD9 = strong signal)
45–52  | 0c 12 18 24 30 48 60 6c                        | Supported rates: 6,9,12,18,24,36,48,54 Mbps
53–60  | 00 00 00 00 00 00 00 00                        | Padding
```

---

## Type 0x05 — ADAPTER_INFO_REQUEST

**Direction**: Xbox → Adapter  
**Transport**: NLB (EtherType 0x886f)

Requests a set of TLV tags from the adapter. Tags are specified as `[Tag][Length Hint]` pairs.

```
Total size: Variable (14 Ethernet + XPP header + 1 tag count + tag payload + Padding)
Body size:  Variable (12 + 1 + (tag pairs) + padding) / 4 DWORDs

Size     | Segment       | Description
---------|---------------|----------------------------------------------
14 bytes | Ethernet hdr  | Standard
12 bytes | XPP header    | type=0x05, body=variable DWORDs
1 byte   | Tag count     | Number of [Tag][Length Hint] pairs
Variable | Tag pairs     | Array of [1-byte Tag][1-byte Length Hint]
0–3 bytes| Padding       | Zeros to DWORD-align
```

The length hint is advisory — the firmware ignores it and uses hardcoded response lengths.
Unknown tags cause a buffer corruption side effect (see Type 0x06) and should be avoided.

### Example: Request tags 0x01, 0x04, 0x11

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

See the Type 0x06 Tag Table for a full list of available tags.

---

## Type 0x06 — ADAPTER_INFO_RESPONSE

**Direction**: Adapter → Xbox  
**Transport**: NLB (EtherType 0x886f)

Response to a Type 0x05 request. Tags are returned as a TLV stream. Tags are only present if they have valid data — parse as a stream, not at fixed offsets.
Requests a set of TLV tags from the adapter. Tags are specified as `[Tag][Length][data}`.
```
Total size: Variable (14 Ethernet + 12 XPP Header + 2 artifact + Payload + padding) = N bytes
Body size:  Variable (12 XPP header + 2 artifact + payload + padding) / 4 = N DWORDs

Size     | Segment          | Description
---------|------------------|----------------------------------------------
14 bytes | Ethernet header  | Standard
12 bytes | XPP header       | type=0x06, body=variable DWORDs
1 byte   | Firmware artifact| Always 0x00 — skip before parsing TLV stream
1 byte   | Tag count echo   | Echoes the count from the Type 0x05 request
Variable | TLV stream       | [Tag][Length][Value] triplets
0–3 bytes| Padding          | Zeros to DWORD-align
```

If a requested tag has no data (e.g. Tag 0x01 when no IP is assigned), it is omitted entirely from the response. Subsequent tags slide to fill the gap.


### Example: Response tags 0x01, 0x04, 0x111
this example shows an example response from prior request example in type 0x05.
```
00 03          04 01 00 11 01 01
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

### Tag Table (Types 0x05 / 0x06)

```
Tag  | Name               | Size | Condition       | Description
-----|--------------------|------|-----------------|---------------------------------------------------
0x01 | IP address         | 4    | IP assigned     | Current adapter IP (big-endian)
0x02 | Connection state   | 1    | Always          | 0x00=no DHCP, 0x01=DHCP acquired, 0x02=static/manual
0x03 | Admin password     | Var  | Always          | XPP admin identity password (max 16 bytes).
     |                    |      |                 | Factory default "admin". Also used as TFTP WRQ auth input.
0x04 | Radio active flag  | 1    | Always          | 0x00=radio off, 0x01=radio on (b-only), 0x02=radio on (b+g)
0x05 | Radio channel      | 1    | Always          | Returns live channel when associated, or saved channel otherwise
0x06 | BSSID              | 6    | If connected    | Current AP MAC, or 00:00:00:00:00:00 if not connected
0x07 | SSID               | Var  | If associated   | Byte 0=length, Bytes 1..N=SSID string
0x08 | Auth type          | 1    | Always          | RESP: 0x02=open/no WEP, 0x04=WEP active (wire-verified).
     |                    |      |                 | REQ hint: 0x00=open/WEP, 0x10=WPA radio on, 0x20=WPA radio off.
     |                    |      |                 | See Tag 0x08 subsection for full decode.
0x09 | Enc type echo      | 1    | Always          | RESP: 0x01=open, 0x02=WEP-64, 0x04=WEP-128 (wire-verified).
     |                    |      |                 | Values 0x00 and >0x04 are rejected. Not a link state in this context.
     |                    |      |                 | See Tag 0x09 subsection for full decode.
0x0A | WEP key slot 0     | —    | WRITE-ONLY      | ⚠ No read handler.
0x0B | WEP key slot 1     | —    | WRITE-ONLY      | ⚠ No read handler.
0x0C | WEP key slot 2     | —    | WRITE-ONLY      | ⚠ No read handler.
0x0D | WEP key slot 3     | —    | WRITE-ONLY      | ⚠ No read handler.
0x0E | Current channel    | 1    | Radio active    | Live channel via hardware (1–14)
0x0F | WEP-128 key        | —    | WRITE-ONLY      | ⚠ No read handler.
0x10 | WPA PMK            | —    | WRITE-ONLY      | ⚠ No read handler.
0x11 | Encryption type    | 1    | Always          | 0x00=no encryption, 0x02=WEP/encryption active


0x81 | Adapter MAC        | 6    | Always          | Adapter's own Ethernet MAC address
0x82 | Regulatory domain  | 1    | Always          | Domain code from hardware EEPROM (see table below)
0x83 | Net reset param    | 1    | Always          | Current reconnect mode value (read-back of Tag 0x83 write)
0x84 | channel            | 1    | Always          | Configured or saved channel
0x85 | TX rate code       | 1    | If associated   | Current PHY speed — see rate code table
0x86 | EEPROM block 0     | 512  | Radio off only  | AR5212 EEPROM bytes 0x000–0x1FF
0x87 | EEPROM block 1     | 512  | Radio off only  | AR5212 EEPROM bytes 0x200–0x3FF
0x88 | EEPROM block 2     | 512  | Radio off only  | AR5212 EEPROM bytes 0x400–0x5FF
0x89 | EEPROM block 3     | 512  | Radio off only  | AR5212 EEPROM bytes 0x600–0x7FF
```

**⚠ Write-only tags (0x0A–0x0D, 0x0F, 0x10)**: These have no read handler. Including them in a read request corrupts the response for that tag entry (a stale byte is decremented and written back). Subsequent tags in the same request are unaffected. Do not include these in ADAPTER_INFO_REQ.

**⚠ EEPROM tags (0x86–0x89)**: Never requested by the Xbox dashboard. Intended for the PC-side setup wizard. The radio must be inactive (Tag 0x04 = 0x00) or the read will return 0xFF-filled data. The TLV length byte for these tags is `0xFF` (indicating a 512-byte extended block).

## Tag 0x02 Connection State
This byte indicates the connection state to the upstream router or network.
```
Return | Meaning
-------|----------------------------
0x00   | Interface up, no DHCP yet
0x01   | DHCP acquired (fully connected)
0x02   |  Static IP / manual mode
```

### Tag 0x08 Auth Type

Tag 0x08 has different values depending on direction. The dash sends a hint in ADAPTER_INFO_REQ; the adapter returns a status in ADAPTER_INFO_RESP. These are not the same encoding.

**ADAPTER_INFO_RESP (adapter → dash) — wire-verified across all captures:**

The value feeds `xpp_select_best_security_mode()` as `param_1`. Only bits `0x10` and `0x20` gate the WPA path; all other bits are ignored by that function.

```
Return | Meaning                          | Effect in dash
-------|----------------------------------|---------------------------------------------
0x02   | Open network / no WEP            | Downgrade path — enc_type from Tag 0x09
0x04   | WEP active (any key length)      | Downgrade path — enc_type from Tag 0x09
0x10   | WPA active, infrastructure       | WPA path — enc_type=4 (requires byte 174 bit 0x10 set in handshake)
0x20   | WPA active, open-system auth     | WPA path — enc_type=4 (requires byte 174 bit 0x10 set in handshake)
```

Note: `0x10` and `0x20` are only effective if the handshake response byte 174 had bit `0x10` set (`cap_wpa1_rsn` non-zero). Without that, the WPA bits in Tag 0x08 are silently ignored and the downgrade path fires regardless.

**ADAPTER_INFO_REQ (dash → adapter) — hint only, decompile-verified:**

The dash encodes this using `xpp_encode_tag08_auth_type(enc_type, radio_active)`. The adapter is not required to echo this value back.

```
Value | Meaning
------|-------------------------------------------
0x00  | Open/WEP (enc_type 1, 2, or 3)
0x10  | WPA active, radio on  (enc_type=4, radio_active != 0)
0x20  | WPA active, radio off (enc_type=4, radio_active == 0)
```

### Tag 0x09 Encryption Type Echo

**This tag has completely different meanings in ADAPTER_INFO_RESP vs CONNECT_REQ.** In ADAPTER_INFO_RESP it is an encryption cipher echo, not a link state. The link state values (`0x01=disassociate`, `0x02=infra`, `0x04=ad-hoc`) belong to CONNECT_REQ Tag 0x09 only.

**ADAPTER_INFO_RESP (adapter → dash) — wire-verified across all captures:**

The value feeds `xpp_select_best_security_mode()` as `param_2`. It is only consulted when Tag 0x08 has no WPA bits set (bits `0x10`/`0x20` both clear).

```
Return | Meaning          | Guard
-------|------------------|-----------------------------------------------
0x00   | —                | REJECTED — entire ADAPTER_INFO_RESP discarded
0x01   | Open / no cipher | Pass — enc_type = 1 (Open)
0x02   | WEP-64 active    | Pass — enc_type = 2 (WEP-64)
0x03   | —                | Pass (accepted but unmatched — falls to Open)
0x04   | WEP-128 active   | Pass — enc_type = 3 (WEP-128)
0x05+  | —                | REJECTED — entire ADAPTER_INFO_RESP discarded
```

For WPA connections (Tag 0x08 = `0x10` or `0x20`): Tag 0x09 is never read by `xpp_select_best_security_mode` since the function returns enc_type=4 immediately. However the value must still pass the guard (`0x01`–`0x04`) or the response is discarded before the function is reached. Send `0x01` for WPA.

### Regulatory Domain Codes (Tag 0x82)

```
Value | Region         | Allowed channels
------|----------------|------------------
0x10  | USA/Canada     | 1–11
0x20  | Canada         | 1–11
0x30  | ETSI           | 1–13
0x31  | Spain          | 10–11
0x32  | France         | 10–13
0x40  | Japan          | 14 only
0x41  | Japan all      | 1–14
other | Unknown        | 1–11 (default)
```

### TX Rate Codes (Tag 0x85)

```
Code  | Rate     | Standard
------|----------|----------
0x00  | Auto     | —
0x02  | 1 Mbps   | 802.11b
0x04  | 2 Mbps   | 802.11b
0x0B  | 5.5 Mbps | 802.11b
0x16  | 11 Mbps  | 802.11b
0x0C  | 6 Mbps   | 802.11g
0x12  | 9 Mbps   | 802.11g
0x18  | 12 Mbps  | 802.11g
0x24  | 18 Mbps  | 802.11g
0x30  | 24 Mbps  | 802.11g
0x48  | 36 Mbps  | 802.11g
0x60  | 48 Mbps  | 802.11g
0x6C  | 54 Mbps  | 802.11g
```

### AR5212 EEPROM Dump (Tags 0x86-0x89)
These tags return the contents of the Atheros AR5212 radio chip's
onboard serial EEPROM The EEPROM is a separate 2KB
chip on the AR5001X MAC/baseband board that holds factory-calibrated radio data burned at
manufacture time.

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

**Special notes**:
- The TLV Length Byte in the response is `0xFF` — a protocol signal indicating an
  "Extended Data Block" of 512 bytes follows, since 512 > 255 (the normal 1-byte length
  maximum).
- The radio must be inactive (tag 0x04 = 0x00) for the EEPROM read to succeed. Querying
  these tags while the radio is associated will return 0xFF-filled blocks.

### Wire Example (Open network, channel 3, WAN connected)

```
Raw payload (after XPP header):
00 09 | 01 04 c0 a8 01 96 | 02 01 00 | 04 01 01 | 05 01 03 |
06 06 c4 4b d1 00 47 4e | 07 04 6f 70 65 6e | 08 01 02 | 09 01 01 | 11 01 02

Decoded:
  Payload           | Meaning
--------------------|--------------------------------------------------
 00                 | Firmware artifact (skip)
 09                 | 9 tags follow
 01 04 c0a80196     | Tag 0x01: IP 192.168.1.150
 02 01 00           | Tag 0x02: DHCP state 0x00
 04 01 01           | Tag 0x04: Radio active
 05 01 03           | Tag 0x05: Channel 3
 06 06 c44bd100474e | Tag 0x06: BSSID c4:4b:d1:00:47:4e
 07 04 6f70656e     | Tag 0x07: SSID "open"
 08 01 02           | Tag 0x08: Auth type open (0x02=open/no WEP)
 09 01 01           | Tag 0x09: Enc type open (0x01=no cipher — DHCP state machine not at 0x52 yet)
 11 01 02           | Tag 0x11: Encryption type 0x02 (set by prior CONNECT_REQ)
```

#### Tag 0x08 in ADAPTER_INFO_RESP — Auth Type

Reports the live 802.11 authentication state. Wire-verified across all captures. This is different from Tag 0x08 in CONNECT_REQ (Type 0x07) where it sets the requested 802.11 auth algorithm, and different from the hint value the dash sends in ADAPTER_INFO_REQ.

The value feeds `xpp_select_best_security_mode()` as `param_1` together with Tag 0x09 as `param_2`. Together they produce the internal `enc_type` (1–4) that drives all subsequent security decisions.

```
Value | Meaning                     | Source in firmware
------|-----------------------------|----------------------------------------------------
0x02  | Open network (no WEP)       | Wire-verified: all open captures
0x04  | WEP encryption active       | Wire-verified: all WEP-64 and WEP-128 captures
0x10  | WPA active, infrastructure  | Decompile only — not seen on wire from stock firmware
0x20  | WPA active, open-system     | Decompile only — not seen on wire from stock firmware
```

Tags 0x08 and 0x09 together report the **NVRAM-configured** state. Tag 0x11 separately reports the **live HAL** state. These can differ during association — for example, an adapter mid-WEP-association will report `tag08=0x04` (WEP configured) and `tag11=0x00` (HAL not yet encrypting) simultaneously.

---

## Type 0x07 — CONNECT_TO_SSID_REQUEST

**Direction**: Xbox → Adapter  
**Transport**: NLB (EtherType 0x886f)

Configures the adapter's connection profile and triggers connection. Settings are saved to NVRAM.

### Packet Format

```
Total size: Variable (14 Ethernet + 12 Header + Payload + padding) = N bytes
Body size:  Vairable (12 XPP header + payload + padding) / 4 = N DWORDs

Size     | Segment       | Description
---------|---------------|----------------------------------------------
14 bytes | Ethernet hdr  | Standard
12 bytes | XPP header    | type=0x07, body=variable DWORDs
1 byte   | TLV count     | Number of TLV tags that follow
Variable | TLV stream    | [Tag][Length][Value] triplets
0–3 bytes| Padding       | Zeros to DWORD-align
```

**Tag ordering**: Tags must appear in ascending numerical order. The parser makes a single forward pass with no backtracking. Unknown tags abort the entire parse — all subsequent tags in the same packet are silently ignored. Do not send unrecognised tags.

### Type 0x07 Tag Table

```
Tag  | Name                | Size  | Description
-----|---------------------|-------|-----------------------------------------------------------
0x00 | Save & reboot       | 0     | Saves current config to flash and triggers reboot
0x01 | IP address          | 4     | Static IP address (big-endian)
0x02 | Connection state    | 1     | 0x02=enable interface, any other=disable
0x03 | Admin password      | 0–16  | XPP admin password. Len=0 clears the password.
     |                     |       | Factory default "admin". Max 16 printable ASCII chars.
0x04 | Operating mode      | 1     | 0x00=disable radio, 0x01=enable radio
0x05 | channel             | 1     | saved or actual wifi channel.
0x06 | Target Xbox MAC     | 6     | MAC address of the paired Xbox console
0x07 | Target SSID         | 1–32  | Network SSID to connect to
0x08 | Security mode       | 1     | WEP/security flag written to hardware
0x09 | Link state          | 1     | 0x01=disassociate/idle, 0x02=infrastructure connect,
     |                     |       | 0x04=ad-hoc connect
0x0A | WEP key slot 0      | 5     | WEP-40 5-byte key for slot 0
0x0B | WEP key slot 1      | 5     | WEP-40 5-byte key for slot 1
0x0C | WEP key slot 2      | 5     | WEP-40 5-byte key for slot 2
0x0D | WEP key slot 3      | 5     | WEP-40 5-byte key for slot 3
0x0E | Radio channel       | 1     | Active Wi-Fi channel (required for ad-hoc)
0x0F | WEP-128 key         | 13    | 13-byte WEP-128 key written to all 4 slots
0x10 | WPA PMK             | 32    | 32-byte Pairwise Master Key (from 64-hex user input).
     |                     |       | ⚠ Stock firmware discards this — see WPA section.
0x11 | Auth mode flag      | 1     | Sets saved encryption state. 0x00=no encryption,
     |                     |       | 0x02=encryption active. Other values silently ignored.
0x12 | WPA passphrase      | 8–63  | ASCII WPA passphrase.
     |                     |       | ⚠ Stock firmware has no handler — aborts parse loop.

Only tags 0x00-0x12 are processed by the xonlinedash.xbe
```

## special function and device specific tags

```
Xbox networking tags
Tag  | Name                | Size  | Description
-----|---------------------|-------|-----------------------------------------------------------     
0x14 | MAC clone           | 6     | MAC address to spoof.
     |                     |       | No handler in stock firmware's Type 0x07 parser —
     |                     |       | MAC cloning operates implicitly via the HANDSHAKE path.

Mn-740 specific
Tag  | Name                | Size  | Description
-----|---------------------|-------|-----------------------------------------------------------  
0x81 | Session MAC init    | 6     | Register Xbox MAC as trusted peer, initialise session
0x82 | Interface reset     | 1     | 0x00=skip disconnect, go straight to MAC reinit.
     |                     |       | Non-zero=disconnect first then reinit.
0x83 | Net reset param     | 1     | Reconnect mode (0, 1, or 2). Factory default 1.
0x84 | Saved channel       | 1     | Stored channel value — reported as current channel when radio not associated (read-back of Tag 0x84 write)
0x85 | TX rate code        | 1     | Force TX rate. Invalid codes silently dropped.

WGA54G specific tags (not confirmed fully)
Tag  | size  | Description
-----|-------|-----------------------------------------------------------  
0x13 | 1-32  | WAN connection type
0x14 | 1-32  | WAN username (PPPoE)
0x15 | 1-32  | WAN password (PPPoE)
0x16 | 4     | WAN IP (static)
0x17 | 4     | WAN subnet mask
0x18 | 4     | WAN gateway
0x19 | 4     | Primary DNS
0x1a | 4     | Secondary DNS
0x1b | 2     | MTU
0x1c | 6     | WAN MAC clone
0x1d | 1     | Interface reset
0x1e | 1     | Net reset param
0x1f | 1     | Max channel ceiling
0x20 | 5     | WEP key slot 3
0x21 | 13    | WEP key slot 4 / WEP-128
0x22 | 1     | TX rate code
0x23 | —     | Silently dropped
0x24 | —     | Silently dropped
0x25 | —     | Silently dropped
0x26 | 1     | UPnP enable flag
0x27 | 1     | Firewall enable flag
0x28 | —     | Silently dropped
0x29 | —     | Silently dropped
0x2a | —     | Silently dropped
0x2b | —     | Silently dropped
0x2c | —     | HMAC auth block
0x2d | —     | HMAC auth block
0x2e | —     | HMAC auth block (string ref confirmed)
0x2f | —     | HMAC auth block
0x30 | —     | HMAC auth block
0x31 | —     | HMAC auth block
0x32 | —     | HMAC auth block
0x33 | —     | HMAC auth block
0x34 | —     | Default/error → no-op
0x35 | 1-4   | DHCP server config
```

**Tag 0x10 stub**: Stock firmware advances the parse pointer past the 34-byte tag (1 tag + 1 len + 32 data) but does not store the PMK. See [WPA/WPA2 Implementation](#wpawpa2-implementation).

**Tag 0x12 parse abort**: Stock firmware has no `case 0x12`. It logs "got_unknown" and exits the TLV loop immediately. Any tags after Tag 0x12 in the same packet are not processed.

**Tags above 0x12** are never sent by the Xbox dashboard, They are management tags for factory/ future purpose.

**Note** The dashboard has two separate code paths for WPA key input Which tag is sent depends
entirely on what the user typed at the on-screen keyboard.

If the user enters Exactly 64 hex-digits the dashboard sends the pre computated pmk directly via Tag 0x10.
if the user enters 8-63 ACSII characters the dashboard sends the raw passphrase via Tag 0x012


### Tag 0x03 — Admin Password

The admin password prevents other consoles from reconfiguring a paired adapter. When set, the adapter's TFTP WRQ auth on port 16932 uses this string as the HMAC input. Factory default is `"admin"`.

```
Set:   Tag 0x03, len=N, val="newpassword"
Clear: Tag 0x03, len=0x00
```

### Tag 0x04 Operating mode
This byte sets the operation mode of the radio

```
Hex  | Description
-----|-------------
0x00 | Disable radio
0x01 | Enable radio
```

### Tag 0x08 Security Mode (CONNECT_REQ)

Sets the 802.11 authentication algorithm the adapter should use for the connection. This is the authentication handshake method, not the encryption cipher.

Encoded by the dash using `xpp_encode_tag08_auth_type(enc_type, shared_key_flag)`.

```
Value | Meaning                                         | Wire seen
------|-------------------------------------------------|----------
0x00  | Open System authentication                      | Yes — all open and WEP open-auth captures
0x10  | WPA + Shared Key 802.11 auth (enc_type=4, shared_key=1) | WPA only
0x20  | WPA + Open System 802.11 auth (enc_type=4, shared_key=0)| WPA only
```

Note: `0x00` is sent for both open networks AND WEP connections using open-auth (the most common WEP mode). The presence of WEP keys in tags `0x0A`–`0x0D` or `0x0F` indicates WEP encryption regardless of this field's value.

---

### Tag 0x09 (XPP_Set_Link_State)
this tag is used to set the connection type and state.

```
Val  | Meaning
-----|------------------------
0x01 | Disassociate / go idle
0x02 | Infrastructure connect
0x04 | Ad-Hoc connect
```
### Tag 0x0E - Ad-hoc radio channel
This tag is used as the channel used in the setup Of an Ad-hoc network.
This is used more for the hosting device that sets up the initial connection,
Any other device join an existing Ad-hoc network will ignore this and scan for the SSID in the connect request and use the channel found during scan to setup the network.
valid values depends on the country code stored in the EEPROM from factory.

```
Value | Region                  | Allowed Channels (2.4 GHz)
------|-------------------------|-----------------------
0x00  | USA / Canada (FCC)      | 1-11
0x01  | Japan (TELEC)           | 1-14
0x02  | Europe (ETSI)           | 1-13
0x03  | Australia / New Zealand | 1-13
0x04  | Korea                   | 1-13
```

**Ad-hoc channel limits:**

The Ad-hoc channel creation option in the Xbox UI shows channels 1–12. This is a hardcoded limit of the dash.
this limit is completely independent of byte `Channel allow list bitmaskt`

When joining (not creating) an ad-hoc network, the channel comes from the SCAN_RESP entry,
this means if a device creates a network outside of channels 1-12 the Xbox can join the network by setting up the Ad-hoc network with the same SSID .

Additionally the dash has a guard that will downgrade a WPA connection to open
if WPA2 enterprise capability is absent, it is believed this is to minimize the risk of loosing BSS sync.

### Tag 0x10 — WPA PMK
This field IS the WPA Pairwise Master Key (PMK) entry.

### Tag 0x12 — WPA Passphrase
This field IS the WPA ASCII key entry.

**Tag 0x12 Wire Format**:
```
Offset | Size  | Field      | Description
-------|-------|------------|------------------
0      | 1     | Tag        | 0x12
1      | 1     | Length     | 8–63 (WPA2 passphrase length)
2-N    | 8-63  | Passphrase | Raw ASCII passphrase (0x20–0x7e only)
```

### Tag 0x14 — MAC Address Cloning
MAC cloning makes the Xbox and adapter appear as a single device to the router, solving NAT and MAC-filter issues. Rather than sending Tag 0x14 in a Type 0x07 packet, the Xbox NIC driver changes its source MAC to the cloned address. The adapter then implicitly registers this MAC during the handshake:

1. Xbox NIC broadcasts HANDSHAKE_REQ from the cloned MAC
2. Adapter stores the cloned MAC as the paired console identity
3. Adapter re-initialises the WLAN interface using the cloned MAC as its transmitter address
4. Router sees one consistent MAC for both Wi-Fi association and DHCP

The HMAC computation always uses the adapter's own hardware MAC as input, not the cloned identity. Tag 0x82 (Interface Reset) with a non-zero value will restore the hardware MAC.

This can also be used to bypass MAC based filtering blocks.

**Alternative use case (2004):** PPPoE-based MAC authentication.
Cloning the PC's MAC bypassed ISP MAC-lockout by making the device present as the official paired device.
With a normal home router the ISP never sees the Xbox MAC — the router's WAN MAC
is what the ISP sees. The MAC clone still benefits router-side DHCP/MAC filtering.

**Format**: 6-byte MAC address in standard network byte order.

### Tag 0x81 — Session MAC Init (hardware pairing)
This tag sets the MAC included in this payload as the trusted device for all communication, all other devices will be ignored even if they send a valid handshake, the Xbox will respond all communication to this MAC.
**Function**: `XPP_Establish_Secure_Identity_Link(p_mac_addr)`:
1. Calls `Net_Init_Socket_Logic(p_mac_addr, 6)` to validate/register the MAC.
2. If successful: calls `NET_Register_Peer_MAC(p_mac_addr)` to store the Xbox MAC as the trusted peer.
3. Sets `g_XPP_Current_Session_ID = XPP_Get_Identity_Token()` to start a new authenticated session.

**Note** The HMAC-SHA1 session authentication in HANDSHAKE derives from this peer MAC, be very at carefull when setting value as this can Softbrick the adaptor if you are unable to reply from the address paired to unset the pairing.

## Tag 0x82 — Interface Reset/Reinit
```
Value  | Meaning
-------|----------------------------------
= 0x00 | Skip disconnect_interface_handle(), go straight to MAC reinit
≠ 0x00 | First call disconnect_interface_handle(0, value) (tear down with that reason code), then reinit
```
**Note**: After the conditional disconnect, the firmware calls `NET_Reinit_Interface_With_MAC()` which reinitializes the WLAN interface using the hardware MAC from `ath_hal_get_hw_info()`. If that returns an all-zero MAC (hardware failure), the reinit step is silently skipped. This is one mechanism for **undoing MAC address spoofing** — reinit restores the hardware MAC.

### Tag 0x84 — Saved Channel / HTTP UI Channel

`g_CFG_Max_Channel` stores the last configured channel, persisted to NVRAM via `Flash_Commit_Settings`.

**What it actually does:**
- Read by `XPP_Get_Channel_Or_Fallback()` as the reported channel in HANDSHAKE_RESP byte 217 and Tag 0x05 response **when the radio is not currently associated**. When the radio is associated, the live channel from `wlan_freq_to_channel_number()` is returned instead.
- Displayed in the HTTP web UI channel dropdown via `net_spinlocked_global_state_reset()`.
- Returned verbatim by Tag 0x84 in ADAPTER_INFO_RESP as a read-back of the stored value.
- Initialised to `0x0b` (channel 11) on factory reset.

**What it does NOT do:**
- It is never consulted during scanning, connection, or channel selection.
- It has no interaction with the handshake channel bitmask (bytes 180–207).
- It does not enforce regulatory channel limits on the radio.

The handshake channel bitmask is the actual regulatory mechanism. Tag 0x84 and the bitmask are completely independent systems that never interact. For an emulator, Tag 0x84 is effectively a no-op — accept the write, store it, return it on read-back.

**Write clamping**: Values written outside the hardware EEPROM's regional min/max are clamped to `0x0b` (channel 11). This only affects the stored value — it does not influence radio behaviour.

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

### Examples:

**Open network** (`lysten_open_ch9_b.log` Pkt#19):
```
Raw (60 bytes):
  0000: 00 12 5a 33 fa 31 00 0d 3a 50 22 73 88 6f 58 42
  0010: 4f 58 01 01 09 07 bf dc 87 0a 04 07 0b 6f 70 65
  0020: 6e 5f 63 68 39 5f 62 67 08 01 00 09 01 01 11 01
  0030: 00 00 00 00 00 00 00 00 00 00 00 00

XPP type=0x07, TLV count=4
  Tag 0x07 SSID         len=11  "open_ch9_bg"
  Tag 0x08 Sec mode     len=1   0x00  (open)
  Tag 0x09 Link state   len=1   0x01  (disassociate/idle)
  Tag 0x11 Auth mode    len=1   0x00  (no encryption)
  Padding: 00 00 00 00 00 00 00 00 00 00 00 00
```

**WEP-64 ASCII with 4 key slots** (`lysten_wep64_ch9_b.log` Pkt#15):
```
Raw (78 bytes):
  0000: 00 12 5a 33 fa 31 00 0d 3a 50 22 73 88 6f 58 42
  0010: 4f 58 01 01 10 07 db 02 46 01 08 07 0c 77 70 61
  0020: 5f 36 34 5f 63 68 39 5f 62 08 01 00 09 01 02 0e
  0030: 01 01 0a 05 61 62 63 64 65 0b 05 61 62 63 64 65
  0040: 0c 05 61 62 63 64 65 0d 05 61 62 63 64 65

XPP type=0x07, TLV count=8
  Tag 0x07 SSID         len=12  "wpa_64_ch9_b"
  Tag 0x08 Sec mode     len=1   0x00
  Tag 0x09 Link state   len=1   0x02  (infrastructure connect)
  Tag 0x0E Radio ch      len=1  0x01  (channel 1)
  Tag 0x0A WEP key 0    len=5   61 62 63 64 65  ("abcde")
  Tag 0x0B WEP key 1    len=5   61 62 63 64 65
  Tag 0x0C WEP key 2    len=5   61 62 63 64 65
  Tag 0x0D WEP key 3    len=5   61 62 63 64 65
```

**Set admin password** (`lysten_password.log` Pkt#9):
```
Raw (60 bytes):
  0000: 00 0d 3a 1f 26 09 00 0d 3a 50 22 73 88 6f 58 42
  0010: 4f 58 01 01 07 07 7b c4 d8 a4 01 03 0a 61 61 62
  0020: 62 63 63 64 64 65 65 00 00 00 00 00 00 00 00 00
  0030: 00 00 00 00 00 00 00 00 00 00 00 00

XPP type=0x07, TLV count=1
  Tag 0x03 Admin pwd    len=10  "aabbccddee"
```

Beacons/multicast cap at 2 Mbps
unicast cap at 11 Mbps
ARF steps up to 11 Mbps ceiling
These rates are a hardcoded firmware limitation designed to ensure BSS stability and prevent 'Hidden Node' collisions during System Link play.

## Clock Synchronization:
Ad-Hoc peers rely on TSF (Timing Synchronization Function) found in beacons to keep their hardware clocks in sync. If these were sent at 54 Mbps, a peer at the edge of the range might miss them, causing the Ad-Hoc network to "split."

Because Ad-Hoc networks lack a central Access Point to manage "Hidden Nodes" (where two Xboxes can see the host but not each other). High-speed OFDM (54 Mbps) is very sensitive to collisions. By capping the data at 11 Mbps (DSSS/CCK), the signal is much more "penetrating" and less likely to drop frames during intense System Link play.

**Related**: Tag 0x82 (`NET_Interface_Reset_And_Reconnect`) calls `NET_Reinit_Interface_With_MAC()`
which restores the hardware MAC from `ath_hal_get_hw_info()` — this clears the clone and restores
the real identity.

---

## Type 0x08 — CONNECT_TO_SSID_RESPONSE

**Direction**: Adapter → Xbox  
**Transport**: NLB (EtherType 0x886f)

Confirms the connection request result.

### Packet Format

```
Total size: 30 bytes (14 Ethernet + 12 XPP + 1 payload + 3 padding)
Body size:  0x04 DWORDs

Size     | Segment         | Description
---------|-----------------|-----------------------------------------------
14 bytes | Ethernet header | Standard
12 bytes | XPP header      | type=0x08, body=0x04 DWORDs
1 byte   | Result code     | See table below
3 bytes  | Padding         | Zeros
```

### Result Codes

```
Code | Description
-----|------------------------------------------------------------------
0x00 | Success — connection accepted and config committed (wire-verified)
0x01 | Rejection / error
0x02 | Retry requested — dashboard retries after ~8 seconds
0x03 | Rejection / error
0x04 | Error (connect-specific)
0x05 | Unconfirmed    | Timed Out
0xFF | Unconfirmed    | General error
```

---

## Type 0x09 — BEACON_REQUEST

**Direction**: Xbox → Adapter  
**Transport**: NLB (EtherType 0x886f)

Keepalive heartbeat. Sent every 1 second while connected.

### Packet Format

```
Total size: 26 bytes (14 Ethernet + 12 XPP)
Body size:  0x03 DWORDs

Size     | Segment         | Description
---------|-----------------|-----------------------------
14 bytes | Ethernet header | Standard
12 bytes | XPP header      | type=0x09, body=0x03 DWORDs
```

**Timing**: Sent every 1 second. If no response is received for 5 seconds the adapter enters standby mode. The adapter also has a 30-second watchdog — if no Ethernet frame is received from the paired Xbox MAC for 30 seconds, the radio shuts down.
the adaptor monitors for any valid Packet to reset the watchdog timer.
If the watchdog timer should elapse the adaptor Requires full re-authentication (Type 0x01 handshake)

---

## Type 0x0A — BEACON_RESPONSE

**Direction**: Adapter → Xbox  
**Transport**: NLB (EtherType 0x886f)

Response to Type 0x09. Returns authentication status, signal strength, and current TX rate. Sent within ~100 ms of receiving a beacon request.

### Packet Format

```
Total size: 46 bytes (14 Ethernet + 12 XPP + 4 payload + 16 uninitialised padding)
Body size:  0x04 DWORDs

Size     | Segment         | Description
---------|-----------------|-----------------------------
14 bytes | Ethernet header | Standard
12 bytes | XPP header      | type=0x0A, body=0x04 DWORDs
4 bytes  | Payload         | See below
16 bytes | Firmware padding| Uninitialised memory — ignore
```

**⚠ The 16 bytes after the 4-byte payload are uninitialised memory, not part of the protocol.** The body size correctly covers only the 4-byte payload. Implementations should tolerate and ignore this trailing data.

### Payload Structure (4 bytes)

```
Offset | Size   | Field        | Values
-------|--------|--------------|----------------------------------------------------
0      | 1 byte | Auth status  | 0x00=authenticated, 0x01=associating,
       |        |              | 0x02=open/idle (also steady-state for open networks),
       |        |              | 0x03=WEP association in progress. Values >0x03 rejected.
1      | 1 byte | Smoothed RSSI| Signed byte. 0x80=pre-association default (-128).
       |        |              | 0xBA=seed value (-70) when not authenticated.
       |        |              | When associated: 10-sample rolling average.
       |        |              | See Signal Strength Scaling.
2      | 1 byte | TX rate code | Raw 802.11 rate code with basic-rate bit stripped (& 0x7F).
       |        |              | See rate code table in Type 0x06.
       |        |              | Ad-hoc mode cap: maximum 0x16 (11 Mbps).
3      | 1 byte | Reserved     | Always 0x00 (may differ during transient states)
```

### Auth Status (Byte 0)
```
Value | Meaning
------|------------------------------------------------------------
0x00  | Authenticated (also briefly seen mid-association on open networks)
0x01  | Associating
0x02  | Open/idle OR steady-state for open (unencrypted) connections
0x03  | WEP 802.11 association in progress (set after WEP CONNECT_REQ committed)
```

### Smoothed_rssi (Byte 1)

This byte shows the 10 sample rolling average rssi of the radio when authenticated.

```
return      | Description / Value
------------|---------------------
0x80        | pre seed buffer state (-128)
0xBA        | seed value (-70)
other       | smoothed RSSI value

```
**Note**: byte 44 signal RSSI has custom scaling see [Signal strength / link quality scaling)](Signal strength / link quality scaling)
Seed value `0xba` (-70) written explicitly when not authenticated
Value `0x80` (-128) is pre-association default; `g_RSSI_Smoothed_Output` is an
uninitialised global — `0x80` is not written by firmware, it reflects BSS/memory state.

### Raw 802.11 rate code (Byte 2)

This byte shows the current rate code of the current connection

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

### ⚠ Rate limit Cap
The firmware enforces a hardware rate cap in ad-hoc mode:
- **Not Linked**:     tx_rate_code = `0x16` (11 Mbps) — returned as the pre-association / not-yet-linked default rate
- **Infrastructure**: tx_rate_code = `0x6C` (54 Mbps) — No Rate limit
- **Ad-hoc**:         tx_rate_code = `0x16` (11 Mbps) — hardcoded ceiling
This is a deliberate firmware design decision for BSS stability and Hidden Node collision avoidance. See Tag 0x07 section for full explanation.


### reserved (Byte 3)
```
Result code | Description/ value
------------|---------------------
  0x00      | hardcoded reserved
```

---

## Types 0x0B, 0x0C, 0x0F — Silently Dropped

The adapter silently discards any frame with these type bytes.
No response is sent. This type is undocumented — it is an unused slot possibly for future expansion.

- **0x0B**: Discarded, internal counter incremented
- **0x0C**: Discarded, internal counter incremented  
- **0x0F**: Discarded with no log and no counter

---

## Type 0x11 — WPA_ASSOC / WPA_EXCHANGE

**Direction**: Bidirectional (Console ↔ Adapter)  
**Transport**: EAPOL (EtherType 0x888e)

Type 0x11 is the WPA authentication sub-protocol. It is **not** an XPP management packet — it has no XPP magic, no body size DWORD count, and no RFC 1071 checksum. It is bidirectional: the console sends WPA_ASSOC_REQ to begin, then the adapter drives the console through IP negotiation and ANonce exchange by sending its own type 0x11 frames.

currently no known adaptor uses the Type 0x011 WPA assoc exchange in practice as no knwn adaptor currently implements WPA this was likely a future feature that was just never implemented.


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

Size     | Field           | Value
---------|-----------------|------------------------------------------------
6 bytes  | Destination MAC | FF:FF:FF:FF:FF:FF (broadcast) or AP MAC (retry)
6 bytes  | Source MAC      | Console MAC
2 bytes  | Frame type word | 0x6388 normal, 0x123c for first packet of a retry pair
1 byte   | Type marker     | 0x11 (constant)
1 byte   | Sub-type        | Direction/state indicator (see tables below)
2 bytes  | Reserved        | 0x0000
2 bytes  | Length          | Big-endian total payload length
2 bytes  | Reserved        | 0x0000
Variable | Payload         | Sub-TLVs: [tag:1][len:1][data:len]
```

### Console → Adapter Sub-types

```
Sub-type | FSM State | Meaning
---------|-----------|--------------------------------------------------
0x09     | Initial   | WPA_ASSOC_REQ first attempt (broadcast)
0x19     | Retry     | WPA_ASSOC_REQ retry (unicast to AP MAC)
0x01     | Exchange  | Credential/IP exchange reply
```

### Adapter → Console Sub-types

```
Sub-type | Frame type | Meaning
---------|------------|--------------------------------------------------
0x01     | 0x21c0     | IP negotiation: challenge token + DHCP cookie
0x09     | 0x21c0     | ANonce delivery
0x01     | 0x2180     | Post-auth IP configuration: gateway + DNS(step 4)
0x01–0x04| any        | IP/DHCP negotiation variants (0x02–0x04 less common)
```

⚠️ **NEVER send sub-types 0x05, 0x07, or 0x08** — these are hardcoded to call `XPP_fsm_fatal_error` on the console, immediately aborting the WPA session. This is NOT a silent drop.

> **Sub-type byte derivation (source-verified):**
> `XPP_build_wpa_assoc_request` computes the sub-type as `(!bVar15 - 1U & 0xF0) + 0x19` where `bVar15 = (fsm_state == 0x11)`.
> - State 0x11 (bVar15=true): `(0 - 1) & 0xF0 = 0xF0`, `0xF0 + 0x19 = 0x109` → **byte truncates to `0x09`**
> - State 0x12 (bVar15=false): `(1 - 1) & 0xF0 = 0x00`, `0x00 + 0x19` = **`0x19`**
>
> The value `0xF9` is **mathematically impossible** from this expression for any bool input. Verified identically in both the XPP and XNET namespace copies of the function.

### WPA Connection State Machine overview (SubStates 0x11–0x15)

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

---

## HMAC-SHA1 Authentication

The HANDSHAKE_RESPONSE (Type 0x02) includes a 20-byte HMAC-SHA1 digest at payload offset 0. This proves the adapter is genuine — only firmware with the correct ROM key and master key string can produce a valid digest. The Xbox dashboard verifies this digest before accepting the response.

**Algorithm**: HMAC-SHA1 (RFC 2104)

**Static Key**: : ``cb275ff238ab61dc8799fa01ad17745e``
  Believed to decode to `"From isolation / Deliver me o Xbox, for I am the MN-740"` The method to decode this string remains unidentified.
**Memory Address**: `0x800bf520` (ROM/Static Data section in firmware)

**g_XPP_HMAC_MASTER_KEY**: `"From isolation / Deliver me o Xbox - / Through the ethernet
                 Copyright (c) Microsoft Corporation. All Rights Reserved."`
**Memory Address**: `0x800bc364` (ROM/Static Data section in firmware)

**SEC_AUTH_COPYRIGHT_POEM**: `"Device is Xbox Compatible. Copyright (c) Microsoft Corporation. All Rights Reserved."`
**Memory Address**: `0x800bc3dc` (ROM/Static Data section in firmware)

**Purpose**: g_XPP_HMAC_MASTER_KEY is a static ROM string used as part of the HMAC input message. Combined with the Xbox's random nonce and the paired router MAC, it ensures only genuine MN-740 firmware — which has this string hardcoded in ROM — can produce a valid HMAC digest. G_XPP_HMAC_Key is the actual HMAC signing key.

## HMAC-SHA1 Authentication


Input : [16 bytes] Random nonce from the HANDSHAKE_REQUEST
      + [6 bytes]  Adapter's own MAC address
      + [117 bytes] "From isolation / Deliver me o Xbox - / Through the ethernet\n
                    Copyright (c) Microsoft Corporation. All Rights Reserved."
      = 139 bytes total

Output: 20-byte SHA1 digest written at payload offset 0 of Type 0x02

The adapter only needs to sign — it never verifies incoming packets beyond the RFC 1071 header checksum.

### Authentication Flow

```
Xbox                                  Adapter
 |                                       |
 |── Type 0x01 [16-byte nonce] ─────────>|
 |                                       | compute HMAC(key, nonce + adapterMAC + masterKey)
 |<── Type 0x02 [20-byte digest + ...] ──|
 |                                       |
 | verify digest locally using same key  |
 | and same input construction           |
 | ✓ match → adapter is authentic        |
```

---

## Checksum Calculation (RFC 1071)

The checksum ensures that integrity of the data contained within the XPP payload

All NLB (EtherType 0x886f) packets carry an RFC 1071 checksum in XPP header bytes 10–11.

- Computed over `body_size × 4` bytes starting at the XPP header (offset 0 of the XPP header)
- The checksum field must be treated as `0x0000` during calculation
- If the checksum fails, the adapter silently drops the packet with no response
- Used in all types: 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A

---


### BBN Device Discovery Protocol
**Sources**: `trialupdate.pcapng` (wire), `NML_bin.c` + `BBN_Handle_Discovery_Task` assembler (firmware-verified)

Before TFTP begins, MSBNUpdate.exe uses a proprietary discovery protocol on UDP port 42424 to locate adapters and obtain their IP address. This is separate from XPP.

**Session participants (wire-verified):**
```
PC (MSBNUpdate.exe): 169.254.250.55, MAC 00:15:5d:01:0a:1b
Adapter (MN-740):    169.254.38.9,   MAC 00:0d:3a:1f:26:09
```

### Transport

The firmware opens **two separate UDP sockets** at boot

- RX socket: bound to port **42424** — receives queries
- TX socket: unbound ephemeral port sends responses to broadcast `255.255.255.255:42424`

Responses are broadcast (not unicast) so multiple PC listeners on the subnet can receive them simultaneously. The adapter's fixed response source port observed on the wire is **1204**.

### Discovery Query Packet (PC → broadcast:42424)

```
Offset | Size    | Value             | Description
-------|---------|-------------------|----------------------------------
0      | 4 bytes | 0x50 0x00 0x00 0x00| Type marker (required — firmware validates)
4      | 4 bytes | variable          | Flags/version
8      | 8 bytes | 0x00...           | Reserved
16     | 4 bytes | random            | Session nonce — echoed in response
```

The firmware checks that the incoming packet is **exactly 20 bytes** and that the first 4 bytes equal `50 00 00 00`. Any other format is rejected.

### Discovery Response Packet (Adapter → broadcast:42424, 126 bytes)

```
Offset | Size     | Field               | Description
-------|----------|---------------------|---------------------------------------------------
0x00   | 4 bytes  | Type marker         | 0x51 0x00 0x00 0x00
0x04   | 4 bytes  | Protocol version    | 0x00 0x00 0x00 0x01
0x08   | 4 bytes  | Factory default flag| 0x01000000=defaults active, 0x00000000=customised
0x0C   | 32 bytes | Long device name    | "MN-740 Bridge" null-padded
0x2C   | 32 bytes | Short model name    | "MN-740" null-padded
0x4C   | 4 bytes  | Device IP           | Big-endian IP address (0.0.0.0 if unassigned)
0x50   | 4 bytes  | Reserved            | 0x00000000
0x54   | 4 bytes  | Subnet mask         | e.g. 0xFFFF0000 for APIPA /16
0x58   | 4 bytes  | Reserved            | 0x00000000
0x5C   | 4 bytes  | Primary DNS         | May retain stale value from prior DHCP lease
0x60   | 6 bytes  | Adapter MAC         | Adapter's hardware MAC address
0x66   | 4 bytes  | Nonce echo          | Bytes 16–19 of the query, copied verbatim
0x6A   | 4 bytes  | Capability flags    | Hardcoded 0x40 0x07 0x00 0x04
0x6E   | 2 bytes  | FW major version    | Byte-swapped (wire: 01 00 = version 1)
0x70   | 2 bytes  | FW minor version    | Byte-swapped
0x72   | 2 bytes  | FW revision         | Byte-swapped
0x74   | 2 bytes  | FW build            | Byte-swapped
0x76   | 2 bytes  | HW major version    | Byte-swapped
0x78   | 2 bytes  | HW minor version    | Byte-swapped
0x7A   | 2 bytes  | HW feature flags    | Byte-swapped
0x7C   | 2 bytes  | HW region ID        | Byte-swapped
```

**Version byte-swap encoding**: each 16-bit version field is stored in native MIPS big-endian order but written to the response buffer via a byte-reversal sequence. The wire value is the byte-reversed form of the stored value. Wire `01 00` → stored `0x0001` = 1. Wire `15 00` → stored `0x0015` = 21.

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

**Nonce echo mechanism** (firmware-verified at `8009ba60`):

Bytes `[16..19]` of the 20-byte query (the session nonce) are copied verbatim to response offset `+0x66` via a direct `memcpy`. The adapter echoes back whatever nonce it received in the most recent valid query.

#### Discovery Timing
```
PC broadcasts query          → adapter responds within ~77ms (first seen response)
PC repeats query periodically → multiple discovery rounds before TFTP begins
Query interval: ~300–1300ms  → adapter responds to each independently
```

MSBNUpdate runs several discovery rounds while waiting for the adapter to become reachable (e.g. while it finishes APIPA address assignment). The session nonce changes each round; the adapter echoes back whatever nonce it received.

---

### Wire-Verified Firmware Block 1 Content
**Source**: `trialupdate.pcapng` — Frame 34, DATA block 1

The first 512-byte firmware block transferred contains the following human-readable strings, which identify it as the **boot stage** firmware (stage 1 of MSBNUpdate's two-stage update):

```
String                              | Significance
------------------------------------|------------------------------------------
"GL2454AP-LT1-M80     -0000.00.00"  | Hardware board identifier (GL2454AP chipset)
"Sat, 06 Sep 2003    "              | Firmware build date
"MN-740 Bootrom"                    | Firmware stage: boot ROM
00:11:22:33:44:55                   | Placeholder/test MAC in firmware image
```

This confirms that MSBNUpdate stages the boot firmware first, consistent with the `SKU_MN-740_BOOT_FW` → `SKU_MN-740_RUNTIME_FW` ordering documented from string analysis.

---

### Wire-Verified DHCP Behaviour (Adapter, No Server Present)
**Source**: `trialupdate.pcapng`

When no DHCP server responds, the adapter falls back to APIPA (`169.254.x.x`) and continues sending DHCP DISCOVER broadcasts indefinitely with exponential backoff:

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

The adapter retains the last-used DHCP IP in NVRAM and requests it on every subsequent DISCOVER.

### IPHlpSvr.exe

`IPHlpSvr.exe` (Microsoft Broadband Networking IPHlpAPI Server Application)
is a Windows 9x/Me helper shim. It provides IP Helper API calls via window
messages to processes that cannot call `GetAdaptersInfo()` directly on those
platforms. It communicates via `SendMessageTimeout` to a hidden window
(`"Could not find IPHlpSvr window."`). It has no involvement in TFTP or XPP
protocol traffic and is irrelevant on Windows XP and later.

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
Port      | Hex    | Registered by               | Path name   | Auth handler
----------|--------|-----------------------------|-------------|-----------------------------
69        | 0x0045 | xpp_sync_radio_state()      | Unpaired    | g_XPP_Active_Frequency
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
- **WRQ auth**: None — the firmware upload path performs no credential check on either port
- **RRQ auth**: None in practice — see Auth Logic section below
- **Concurrent sessions**: Only one TFTP session is permitted at a time (`g_TFTP_Session_Active_Flag` ref-count). A second request while a session is active is logged and rejected.
- **XPP session prerequisite**: `g_XPP_Session_Handle` must be `-1` (set by successful XPP handshake) or any request on either port gets `"Transfers currently disabled"`.
- **Data transfer port**: After auth passes, the adapter opens a new ephemeral UDP port for the actual DATA/ACK exchange. Ephemeral ports start at 1200 (0x4b0), allocated by `UDP_Allocate_Dynamic_Port()` seeded from uptime ticks. The client must send subsequent ACK packets to this ephemeral port, not to 69 or 16932.
- **Retransmit backoff**: Exponential — starts at 5 ticks, doubles on each retry, capped at 150 ticks. Minimum interval 10 ticks. Retry limit is set at session creation; exhaustion → ERROR `"Retry limit exceeded"`.
- **RTT-adaptive interval**: On each successful ACK, `xpp_calculate_link_latency()` adjusts the retry interval based on measured round-trip time. The interval converges toward `RTT + smoothed_RTT + 1`, clamped to [10, 150].
- **Filename length limit**: Filenames must be shorter than 80 characters (0x51). Longer names are silently ignored by `xpp_vfs_open()`.

**Port selection by use case:**
```
Use case                    | Port  | Notes
----------------------------|-------|------------------------------------------
Firmware flash (WRQ)        | 69    | Standard path, no auth, any client
Firmware flash (WRQ)        | 16932 | Also works — WRQ has no auth on either port
Read config files (RRQ)     | 16932 | Auth handler present but RRQ bypasses it (see below)
Read debug log (RRQ)        | 16932 | Auth handler present but RRQ bypasses it (see below)
Virtual file writes (WRQ)   | 16932 | No auth on WRQ, but payload has embedded tokens
```

---

### TFTP Wire Format — Port 16932 (RRQ and WRQ)

Both RRQ and WRQ packets sent to port 16932 use the same 67-byte UDP payload structure. The auth material is embedded inside the TFTP filename field as binary data. The firmware's auth handler reads auth bytes at fixed offsets into the UDP payload regardless of TFTP framing.

```
UDP payload offset | TFTP field           | Auth purpose
-------------------|----------------------|----------------------------------
0                  | opcode[0] = 0x00     | (not auth)
1                  | opcode[1] = 0x01/02  | (not auth — RRQ=1, WRQ=2)
2–7                | filename bytes 0–5   | auth.src_mac (6 bytes)
8–39               | filename bytes 6–37  | auth.padding (32 bytes, ignored by firmware)
40–59 (0x26–0x39)  | filename bytes 36–55 | auth.HMAC-SHA1 (20 bytes)
60                 | filename null term   | end of filename field
61–65              | mode string          | "octet"
66                 | mode null term       | end of mode field
```

Total packet length: **67 bytes**

**Wire-verified WRQ hex (trialupdate.pcapng frame 32, UDP payload):**
```
00 02                          ← TFTP opcode: WRQ
00 0d 3a 1f 26 09              ← auth.src_mac (adapter MAC in filename bytes 0–5)
d1 d0 de c1 2a 5d e5 5d f8 38
02 ed ba 6c 56 b8 cd 15 8e 23
25 52 16 08 2a b4 a2 04 fe 5f
6d 6b                          ← auth.padding (32 bytes, random in MSBNUpdate)
89 d3 e1 6d 31 54 09 6e 1c 89
f6 b5 94 af b6 f7 2a c2 49 80  ← auth.HMAC-SHA1 (firmware ignores for WRQ)
00                             ← filename null terminator
6f 63 74 65 74                 ← "octet"
00                             ← mode null terminator
```

**RRQ payload structure** (67 bytes, same layout):
```
00 01                          ← TFTP opcode: RRQ
<6 bytes src_mac>              ← auth.src_mac in filename bytes 0–5
<32 bytes padding>             ← ignored by firmware
<20 bytes HMAC-SHA1>           ← auth.HMAC at offset 0x26
00                             ← filename null terminator
6f 63 74 65 74                 ← "octet"
00                             ← mode null terminator
```

The actual VFS filename the client wants to read is **not present** in this packet. The firmware uses the auth bytes (which form the filename field on the wire) to perform auth, then maps the request to the VFS filename that was registered when the TFTP socket was opened. The client indicates which file it wants by choosing which port it targets: the files readable via port 16932 RRQ are fixed — `"dbgout.txt"`, `"ar5eepo.dat"`, `"ar5maco.dat"`, and `"image"`.

**Implementation note**: Because the filename field contains binary auth data, a TFTP opcode parser that tries to extract a printable filename string will read garbage. The firmware does not use the filename field for file selection on port 16932 — the registered VFS handler is invoked unconditionally once auth passes.

---

### Auth Logic — Port 16932

**Firmware function**: `XPP_Secure_Config_Update()` decompiled from `NML_bin.c`.

The firmware's auth callback receives `tftp_op_mode` as an inverted value relative to the TFTP opcode: WRQ (opcode 2) maps to `tftp_op_mode=1`, RRQ (opcode 1) maps to `tftp_op_mode=2`. This is an internal firmware encoding, not the wire opcode.

```c
void XPP_Secure_Config_Update(undefined4 param_1, char *param_2, uint tftp_op_mode)
{
    // param_2 = raw UDP payload pointer

    if ((tftp_op_mode & 0xffff) == 2) {
        // RRQ path — log and return immediately (NO auth checks performed)
        wlan_log_debug_info(4, s_tftp_update, s_tftpd_put);
    }
    else if ((tftp_op_mode & 0xffff) == 1) {
        // WRQ path — perform two auth checks:
        wlan_log_debug_info(4, s_tftp_update, s_tftpd_get);

        // CHECK 1: MAC match
        iVar1 = wlan_mac_addr_equal(param_2, &g_NET_Interface_MAC_Table, 6);
        if (iVar1 == 0) {
            // MAC matched — proceed to HMAC check

            // CHECK 2: HMAC verification
            strcpy(&DAT_800cdb6c, g_NVRAM_User_Settings.Legacy_Padding);
            sVar2 = strlen(g_NVRAM_User_Settings.Legacy_Padding);
            xpp_calculate_hmac_sha1((SHA_CTX *)&DAT_800cdb6c, sVar2, -0x7ff32014, 0x14);
            iVar1 = wlan_mac_addr_equal(param_2 + 0x26, &DAT_800cdfec, 0x14);
            if (iVar1 == 0) {
                wlan_log_debug_info(4, s_tftp_update, s_filename_ok);
            }
            else {
                wlan_log_debug_info(4, s_tftp_update, s_password_error1);
            }
        }
        else {
            wlan_log_debug_info(4, s_tftp_update, s_mac_error);
        }
    }
}
```

**Auth summary:**

```
Operation | tftp_op_mode | Auth performed
----------|--------------|------------------------------------------
RRQ       | 2            | NONE — returns immediately, no checks
WRQ       | 1            | MAC check then HMAC-SHA1 check (both must pass)
```

**WRQ auth checks (when auth is performed):**

```
Check     | What is compared                                        | Failure result
----------|--------------------------------------------------------|---------------------
MAC check | param_2[0x00..0x05] vs g_NET_Interface_MAC_Table:
          |   UNPAIRED adapter → adapter hardware MAC              | log "mac_error", refuse
          |   PAIRED adapter   → paired Xbox console MAC           |
HMAC check| param_2[0x26..0x39] vs HMAC-SHA1(key=g_XPP_HMAC_Key,
          |   input=g_NVRAM_User_Settings.Legacy_Padding (admin_id))| log "password_error1", refuse
```

`g_NET_Interface_MAC_Table` is dual-use: at boot it holds the **adapter hardware MAC** (populated by `eth_brecis_msp_init()`); after pairing it is overwritten with the **paired Xbox console MAC** by `CFG_Set_Paired_Xbox_MAC()`. The adapter hardware MAC is available in the BBN discovery response at offset `+0x60`.

**HMAC computation for WRQ auth (default config):**

```
Key:   cb275ff238ab61dc8799fa01ad17745e  (g_XPP_HMAC_Key, 16-byte ROM constant)
Input: "admin"  (g_NVRAM_User_Settings.Legacy_Padding default)
Result: 82 2f 85 b7 ca 0c f6 fa ad 5f 3c 26 04 30 62 6d 1b 08 3e c8
```

**Both ports — WRQ has no access control from the firmware's perspective.** `XPP_Secure_Config_Update` performs MAC and HMAC checks but only on the WRQ path (`tftp_op_mode=1`). Port 69 WRQ has no auth handler registered at all. Any host that has established an XPP session can flash new firmware on either port.

**Note on dispatch paths**: The firmware also checks `if (param_4 == 0) OR (g_XPP_Link_State == NULL)` — if port 16932 is used but `g_XPP_Link_State` was never registered, it falls through to the port 69 auth path as a fallback.

---

### WRQ Initial ACK — Block 0 Sent Before DATA

From `TFTP_Process_New_Request()` decompile:

For a WRQ (write request), the adapter sends **ACK block 0 immediately** upon accepting the request — before receiving any DATA:

```c
// WRQ path (opcode == 2):
*(undefined2 *)&p_tftp_session_desc->field_0x2c = 0;       // block number = 0
net_tftp_send_acknowledgment(p_tftp_session_desc, ...);     // send ACK 0
*(undefined2 *)&p_tftp_session_desc->field_0x2c = 1;       // next expected = 1
*(undefined4 *)&p_tftp_session_desc->field_0x38 = 1;       // state = RECV
```

This is standard RFC 1350 WRQ behaviour — the server sends ACK 0 to signal readiness, client then sends DATA block 1. An emulator **must** send ACK block 0 in response to WRQ before the client will begin sending data. Failure to send ACK 0 causes the client to time out waiting.

**For RRQ (read request):**

The block number starts at 1 — the adapter opens the file and begins sending DATA block 1 immediately:

```c
// RRQ path (opcode == 1):
*(undefined4 *)&p_tftp_session_desc->field_0x38 = 6;       // state = SEND
*(undefined2 *)&p_tftp_session_desc->field_0x2c = 1;       // next block = 1
*(undefined4 *)&p_tftp_session_desc->field_0x28 = 0x200;   // block size = 512
```

No ACK 0 is sent for RRQ — the adapter sends DATA block 1 directly to the client's source port as soon as the request is accepted.

---

### Standard TFTP Packet Format

```
WRQ/RRQ:   [opcode:2][filename\0][mode\0]
DATA:      [opcode:2][block:2][data:≤512]
ACK:       [opcode:2][block:2]
ERROR:     [opcode:2][error_code:2][message\0]
```
Opcodes: 1=RRQ, 2=WRQ, 3=DATA, 4=ACK, 5=ERROR

### WRQ Filename
The standard firmware upgrade filename is `"image"`. MSBNUpdate.exe uses `"boot.bin"` as its WRQ filename. Both are accepted by the firmware — the completion callback (`xpp_tftp_commit_config`) does not validate the filename at all; it flashes whatever data was received into `g_HTTP_UPLOAD_BUFFER` regardless of what the file was named. Any filename triggers the same flash-and-reboot path.

### TFTP Credentials
The adapter has two separate credentials stored in NVRAM, both defaulting to `"admin"` at factory reset:

**HTTP username / XPP device identity**: `xpp_identity_username` (default `"admin"`).
Populated into `XPP_Identity_t.password` at boot. Used as the HTTP Basic Auth username.
No XPP TLV tag writes this field — it can only be changed via the HTTP web config page.

**HTTP password / TFTP WRQ auth input / CLI admin_id**: `g_NVRAM_User_Settings.Legacy_Padding` — the XPP admin identity password (max 16 chars + NUL = 17 bytes total).
This is the credential used by `XPP_Secure_Config_Update` as the HMAC input for TFTP WRQ authentication on port 16932. It is also used as the HTTP Basic Auth password and copied to `XPP_Identity_t.admin_id` at boot for CLI session auth.
Written by Tag 0x03 in Type 0x07 CONNECT_REQ. Also changeable via HTTP web UI.

Both default to `"admin"` at factory reset giving HTTP credentials of `admin:admin`.
Tag 0x03 changes only the password/HMAC side (`Legacy_Padding` / `admin_id`), not the username side (`xpp_identity_username`).
Factory reset restores both via `Flash_Commit_Settings()` → `strcpy(STR_DEFAULT_CREDENTIAL)`.

---

### TFTP — Emulator Implementation Checklist

The most likely causes of TFTP failure, ordered by probability:

```
Priority | Issue                                              | Fix
---------|---------------------------------------------------|----------------------------------------------
1 (HIGH) | Not sending ACK block 0 after WRQ accepted         | Send ACK opcode 4, block 0 immediately
         |                                                    | on WRQ receipt — before client sends DATA 1
2 (HIGH) | Sending ACK/DATA to wrong port after session starts| Re-address to adapter's EPHEMERAL TID port
         |                                                    | (learned from first DATA block's source port)
3 (HIGH) | XPP session handle not set before TFTP             | Must complete Type 0x01/0x02 handshake first
4 (HIGH) | ICMP port-unreachable from OS aborting transfer    | Bind a UDP socket to the client's src port
         |                                                    | (e.g. 32069) to absorb adapter DATA replies
         |                                                    | at OS level — prevents ICMP port-unreachable
         |                                                    | which the adapter treats as fatal
5 (MED)  | No IP route back to adapter (APIPA)                | Add a host IP in 169.254.0.0/16 on the NIC
         |                                                    | connected to the adapter before TFTP
6 (MED)  | Adapter cannot ARP for client's source IP          | Send a gratuitous ARP reply before and after
         |                                                    | the RRQ so the adapter's ARP table maps the
         |                                                    | client src IP → client MAC without an extra
         |                                                    | round-trip
7 (LOW)  | Final zero-length DATA packet not handled          | When file_size % 512 == 0, send a 4-byte
         |                                                    | zero-payload DATA as EOF. For port 16932
         |                                                    | client does NOT wait for ACK after this.
         |                                                    | For port 69 client waits but swallows timeout.
```

**Step-by-step WRQ flow:**

```
Client → Adapter  UDP dst=69     [WRQ opcode=2][auth_in_filename_field][mode\0]
Adapter → Client  UDP dst=client-src-port (ephemeral TID) [ACK opcode=4][block=0]
Client → Adapter  UDP dst=ephemeral-TID   [DATA opcode=3][block=1][512 bytes]
Adapter → Client  UDP dst=client-src-port [ACK opcode=4][block=1]
...
Client → Adapter  UDP dst=ephemeral-TID   [DATA opcode=3][block=N][<512 bytes final]
Adapter → Client  UDP dst=client-src-port [ACK opcode=4][block=N]
  (adapter: xpp_tftp_commit_config → xpp_flash_write_manager → reboot if size==0x100000)
```

**Step-by-step RRQ flow (port 16932):**

The client must use raw Ethernet/IP/UDP frames (Npcap or similar) rather than standard OS UDP sockets. The adapter's DATA replies come from an ephemeral source port back to the client's fixed source port. A standard OS UDP socket cannot reliably receive these because:
- Windows Firewall drops unsolicited inbound UDP from unpredictable source ports
- The source IP in the raw RRQ packet is typically a synthesised address not assigned to any NIC

The correct approach: send RRQ as a raw Ethernet frame, bind a dummy UDP socket to the client's src port to suppress ICMP port-unreachable, and receive DATA via a separate raw Npcap handle.

```
Client → Adapter  raw Ethernet/IP/UDP dst=16932  [RRQ 67-byte payload]
  (send gratuitous ARP reply: client-src-ip is-at client-mac — before and after RRQ)
Adapter → Client  UDP from ephemeral-TID → client-src-port [DATA opcode=3][block=1][512 bytes]
Client → Adapter  raw Ethernet/IP/UDP dst=ephemeral-TID [ACK opcode=4][block=1]
...
Adapter → Client  UDP from ephemeral-TID → client-src-port [DATA opcode=3][block=N][<512 final]
Client → Adapter  raw Ethernet/IP/UDP dst=ephemeral-TID [ACK opcode=4][block=N]
```

**Wire-verified RRQ session (trialupdate.pcapng adapted for RRQ context):**

```
Frame N:   Client → Adapter:16932  RRQ (67 bytes)
Frame N+1: Adapter:1205 → Client:32069  DATA block 1 (516 bytes)  ← RTT ~10ms
Frame N+2: Client → Adapter:1205   ACK block 1 (4 bytes: 00 04 00 01)
...
```

The adapter allocates ephemeral port starting from ~1200 (0x4b0). All subsequent DATA and ACK exchanges use `adapter:TID ↔ client:src_port`. The client must learn the TID from the first DATA block's source port and address all subsequent ACKs to it.

---

### Network Requirements for TFTP (APIPA Adapters)

When the MN-740 is connected directly to a PC with no router or switch, it
self-assigns an APIPA address (`169.254.x.x/16`) because no DHCP server is
present. The client must have an address on the same `/16` subnet; without one
the UDP reply from the adapter has no route back.

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

`route add` does NOT work for 169.254.x.x. The Windows IP stack enforces
that APIPA destinations are only reachable via an interface that already has an
address in the `169.254.0.0/16` range.

**Synthesised source IP for raw RRQ frames**: When the client has no 169.254 address yet, the raw RRQ frame must carry a plausible src IP that the adapter can ARP for and route a reply to. A simple approach: XOR the last octet of the adapter's IP with 1 to produce a collision-free adjacent address in the same /24 (e.g. adapter at 169.254.250.49 → client uses 169.254.250.48). Send a gratuitous ARP reply associating this synthesised IP with the client's real MAC before sending the RRQ.

---

### Virtual File System — Complete File Catalogue
The firmware implements a virtual filesystem rooted in `g_HTTP_UPLOAD_BUFFER` (1 MB RAM).
All filenames are matched by `strcmp()` — there is no real filesystem on the adapter.

**RRQ — Files readable from the adapter** (all require a valid XPP session; auth bypassed for RRQ as described above):

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
"image"        | 1 MB   | Full firmware image read from flash.
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

### AMACAEPM Magic Header
**Purpose**: Integrity check for paired Xbox configuration — firmware-verified
**Expansion** ("Adapter MAC Address & Endpoint Manager"): NOT firmware-verified, inferred label only

### Pairing Process (firmware-verified behaviour)
**Factory Reset**: `g_XPP_Paired_Flag = 0` (unpaired)

**Pairing**: `CFG_Set_Paired_Xbox_MAC()` copies the Xbox MAC and sets `g_XPP_Paired_Flag = 1`,
then calls `Flash_Commit_Settings()` + `CFG_Save_To_Flash()`

**Subsequent Connections**: adapter checks source MAC against stored paired MAC via
`NET_Register_Peer_MAC()` — only responds to the paired Xbox MAC

### Security Model
**Pairing Lock**: Once paired, adapter only responds to that Xbox MAC (firmware-verified)
**Reset**: Factory reset clears paired state (firmware-verified)

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

**WRQ filename is `"boot.bin"`, not `"image"`.** The firmware dump RRQ uses
`"image"` (firmware source: `XPP_flash_read_wrapper`). The official update WRQ
uses `"boot.bin"`. These are two different TFTP code paths.

### BOOT_ME Signal — Gateway Only

The `BOOT_ME` signal (`"Wait for BOOT_ME, recvd: %d"` / `"Received BOOT_ME"`)
appears only in the **gateway update path** (MN-700 base station, BCM94710AP
chipset). The MN-740 wireless bridge update does **not** use `BOOT_ME`. The
bridge reboot is detected by polling XPP handshake responses, not a broadcast
beacon signal.

### Final Zero-Length DATA Packet

`"sent last zero data packet, host timed out, but OK"` confirms that MSBNUpdate.exe deliberately sends a zero-length DATA packet as the final transfer step when the firmware image size is an exact multiple of 512 bytes.

**Behaviour differs by TFTP path (decompile-verified):**

- **Generic/CE path (`TFTP_SendFileGeneric`, port 69)**: sends the 4-byte zero-payload DATA packet, then calls `TFTP_WaitForACK`. If the adapter does not ACK (it may have already rebooted), the timeout exception is caught by `TFTP_FinalPacketTimeoutHandler` and swallowed.
- **MN-740 path (`TFTP_SendFileMN740`, port 16932)**: sends the 4-byte zero-payload DATA packet and **does not call `TFTP_WaitForACK` afterward**. The client simply does not wait. An emulator receiving firmware over port 16932 should not expect the client to wait for ACK on the final zero-payload block.

When the final block is a non-zero partial block (< 512 bytes), both paths call `TFTP_WaitForACK` normally.

### MSBNUpdate HMAC Keys — Two Independent Keys, Two Roles

**Source**: `MSBNUpdate.exe` decompile (`TFTP_BuildAuthHeader`, `TFTP_ComputeHMACSHA1`) + wire capture cross-verification.

MSBNUpdate.exe and the adapter firmware each use a **separate, independent HMAC-SHA1 key**. They are not derived from each other:

```
Party          | Key                                       | Size    | Used for
---------------|-------------------------------------------|---------|-----------------------------
MSBNUpdate.exe | d302a0fee8f94a7e89742193380bc68c          | 64 bytes| Computing HMAC in WRQ
               | 2c230023136a4adc9af3165d6946d14b          |         | filename field (firmware ignores)
               | 91cc3337075e4e7997bb48d32d5b909a          |         |
               | 6ef9ab2df43542759bcf8ea21ddff53c          |         |
Adapter FW     | cb275ff238ab61dc8799fa01ad17745e          | 16 bytes| WRQ auth HMAC verification
               |                                           |         | (checked by XPP_Secure_Config_Update)
```

Both sides use `admin_id` (default `"admin"`) as the HMAC data input, but produce different digests because the keys differ:

```
HMAC-SHA1(key=MSBNUpdate_64byte_key, data="admin") = 89d3e16d3154096e1c89f6b594afb6f72ac24980
    → value in WRQ auth.HMAC field (trialupdate.pcapng frame 32 ✅)

HMAC-SHA1(key=fw_rom_key_16byte,     data="admin") = 822f85b7ca0cf6faad5f3c260430626d1b083ec8
    → value firmware verifies in WRQ auth.HMAC field
```

The MSBNUpdate 64-byte key (`g_TFTP_HMACKeyBlock`) lives in the `.data` section of `MSBNUpdate.exe` at VA `0x004d8418` and is referenced only by `TFTP_BuildAuthHeader`. It has no relationship to any firmware constant.

Since RRQ bypasses all auth checks, no HMAC is required in an RRQ packet. Any value (including zeros) at the HMAC offset is silently ignored.

---

### Password Validation Flow

`"MN740 Connect, bad password"` appears in the TFTP code area, not the XPP
discovery code. The password is validated before the TFTP session opens.
Internally this is done via the XPP channel (CONNECT_REQ Tag 0x03) — the
same `g_NVRAM_User_Settings.Legacy_Padding` (`admin_id`) credential described in the TFTP credentials section above.
If the password is wrong the TFTP session is never attempted.


----

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

### Security Implications
**Actual Security Relies On:**
1. HMAC-SHA1 challenge-response — proves adapter has genuine ROM key and ROM string
2. `g_ROUTER_MAC_ADDRESS` / Ethernet `src_mac` binds the HMAC to a specific adapter MAC
3. Nonce randomness — each session uses a fresh 16-byte random nonce (via `XNetRandom`)
4. Physical LAN isolation (no WAN routing)

**Note**: MAC address pairing (`mac.dat`) and the 30-second watchdog are
secondary mechanisms — the primary authentication is the HMAC challenge-response.

---

## Signal Strength Scaling
the firmware scales the signal strength depending on what packet or payload the data is to be processed as below are ethe three different places the signal is scaled:

### BEACON_RESPONSE (Type 0x0A) — Smoothed RSSI

Byte 1 of the BEACON_RESPONSE payload is a signed byte representing a smoothed RSSI value.

- `0x80` (-128): pre-association default
- `0xBA` (-70): seed value written when not authenticated
- When associated: 10-sample rolling average

### NETWORKS_LIST_RESPONSE (Type 0x04) — Per-Slot Signal

Byte 44 of each network slot is a 0–255 scaled quality value.

### Dashboard Signal Bar Thresholds

The Xbox dashboard converts the smoothed RSSI byte from BEACON_RESPONSE into 0–5 signal bars:

```
| Bars | RSSI threshold | dBm        | visual          |
|------|----------------|------------|-----------------|
| 0    | rssi ≤ -0x5b   | ≤ -91 dBm  | ░░░░░ no signal |
| 1    | rssi ≤ -0x52   | ≤ -82 dBm  | █░░░░           |
| 2    | rssi ≤ -0x48   | ≤ -72 dBm  | ██░░░           |
| 3    | rssi ≤ -0x44   | ≤ -68 dBm  | ███░░           |
| 4    | rssi ≤ -0x3a   | ≤ -58 dBm  | ████░           |
| 5    | rssi > -0x3a   | > -58 dBm  | █████ excellent |
```

---

## Error code flags

XPP Wire Result Bytes (payload byte at offset 0x00 in Type 0x06 and 0x08 responses)

```
Wire Byte | Meaning                     | Dashboard sets error_code to
----------|-----------------------------|------------------------------
0x00      | Success — TLV data follows  | 0x00000000 (cleared)
0x01      | Error / rejected            | 0x80000003 (hard error)
0x02      | Retry requested             | 0x80000002 (retry), retries after ~8 seconds
0x03      | Error / rejected            | 0x80000003 (hard error)
0x04      | Error (connect only)        | 0x80000003 (hard error, Type 0x08 only)
```

## MAC.DAT Pairing File Format

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

## Connection Workflows

### Infrastructure Mode

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

### Ad-Hoc Mode

1-4. [Same handshake and beacon sequence as infrastructure]

5. Xbox → Adapter:  CONNECT_TO_SSID_REQUEST (Type 0x07)
   - Tag 0x07: SSID
   - Tag 0x0e: Radio Channel (MANDATORY for ad-hoc - e.g., 0x06 for channel 6)
   - Tag 0x09: 0x04 (Ad-hoc connect)
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
   - Tag 0x08: 0x02 (open — no WEP active, wire-verified ✅)
   - Tag 0x09: 0x01 (open cipher — no encryption active, wire-verified ✅)
   - Tag 0x02: 0x00 (DHCP state machine not yet at 0x52)

3. The Xbox queries Type 0x05 / 0x06 every ~3-5 beacons while connected.

4. Transient beacon anomalies during re-association (packets like `d5 82 00 d7` and `08 e8 00 d7`)
   appear briefly — Byte 3 (reserved) is **not** always 0x00 during these transitional states.
   These are short-lived and the adapter returns to stable `02 80 6c 00` quickly.

5. The Xbox sends ADAPTER_INFO_REQ without first sending a NETWORKS_LIST_REQ or CONNECT_REQ
   in this capture — the adapter was already configured from a previous session stored in NVRAM.

**Confirmed working configuration (for emulator implementors)**:
- Type 0x0a rate=`0x6c` (54 Mbps) is correct for infrastructure when radio associates
- Type 0x06 Tag 0x05 returns the raw channel number (e.g. Channel 3 = `0x03`) ✅
- Tag 0x09 = `0x01` (open cipher) is the correct value for an open network in ADAPTER_INFO_RESP. This is the encryption-type echo, not a link state. It can coexist with a saved IP in Tag 0x01 since Tag 0x01 returns the stored static/last-used IP regardless of current link state.

---

### Tag 0x11 - CFG_Set_XPP_Auth_Mode

**Firmware Function**: `CFG_Set_XPP_Auth_Mode()`  
**Purpose**: Sets `g_XPP_Auth_Mode_Enabled` (NVRAM, persists across power cycles) so the adapter can report the correct encryption state in ADAPTER_INFO_RESP Tag 0x11 before a live radio association exists.

**Accepted values** (only `0x00` and `0x02` are processed — all others silently ignored):
- `0x00` — sets `g_XPP_Auth_Mode_Enabled = 0` → ADAPTER_INFO_RESP Tag 0x11 reports `0x00` (no encryption)
- `0x02` — sets `g_XPP_Auth_Mode_Enabled = 1` → ADAPTER_INFO_RESP Tag 0x11 reports `0x02` (encryption active)

**Wire-verified**: `0x02` is sent in CONNECT_REQ for all WEP connections. `0x00` is sent for open networks. `0x01` in CONNECT_REQ Tag 0x11 would be silently ignored (not in accepted values whitelist).

**NVRAM vs HAL — the key distinction between Tag 0x11 and Tags 0x08/0x09:**

Tags 0x08 and 0x09 report the **NVRAM-configured** encryption state — what the adapter has been told to use. Tag 0x11 reports the **live HAL state** — what the Marvell 88W8310 chipset is actually doing right now. These can and do differ during association.

Wire-verified across 9 captures (`_b` = not yet associated, `_bg` = associated):

```
Network type | tag 0x08 | tag 0x09 | tag 0x11 (not assoc) | tag 0x11 (associated)
-------------|----------|----------|----------------------|----------------------
Open         | 0x02     | 0x01     | 0x00                 | 0x02
WEP-64       | 0x04     | 0x02     | 0x00                 | 0x02
WEP-128      | 0x04     | 0x04     | 0x00                 | 0x02
```

An adapter mid-association legitimately has `tag08=0x04` (WEP configured in NVRAM), `tag09=0x02` (WEP-64 configured in NVRAM), and `tag11=0x00` (HAL not yet encrypting) simultaneously. This is not an error state — tag 0x11 is the lagging indicator that only flips once the key material is installed in silicon.

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

### Phase 7 — TFTP (Optional)
- [ ] BBN discovery responder (UDP port 42424)
- [ ] TFTP server on port 69 (WRQ firmware flash)
- [ ] TFTP server on port 16932 (RRQ file reads, WRQ with MAC+HMAC auth)
- [ ] Virtual file system (dbgout.txt, ar5eepo.dat, ar5maco.dat, image)


### Phase 8: WPA/WPA2 (Firmware Patch)
**see [WPA/WPA2 Implementation](#wpa-wpa2-implementation)**

**Xbox sends PMK**:
- [ ] Patch `XPP_Parse_Entry()` case 0x10 to store 32-byte PMK to `G_WPA_PMK`
- [ ] Implement `eapol_handle_key_exchange()` body:
  - [ ] ANonce/SNonce exchange
  - [ ] PTK derivation via PRF-512(PMK, ANonce, SNonce, MACs)
  - [ ] MIC verification on handshake msg 3
  - [ ] PTK install via `ath_hal_set_key_cache_entry()`
  - [ ] GTK unwrap and install via `ath_hal_install_hw_key()`
  - [ ] Send handshake msg 4 confirmation
- [ ] Add `XPP_SEC_TKIP = 0x03` and `XPP_SEC_CCMP = 0x04` to `wlan_get_encryption_type()`

**Firmware calculates PMK**:
- [ ] Allocate `G_WPA_Passphrase[64]` in NVRAM
- [ ] Patch `XPP_Parse_Entry()` case 0x10 to store raw passphrase
- [ ] Wire `XPP_PBKDF2_F_Block()` into `wireless_worker_task()` async signal
- [ ] All items from Path 1 `eapol_handle_key_exchange()` above
- [ ] Add `XPP_SEC_TKIP = 0x03` and `XPP_SEC_CCMP = 0x04` to `wlan_get_encryption_type()`

** Receive Passphrase via Type 0x11 WPA_ASSOC_REQ


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

## WPA/WPA2 Implementation

**The MN-740 is fully capable of WPA (TKIP) and WPA2 (AES-CCMP) in hardware.** The limitation is
purely firmware. The hardware was designed for WPA/WPA2 from the start but the firmware was never
finished, the likely reason it was never implemented was to ensure BSS stability and clock sync with Ad-hoc connections higher security methods can put straining on the hardware and effect timing.
The firmware already restricts the rate code and downgrades Adhoc networks to open if wpa2 enterprize support is not available in the adaptor.

**Hardware**: The Marvell Libertas 88W8310 security engine is a dedicated hardware block with
silicon-level AES-Rijndael at 54Mbps, TKIP MIC generation, and a full hardware key cache.
All of this is confirmed accessible from firmware via `ath_hal_set_key_cache_entry()`,
`ath_hal_ccmp_aes_encrypt()`, and `wlan_ccmp_decrypt_verify()`.

### The Three Gaps

**Gap 1 — WPA not advertised in HANDSHAKE_RESP**  
Byte 174 in the HANDSHAKE_RESPONSE is hardcoded to `0x06`, which has bit 0x10 clear. The dashboard checks this bit before showing the WPA PSK menu option. Change byte 174 to `0x16` to enable the WPA PSK option.

**Gap 2 — PMK received from Xbox but discarded**  
When the user enters a 64-character hex WPA key, the dashboard sends a 32-byte PMK in CONNECT_REQ Tag 0x10. Stock firmware advances the parse pointer past this tag without storing the value. When the user enters an ASCII passphrase (8–63 chars), the dashboard sends Tag 0x12, which has no handler at all — the parse loop aborts immediately.

**Gap 3 — 4-way handshake stubbed**  
The EAPOL key exchange function exists but logs "EAP Failure" and returns immediately. ANonce/SNonce exchange, PTK derivation, MIC verification, and GTK installation are all absent.

### Firmware Components Already Present

```
Component            | Status
---------------------|------------------------------------------
AES crypto engine    | Complete
CCMP encrypt/decrypt | Complete
Hardware key cache   | Complete
TKIP MIC             | Complete
WPA security init    | Complete
WPA/RSN IE handling  | Complete
EAPOL state machine  | Complete
PBKDF2 derivation    | Present but never called (dead code)
Tag 0x10 receive     | Stub — discards PMK
Tag 0x12 receive     | No handler — aborts parse
4-way handshake      | Stub — logs failure and returns
```

### Methods to implement WPA/ WPA key exchange

input pmk via tag 0x10 (hex entry)
input key via tag 0x12 (ASCII entry)

#### Xbox Sends PMK (hex key entry path)

The Xbox already computes and sends the 32-byte PMK for 64-hex input. No Xbox modification required.

**Steps:**
1. Set byte 174 of HANDSHAKE_RESP to `0x16` (add bit 0x10)
2. Add `case 0x10` to the TLV parser: store the 32-byte PMK and set a ready flag
3. Implement `eapol_handle_key_exchange()`:
   - Receive ANonce from AP message 1
   - Generate SNonce
   - Derive PTK via PRF-512(PMK, ANonce, SNonce, AP MAC, STA MAC)
   - Verify MIC on AP message 3
   - Install PTK via `ath_hal_set_key_cache_entry()`
   - Extract and install GTK from message 3
   - Send message 4 confirmation
4. Drive the Type 0x11 exchange with the console (IP negotiation + ANonce delivery)
5. Add encryption type constants: `XPP_SEC_TKIP=0x03`, `XPP_SEC_CCMP=0x04`

### Firmware Derives PMK from Passphrase (ACSII key entry path)

When the user enters an ASCII passphrase, the dashboard sends Tag 0x12. Add a `case 0x12` handler that calls the existing PBKDF2 function to derive the PMK, then follow Path 1 steps 3–5.

**Steps:**
1. Set byte 174 of HANDSHAKE_RESP to `0x16` (add bit 0x10)
2. Add `case 0x12` to the TLV parser: store the 8-32 character Passphrase and set a ready flag
3. Implement `eapol_handle_key_exchange()`:
   - Receive ANonce from AP message 1
   - Generate SNonce
   - Derive PTK via PRF-512(PMK, ANonce, SNonce, AP MAC, STA MAC)
   - Verify MIC on AP message 3
   - Install PTK via `ath_hal_set_key_cache_entry()`
   - Extract and install GTK from message 3
   - Send message 4 confirmation
4. Drive the Type 0x11 exchange with the console (IP negotiation + ANonce delivery)
5. Add encryption type constants: `XPP_SEC_TKIP=0x03`, `XPP_SEC_CCMP=0x04`

**Note**: PBKDF2 takes ~100–200 ms and must run in a worker task context, not the network interrupt handler.

### Patch Comparison

```
                      | Path 1: Tag 0x10 PMK  | Path 2: Tag 0x12 passphrase
----------------------|-----------------------|-----------------------------
Xbox input            | 64-char hex string    | 8–63 ASCII passphrase
PMK computation       | Xbox pre-computes     | Firmware runs PBKDF2
Worker task required  | No                    | Yes (~100–200 ms)

```

### Additional Change Required

`wlan_get_encryption_type()` currently only returns `0x00` (none), `0x01` (WEP), `0x02`
(WPA/WPA2 generic). Two new constants must be defined for the XPP Tag 0x11 handler so the
adapter correctly reports its active cipher mode:

```c
XPP_SEC_TKIP = 0x03   // WPA-TKIP
XPP_SEC_CCMP = 0x04   // WPA2-AES-CCMP
```

---

## DHCP Implementation & XPP Interaction

### Overview
The MN-740 operates as a **Layer 2 Transparent Bridge**. While it does not act as a DHCP client itself for its primary function, it performs **Passive DHCP Snooping** to maintain its internal state. The adapter "listens" to the DHCP handshake between the Xbox console and the network Gateway to populate its internal status registers.

### DHCP Snooping Mechanic
When the Xbox Console initiates a DHCP transaction, the adapter’s firmware intercepts specific UDP packets on **Ports 67 (Server)** and **68 (Client)**.

1. **Intercept**: The firmware monitors traffic for the **DHCP Magic Cookie**: `0x63 0x82 0x53 0x63`.
2. **Filter**: It specifically looks for **Option 53 (Message Type)** with a value of `0x05` (**DHCP ACK**).
3. **Extraction**: Upon detecting an ACK, the firmware extracts the `yiaddr` (Your IP Address) and **Option 54 (Server Identifier)**.

### Relationship to Type 0x02 (Status Response)
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

## Required Secrets

The HMAC-SHA1 authentication requires three static values that are hardcoded in the MN-740 firmware ROM. For an emulator or software adapter, embed these directly:

```
HMAC key (16 bytes):
  cb 27 5f f2 38 ab 61 dc 87 99 fa 01 ad 17 74 5e

HMAC master key string (117 bytes):
  "From isolation / Deliver me o Xbox - / Through the ethernet\n
   Copyright (c) Microsoft Corporation. All Rights Reserved."

HANDSHAKE_RESP copyright string (84 bytes, null-padded):
  "Device is Xbox Compatible. Copyright (c) Microsoft Corporation. All Rights Reserved."
```

---

### Quirky error handler string

The device has a very funny error handling string as a line from the
three stooges that is common on other dlink products:

"Hey Moe, it dont woik. NYUK NYUK NYUK NYUK"

Any unknown TLV tag sent will print this error on the debug serial port.

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

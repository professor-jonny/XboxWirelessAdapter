# Xbox Wireless Protocol Analysis - Ad-hoc Mode Discovery

## Log File: log.log2.txt
**Capture Date**: Wed Jan 21, 2026  
**Packet Range**: #59-#480, then jumps to #956+  
**Setup**: Xbox-to-Xbox ad-hoc using 2 MN-740 adapters

## Hardware Configuration
- **Adapter 1 MAC**: `00:15:5d:01:0a:0b` (connected to Xbox 1)
- **Adapter 2 MAC**: `00:12:5a:33:fa:31` (connected to Xbox 2)  
- **Ad-hoc BSSID**: `02:0d:0a:51:a6:03`
- **Ad-hoc SSID**: "mshome" (Microsoft's default ad-hoc network name)

## Key Discoveries

### 1. Ad-hoc Mode Setup
- Factory reset both adapters
- Selected "ad-hoc" mode on each Xbox
- Adapters **automatically** created/joined "mshome" network
- No manual SSID or password configuration needed
- Open network (no encryption)

### 2. Successful Ad-hoc Connection (Packets #316-#318)

**Packet #316**: HANDSHAKE_REQUEST from Xbox
```
Type: 0x01, Nonce: 0xb9b6
Challenge: 18 a7 66 df 05 4d 08 36 58 e8 c9 2f 61 a9 05 b4
```

**Packet #317**: HANDSHAKE_RESPONSE from Adapter (Real MN-740)
```
Type: 0x02, Nonce: 0xb9b6, Length: 282 bytes
Firmware: "1.0.2.26 Boot: 1.3.0.06"
Status: DISCONNECTED initially (before ad-hoc join)
SSID Length: 0x00
Last 4 bytes: 02 00 00 00
```

**Packet #318**: HANDSHAKE_RESPONSE from Console (Echo)
```
Type: 0x02, Nonce: 0xb9b6, Length: 282 bytes
Firmware: "1.0.2.21 Boot: 1.3.0.05"
BSSID at offset 0xc0-0xc5: 02 0d 0a 51 a6 03
SSID Length: 0x06 (6 bytes)
SSID: "mshome" (6d 73 68 6f 6d 65)
Last 4 bytes: 02 01 00 00 (CONNECTED)
```

### 3. BEACON Exchange Pattern

**Before ad-hoc connection** (Packets #59-60):
```
Adapter→Console (Type 0x0a): 02 80 00 00
Console→Adapter (Type 0x0a): 02 80 16 00
```

**After ad-hoc connection** (Packets #320-321):
```
Adapter→Console: 02 80 00 00
Console→Adapter: 00 d2 16 00  ← Status changed!
```

**Later in session** (Packets #372-373):
```
Adapter→Console: 02 80 00 00
Console→Adapter: 03 80 16 00  ← Status byte = 0x03
```

### 4. Extended ADAPTER_INFO_RESPONSE Format

**Standard short format** (Packets #110, #353):
```
Type: 0x06, Length: 282 bytes
Payload: All zeros (placeholder response)
```

**Detailed long format** (Packet #111):
```
Type: 0x06, Length: 70 bytes (0x0e DWORDs)
Payload contains:
- Status: 0x00 (Success)
- IP Address: c0 a8 01 b5 (192.168.1.181)
- BSSID: 02 0d 0a 51 a6 03
- SSID: "mshome"
- PHY Mode: 0x02 (likely 802.11g)
- Additional status flags

Structure (tentative):
00 09 01 04 c0 a8 01 b5 02 01 00 04 01 00 05 01 0b 
06 06 02 0d 0a 51 a6 03 07 06 6d 73 68 6f 6d 65 
08 01 02 09 01 01 11 01 00
```

### 5. Failed Connection Attempt (Packet #367)

**CONNECT_TO_SSID_REQUEST**:
```
Type: 0x07, Nonce: 0xb9c7
Payload: 04 04 01 00 05 01 07 07 04 31 31 32 32 11 01 02

Structure needs clarification:
- Contains password "1122" (31 31 32 32)
- Unknown TLV tags (0x04, 0x05, 0x07, 0x11)
- This was an attempt to connect to imaginary network
```

**Response** (Packet #368):
```
Type: 0x08 (CONNECT_TO_SSID_RESPONSE)
Payload: 00 00 00 00... (all zeros)
Result: Failed (imaginary network doesn't exist)
```

### 6. ADAPTER_INFO_REQUEST Format (Packet #109)

```
Type: 0x05, Length: 60 bytes
Payload (20 bytes):
09 01 04 02 01 04 01 05 01 06 06 07 20 08 01 09 01 11 01

This appears to request specific fields using tag values:
0x09, 0x02, 0x01, 0x05, 0x06, 0x08, 0x09, 0x11
```

## HANDSHAKE_RESPONSE Structure (256 bytes)

```
Offset   Size   Field
------   ----   -----
0-19     20     HMAC-SHA1 signature
20-103   84     Copyright string "Device is Xbox Compatible..."
104-135  32     Adapter name (null-padded)
136-167  32     Firmware version (null-padded)
168-218  51     Capabilities/metadata (BSSID appears here)
219      1      Current SSID length
220-251  32     Current SSID string (null-padded)
252-255  4      Connection status flags
```

### Status Bytes (252-255):
- **Connected**: `02 01 00 00`
- **Disconnected**: `02 00 00 00`
- Pattern: `02 [connected_flag] 00 00`

## Comparison with Other Logs

### Infrastructure Mode (emulator.log, emulator2.log)
- Connects to real AP (Kids2.4g, Adults2.4G)
- BSSID is real AP MAC
- Standard WPA/Open security

### Disconnected (emulator3.log)
- SSID length: 0x00
- Status: `02 00 00 00`
- BSSID field empty or stale data

### Ad-hoc Mode (log.log2.txt) ✓
- SSID: "mshome" (automatic)
- BSSID: `02:0d:0a:51:a6:03` (locally administered)
- Both adapters peer-to-peer
- No AP required

## Missing Data / Next Steps

### Packet Gap: #481-#955 (475 packets missing)
Expected to contain:
1. WEP64 connection attempt (imaginary network)
2. Open network connection attempt (imaginary network)
3. WEP128 connection attempt (imaginary network)
4. Error responses from adapter
5. Timeout behavior

### Questions to Resolve
1. **Ad-hoc indicator**: Where in the handshake response is ad-hoc mode flagged?
   - Checked bytes 0xf0-0xf3: Not conclusive
   - Checked capability flags 0xc6-0xcb: Same across modes
   - May be in the 51-byte metadata section

2. **CONNECT_TO_SSID_REQUEST format**: 
   - Current TLV tags (0x04, 0x05, 0x07, 0x11) don't match docs
   - Need to see successful infrastructure connection request
   - Password "1122" visible but structure unclear

3. **ADAPTER_INFO response variations**:
   - When does adapter use 70-byte vs 282-byte format?
   - What triggers detailed response with IP/BSSID/SSID?

4. **BEACON status byte progression**:
   - 0x00 → 0x03 transition meaning?
   - 0xd2 value significance?

## Files Needed
- Complete log.log2.txt (packets #481-#955 and beyond #956)
- This will show failed connection attempts and error handling

## Technical Notes
- Real MN-740 firmware: v1.0.2.26, Boot v1.3.0.06
- Console reports slightly different version in echo: v1.0.2.21
- IP address 192.168.1.181 suggests DHCP working in ad-hoc
- Ad-hoc BSSID starts with 0x02 (locally administered bit set)

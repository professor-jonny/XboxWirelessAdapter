# Xbox Wireless Protocol Fuzzing Guide

This guide explains how to fuzz the Xbox console's wireless adapter protocol to discover additional features, security vulnerabilities, and protocol details.

## Table of Contents

- [Overview](#overview)
- [Hardware Requirements](#hardware-requirements)
- [Software Requirements](#software-requirements)
- [Setup Process](#setup-process)
- [Running Fuzzing Tests](#running-fuzzing-tests)
- [Analyzing Results](#analyzing-results)
- [Safety and Best Practices](#safety-and-best-practices)
- [Troubleshooting](#troubleshooting)

---

## Overview

### What is Protocol Fuzzing?

Fuzzing is an automated testing technique that sends malformed, unexpected, or random data to a system to discover bugs, crashes, or undocumented behavior. In this case, we're fuzzing the Xbox wireless protocol to:

- Discover all valid security type values
- Find additional TLV tags the Xbox recognizes
- Test boundary conditions (length limits, buffer overflows)
- Document error responses and behavior
- Identify potential security vulnerabilities

### How It Works

```
[Your PC] ←--Ethernet Cable--→ [Xbox Console]
     ↓
PC runs emulator that pretends to be wireless adapter
     ↓
Sends hundreds/thousands of test packets
     ↓
Xbox responds (or crashes)
     ↓
Wireshark captures all traffic for analysis
```

The PC acts as a fake wireless adapter, sending modified/fuzzed packets to the Xbox over a direct Ethernet connection.

---

## Hardware Requirements

### Required Hardware

1. **PC with Ethernet port**
   - Linux recommended (Ubuntu, Debian, Fedora, etc.)
   - macOS with appropriate raw socket permissions
Note: it will not work in WSL/wsl2 in windows as the network is NAT.
for it to work in windows one would need a virtual machine with network passthrough
it in theory should will work in hyper-v with an extrrnal virtual switch but this cant
be configured in WSL.

2. **Original Xbox console**
   - Any revision (v1.0 - v1.6)
   - Powered on and functional
   - Access to network settings

3. **Ethernet cable**
   - CAT5/CAT5e/CAT6 cable
   - Crossover cable OR regular cable (most modern NICs auto-detect)
   
### Optional Hardware

- **Network switch/hub** - Allows easier packet capture
- **Second PC** - For dedicated Wireshark capture
- **Serial debug cable** - For Xbox kernel debugging (advanced)

---

## Software Requirements

### Required Software

1. **GCC compiler**
   ```bash
   sudo apt-get install build-essential
   ```

2. **OpenSSL development libraries**
   ```bash
   sudo apt-get install libssl-dev
   ```

3. **Wireshark or tcpdump**
   ```bash
   sudo apt-get install wireshark tcpdump tshark
   ```

4. **Root/sudo access**
   - Required for raw socket access
   - Required for network interface manipulation

### Required Files

You need the extracted secrets from the Xbox dashboard:
- `secrets/hmac_key.bin` (16 bytes)
- `secrets/hmac_salt.bin` (117 bytes / 0x75)
- `secrets/auth_copyright.bin` (84 bytes / 0x54)

If you don't have these, run:
```bash
python3 extract_secrets.py xonlinedash.xbe
```

---

## Setup Process

### 1. Physical Connection

**Option A: Direct Connection (Recommended)**
```
[PC eth0] ←--Cable--→ [Xbox Ethernet Port]
```

**Option B: Through Switch**
```
[PC eth0] ←--→ [Switch] ←--→ [Xbox]
                  ↓
           [PC2 - Wireshark]
```

### 2. Network Interface Configuration

```bash
# Identify your Ethernet interface
ip link show

# Example output:
# 2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 ...
# 3: wlan0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 ...

# Flush any IP configuration (we're using raw Ethernet)
sudo ip addr flush dev eth0

# Bring interface up
sudo ip link set eth0 up

# Verify interface is up
ip link show eth0
# Should show: ... state UP ...
```

### 3. Compile the Fuzzer

```bash
# Navigate to your project directory
cd /path/to/XboxWirelessAdapter

# Compile the fuzzer
gcc -o xbox_fuzzer xbox_fuzzer.c -lssl -lcrypto -Wall -O2

# Verify compilation
ls -lh xbox_fuzzer
# Should show executable with size ~50-100 KB
```

### 4. Verify Secrets are Present

```bash
# Check secrets directory
ls -lh secrets/

# Expected output:
# -rw-r--r-- 1 user user   84 Jan  8 12:00 auth_copyright.bin
# -rw-r--r-- 1 user user   16 Jan  8 12:00 hmac_key.bin
# -rw-r--r-- 1 user user  117 Jan  8 12:00 hmac_salt.bin

# Verify file sizes
wc -c secrets/*.bin
#    84 secrets/auth_copyright.bin
#    16 secrets/hmac_key.bin
#   117 secrets/hmac_salt.bin
```

---

## Running Fuzzing Tests

### Single Test Mode

Run one specific fuzzing test:

#### Test 1: Security Types
```bash
# Terminal 1: Start packet capture
sudo tcpdump -i eth0 -w security_types.pcap ether proto 0x886f

# Terminal 2: Run fuzzer
sudo ./xbox_fuzzer eth0 --fuzz-security-types

# On Xbox: Go to Network Settings → Wireless Setup
# The fuzzer will automatically respond to the handshake
# Then test all 256 security type values (0x00 - 0xFF)
```

#### Test 2: TLV Tags
```bash
# Test unknown TLV tags (0x04 - 0x20)
sudo tcpdump -i eth0 -w tlv_tags.pcap ether proto 0x886f &
sudo ./xbox_fuzzer eth0 --fuzz-tlv-tags
```

#### Test 3: SSID Length Limits
```bash
# Test SSID lengths from 0 to 64 bytes
sudo tcpdump -i eth0 -w ssid_lengths.pcap ether proto 0x886f &
sudo ./xbox_fuzzer eth0 --fuzz-ssid-lengths
```

#### Test 4: Password Length Limits
```bash
# Test password lengths from 0 to 128 bytes
sudo tcpdump -i eth0 -w password_lengths.pcap ether proto 0x886f &
sudo ./xbox_fuzzer eth0 --fuzz-password-lengths
```

### Complete Test Suite

Run all fuzzing tests in sequence:

```bash
sudo ./xbox_fuzzer eth0 --fuzz-all
```

This will run all four test modes with 5-second delays between each.

### Automated Fuzzing Script

Create `fuzz_all.sh`:

```bash
#!/bin/bash
# Complete automated fuzzing campaign

INTERFACE="${1:-eth0}"
OUTPUT_DIR="fuzz_results_$(date +%Y%m%d_%H%M%S)"

echo "=========================================="
echo "  Xbox Wireless Protocol Fuzzer"
echo "=========================================="
echo ""
echo "Interface: $INTERFACE"
echo "Output: $OUTPUT_DIR/"
echo ""

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Function to run a single test
run_test() {
    local test_name="$1"
    local test_arg="$2"

    echo ""
    echo "--- Running: $test_name ---"

    # Start packet capture
    sudo tcpdump -i $INTERFACE -w "$OUTPUT_DIR/${test_name}.pcap" \
         ether proto 0x886f > /dev/null 2>&1 &
    local TCPDUMP_PID=$!

    # Wait for tcpdump to start
    sleep 2

    # Run fuzzer
    sudo ./xbox_fuzzer $INTERFACE $test_arg 2>&1 | \
         tee "$OUTPUT_DIR/${test_name}.log"

    # Stop packet capture
    sudo kill $TCPDUMP_PID 2>/dev/null
    wait $TCPDUMP_PID 2>/dev/null

    echo "✓ Complete: $test_name"
    echo "  PCAP: $OUTPUT_DIR/${test_name}.pcap"
    echo "  Log:  $OUTPUT_DIR/${test_name}.log"

    # Cooldown period
    sleep 5
}

# Run all tests
run_test "security_types" "--fuzz-security-types"
run_test "tlv_tags" "--fuzz-tlv-tags"
run_test "ssid_lengths" "--fuzz-ssid-lengths"
run_test "password_lengths" "--fuzz-password-lengths"

echo ""
echo "=========================================="
echo "  Fuzzing Campaign Complete!"
echo "=========================================="
echo ""
echo "Results saved to: $OUTPUT_DIR/"
echo ""
echo "Analyze with:"
echo "  wireshark $OUTPUT_DIR/*.pcap"
echo "  cat $OUTPUT_DIR/*.log"
echo ""
```

Make it executable and run:
```bash
chmod +x fuzz_all.sh
./fuzz_all.sh eth0
```

---

## Analyzing Results

### Using Wireshark

#### Open Capture File
```bash
wireshark fuzz_results_*/security_types.pcap
```

#### Apply Display Filters

Filter for Xbox protocol packets only:
```
eth.type == 0x886f
```

Filter for packets from Xbox (responses):
```
eth.src == xx:xx:xx:xx:xx:xx
```
(Replace with actual Xbox MAC address)

Filter for specific packet types:
```
data[21:1] == 08
```
(Byte 21 is packet type, 0x08 = CONNECT_TO_SSID_RESPONSE)

#### Export Packet Data

1. Select packets of interest
2. File → Export Packet Dissections → As CSV/JSON/Plain Text
3. Analyze in spreadsheet or text editor

### Using tshark (Command Line)

```bash
# Count total packets
tshark -r security_types.pcap -Y "eth.type == 0x886f" | wc -l

# Extract packet data as hex
tshark -r security_types.pcap -Y "eth.type == 0x886f" \
       -T fields -e data > packets.hex

# Show packet types
tshark -r security_types.pcap -Y "eth.type == 0x886f" \
       -T fields -e frame.number -e data[21:1]

# Filter for responses only
tshark -r security_types.pcap \
       -Y "eth.type == 0x886f && data[21:1] == 08"
```

### Analyzing Logs

```bash
# View complete log
cat fuzz_results_*/security_types.log

# Extract security types that produced responses
grep "Testing security type" fuzz_results_*/security_types.log

# Search for errors or unusual behavior
grep -i "error\|fail\|crash" fuzz_results_*/*.log
```

### Python Analysis Script

Create `analyze_fuzz.py`:

```python
#!/usr/bin/env python3
import sys
from scapy.all import rdpcap, hexdump

def analyze_pcap(filename):
    packets = rdpcap(filename)

    xbox_responses = []

    for pkt in packets:
        if pkt.haslayer('Ether') and pkt['Ether'].type == 0x886f:
            raw = bytes(pkt['Ether'].payload)
            if len(raw) >= 22:
                packet_type = raw[7]
                nonce = (raw[8] << 8) | raw[9]

                # If it's a response (even packet types)
                if packet_type % 2 == 0:
                    xbox_responses.append({
                        'type': packet_type,
                        'nonce': nonce,
                        'data': raw.hex()
                    })

    return xbox_responses

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <pcap_file>")
        sys.exit(1)

    responses = analyze_pcap(sys.argv[1])

    print(f"Found {len(responses)} Xbox responses")
    print("\nPacket Type Distribution:")

    type_counts = {}
    for r in responses:
        type_counts[r['type']] = type_counts.get(r['type'], 0) + 1

    for ptype, count in sorted(type_counts.items()):
        print(f"  Type 0x{ptype:02x}: {count} packets")
```

Run it:
```bash
python3 analyze_fuzz.py fuzz_results_*/security_types.pcap
```

### What to Look For

#### 1. Valid Security Types
- Security type values where Xbox responds with success
- Different error codes in CONNECT_TO_SSID_RESPONSE
- Example findings:
  - `0x00` = Open (no security)
  - `0x01` = WEP
  - `0x02` = WPA-PSK
  - `0x04` = WPA2-PSK (if Xbox 360 adapter)
  - `0xFF` = Might trigger error or be ignored

#### 2. Recognized TLV Tags
- Tags where Xbox behavior changes
- New error messages or response codes
- Example findings:
  - `0x04` = Encryption type (speculative)
  - `0x05` = MAC address (speculative)
  - Unknown tags might be silently ignored or trigger errors

#### 3. Buffer Overflow Indicators
- Xbox crashes or reboots
- Truncated responses
- Error codes for "too long" inputs
- Example findings:
  - SSID > 32 bytes → Error code 0x01
  - Password > 63 bytes → Connection fails
  - Extremely long values → Xbox crashes (security issue!)

#### 4. Undocumented Features
- Unexpected successful connections
- Debug output or special modes
- Hidden packet types
- Example findings:
  - Special security type enables debug mode
  - Certain TLV combinations unlock features

---

## Safety and Best Practices

### Before Fuzzing

1. **Backup your Xbox**
   - Save any important data
   - Note current settings
   - Take photos of configuration screens

2. **Use a test Xbox if possible**
   - Fuzzing can cause crashes/corruption
   - A dedicated test unit is safer

3. **Prepare for recovery**
   - Know how to hard reset Xbox
   - Have alternate network setup method ready
   - Keep Xbox installation disc handy

### During Fuzzing

1. **Monitor the Xbox**
   - Watch for crashes, freezes, reboots
   - Note any error messages on screen
   - Document unusual behavior

2. **Save results frequently**
   - Don't rely on one long capture
   - Split tests into manageable chunks
   - Back up PCAP files regularly

3. **Pace your tests**
   - Don't overwhelm the Xbox
   - Use delays between test packets (200-500ms)
   - Let Xbox recover between test suites

### After Fuzzing

1. **Document findings**
   - Save all PCAPs and logs
   - Screenshot Xbox error messages
   - Note reproducible crashes

2. **Verify Xbox health**
   - Test normal network functionality
   - Ensure settings weren't corrupted
   - Reset to defaults if needed

3. **Responsible disclosure**
   - If you find security vulnerabilities, report them
   - Don't publicly disclose critical bugs immediately
   - Give time for patches (if applicable)

### Legal and Ethical Considerations

- ✅ Testing your own Xbox: Legal
- ✅ Reverse engineering for interoperability: Generally legal
- ⚠️ Sharing exploits: Consider responsible disclosure
- ❌ Using findings to attack others' Xboxes: Illegal
- ❌ Circumventing security for piracy: Illegal

**Disclaimer:** This guide is for educational and research purposes. You are responsible for ensuring your activities comply with applicable laws.

---

## Troubleshooting

### Problem: "Permission denied" when running fuzzer

**Solution:**
```bash
# Run with sudo
sudo ./xbox_fuzzer eth0 --fuzz-security-types

# Or grant CAP_NET_RAW capability (persistent)
sudo setcap cap_net_raw+ep ./xbox_fuzzer
./xbox_fuzzer eth0 --fuzz-security-types
```

### Problem: "Failed to load secrets"

**Solution:**
```bash
# Check secrets exist
ls -lh secrets/

# Verify file sizes
wc -c secrets/*.bin
#    84 secrets/auth_copyright.bin
#    16 secrets/hmac_key.bin
#   117 secrets/hmac_salt.bin

# Re-extract if needed
python3 extract_secrets.py xonlinedash.xbe
```

### Problem: Xbox doesn't respond to handshake

**Solution:**
1. Check cable connection
2. Verify interface is up: `ip link show eth0`
3. Check Xbox is on and in wireless setup screen
4. Try different Ethernet cable
5. Verify no firewall is blocking: `sudo iptables -L`
6. Check Xbox MAC address in fuzzer debug output

### Problem: tcpdump shows no packets

**Solution:**
```bash
# Verify interface is correct
ip link show

# Check tcpdump filter
sudo tcpdump -i eth0 -n

# Try without filter first
sudo tcpdump -i eth0

# Verify Xbox is sending packets
# Should see broadcasts from Xbox on startup
```

### Problem: Fuzzer compiles but crashes immediately

**Solution:**
```bash
# Run with debug symbols
gcc -g -o xbox_fuzzer xbox_fuzzer.c -lssl -lcrypto
gdb ./xbox_fuzzer

# Check for missing libraries
ldd ./xbox_fuzzer

# Verify OpenSSL is installed
openssl version
```

### Problem: Xbox crashes during fuzzing

**Expected behavior!** This is what fuzzing can discover:

1. **Power cycle Xbox** - Hold power button for 10 seconds
2. **Document the crash:**
   - What test was running?
   - What was the last packet sent?
   - Can you reproduce it?
3. **Save the PCAP** - Contains the crash-inducing packet
4. **Continue testing** - But skip that specific input

### Problem: Results are inconsistent

**Solution:**
- Xbox state might affect results
- Reset Xbox between test runs
- Use fresh boot each time
- Check for timing issues (increase delays)
- Verify Xbox isn't actually connecting to real networks

---

## Example Results

### Sample Output

```
========================================
  Xbox Wireless Protocol Fuzzer
========================================

✓ Listening on eth0 (MAC: 00:11:22:33:44:55)

Waiting for Xbox handshake...
(Go to Xbox Network Settings → Wireless Setup)

Received handshake request
✓ Handshake complete!

========================================
  Starting Fuzzing Tests
========================================

=== FUZZING SECURITY TYPES (0x00 - 0xFF) ===
This will test all 256 possible security type values...

[  1/256] Testing security type 0x00... sent
[  2/256] Testing security type 0x01... sent
[  3/256] Testing security type 0x02... sent
...
[256/256] Testing security type 0xff... sent

✓ Security type fuzzing complete!

========================================
  Fuzzing Complete!
========================================

Now analyze the pcap file for Xbox responses.
```

### Sample Findings Document

Create `FINDINGS.md`:

```markdown
# Xbox Wireless Protocol Fuzzing Results

Date: 2025-01-08
Xbox Model: v1.4
Tester: [Your Name]

## Security Type Fuzzing

### Valid Security Types
- 0x00: Open - Xbox accepts, no password required
- 0x01: WEP - Xbox accepts, requires WEP key
- 0x02: WPA-PSK - Xbox accepts, requires passphrase

### Invalid Security Types
- 0x03: Xbox returns error code 0x02
- 0x04-0xFF: Xbox returns error code 0x03 (unsupported)

## TLV Tag Fuzzing

### Recognized Tags
- 0x01: SSID (confirmed)
- 0x02: Password (confirmed)
- 0x03: Security type (confirmed)

### Unrecognized Tags
- 0x04-0x20: All ignored by Xbox, no error

## Buffer Overflow Testing

### SSID Length Limits
- 0-32 bytes: Accepted
- 33-64 bytes: Error code 0x01
- 65+ bytes: Xbox crashes (SECURITY ISSUE!)

### Password Length Limits
- 0-63 bytes: Accepted
- 64-128 bytes: Error code 0x02

## Recommendations

1. Document security type values in protocol spec
2. Report SSID buffer overflow to Microsoft
3. Test Xbox 360 adapter for WPA2 support
```

---

## Next Steps

After completing fuzzing:

1. **Update protocol documentation** with confirmed values
2. **Submit findings** to project repository
3. **Test with real wireless networks** to verify security types
4. **Implement additional features** based on discovered tags
5. **Consider automated regression testing** for protocol changes

## Additional Resources

- [Wireshark User Guide](https://www.wireshark.org/docs/wsug_html_chunked/)
- [AFL Fuzzing Documentation](https://aflplus.plus/)
- [Xbox Development Wiki](https://xboxdevwiki.net/)
- [WPA/WPA2 Protocol Specifications](https://www.wi-fi.org/)

## Contributing

If you discover new protocol features through fuzzing:

1. Document your findings clearly
2. Include PCAP files and logs
3. Submit a pull request with updated documentation
4. Share interesting findings in issues/discussions

---

**Happy Fuzzing! 🎮⚡**

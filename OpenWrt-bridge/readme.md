# OpenWrt Xbox Wireless Adapter

**Configure your OpenWrt router directly from your Xbox console**

This package turns your OpenWrt router into an Xbox Wireless Adapter (MN-740) emulator, allowing you to set up WiFi networks directly from the Xbox dashboard using the native Xbox wireless configuration interface.

## ⚠️ Important Notes

- **Requires Xbox Dashboard Secrets**: You must extract cryptographic keys from your Xbox dashboard file (xonlinedash.xbe) for authentication to work dashboard 5960 (MD5: 8149654a030d813bcc02a24f39fd3ce9)
- **Password Length Limitation**: Xbox UI limits password entry to ~13 characters for WEP compatibility. For longer WPA/WPA2 passwords, you may need to pre-configure or modify your network password to meet this limit.

**Dev Info**: There is still a lot of work to do this is just really a proof of concept.
I'm not really confidant on python or reverse engineering so I may have interpreted some info wrong from Agarmash's original python emulator, and my own research. 

## What This Does

- **Replaces the Microsoft Xbox Wireless Adapter (MN-740)** with generic OpenWrt hardware
- **Configure WiFi from Xbox dashboard** - Use your Xbox controller to select networks and enter passwords
- **No PC needed** - No need to preconfigure WiFi settings with another device
- **Native Xbox UI** - Familiar interface, just like the original adapter
- **Any WiFi Security** - Supports Open, WEP, WPA, WPA2, WPA3 (despite Xbox UI showing WEP options)

## Requirements

- OpenWrt router (19.07 or newer) with:
  - WiFi radio capability
  - OpenSSL support
  - Minimum 8MB flash
- Xbox dashboard file (xonlinedash.xbe) for secret extraction
- Python 3 (for one-time secret extraction

## Hardware Recommendations

Tested/recommended hardware:
- **NanoPi R4S** - Dual Gigabit Ethernet, built-in WiFi
- **Raspberry Pi 4** with USB WiFi adapter
- **GL.iNet routers** (GL-AX1800, GL-MT3000, etc.)
- Any OpenWrt device with Ethernet + WiFi

## Quick Start

### 1. Extract Xbox Secrets

**On your computer with Python 3:**

```bash
# Get xonlinedash.xbe from your Xbox (usually in C:\xodash\)
# You can FTP it from a modded Xbox or extract from dashboard installer

# Download extraction script
wget https://raw.githubusercontent.com/professor-jonny/XboxWirelessAdapter/main/extract_secrets.py

# Extract secrets
python3 extract_secrets.py xonlinedash.xbe

# Verify files were created
ls secrets/
# Should show: hmac_salt.bin (117 bytes), hmac_key.bin (16 bytes), auth_copyright.bin (84 bytes)
```

### 2. Install Package

**Build from Source**
```bash
# In OpenWrt buildroot
git clone https://github.com/yourusername/xboxwireless package/xboxwireless

# Configure
make menuconfig
# Navigate to: Network -> xboxwireless [M]

# Build
make package/xboxwireless/compile V=s

# Install on router old package system:
scp bin/packages/*/base/xboxwireless_*.ipk root@192.168.1.1:/tmp/
ssh root@192.168.1.1 'opkg install /tmp/xboxwireless_*.ipk'

# Install on router alpine package system:
scp bin/packages/*/base/xboxwireless_*.apk root@192.168.1.1:/tmp/
ssh root@192.168.1.1 'apk add /tmp/xboxwireless_*.apk'


```

### 3. Transfer Secrets to Router

```bash
# Copy secrets directory to router
scp -r secrets/ root@192.168.1.1:/etc/xboxwireless/

# Verify on router
ssh root@192.168.1.1
ls -l /etc/xboxwireless/secrets/
# Should show: hmac_salt.bin (117), hmac_key.bin (16), auth_copyright.bin (84)
```

### 4. Configure

```bash
# SSH into router
ssh root@192.168.1.1

# Configure interface (port where Xbox connects)
uci set xboxwireless.xboxwireless.enabled='1'
uci set xboxwireless.xboxwireless.interface='eth0'
uci set xboxwireless.xboxwireless.wifi_device='radio0'
uci set xboxwireless.xboxwireless.network='wwan'
uci commit xboxwireless

# Enable and start
/etc/init.d/xboxwireless enable
/etc/init.d/xboxwireless start
```

### 5. Connect Xbox

1. **Physical Connection**
   - Connect Xbox to router's Ethernet port (default: eth0/LAN1)
   - Power on Xbox

2. **Configure from Xbox Dashboard**
   - Go to: **Settings → Network Settings → Advanced → Wireless Adapter**
   - (Or for older dashboards: Insert Xbox Network Setup disc)
   - Xbox will detect the "Xbox Wireless Adapter"
   - Select your WiFi network from the list
   - Enter WiFi password (max ~13 characters visible in Xbox UI)
   - Xbox sends configuration to router

3. **Verify Connection**
   ```bash
   # On router, check logs
   logread | grep xboxwireless

   # Check WiFi status
   /usr/sbin/xboxwireless-config.sh --status

   # Verify internet
   ifconfig wwan
   ```

## How It Works

```
┌─────────────┐         ┌──────────────┐         ┌─────────────┐
│             │ Ethernet│              │  WiFi   │             │
│    Xbox     ├────────→│   OpenWrt    ├────────→│   WiFi AP   │
│  Console    │ Protocol│    Router    │ Client  │  (Internet) │
│             │  0x886f │              │  Mode   │             │
└─────────────┘         └──────────────┘         └─────────────┘
     ↓                         ↓                         ↓
  Sends WiFi          Receives & parses           Connects to
  credentials         HMAC authenticates           your network
  via MS NLB          Configures radio             Provides inet
```

**Protocol Flow:**
1. Xbox broadcasts handshake request with auth challenge
2. Router responds with HMAC-SHA1 signature (using extracted secrets)
3. Xbox accepts authentication, sends beacon keepalives
4. Xbox requests network list, router scans WiFi
5. User selects network and enters password on Xbox
6. Xbox sends connection request with SSID/password
7. Router configures WiFi client, connects to network
8. Router bridges traffic between Xbox (Ethernet) and WiFi
9. Xbox gets internet access, reports success

**Key Protocol Details:**
- Uses Ethernet protocol 0x886f (MS NLB heartbeat)
- Custom Xbox protocol with "XBOX" signature
- HMAC-SHA1 authentication required
- Encrypted WiFi credentials transfer
- TLV-encoded configuration data

## Password Length Workaround

The Xbox UI was designed for WEP (max 13 ASCII characters). For WPA/WPA2 networks with longer passwords:

**Option 1: Temporarily shorten your WiFi password**
```bash
# On your WiFi router, temporarily set a 13-char password
# Configure Xbox
# Change back to long password
```

**Option 2: Pre-configure on OpenWrt** (future feature please implement me!!!)
```bash
# Could pre-set password in UCI config
uci set xboxwireless.networks.home='network'
uci set xboxwireless.networks.home.ssid='MyNetwork'
uci set xboxwireless.networks.home.password='VeryLongPassword123!'
uci commit xboxwireless
```

## Configuration Options

### /etc/config/xboxwireless

```bash
config xboxwireless
    option enabled '1'           # Enable/disable service
    option interface 'eth0'      # Ethernet port Xbox connects to
    option wifi_device 'radio0'  # WiFi radio to use (radio0=2.4GHz, radio1=5GHz)
    option network 'wwan'        # Network interface name for WiFi client
```

### Service Management

```bash
# Start/Stop/Restart
/etc/init.d/xboxwireless start
/etc/init.d/xboxwireless stop
/etc/init.d/xboxwireless restart

# Enable/Disable auto-start
/etc/init.d/xboxwireless enable
/etc/init.d/xboxwireless disable

# Check status
/etc/init.d/xboxwireless status
ps | grep xboxwireless
```

### Manual Testing

```bash
# Stop service
/etc/init.d/xboxwireless stop

# Run with debug output
/usr/sbin/xboxwireless eth0

# Run without debug
/usr/sbin/xboxwireless eth0 --no-debug
```

## Troubleshooting

### Service Won't Start

```bash
# Check secrets exist and have correct sizes
ls -l /etc/xboxwireless/secrets/
# Should be: hmac_salt.bin (117), hmac_key.bin (16), auth_copyright.bin (84)

# Check file permissions
chmod 600 /etc/xboxwireless/secrets/*

# Check OpenSSL is installed
opkg list-installed | grep libopenssl

# Run manually to see errors
/usr/sbin/xboxwireless eth0
```

### Xbox Doesn't Detect Adapter

```bash
# Verify daemon is running
ps | grep xboxwireless

# Check Ethernet link
ethtool eth0 | grep Link

# Monitor for Xbox packets (should see 0x886f protocol)
tcpdump -i eth0 ether proto 0x886f

# Check logs
logread | grep xboxwireless
```

### Authentication Fails

```bash
# Verify dashboard MD5
md5sum xonlinedash.xbe
# Should be: 8149654a030d813bcc02a24f39fd3ce9 for version 5960

# Re-extract secrets if MD5 doesn't match
python3 extract_secrets.py xonlinedash.xbe

# Check HMAC calculation in debug mode
/usr/sbin/xboxwireless eth0 | grep HMAC
```

### WiFi Won't Connect

```bash
# Check WiFi radio is enabled
uci get wireless.radio0.disabled
# Should be '0' or not set

# Verify WiFi configuration
uci show wireless | grep xbox

# Check available networks
iwlist wlan0 scan | grep ESSID

# Test manually
/usr/sbin/xboxwireless-config.sh "TestSSID" "testpass" 2
```

### No Internet Access

```bash
# Check routing
ip route show

# Test internet from router
ping -I wwan 8.8.8.8

# Check firewall
uci show firewall | grep wwan

# Verify DNS
cat /etc/resolv.conf
```

## Monitoring

```bash
# Real-time logs
logread -f | grep xboxwireless

# Connection status
/usr/sbin/xboxwireless-config.sh --status

# WiFi interface status
ifconfig wwan
iwconfig wwan

# Packet capture
tcpdump -i eth0 -X ether proto 0x886f
```

## Package Contents

```
/usr/sbin/xboxwireless              # Main daemon (C binary)
/usr/sbin/xboxwireless-config.sh    # WiFi configuration helper
/etc/init.d/xboxwireless            # Procd init script
/etc/config/xboxwireless            # UCI configuration
/etc/xboxwireless/secrets/          # Cryptographic keys (you provide)
/usr/share/xboxwireless/            # Documentation
```

## Security Notes
- **Firewall**: Only necessary Xbox Live ports should be open (88/UDP, 3074/TCP+UDP)


## Performance Tips

- Use 5GHz WiFi for better performance (if available)
- Disable WiFi power saving: `uci set wireless.xbox_sta.powersave='0'`
- Use WPA2 (faster than WPA3 on older hardware)
- Set static DHCP lease for Xbox
- Enable QoS for gaming traffic

## Credits

This project is based on excellent reverse engineering work by:
- **[@agarmash](https://github.com/agarmash)** - [XboxWirelessAdapter](https://github.com/agarmash/XboxWirelessAdapter) - Original protocol research


## License

GPL-2.0-or-later

This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later version.

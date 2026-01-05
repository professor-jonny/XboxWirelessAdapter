# OpenWrt Xbox Wireless

**Configure your OpenWrt router's directly from your Xbox console**

This package turns your OpenWrt router into an Xbox Wireless Adapter emulator, allowing you to set up WiFi networks directly from the Xbox dashboard using the native Xbox wireless configuration interface.

Note: this is still very much a work in progress and has not been tested it is just the bones of the
package to support configuring an OpenWrt device from the built in Xbox MN740 wireless API.

There is still a lot of work to do this is just really a proof of concept.
I'm no really confidant on python or reverse engineering so I may have interpreted some info wrong
in my C code conversion.

There is a few candidates for hardware but one cheap device is the nanopi r4s or any of the pi boards
that you can plug in Ethernet and has a native Wi-Fi or a compatible USB Wi-Fi adaptor should do.

## What This Does

- **Replaces the Microsoft Xbox Wireless Adapter with generic Openwrt hardware**
- **Configure WiFi from Xbox dashboard** - Use your Xbox controller to select networks and enter passwords
- **No PC needed** - No need to preconfigure with Windows or other devices
- **Native Xbox UI** - Familiar interface, just like connecting to Xbox Live

## Requirements

- OpenWrt router (19.07 or newer)
- Xbox console connected via Ethernet to router
- WiFi radio in the router (to connect to upstream network)

## Quick Start

### Installation


**Build from Source**
```bash
# copy this package into your OpenWrt buildroot
package/network/xboxwireless/

# Configure
make menuconfig
# Navigate to: Network -> xboxwireless [M]

# Build
make package/network/xboxwireless/compile V=s

# Install on router with opkg:
scp bin/packages/*/base/xboxwireless_*.ipk root@192.168.1.1:/tmp/
ssh root@192.168.1.1
opkg install /tmp/xboxwireless_*.ipk

# Install on router with apk (newer package system):
scp bin/packages/*/base/xboxwireless_*.apk root@192.168.1.1:/tmp/
ssh root@192.168.1.1
apk add /tmp/xboxwireless_*.apk

```

### Configuration

The package auto-starts with default settings. To customize:

```bash
# Edit configuration
uci set xboxwireless.xboxwireless.interface='eth0'  # Port Xbox connects to
uci set xboxwireless.xboxwireless.wifi_device='radio0'  # WiFi radio to use
uci commit xboxwireless

# Restart service
/etc/init.d/xboxwireless restart
```

### Usage

1. **Connect Xbox to Router**
   - Connect your Xbox console to the router's LAN port via Ethernet
   - The port should match the one configured above (default: eth0)

2. **Configure WiFi from Xbox**
   - On Xbox, go to: **Settings → Network Settings → advanced → wireless → Settings**
   - Select your WiFi network from the list
   - Enter the WiFi password using the Xbox controller
   - Xbox will send the configuration to the router
note: for older dashboards you may require the Xbox network setup disk to configure the device

3. **Done!**
   - The router will connect to the WiFi network
   - Xbox gets internet access through the router
   - Check router logs: `logread | grep xboxwireless`

## Caveats
The original device only supported WEP security and that has a limitation key length to modern standards,
the Xbox UI also has a limitation on some unicode characters:
The Xbox has no concept of WPA WPA2 WPA3 SAE etc...
As we are emulating the interface we can connect to any network but our key length becomes an issue
WEP limits us to 13 ASCII characters so your home networks password can not break that limit
or you cant enter it in the Xbox.
For example in WPA/WPA2 the password standard is (8-63 chars) far greater than you can type on the xbox.

So be sure to select WEP 128-bit so you can have a longest password possible and be sure to limit your hom network's password to 13 characters.

in theory we can pre set the password on the openwrt device.
## How It Works

```
┌─────────────┐         ┌──────────────┐         ┌─────────────┐
│             │ Ethernet│              │  WiFi   │             │
│    Xbox     ├────────→│    OpenWrt   ├────────→│     AP      │
│  Console    │ Protocol│    Router    │ Client  │  (Internet) │
│             │  0x8863 │              │  Mode   │             │
└─────────────┘         └──────────────┘         └─────────────┘
```

1. **Xbox sends WiFi credentials** over Ethernet using Xbox Wireless Adapter protocol (0x8863)
2. **Daemon receives and parses** the SSID, password, and security settings
3. **Router configures WiFi** as a client to connect to your network
4. **Router bridges traffic** between Xbox (Ethernet) and WiFi
5. **Status reports back** to Xbox (connected, IP address, signal strength)

## Package Contents

- **`/usr/sbin/xboxwireless`** - Main daemon (C binary)
- **`/usr/sbin/xboxwireless-config.sh`** - WiFi configuration helper script
- **`/etc/init.d/xboxwireless`** - Init script for auto-start
- **`/etc/config/xboxwireless`** - UCI configuration file

## Advanced Configuration

### Multiple WiFi Radios

If your router has multiple WiFi radios, specify which one to use:

```bash
# Use 5GHz radio
uci set xboxwireless.xboxwireless.wifi_device='radio1'
uci commit xboxwireless
/etc/init.d/xboxwireless restart
```

### Custom Network Interface

Change the network interface name for the WiFi connection:

```bash
uci set xboxwireless.xboxwireless.network='xbox_wan'
uci commit xboxwireless
/etc/init.d/xboxwireless restart
```

### Disable Auto-start

```bash
/etc/init.d/xboxwireless disable
/etc/init.d/xboxwireless stop
```

## Troubleshooting

### Xbox doesn't detect the adapter

**Check daemon is running:**
```bash
ps | grep xboxwireless
```

**Check logs:**
```bash
logread | grep xboxwireless
```

**Verify Xbox is connected to correct port:**
```bash
# Should show link detected
ethtool eth0 | grep Link
```

**Monitor for Xbox protocol packets:**
```bash
tcpdump -i eth0 ether proto 0x8863
```

### WiFi doesn't connect after configuration

**Check wireless config was applied:**
```bash
uci show wireless | grep xbox
```

**Verify radio is enabled:**
```bash
uci get wireless.radio0.disabled
# Should be '0' or not set
```

**Check WiFi status manually:**
```bash
/usr/sbin/xboxwireless-config.sh --status
```

**View wireless logs:**
```bash
logread | grep -E 'wireless|wpa'
```

### Reset WiFi configuration

```bash
# Remove Xbox wireless config
uci delete wireless.xbox_sta
uci commit wireless
wifi reload
```

## Monitoring

**Real-time logs:**
```bash
logread -f | grep xbox
```

**Check connection status:**
```bash
/usr/sbin/xboxwireless-config.sh --status
```

**List active connections:**
```bash
ip addr show wwan  # or your network interface name
```

### Testing

```bash
# Monitor packet exchanges
sudo tcpdump -i eth0 -X ether proto 0x8863

# Test config script manually
./files/xboxwireless-config.sh "TestNetwork" "password123" 2
```

## Credits

This project is based on excelent reverse engineering work from:
- **[XboxWirelessAdapter](https://github.com/agarmash/XboxWirelessAdapter)** by [@agarmash](https://github.com/agarmash)


## License

GPL-2.0-or-later

This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later version.

##

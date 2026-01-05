# OpenWrt Xbox Wireless Package

## Configuration

Edit `/etc/config/xboxwireless`:

```bash
uci set xboxwireless.xboxwireless.enabled='1'
uci set xboxwireless.xboxwireless.interface='eth0'    # Interface Xbox connects to
uci set xboxwireless.xboxwireless.wifi_device='radio0' # WiFi device to configure
uci set xboxwireless.xboxwireless.network='wwan'      # Network interface name
uci commit xboxwireless

# Restart service
/etc/init.d/xboxwireless restart
```

## Usage

1. **Connect Xbox to Router**: Connect Xbox console to the router's Ethernet port specified in config (default: eth0)

2. **Configure WiFi from Xbox**:
   - Go to Xbox Settings > Network Settings
   - Select "Set up wireless network"
   - Choose your WiFi network
   - Enter password
   - Xbox will send configuration to router

3. **Monitor Status**:
```bash
# Check if daemon is running
ps | grep xboxwireless

# Check logs
logread | grep xboxwireless

# Manual status check
/usr/sbin/xboxwireless-config.sh --status
```

## Service Management

```bash
# Start service
/etc/init.d/xboxwireless start

# Stop service
/etc/init.d/xboxwireless stop

# Restart service
/etc/init.d/xboxwireless restart

# Enable on boot
/etc/init.d/xboxwireless enable

# Disable on boot
/etc/init.d/xboxwireless disable

# Check status
/etc/init.d/xboxwireless status
```

## Troubleshooting

### Daemon won't start
```bash
# Check config
cat /etc/config/xboxwireless

# Check interface exists
ip link show eth0

# Run manually to see errors
/usr/sbin/xboxwireless eth0
```

### Xbox not connecting
```bash
# Check logs
logread -f | grep xbox

# Verify Xbox is on correct port
# Check for protocol 0x8863 packets
tcpdump -i eth0 ether proto 0x8863
```

### WiFi not connecting after config
```bash
# Check wireless config
uci show wireless | grep xbox

# Check if radio is enabled
uci get wireless.radio0.disabled

# Manually test config script
/usr/sbin/xboxwireless-config.sh "TestSSID" "password123" 2
```

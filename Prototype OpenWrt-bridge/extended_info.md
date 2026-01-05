# Xbox Wireless Adapter - Cheat Sheet

Quick command reference for daily use. See README.md for full documentation.

## Service Control

```bash
/etc/init.d/xboxwireless start|stop|restart|enable|disable
```

## Status Checks

```bash
ps | grep xboxwireless                      # Is it running?
logread -f | grep xboxwireless              # Live logs
/usr/sbin/xboxwireless-config.sh --status  # WiFi status
ifconfig wwan                                # IP address
iwconfig wwan                                # Signal strength
```

## Configuration

```bash
uci set xboxwireless.xboxwireless.enabled='1'
uci set xboxwireless.xboxwireless.interface='eth0'
uci set xboxwireless.xboxwireless.wifi_device='radio0'
uci commit xboxwireless
/etc/init.d/xboxwireless restart
```

## Troubleshooting

```bash
# Check secrets (must be 117, 16, 84 bytes)
ls -l /etc/xboxwireless/secrets/

# Run with debug
/etc/init.d/xboxwireless stop
/usr/sbin/xboxwireless eth0

# Monitor Xbox packets (protocol 0x886f)
tcpdump -i eth0 ether proto 0x886f

# Check WiFi radio enabled
uci get wireless.radio0.disabled  # Should be 0 or error

# Test WiFi manually
/usr/sbin/xboxwireless-config.sh "SSID" "password" 2
```

## Quick Fixes

**Service won't start:** Check secrets exist
**Xbox can't find adapter:** Wrong interface or cable unplugged
**Auth fails:** Wrong dashboard version, re-extract secrets
**WiFi won't connect:** Radio disabled or wrong password
**No internet:** Check `ip route` and firewall

## Key Facts

- Protocol: **0x886f** (MS NLB, NOT 0x8863)
- Dashboard: 5960+ (MD5: `8149654a030d813bcc02a24f39fd3ce9`)
- Password limit: ~13 chars visible in Xbox UI (protocol supports more)
- Secrets: Must extract from xonlinedash.xbe
- Files: hmac_salt.bin (117), hmac_key.bin (16), auth_copyright.bin (84)

## Files

```
/usr/sbin/xboxwireless              # Main daemon
/usr/sbin/xboxwireless-config.sh    # WiFi helper
/etc/init.d/xboxwireless            # Init script
/etc/config/xboxwireless            # Config
/etc/xboxwireless/secrets/          # Keys
```

## One-Time Setup Reminder

```bash
# 1. Extract secrets (on your PC)
python3 extract_secrets.py xonlinedash.xbe

# 2. Transfer to router
scp -r secrets/ root@192.168.1.1:/etc/xboxwireless/

# 3. Enable and start
/etc/init.d/xboxwireless enable
/etc/init.d/xboxwireless start

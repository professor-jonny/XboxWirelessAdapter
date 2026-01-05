#!/bin/sh
# Xbox Wireless WiFi Configuration Helper
# This script configures OpenWrt WiFi as a client (station mode)

SSID="$1"
PASSWORD="$2"
SECURITY="$3"
DEVICE="${4:-radio0}"
NETWORK="${5:-wwan}"

usage() {
    echo "Usage: $0 <ssid> <password> <security_type> [device] [network]"
    echo ""
    echo "Security types:"
    echo "  0 - Open (no password)"
    echo "  1 - WEP"
    echo "  2 - WPA/WPA2-PSK"
    echo "  3 - WPA2-PSK"
    echo "  4 - WPA3-SAE"
    echo ""
    echo "Example: $0 'MyNetwork' 'password123' 2 radio0 wwan"
    exit 1
}

[ -z "$SSID" ] && usage

log() {
    logger -t xboxwireless "$1"
    echo "$1"
}

# Map security type to OpenWrt encryption
get_encryption() {
    case "$1" in
        0) echo "none" ;;
        1) echo "wep-open" ;;
        2) echo "psk-mixed" ;;
        3) echo "psk2" ;;
        4) echo "sae" ;;
        *) echo "psk2" ;;
    esac
}

# Check if wireless interface already exists
cleanup_existing() {
    log "Cleaning up existing Xbox wireless configuration..."
    
    # Remove any existing interface with same network name
    uci -q delete wireless.xbox_sta 2>/dev/null
    uci commit wireless
}

# Configure wireless as station (client)
configure_wifi() {
    local encryption=$(get_encryption "$SECURITY")
    
    log "Configuring WiFi client mode..."
    log "SSID: $SSID"
    log "Security: $encryption"
    log "Device: $DEVICE"
    
    # Remove existing config
    cleanup_existing
    
    # Create new wireless interface
    uci set wireless.xbox_sta=wifi-iface
    uci set wireless.xbox_sta.device="$DEVICE"
    uci set wireless.xbox_sta.network="$NETWORK"
    uci set wireless.xbox_sta.mode='sta'
    uci set wireless.xbox_sta.ssid="$SSID"
    uci set wireless.xbox_sta.encryption="$encryption"
    
    # Set password if not open network
    if [ "$SECURITY" != "0" ]; then
        uci set wireless.xbox_sta.key="$PASSWORD"
    fi
    
    # Disable power saving for better performance
    uci set wireless.xbox_sta.disabled='0'
    
    # Commit wireless config
    uci commit wireless
    
    log "Wireless configuration complete"
}

# Configure network interface
configure_network() {
    log "Configuring network interface..."
    
    # Check if network interface exists
    if ! uci -q get network."$NETWORK" >/dev/null; then
        log "Creating network interface $NETWORK"
        uci set network."$NETWORK"=interface
        uci set network."$NETWORK".proto='dhcp'
    fi
    
    uci commit network
    log "Network configuration complete"
}

# Configure firewall to allow traffic from wwan to lan
configure_firewall() {
    log "Configuring firewall..."
    
    # Check if zone for wwan exists
    if ! uci -q get firewall.@zone[1].name | grep -q "wan"; then
        log "Firewall already configured"
        return
    fi
    
    # Add wwan to wan zone if not already there
    wan_networks=$(uci -q get firewall.@zone[1].network)
    if ! echo "$wan_networks" | grep -q "$NETWORK"; then
        uci add_list firewall.@zone[1].network="$NETWORK"
        uci commit firewall
        log "Added $NETWORK to wan firewall zone"
    fi
}

# Enable the radio if disabled
enable_radio() {
    local disabled=$(uci -q get wireless."$DEVICE".disabled)
    
    if [ "$disabled" = "1" ]; then
        log "Enabling radio $DEVICE"
        uci set wireless."$DEVICE".disabled='0'
        uci commit wireless
    fi
}

# Reload network services
reload_network() {
    log "Reloading network services..."
    
    # Reload wireless
    wifi reload
    
    # Wait a moment for interface to come up
    sleep 2
    
    # Reload network
    /etc/init.d/network reload
    
    log "Network services reloaded"
}

# Check connection status
check_connection() {
    log "Checking connection status..."
    
    local max_wait=30
    local count=0
    
    while [ $count -lt $max_wait ]; do
        # Check if interface is up
        if ifconfig | grep -q "$NETWORK"; then
            # Check if we have an IP
            local ip=$(ifconfig "$NETWORK" 2>/dev/null | grep 'inet addr' | cut -d: -f2 | awk '{print $1}')
            
            if [ -n "$ip" ]; then
                log "Connected successfully! IP: $ip"
                echo "STATUS:CONNECTED:$ip"
                return 0
            fi
        fi
        
        sleep 1
        count=$((count + 1))
    done
    
    log "Connection timeout - failed to get IP address"
    echo "STATUS:FAILED:TIMEOUT"
    return 1
}

# Get current status
get_status() {
    # Check if interface exists and is up
    if ifconfig | grep -q "$NETWORK"; then
        local ip=$(ifconfig "$NETWORK" 2>/dev/null | grep 'inet addr' | cut -d: -f2 | awk '{print $1}')
        
        if [ -n "$ip" ]; then
            # Get signal strength if available
            local signal=$(iwconfig "$NETWORK" 2>/dev/null | grep 'Signal level' | sed 's/.*Signal level=\([^ ]*\).*/\1/')
            echo "STATUS:CONNECTED:$ip:$signal"
            return 0
        fi
    fi
    
    # Check if we're trying to connect
    if [ -f /tmp/xboxwireless.connecting ]; then
        echo "STATUS:CONNECTING"
        return 0
    fi
    
    echo "STATUS:DISCONNECTED"
    return 1
}

# Main execution
case "$1" in
    --status)
        get_status
        exit 0
        ;;
    --help|-h)
        usage
        ;;
esac

# Validate inputs
if [ -z "$SSID" ]; then
    log "ERROR: SSID is required"
    exit 1
fi

# Mark as connecting
touch /tmp/xboxwireless.connecting

# Execute configuration steps
enable_radio
configure_wifi
configure_network
configure_firewall
reload_network

# Check if connection succeeded
if check_connection; then
    rm -f /tmp/xboxwireless.connecting
    exit 0
else
    rm -f /tmp/xboxwireless.connecting
    exit 1
fi

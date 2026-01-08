#!/usr/bin/env python3
"""
Enhanced Xbox Wireless Protocol Fuzzing Analyzer
Provides detailed analysis of fuzzing results with response correlation
"""
import sys
from scapy.all import rdpcap
from collections import defaultdict
from datetime import datetime

# Protocol constants
XBOX_ETHERTYPE = 0x886f

PACKET_TYPES = {
    0x01: "Handshake Request",
    0x02: "Handshake Response", 
    0x07: "WiFi Config Request",
    0x08: "WiFi Config Response",
    0x09: "Beacon Request",
    0x0a: "Beacon Response",
}

def parse_xbox_packet(raw_data):
    """Parse Xbox protocol packet structure"""
    if len(raw_data) < 12:
        return None
    
    if raw_data[:4] != b'XBOX':
        return None
    
    return {
        'magic': raw_data[:4].decode('ascii'),
        'version': (raw_data[4], raw_data[5]),
        'body_size': raw_data[6],
        'packet_type': raw_data[7],
        'nonce': (raw_data[8] << 8) | raw_data[9],
        'checksum': (raw_data[10] << 8) | raw_data[11],
        'payload': raw_data[12:] if len(raw_data) > 12 else b''
    }

def parse_tlv_payload(payload):
    """Parse TLV (Type-Length-Value) encoded payload"""
    tlvs = []
    pos = 0
    
    while pos < len(payload) - 1:
        if pos + 1 >= len(payload):
            break
            
        tag = payload[pos]
        length = payload[pos + 1]
        pos += 2
        
        if pos + length > len(payload):
            break
            
        value = payload[pos:pos + length]
        pos += length
        
        tlvs.append({
            'tag': tag,
            'length': length,
            'value': value
        })
    
    return tlvs

def get_fuzz_category(nonce):
    """Determine fuzzing category from nonce value"""
    if 0x1000 <= nonce <= 0x10FF:
        return "security_type", nonce - 0x1000
    elif 0x2000 <= nonce <= 0x20FF:
        return "tlv_tag", nonce - 0x2000
    elif 0x3000 <= nonce <= 0x30FF:
        return "ssid_length", nonce - 0x3000
    elif 0x4000 <= nonce <= 0x40FF:
        return "password_length", nonce - 0x4000
    return "unknown", nonce

def analyze_pcap(filename):
    """Comprehensive pcap analysis"""
    print(f"{'='*70}")
    print(f"  Xbox Protocol Fuzzing Analysis")
    print(f"{'='*70}\n")
    
    try:
        packets = rdpcap(filename)
    except Exception as e:
        print(f"Error reading pcap: {e}")
        return
    
    print(f"Total packets in capture: {len(packets)}\n")
    
    # Data structures for analysis
    xbox_packets = []
    requests = []
    responses = []
    response_map = defaultdict(list)
    
    # Parse all Xbox packets
    for i, pkt in enumerate(packets):
        if not pkt.haslayer('Ether'):
            continue
            
        if pkt['Ether'].type != XBOX_ETHERTYPE:
            continue
        
        raw = bytes(pkt['Ether'].payload)
        parsed = parse_xbox_packet(raw)
        
        if parsed:
            parsed['packet_num'] = i
            parsed['timestamp'] = float(pkt.time)
            parsed['src_mac'] = pkt['Ether'].src
            parsed['dst_mac'] = pkt['Ether'].dst
            
            xbox_packets.append(parsed)
            
            # Categorize as request or response
            if parsed['packet_type'] % 2 == 1:  # Odd = request
                requests.append(parsed)
            else:  # Even = response
                responses.append(parsed)
                response_map[parsed['nonce']].append(parsed)
    
    print(f"Xbox Protocol Packets: {len(xbox_packets)}")
    print(f"  Requests:  {len(requests)}")
    print(f"  Responses: {len(responses)}\n")
    
    # Packet type distribution
    print(f"{'='*70}")
    print("Packet Type Distribution")
    print(f"{'='*70}\n")
    
    type_counts = defaultdict(int)
    for pkt in xbox_packets:
        type_counts[pkt['packet_type']] += 1
    
    for ptype in sorted(type_counts.keys()):
        name = PACKET_TYPES.get(ptype, f"Unknown (0x{ptype:02x})")
        direction = "←" if ptype % 2 == 0 else "→"
        print(f"  {direction} 0x{ptype:02x} {name:30s} {type_counts[ptype]:4d} packets")
    
    # Analyze fuzzing results
    print(f"\n{'='*70}")
    print("Fuzzing Campaign Analysis")
    print(f"{'='*70}\n")
    
    fuzz_requests = [r for r in requests if r['packet_type'] == 0x07]
    
    if not fuzz_requests:
        print("No fuzzing requests (type 0x07) found in capture\n")
        return
    
    # Group by fuzzing category
    categories = defaultdict(list)
    for req in fuzz_requests:
        category, value = get_fuzz_category(req['nonce'])
        categories[category].append((value, req))
    
    for category in sorted(categories.keys()):
        items = sorted(categories[category], key=lambda x: x[0])
        print(f"\n[{category.upper().replace('_', ' ')}]")
        print(f"  Test cases: {len(items)}")
        
        # Check for responses
        responded = 0
        no_response = 0
        
        for value, req in items:
            if req['nonce'] in response_map:
                responded += 1
            else:
                no_response += 1
        
        print(f"  Responses:  {responded}")
        print(f"  No response: {no_response}")
        
        if responded > 0:
            print(f"  ✓ Xbox accepted and responded to some test cases")
        else:
            print(f"  ⚠ Xbox did not respond to any test cases in this category")
    
    # Detailed TLV analysis for interesting responses
    print(f"\n{'='*70}")
    print("Detailed Response Analysis")
    print(f"{'='*70}\n")
    
    interesting_responses = [r for r in responses if r['packet_type'] == 0x08]
    
    if interesting_responses:
        print(f"Found {len(interesting_responses)} WiFi Config Responses (0x08)\n")
        
        for resp in interesting_responses[:5]:  # Show first 5
            category, value = get_fuzz_category(resp['nonce'])
            print(f"  Response to nonce 0x{resp['nonce']:04x} ({category}: {value})")
            print(f"    Payload length: {len(resp['payload'])} bytes")
            
            if len(resp['payload']) > 0:
                print(f"    First 32 bytes: {resp['payload'][:32].hex()}")
            print()
    
    # Beacon analysis
    beacons = [r for r in responses if r['packet_type'] == 0x0a]
    if beacons:
        print(f"\nBeacon Activity:")
        print(f"  Total beacons: {len(beacons)}")
        
        if len(beacons) >= 2:
            time_diffs = []
            for i in range(1, len(beacons)):
                diff = beacons[i]['timestamp'] - beacons[i-1]['timestamp']
                time_diffs.append(diff)
            
            if time_diffs:
                avg_interval = sum(time_diffs) / len(time_diffs)
                print(f"  Average interval: {avg_interval:.3f} seconds")
    
    # Anomaly detection
    print(f"\n{'='*70}")
    print("Anomaly Detection")
    print(f"{'='*70}\n")
    
    anomalies = []
    
    # Check for unusual payload sizes
    for pkt in xbox_packets:
        if len(pkt['payload']) > 256:
            anomalies.append(f"Large payload: {len(pkt['payload'])} bytes in packet {pkt['packet_num']}")
    
    # Check for unexpected packet types
    expected_types = set(PACKET_TYPES.keys())
    for pkt in xbox_packets:
        if pkt['packet_type'] not in expected_types:
            anomalies.append(f"Unknown packet type 0x{pkt['packet_type']:02x} in packet {pkt['packet_num']}")
    
    if anomalies:
        print("Potential anomalies detected:")
        for anomaly in anomalies[:10]:
            print(f"  • {anomaly}")
    else:
        print("No anomalies detected - Xbox handled all fuzzing gracefully")
    
    # Summary
    print(f"\n{'='*70}")
    print("Summary")
    print(f"{'='*70}\n")
    
    response_rate = (len(responses) / len(requests) * 100) if requests else 0
    
    print(f"Total fuzzing requests sent: {len(fuzz_requests)}")
    print(f"Overall response rate: {response_rate:.1f}%")
    
    if response_rate > 80:
        print("\n✓ Protocol appears robust - Xbox responded to most fuzzing attempts")
    elif response_rate > 50:
        print("\n⚠ Mixed results - Some fuzzing caused Xbox to stop responding")
    else:
        print("\n✗ Poor response rate - Fuzzing may have caused protocol issues")
    
    print()

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <pcap_file>")
        print(f"\nAnalyzes Xbox Wireless Protocol fuzzing results")
        print(f"Expected pcap from: sudo tcpdump -i eth0 -w capture.pcap 'ether proto 0x886f'")
        sys.exit(1)
    
    analyze_pcap(sys.argv[1])

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

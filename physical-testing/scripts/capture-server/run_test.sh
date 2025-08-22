#!/bin/bash
# Automated test runner - fixed messaging

IFACE="enp4s0f1"
RESULTS="/srv/darknet-testing/results/test_$(date +%Y%m%d_%H%M%S)"
DURATION=30

if [ "$EUID" -ne 0 ]; then 
   echo "ERROR: Run as root"
   exit 1
fi

mkdir -p "$RESULTS"

echo "============================================"
echo "AUTOMATED PACKET CAPTURE TEST"
echo "============================================"
echo ""
echo "Select test speed:"
echo "1) 10K pps"
echo "2) 100K pps" 
echo "3) 1M pps"
echo "4) 1 Gbps"
echo "5) 5 Gbps"
echo "6) 10 Gbps"
echo ""

read -p "Speed [1-6]: " choice

case $choice in
    1) SPEED="10K"; DESC="10,000 pps" ;;
    2) SPEED="100K"; DESC="100,000 pps" ;;
    3) SPEED="1M"; DESC="1 million pps" ;;
    4) SPEED="1G"; DESC="1 Gbps" ;;
    5) SPEED="5G"; DESC="5 Gbps" ;;
    6) SPEED="10G"; DESC="10 Gbps" ;;
    *) echo "Invalid"; exit 1 ;;
esac

echo ""
echo "Test Configuration:"
echo "- Speed: $DESC"
echo "- Duration: 30 seconds per tool"
echo "- Tools: tcpdump, PF_RING, netsniff-ng"
echo ""
echo "IMPORTANT: Start traffic generator on dev02"
echo "          Select option $choice (same speed)"
echo "          It will run continuously for 150 seconds"
echo ""
read -p "Press ENTER when traffic is running on dev02..."

echo ""
echo "Starting capture tests at $DESC..."
echo "======================================="

# Tool 1: tcpdump
echo "[1/3] Testing tcpdump (30 seconds)..."
timeout -k 2 $DURATION tcpdump -i $IFACE -w $RESULTS/tcpdump_${SPEED}.pcap -nn -B 65536 -q > "$RESULTS/tcpdump_${SPEED}.log" 2>&1
size1=$(ls -lh $RESULTS/tcpdump_${SPEED}.pcap 2>/dev/null | awk '{print $5}')
echo "      Captured: $size1"
echo "      Waiting 5 seconds before next tool..."
sleep 5

# Tool 2: PF_RING
echo "[2/3] Testing PF_RING (30 seconds)..."
timeout -k 2 $DURATION /usr/local/bin/tcpdump -i $IFACE -w $RESULTS/pfring_${SPEED}.pcap -nn -q > "$RESULTS/pfring_${SPEED}.log" 2>&1
size2=$(ls -lh $RESULTS/pfring_${SPEED}.pcap 2>/dev/null | awk '{print $5}')
echo "      Captured: $size2"
echo "      Waiting 5 seconds before next tool..."
sleep 5

# Tool 3: netsniff-ng
echo "[3/3] Testing netsniff-ng (30 seconds)..."
timeout -k 2 $DURATION netsniff-ng --in $IFACE --out $RESULTS/netsniff_${SPEED}.pcap --silent > "$RESULTS/netsniff_${SPEED}.log" 2>&1
size3=$(ls -lh $RESULTS/netsniff_${SPEED}.pcap 2>/dev/null | awk '{print $5}')
echo "      Captured: $size3"

echo ""
echo "======================================="
echo "ALL TESTS COMPLETE!"
echo "======================================="
echo ""
echo "Results Summary at $DESC:"
echo "- tcpdump:    $size1"
echo "- PF_RING:    $size2"
echo "- netsniff:   $size3"
echo ""
echo "Results saved to: $RESULTS"
echo ""
echo "Traffic generator on dev02 can be stopped (Ctrl+C)"

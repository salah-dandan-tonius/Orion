#!/bin/bash
# Results analyzer - 

# Get the latest test directory (most recent by timestamp)
LATEST=$(ls -td /srv/darknet-testing/results/test_* 2>/dev/null | head -1)

if [ -z "$LATEST" ]; then
    echo "ERROR: No test results found"
    exit 1
fi

echo ""
echo "=========================================="
echo "ANALYSIS OF LATEST TEST"
echo "=========================================="
echo "Directory: $(basename $LATEST)"
echo "Full path: $LATEST"
echo ""

# Check if capinfos is installed
if ! command -v capinfos &> /dev/null; then
    echo "WARNING: capinfos not installed, showing file sizes only"
    echo "Install with: sudo apt-get install -y wireshark-common"
    echo ""
fi

echo "Tool        | Speed | File Size | Packets Captured"
echo "------------|-------|-----------|------------------"

for pcap in $LATEST/*.pcap; do
    if [ -f "$pcap" ]; then
        # Extract tool and speed from filename
        basename=$(basename $pcap .pcap)
        tool=$(echo $basename | cut -d_ -f1)
        speed=$(echo $basename | cut -d_ -f2)
        
        # Get file size
        size=$(ls -lh $pcap | awk '{print $5}')
        
        # Get packet count if capinfos exists
        if command -v capinfos &> /dev/null; then
            packets=$(capinfos $pcap 2>/dev/null | grep "Number of packets:" | awk '{print $4}' | tr -d ',')
            if [ -z "$packets" ]; then
                packets="error"
            fi
        else
            packets="n/a"
        fi
        
        printf "%-11s | %-5s | %9s | %s\n" "$tool" "$speed" "$size" "$packets"
    fi
done

echo ""
echo "To see details for a specific file:"
echo "capinfos $LATEST/<filename>.pcap"

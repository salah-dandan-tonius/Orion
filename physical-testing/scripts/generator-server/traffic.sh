#!/bin/bash
PCAP="/srv/Orion/pcaps/capture.pcap"
IFACE="enp4s0f1"
DURATION=150
if [ "$EUID" -ne 0 ]; then
echo "ERROR: Run as root"
exit 1
fi
echo "======================================"
echo "TRAFFIC GENERATOR"
echo "======================================"
echo "Select speed (must match dev01):"
echo "1) 10K pps"
echo "2) 100K pps"
echo "3) 1M pps"
echo "4) 1 Gbps"
echo "5) 5 Gbps"
echo "6) 10 Gbps"
read -p "Speed [1-6]: " choice
case $choice in
1) RATE="--pps=10000"; DESC="10K pps" ;;
2) RATE="--pps=100000"; DESC="100K pps" ;;
3) RATE="--pps=1000000"; DESC="1M pps" ;;
4) RATE="--mbps=1000"; DESC="1 Gbps" ;;
5) RATE="--mbps=5000"; DESC="5 Gbps" ;;
6) RATE="--topspeed"; DESC="10 Gbps" ;;
*) echo "Invalid"; exit 1 ;;
esac
echo "Sending at $DESC for $DURATION seconds..."
tcpreplay -i IFACE $RATE --loop=0 --duration=
DURATION $PCAP 2>/dev/null &
PID=$!

for i in $(seq 10 10 $DURATION); do
echo -ne "\rProgress: $i / $DURATION seconds"
sleep 10
done
wait $PID
echo -e "\nTraffic complete!"

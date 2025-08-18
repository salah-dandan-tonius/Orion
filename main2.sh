#!/bin/bash

set -euo pipefail

TOOL="legacy"
IFACE="wlo1"
SERVE=false
PORT=8000

PCAP_DIR="/var/pcaps"
LOG_FILE="/var/log/pcapture/pcapture.txt"
ZIP=false
EXT="pcap"
PCAP_FILE="$(date +"%Y-%m-%d.%H").$EXT"

mkdir -p "$PCAP_DIR"

#=== Helpers ===#
log() {
    local when=$(date +"%F %T")
    echo "[$when] $*" | tee -a "$LOG_FILE"
}

check_iface() {
    local iface="$1"
    local retries=5
    local wait=2

    if [[ ! -d "/sys/class/net/$iface" ]]; then
        log "Error: Interface $iface does not exist."
        exit 1
    fi

    for ((i=0;i<retries;i++)); do
        state=$(cat /sys/class/net/$iface/operstate)
        if [[ "$state" == "up" ]]; then
            log "Interface $iface is up."
            return
        fi
        log "Interface $iface is $state, retrying in $wait seconds..."
        sleep "$wait"
    done

    log "Error: Interface $iface did not come up after $((retries*wait)) seconds."
    exit 1
}

#???
sanity_check() {

}

#=== Argument Parsing ===#
while [[ $# -gt 0 ]]; do
    case "$1" in
        --tool)
            if [[ $# -lt 2 ]]; then
                echo "Error: --tool requires an argument"
                echo "Usage: $0 [--tool legacy|tcpdump|tcpdump-pfring|xdpdump|netsniff-ng] [--iface <interface>] [--serve <port>] [--zip]"
                exit 1
            fi
            TOOL="$2"
            shift 2
            ;;
        --iface)
            if [[ $# -lt 2 ]]; then
                echo "Error: --iface requires an argument"
                echo "Usage: $0 [--tool legacy|tcpdump|tcpdump-pfring|xdpdump|netsniff-ng] [--iface <interface>] [--serve <port>] [--zip]"
                exit 1
            fi
            IFACE="$2"
            shift 2
            ;;
        --serve)
            if [[ $# -lt 2 ]]; then
                echo "Error: --serve requires an argument"
                echo "Usage: $0 [--tool legacy|tcpdump|tcpdump-pfring|xdpdump|netsniff-ng] [--iface <interface>] [--serve <port>] [--zip]"
                exit 1
            fi
            SERVE=true
            PORT="$2"
            shift 2
            ;;
        --zip)
            ZIP=true
            EXT="pcap.gz"
            shift
            ;;
        --help)
            echo "Usage: $0 [--tool legacy|tcpdump|tcpdump-pfring|xdpdump|netsniff-ng] [--iface <interface>] [--serve <port>] [--zip]"
            exit 0
            ;;
        *)
            echo "Unknown argument: $1"
            echo "Usage: $0 [--tool legacy|tcpdump|tcpdump-pfring|xdpdump|netsniff-ng] [--iface <interface>] [--serve <port>] [--zip]"
            exit 1
            ;;
    esac
done

case "$TOOL" in
    legacy|tcpdump|tcpdump-pfring|xdpdump|netsniff-ng)
        ;;
    *)
        log "Error: Invalid tool '$TOOL'. Valid options are: legacy tcpdump tcpdump-pfring xdpdump netsniff-ng"
        exit 1
        ;;
esac

check_iface "$IFACE"

if [[ "$SERVE" == true ]]; then
    if ! [[ "$PORT" =~ ^[0-9]+$ ]]; then
        log "Error: Invalid port "$PORT". Must be a number"
        exit 1
    fi

    echo "Serving $LOG_FILE on http://localhost:$PORT/"
    (cd "$(dirname "$LOG_FILE")" && python3 -m http.server "$PORT")
fi
#!/bin/bash

set -euo pipefail

TOOL="legacy"
IFACE="wlo1"
SERVE=false
PORT=8000
ZIP=false

usage() {
    echo "Usage: $0 [-t|--tool <tool>] [-i|--iface <iface>] [-s|--serve <port>] [-z|--zip] [-h|--help]"
    echo "Tools: legacy, tcpdump, tcpdump-pfring, xdpdump, netsniff-ng"
}

PARSED=$(getopt -o t:i:s:zh --long tool:,iface:,serve:,zip,help -- "$@") || { usage; exit 1; }
eval set -- "$PARSED"

while true; do
    case "$1" in
        -t|--tool) TOOL="$2"; shift 2 ;;
        -i|--iface) IFACE="$2"; shift 2 ;;
        -s|--serve) SERVE=true; PORT="$2"; shift 2 ;;
        -z|--zip) ZIP=true; shift ;;
        -h|--help) usage; exit 0 ;;
        --) shift; break ;;
        *) echo "Unknown option: $1"; usage; exit 1 ;;
    esac
done

VALID_TOOLS=("legacy" "tcpdump" "tcpdump-pfring" "xdpdump" "netsniff-ng")
if [[ ! " ${VALID_TOOLS[*]} " =~ " $TOOL " ]]; then
    echo "Error: Invalid tool '$TOOL'. Must be one of: ${VALID_TOOLS[*]}"
    exit 1
fi

if ! ip link show "$IFACE" &>/dev/null; then
    echo "Error: Network interface '$IFACE' does not exist."
    exit 1
fi

if ! [[ "$PORT" =~ ^[0-9]+$ ]] || [ "$PORT" -lt 0 ] || [ "$PORT" -gt 65535 ]; then
    echo "Error: Invalid port number '$PORT'. Must be 0-65535."
    exit 1
fi
#=============================================================================
PCAP_DIR="/var/pcaps"
LOG_DIR="/var/log/pcapture"
LOG_FILE="$LOG_DIR/pcapture.txt"

mkdir -p "$PCAP_DIR" "$LOG_DIR"
touch "$LOG_FILE"

log() {
    local when=$(date +"%F %T")
    echo "[$when] $*" | tee -a "$LOG_FILE"
}

if $SERVE; then
    (cd "$LOG_DIR" && python3 -m http.server "$PORT") &>/dev/null &
    SERVER_PID=$!
    sleep 2
    if ! kill -0 "$SERVER_PID" &>/dev/null; then
        log "WARNING: HTTP server failed to start on port $PORT"
    else
        log "Started HTTP server on port $PORT (PID: $SERVER_PID)"
    fi
fi
#=============================================================================
cleanup() {
    if [[ -n "${SERVER_PID:-}" ]] && kill -0 "$SERVER_PID" &>/dev/null; then
        log "Stopping HTTP server (PID: $SERVER_PID)"
        kill "$SERVER_PID"
    fi

    if [[ -n "${CAPTURE_PID:-}" ]] && kill -0 "$CAPTURE_PID" &>/dev/null; then
        log "Stopping $TOOL (PID: $CAPTURE_PID)"
        kill "$CAPTURE_PID"
    fi

    exit 0
}

trap cleanup SIGINT SIGTERM
#=============================================================================
# Handle the sanity check
ARCHIVE_DIR="$PCAP_DIR/archive"
mkdir -p "$ARCHIVE_DIR"

for f in "$PCAP_DIR"/*.partial; do
	[ -e "$f" ] || continue
	ts=$(date +"%F_%H%M%S")
	base=$(basename "$f")
	newname="${base%.partial}_${ts}_$$.partial"
	mv "$f" "$ARCHIVE_DIR/$newname"
	log "Archived leftover partial file: $f -> $ARCHIVE_DIR/$newname"
done

case "$TOOL" in
    legacy)
    	bin/legacy -k -i "$IFACE" -s "$PCAP_DIR" &
	log "Starting legacy on $IFACE..."
	;;
    tcpdump)
        if $ZIP; then
            tcpdump -i "$IFACE" -G 3600 -w "$PCAP_DIR/%Y-%m-%d.%H.pcap.gz" -nn -U &>/dev/null &
        else
            tcpdump -i "$IFACE" -G 3600 -w "$PCAP_DIR/%Y-%m-%d.%H.pcap" -nn -U &>/dev/null &
        fi
        log "Starting tcpdump on $IFACE..."
        ;;
    tcpdump-pfring)
        ;;
    xdpdump)
        ;;
    netsniff-ng)
    	netsniff-ng -i "$IFACE" -o "$PCAP_DIR/%Y-%m-%d.%H.pcap" --interval 1hrs --prio-high --silent &>/dev/null &
	log "Starting netsniff-ng on $IFACE..."
	;;
    *)
        ;;
esac

CAPTURE_PID=$!
wait $CAPTURE_PID

# Failing with zip
# unbound variable if just --tool

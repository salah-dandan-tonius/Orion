#!/bin/bash

set -euo pipefail

#=== Configuration ===#
LOG_DIR="/var/log/pcapture"
PCAP_DIR="/var/pcaps"
IFACE="wlo1"
THRESHOLD_DROPS=10
MONITOR_INTERVAL=60 # seconds
TOOL="tcpdump"

#=== Argument Parsing ===#
while [[ $# -gt 0 ]]; do
    case "$1" in
        --tool)
            TOOL="$2"
            shift 2
            ;;
        --iface)
            IFACE="$2"
            shift 2
            ;;
        --help)
            echo "Usage: $0 [--tool tcpdump|netsniff-ng|tcpdump-pfring|legacy|xdpdump] [--iface <interface>]"
            exit 0
            ;;
        *)
            echo "Unknown argument: $1"
            echo "Usage: $0 [--tool tcpdump|netsniff-ng|tcpdump-pfring|legacy|xdpdump] [--iface <interface>]"
            exit 1
            ;;
    esac
done

#=== Helpers ===#
iface_state() {
    cat "/sys/class/net/$IFACE/operstate" 2>/dev/null || echo ""
}

log() {
    local when=$(date +"%F %T")
    echo "[$when] $*" | tee -a "$LOG_DIR/pcapture.log"
}

mark_corrupt() {
    local pfile=$1
    touch "${pfile}.corrupt"
    log "Marked $pfile as corrupt"
}

sanity_check() {
    case "$TOOL" in
        tcpdump|netsniff-ng|tcpdump-pfring|legacy|xdpdump)
            ;;
        *)
            log "ERROR: Unsupported tool '$TOOL'"
            return 1
            ;;
    esac

    if [[ "$(iface_state)" != "up" ]]; then
        log "ERROR: Interface $IFACE is down."
        return 1
    fi

    mkdir -p "$LOG_DIR" "$PCAP_DIR"
    local now_f="$PCAP_DIR/$(date +'%Y-%m-%d.%H').pcap"

    if [[ -f "$now_f" ]]; then
        log "WARNING: pcap for current time already exists ($now_f). Possibly unclean shutdown."

        local magic=$(head -c 4 "$now_f" | od -An -t x4 | tr -d ' ')
        case "$magic" in
            a1b2c3d4|d4c3b2a1|a1b23c4d|4d3cb2a1)
                log "INFO: Valid pcap magic header at $now_f"
                ;;
            *)
                log "WARNING: Invalid pcap magic number - corrupt header ($now_f)."
                mark_corrupt "$now_f"
                return 1
                ;;
        esac

        if ! capinfos "$now_f" &>/dev/null; then
            log "WARNING: capinfos failed - possibly truncated or invalid pcap ($now_f)."
            mark_corrupt "$now_f"
            return 1
        else
            # This is temporary. In the next release, data will be added to a second file. For example,
            # YYYY-mm-dd.HH.2.pcap where 2 indicates a 2nd attempt
            log "INFO: Valid pcap file found ($now_f). Data will be overwritten."
        fi
    fi

    return 0
}

#=== Stat Readers ===#
get_stat() {
    local stat=$1
    cat "/sys/class/net/$IFACE/statistics/$stat" 2>/dev/null || echo 0
}

get_write_bytes() {
    awk '/^write_bytes:/ {print $2}' "/proc/$1/io" 2>/dev/null || echo 0
}

#=== Monitor Logic ===#
initial_packets=0
initial_dropped=0
start_monitor() {
    local prev_dropped=$(get_stat rx_dropped)
    local prev_errors=$(get_stat rx_errors)
    local prev_fifo=$(get_stat rx_fifo_errors)
    local prev_over=$(get_stat rx_over_errors)

    local prev_packets=$(get_stat rx_packets)
    local prev_bytes=$(get_stat rx_bytes)
    local prev_write_bytes=$(get_write_bytes $DUMP_PID)

    local total_packets=0
    local total_dropped=0

    local min_bytes=$prev_bytes max_bytes=$prev_bytes sum_bytes=0 count_bytes=0
    local min_write=$prev_write_bytes max_write=$prev_write_bytes sum_write=0 count_write=0

    while true; do
        sleep "$MONITOR_INTERVAL"

        local curr_dropped=$(get_stat rx_dropped)
        local curr_errors=$(get_stat rx_errors)
        local curr_fifo=$(get_stat rx_fifo_errors)
        local curr_over=$(get_stat rx_over_errors)

        local curr_packets=$(get_stat rx_packets)
        local curr_bytes=$(get_stat rx_bytes)
        local curr_write_bytes=$(get_write_bytes $DUMP_PID)
        
        local ddiff=$((curr_dropped - prev_dropped))
        local ediff=$((curr_errors - prev_errors))
        local fdiff=$((curr_fifo - prev_fifo))
        local odiff=$((curr_over - prev_over))

        local pdiff=$((curr_packets - prev_packets))
        local bdiff=$((curr_bytes - prev_bytes))
        local wdiff=$((curr_write_bytes - prev_write_bytes))

        (( curr_bytes < min_bytes )) && min_bytes=$curr_bytes
        (( curr_bytes > max_bytes )) && max_bytes=$curr_bytes

        (( curr_write_bytes < min_write )) && min_write=$curr_write_bytes
        (( curr_write_bytes > max_write )) && max_write=$curr_write_bytes

        sum_bytes=$((sum_bytes + bdiff))
        sum_write=$((sum_write + wdiff))
        count_bytes=$((count_bytes + 1))
        count_write=$((count_write + 1))

        total_packets=$((total_packets + pdiff))
        total_dropped=$((total_dropped + ddiff))

        if (( ddiff > THRESHOLD_DROPS )); then
            log "WARNING: Dropped packets increased by $ddiff on $IFACE"
        fi
        # NOTE: For the exact meaning of these stats, see https://github.com/torvalds/linux/blob/master/Documentation/ABI/testing/sysfs-class-net-statistics
        (( ediff > 0 )) && log "WARNING: RX errors increased by $ediff (bad frames, CRC, etc.)"
        (( fdiff > 0 )) && log "WARNING: RX FIFO errors increased by $fdiff (overflow in NIC buffers)"
        (( odiff > 0 )) && log "WARNING: RX overflow errors increased by $odiff (system buffers full)" # Indicates number of packets that are oversized (larger than MTU)

        prev_dropped=$curr_dropped
        prev_errors=$curr_errors
        prev_fifo=$curr_fifo
        prev_over=$curr_over

        prev_packets=$curr_packets
        prev_bytes=$curr_bytes
        prev_write_bytes=$curr_write_bytes

        if (( count_bytes > 0 && (count_bytes % (60 / MONITOR_INTERVAL) == 0) )); then # change back to an hour
            local avg_bytes=$((sum_bytes / count_bytes))
            local avg_write=$((sum_write / count_write))

            log "Hourly summary: Packets received=$total_packets, Dropped=$total_dropped"
            log "Network bytes - Min=$min_bytes, Max=$max_bytes, Avg=$avg_bytes"
            log "Write bytes - Min=$min_write, Max=$max_write, Avg=$avg_write"

            total_packets=0
            total_dropped=0

            min_bytes=$curr_bytes
            max_bytes=$curr_bytes
            sum_bytes=0
            count_bytes=0

            min_write=$curr_write_bytes
            max_write=$curr_write_bytes
            sum_write=0
            count_write=0
        fi
    done
}

#=== Cleanup Logic ===#
cleanup() {
    local signal="$1"

    log "Received signal $signal. Stopping..."

    kill "$DUMP_PID" "$MONITOR_PID" 2>/dev/null || true
    wait "$DUMP_PID" "$MONITOR_PID" 2>/dev/null || true

    xdp-loader unload --all "$IFACE" &>/dev/null || true

    local final_packets=$(( $(get_stat rx_packets) - initial_packets))
    local final_dropped=$(( $(get_stat rx_dropped) - initial_dropped))
    log "Final stats: packets=$final_packets, dropped=$final_dropped"
    log "Exiting..."
    exit 0
}

trap 'cleanup SIGINT' SIGINT
trap 'cleanup SIGTERM' SIGTERM

#=== XDP Rotation Function ===#
rotate_xdpdump() {
    while true; do
        local out_file="$PCAP_DIR/$(date +'%Y-%m-%d.%H').pcap"
        timeout 3600 xdpdump -i "$IFACE" --use-pcap -w "$out_file" &>/dev/null
        log "xdpdump finished or timed out. Rotating..."
    done
}

#=== Main ===#
if sanity_check; then
    log "Interface $IFACE is up. Starting capture with $TOOL..."

    case "$TOOL" in
        tcpdump)
            tcpdump -i "$IFACE" -G 3600 -w "$PCAP_DIR/%Y-%m-%d.%H.pcap" -nn -U &>/dev/null &
            ;;
        netsniff-ng)
            netsniff-ng -i "$IFACE" -o "$PCAP_DIR/%Y-%m-%d.%H.pcap" --interval 1hrs --prio-high --silent &>/dev/null &
            ;;
        tcpdump-pfring)
            bin/tcpdump-pfring -i "$IFACE" -G 3600 -w "$PCAP_DIR/%Y-%m-%d.%H.pcap" -nn -U &>/dev/null &
            ;;
        legacy)
            gcc src/legacy.c -lpcap -lz -o bin/legacy &>/dev/null
            bin/legacy -u -i "$IFACE" -s "$PCAP_DIR" &
            ;;
        xdpdump)
            clang -O2 -g -Wall -target bpf -c src/xdp_pass.c -o bin/xdp_pass.o
            xdp-loader load -m skb -s xdp "$IFACE"  bin/xdp_pass.o
            rotate_xdpdump &
            ;;
    esac
    DUMP_PID=$!
    log "Started $TOOL (PID $DUMP_PID)"

    start_monitor &
    MONITOR_PID=$!
    log "Started monitor (PID $MONITOR_PID)"

    initial_packets=$(get_stat rx_packets)
    initial_dropped=$(get_stat rx_dropped)

    wait $MONITOR_PID $DUMP_PID
else
    exit 1
fi

# Add logic to only record up to the end of the hour
# Cancelling with xdpdump may corrupt the pcap file. Handle this
# 

# ip -s link vs ifconfig vs ethtool vs /sys/class/net/<interface>/statistics/*
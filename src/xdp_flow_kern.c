#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>

// Macros needed for flow map configuration and bounds checking on received packet
#define FLOW_MAP_MAX_ENTRIES 16384
#define IPV4_HEADER_MIN_SIZE 20
#define IPV4_HEADER_MAX_SIZE 60
#define TCP_HEADER_MIN_SIZE  20
#define TCP_HEADER_MAX_SIZE  60
#define UDP_PACKET_MIN_SIZE  8
#define UDP_PACKET_MAX_SIZE  65507

/*
    Represents the key for every key-value pair in our hash map. For each packet
    received by the NIC, if the source ip, destination ip, source port, destination port,
    and protocol (TCP or UDP) matches that of a key already in the hash map, it will be
    considered part of the same flow, and thus the "packets" field for that entry will
    be incremented and the "bytes" field will also increase by the amount of bytes in the
    received packet.

    Please note that all flow_key fields are stored in Network Byte Order.
*/
struct flow_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  proto;
};

/*
    Represents the value for every key-value pair in our hash map. Many more features besides
    just packet count and byte count can be added. This is just a preliminary result.

    Please note that both fields are stored in Host Byte Order.
*/
struct flow_value {
    __u64 packets;
    __u64 bytes;
};

/* 
    Represents the actual hash map. This follows the eBPF syntax for creating a key-value
    hash map which will store all of our flow data. To see this map being updated in real-time,
    run "sudo watch -n1 cat /sys/fs/bpf/flow_map" in a terminal and watch the entries change.
*/
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, FLOW_MAP_MAX_ENTRIES);
    __type(key, struct flow_key);
    __type(value, struct flow_value);
    __uint(key_size, sizeof(struct flow_key));
    __uint(value_size, sizeof(struct flow_value));
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} flow_map SEC(".maps");

SEC("xdp")
int xdp_prog(struct xdp_md* ctx) {
    // Pointers to start and end of packet
    void* data = (void*)(long)ctx->data;
    void* data_end = (void*)(long)ctx->data_end;

    // Filter for IPv4 only
    struct ethhdr* eth = (struct ethhdr*)data;
    if ((void*)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != __constant_htons(ETH_P_IP)) return XDP_PASS;

    // Filter for TCP and UDP only
    struct iphdr* ip = (struct iphdr*)(eth + 1);
    if ((void*)(ip + 1) > data_end) return XDP_PASS;
    __u32 ip_header_length = ip->ihl * 4;
    if (ip_header_length < IPV4_HEADER_MIN_SIZE || ip_header_length > IPV4_HEADER_MAX_SIZE || (void*)ip + ip_header_length > data_end) return XDP_PASS;
    if (ip->protocol != IPPROTO_TCP && ip->protocol != IPPROTO_UDP) return XDP_PASS;

    // Key values for this packet
    __u32 src_ip = ip->saddr;
    __u32 dst_ip = ip->daddr;
    __u16 src_port;
    __u16 dst_port;
    __u8  proto = ip->protocol;

    // TCP parsing for ports
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr* tcp = (struct tcphdr*)((void*)ip + ip_header_length);
        if ((void*)(tcp + 1) > data_end) return XDP_PASS;
        __u32 tcp_header_length = tcp->doff * 4;
        if (tcp_header_length < TCP_HEADER_MIN_SIZE || tcp_header_length > TCP_HEADER_MAX_SIZE || (void*)tcp + tcp_header_length > data_end) return XDP_PASS;
        src_port = tcp->source;
        dst_port = tcp->dest;
    }

    // UDP parsing for ports
    else {
        struct udphdr* udp = (struct udphdr*)((void*)ip + ip_header_length);
        if ((void*)(udp + 1) > data_end) return XDP_PASS;
        __u32 udp_packet_length = __constant_ntohs(udp->len);
        if (udp_packet_length < UDP_PACKET_MIN_SIZE || udp_packet_length > UDP_PACKET_MAX_SIZE || (void*)udp + udp_packet_length > data_end) return XDP_PASS;
        src_port = udp->source;
        dst_port = udp->dest;
    }

    // Create key instance
    struct flow_key key = {
        .src_ip   = src_ip,
        .dst_ip   = dst_ip,
        .src_port = src_port,
        .dst_port = dst_port,
        .proto    = proto
    };

    // Amount of bytes in the current packet (from start to finish; Ethernet frame and all other headers are included)
    __u64 bytes = data_end - data;

    // If the key already exists in the map, update its value. Otherwise create an entry for it
    struct flow_value* value = bpf_map_lookup_elem(&flow_map, &key);
    if (!value) {
        struct flow_value new_value = {
            .packets = 1,
            .bytes = bytes
        };
        bpf_map_update_elem(&flow_map, &key, &new_value, BPF_NOEXIST);
    } else {
        __sync_fetch_and_add(&value->packets, 1);
        __sync_fetch_and_add(&value->bytes, bytes);
    }

    return XDP_PASS;
}

/*
    NOTES / QUESTIONS:

    - There is currently no logic to handle IP fragmentation
    - When reading in values from the packet, you have to use __constant_ntohs() if
      you're going to perform computations / comparisons with values not also in a
      network packet. This doesn't apply if the value in question is a byte or less.
    - Currenlty, TCP packet bound checks only check for the header length, whereas 
      UDP packet bound checks check for the entire packet length. This is just because
      the UDP header doesn't have a header length field and instead just a packet
      length field.

    - Is it necessary to use __u32 for packet and header lengths?
    - Are there any restrictions / possible accompanying race conditions
      with using __sync_fetch_and_add ?
    - Would it make more sense to drop all packets since the sole purpose of this
      program is to write stuff to disk?
*/

char _license[] SEC("license") = "GPL";
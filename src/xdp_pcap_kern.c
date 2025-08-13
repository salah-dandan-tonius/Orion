#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>

#define RINGBUF_MAX_ENTRIES  16384
#define MAX_PACKET_SIZE      256
#define IPV4_HEADER_MIN_SIZE 20
#define IPV4_HEADER_MAX_SIZE 60

/*
    Represents each packet's pcap entry which will enter the ring buffer and then be written to
    a pcap.gz file. The ring buffer is pinned to /sys/fs/bpf/ringbuf
*/
struct pcap_entry {
    __u32 timestamp_s;
    __u32 timestamp_ns;
    __u32 caplen;
    __u32 len;
    __u8  data[MAX_PACKET_SIZE];
};

/*
    Represents the actual ring buffer in kernel memory which will then get
    mapped to user-space.
*/
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, RINGBUF_MAX_ENTRIES);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} ringbuf SEC(".maps");

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
    
    // Reserve space in ring buffer for pcap entry
    struct pcap_entry* entry = bpf_ringbuf_reserve(&ringbuf, sizeof(struct pcap_entry), 0);
    if (!entry) return XDP_PASS;
    
    // Assign pcap entry fields
    entry->len = sizeof(struct ethhdr) + __constant_ntohs(ip->tot_len);    // Total original length = ethernet frame + ip packet
    entry->caplen = data_end - data;                                       // Total captured length = end memory address - start memory address
    if (entry->caplen > MAX_PACKET_SIZE) entry->caplen = MAX_PACKET_SIZE;  // Truncate the packet if it's too big
    __u64 timestamp_ns = bpf_ktime_get_ns();                               // Consider moving this to the beginning of the function for more precision
    entry->timestamp_s = timestamp_ns / 1000000000;                        // Timestamp in seconds
    entry->timestamp_ns = timestamp_ns % 1000000000;                       // Remainder of timestamp in nanoseconds

    __u32 pkt_len = data_end - data;
    if (pkt_len > MAX_PACKET_SIZE) pkt_len = MAX_PACKET_SIZE;

    // Copy NIC packet memory (ctx) to pcap entry memory
    if (bpf_probe_read_kernel(entry->data, pkt_len, data) < 0) {
        bpf_ringbuf_discard(entry, 0);
        return XDP_PASS;
    }

    // Write pcap entry to ring buffer
    bpf_ringbuf_submit(entry, 0);
    return XDP_PASS;
}

// WILL FAIL WITHOUHT LICENSE!
char _license[] SEC("license") = "GPL";

/*
    - It might be inefficient to create an empty array MAX_PACKET_SIZE bytes long every time.
      Consider using bpf_ringbuf_output instead, although there will be more overhead.

    - Maybe its failing because there is a bunch of empty stuff
*/
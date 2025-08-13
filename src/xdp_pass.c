/*
    This is just a dummy xdp program to pass all packets so that
    xdpdump does not run in legacy mode
*/

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
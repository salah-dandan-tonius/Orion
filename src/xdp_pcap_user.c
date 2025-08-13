#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <zlib.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#define MAP_PATH "/sys/fs/bpf/ringbuf"
#define OUTPUT_FILE "netflow.pcap.gz"
#define MAX_PACKET_SIZE 256


struct pcap_global_header {
    __u32 magic_number;
    __u16 version_major;
    __u16 version_minor;
    __u32 thiszone;
    __u32 sigfigs;
    __u32 snaplen;
    __u32 network;
};

struct pcap_entry {
    __u32 timestamp_s;
    __u32 timestamp_ns;
    __u32 caplen;
    __u32 len;
    __u8  data[MAX_PACKET_SIZE];
};

struct pcap_pkthdr {
    __u32 ts_sec;
    __u32 ts_usec;
    __u32 caplen;
    __u32 len;
};

static gzFile pcap_gz = NULL;

static int handle_event(void* ctx, void* data, size_t size) {
    struct pcap_entry* entry = data;
    struct pcap_pkthdr hdr = {
        .ts_sec = entry->timestamp_s,
        .ts_usec = entry->timestamp_ns / 1000,
        .caplen = entry->caplen,
        .len = entry->len
    };

    if (gzwrite(pcap_gz, &hdr, sizeof(hdr)) != sizeof(hdr)) {
        perror("gzwrite (header)");
        return -1;
    }

    if (gzwrite(pcap_gz, entry->data, entry->caplen) != entry->caplen) {
        perror("gzwrite (data)");
        return -1;
    }

    printf("Packet written: %u bytes\n", entry->len);
    return 0;
}

static volatile sig_atomic_t stop = 0;
static void handle_signal(int sig) {
    stop = 1;
}

int main() {
    signal(SIGINT, handle_signal);

    int map_fd = bpf_obj_get(MAP_PATH);
    if (map_fd < 0) {
        fprintf(stderr, "Failed to open BPF map at %s: %s\n", MAP_PATH, strerror(errno));
        exit(EXIT_FAILURE);
    }

    struct ring_buffer* ringbuf = ring_buffer__new(map_fd, handle_event, NULL, NULL);
    if (!ringbuf) {
        fprintf(stderr, "Failed to create ring buffer: %s\n", strerror(errno));
        close(map_fd);
        exit(EXIT_FAILURE);
    }

    pcap_gz = gzopen(OUTPUT_FILE, "wb");
    if (!pcap_gz) {
        fprintf(stderr, "Failed to open pcap.gz file: %s\n", strerror(errno));
        ring_buffer__free(ringbuf);
        close(map_fd);
        exit(EXIT_FAILURE);
    }

    struct pcap_global_header gh = {
        .magic_number  = 0xA1B2C3D4,
        .version_major = 2,
        .version_minor = 4,
        .thiszone      = 0,
        .sigfigs       = 0,
        .snaplen       = MAX_PACKET_SIZE,
        .network       = 1
    };

    if (gzwrite(pcap_gz, &gh, sizeof(gh)) != sizeof(gh)) {
        perror("gzwrite (global header)");
        gzclose(pcap_gz);
        ring_buffer__free(ringbuf);
        close(map_fd);
        exit(EXIT_FAILURE);
    }

    while (!stop) {
        int err = ring_buffer__poll(ringbuf, 100);
        if (err < 0) {
            perror("Error polling ring buffer");
            break;
        }
    }

    printf("Closing pcap.gz file...\n");
    gzclose(pcap_gz);
    ring_buffer__free(ringbuf);
    close(map_fd);
    exit(EXIT_FAILURE);
}
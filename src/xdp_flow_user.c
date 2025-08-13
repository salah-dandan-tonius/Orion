#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <bpf/bpf.h>

/*
    Defines the path where the flow map already exists, and the
    name of the output file to which you would like to write 
    a csv representation of said map.
*/
#define MAP_PATH "/sys/fs/bpf/flow_map"
#define OUTPUT_FILE "flow_stats.csv"

// Key struct as defined in kernel-level program
struct flow_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  proto;
};

// Value struct as defined in kernel-level program
struct flow_value {
    __u64 packets;
    __u64 bytes;
};

// Converts the protocol field in each packet to a string representation
const char* proto_to_str(__u8 proto) {
    switch (proto) {
        case IPPROTO_TCP: return "TCP";
        case IPPROTO_UDP: return "UDP";
        default: return "UNKNOWN";
    }
}

int main() {
    // Open the flow map
    int map_fd = bpf_obj_get(MAP_PATH);
    if (map_fd < 0) {
        fprintf(stderr, "Failed to open BPF map at %s: %s\n", MAP_PATH, strerror(errno));
        exit(EXIT_FAILURE);
    }

    // Open the CSV file which you are creating
    FILE* csv = fopen(OUTPUT_FILE, "w");
    if (!csv) {
        fprintf(stderr, "Failed to create output file %s: %s\n", OUTPUT_FILE, strerror(errno));
        exit(EXIT_FAILURE);
    }

    // Write the CSV header
    fprintf(csv, "Source IP,Destination IP,Source Port,Destination Port,Protocol,Packets,Bytes\n");

    struct flow_key key;
    struct flow_key next_key;
    struct flow_value value;

    // Try to get the first key
    int err = bpf_map_get_next_key(map_fd, NULL, &next_key);
    if (err < 0) {
        fprintf(stderr, "Map is empty or error getting first key: %s\n", strerror(errno));
        fclose(csv);
        close(map_fd);
        exit(EXIT_FAILURE);
    }

    // Loop over the rest of the key-value pairs in the map and write to csv for each entry
    do {
        key = next_key;

        // Returns 0 on success
        if (bpf_map_lookup_elem(map_fd, &key, &value)) { //?
            fprintf(stderr, "Failed to lookup value for key\n");
            continue;
        }

        char src_ip[INET_ADDRSTRLEN];
        char dst_ip[INET_ADDRSTRLEN];

        inet_ntop(AF_INET, &key.src_ip, src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &key.dst_ip, dst_ip, INET_ADDRSTRLEN);

        __u16 src_port = ntohs(key.src_port);
        __u16 dst_port = ntohs(key.dst_port);

        const char* proto = proto_to_str(key.proto);

        fprintf(csv, "%s,%s,%u,%u,%s,%llu,%llu\n",
                src_ip, dst_ip, src_port, dst_port,
                proto, value.packets, value.bytes);
    } while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0);

    fclose(csv);
    close(map_fd);
    exit(EXIT_SUCCESS);
}
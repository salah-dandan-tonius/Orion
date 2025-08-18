# This makefile is pretty redundant. It's mainly  just for the "make clean" which will remove
# your pcap files and the pcap log created

all:
	gcc src/legacy.c -lpcap -lz -o bin/legacy &>/dev/null
	clang -O2 -g -Wall -target bpf -c src/xdp_pass.c -o bin/xdp_pass.o

clean:
	@sudo rm -rf /var/log/pcapture/*
	@sudo rm -rf /var/pcaps/*

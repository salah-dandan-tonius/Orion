# This makefile is pretty redundant. It's mainly  just for the "make clean" which will remove
# your pcap files and the pcap log created

run:
	@sudo ./main.sh

clean:
	@sudo rm -rf /var/log/pcapture/*
	@sudo rm -rf /var/pcaps/*

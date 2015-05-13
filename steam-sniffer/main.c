//
//  main.c
//  steam-sniffer
//
//  Created by Vasil Stoychev on 5/12/15.
//  Copyright (c) 2015 Vasil Stoychev. All rights reserved.
//

#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>

#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>

/**
 * Compiling using:
 * gcc main.c -lpcap -I/usr/include/pcap -o main && sudo ./main
 */

int main(int argc, const char * argv[]) {
	fprintf(stdout, "steam-sniffer for dota 2!\n");
	
	char errbuf[PCAP_ERRBUF_SIZE];
	
	pcap_if_t *devices, *device;
	
	if (pcap_findalldevs(&devices, errbuf) == -1) {
		fprintf(stderr, "Can't fetch network devices: %s\n", errbuf);
		
		return 1;
	}
	
	int found = 0;
	for (device = devices; device != NULL; device = device->next) {
		pcap_addr_t *device_addr;
		
		for (device_addr = device->addresses; device_addr != NULL; device_addr = device_addr->next) {
			if (device_addr->addr->sa_family == AF_INET && device_addr->addr && device_addr->netmask) {
				fprintf(stdout, "Found a device %s\n", device->name);
				
				found = 1;
				
				break;
			}
		}
		
		if (found == 1) {
			break;
		}
	}
	
	pcap_t *handle;
	
	handle = pcap_open_live(device->name, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Can't open the device %s for capturing: %s\n", device->name, errbuf);
		
		return 2;
	}
	
	fprintf(stdout, "Capturing device: %s\n", device->name);

	// captuire individual packets
	int res = 0;
	const u_char *packet;
	struct pcap_pkthdr *header;

	while ((res = pcap_next_ex(handle, &header, &packet)) >= 0) {
		if (res == 0) {
			continue;
		}

		fprintf(stdout, "Captured [%d] of [%d] bytes\n", header->caplen, header->len);

		if (packet[9] == 17) {
			fprintf(stdout, "UDP Packet\n");

			fprintf(stdout, "version: %x\n", (int) *(packet + 14) >> 4);

			int len = header->caplen;
			int i = 0;
			fprintf(stdout, "packet: \n");
			while (len-- >= 0) {
				fprintf(stdout, "%02x", (int) *(packet + 14 + i));
				i++;
			}
			fprintf(stdout, "\n\n");
		}
	}

	fprintf(stdout, "pcap_next_ex returned error: %s\n", pcap_geterr(handle));

	pcap_close(handle);
	
	pcap_freealldevs(devices);
	
	return 0;
}

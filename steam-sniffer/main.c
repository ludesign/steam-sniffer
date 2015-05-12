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

void processing(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

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
	
	pcap_loop(handle, -1, processing, NULL);
	
	pcap_freealldevs(devices);
	
	return 0;
}

void processing(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	int size = header->len;
	
	fprintf(stdout, "Header length: %d\n", size);
}

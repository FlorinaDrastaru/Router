#include "functions.h"


int comparator(const void *r1, const void *r2)  { 	
	uint32_t mask1 = ((struct route_table_entry *)r1)->mask;
	uint32_t mask2 = ((struct route_table_entry *)r2)->mask;
	uint32_t prefix1 = ((struct route_table_entry *)r1)->prefix;
	uint32_t prefix2 = ((struct route_table_entry *)r2)->prefix;

	if (prefix1 != prefix2) {
		int dif = (int)(prefix1 - prefix2);
		return dif;
	} else {
    	if (mask1 > mask2) {
			return -1;
		} else if (mask1 < mask2) {
			return 1;
		}
	}
} 

struct route_table_entry *get_best_route(struct route_table_entry *table, int low, int high, uint32_t dest_ip, int n) {
	if (high >= low) {
		int mid = (low + high) / 2;
		if ((mid == 0 || 
					(table[mid].prefix > table[mid-1].prefix))
					&& (table[mid].prefix == (dest_ip & table[mid].mask)))

			return &table[mid];
		
		else if ((dest_ip & table[mid].mask) > table[mid].prefix)
			return get_best_route(table, (mid+1), high, (dest_ip & table[mid].mask), rtable_size);
		else
			return get_best_route(table, low, (mid-1), (dest_ip & table[mid].mask), rtable_size);
	}
	return NULL;

}

void match(struct route_table_entry *table, char *prefix, char *next_hop, char *mask, char *interface, int i) {
	table[i].prefix = inet_addr(prefix);
	table[i].next_hop = inet_addr(next_hop);
	table[i].mask = inet_addr(mask);
	table[i].interface = atoi(interface);
}

void parse_table() {
    FILE *f;
    f = fopen("rtable.txt", "r");
    char line[1000];
    int i = 0;
    while(fgets(line, sizeof(line), f)) {
        char prefix[50], next_hop[50], mask[50], interface[50];
        sscanf(line, "%s%s%s%s", prefix, next_hop, mask, interface);
	match(rtable, prefix, next_hop, mask, interface, i);
        i++;
    }
    fclose(f);
}

struct arp_entry *get_arp_entry(__u32 ip) {
	for(int i = 0; i < arp_table_len; i++) {
		if(arp_table[i].ip == ip) 
			return &arp_table[i];
	}
    return NULL;
}

void parse_arp_table() 
{
	FILE *f;
	//fprintf(stderr, "Parsing ARP table\n");
	f = fopen("arp_table.txt", "r");
	char line[100];
	int i = 0;
	for(i = 0; fgets(line, sizeof(line), f); i++) {
		char ip_str[50], mac_str[50];
		sscanf(line, "%s %s", ip_str, mac_str);

		arp_table[i].ip = inet_addr(ip_str);
		int rc = hwaddr_aton(mac_str, arp_table[i].mac);
		DIE(rc < 0, "invalid MAC");
	}
	
	fclose(f);
}

void complete_icmp_header(int icmp_type, struct icmphdr *icmp_hdr) {
	icmp_hdr->type = icmp_type;
	icmp_hdr->checksum = 0;
	icmp_hdr->checksum = checksum(icmp_hdr, sizeof(struct icmp));
}

void icmp_protocol(int icmp_type, struct ether_header *eth_hdr, struct iphdr *ip_hdr, packet m) {
	packet pkt;
	memset(pkt.payload, 0, sizeof(pkt.payload));
	pkt.len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);

	struct ether_header *eth_hdr2 = (struct ether_header *)pkt.payload;
	struct iphdr *ip_hdr2 = (struct iphdr *)(pkt.payload + sizeof(struct ether_header));
	struct icmphdr *icmp_hdr = (struct icmphdr *)(pkt.payload + (sizeof(struct ether_header) + sizeof(struct iphdr)));
	
	eth_hdr2->ether_type = htons(ETHERTYPE_IP);
	memcpy(eth_hdr2->ether_shost, eth_hdr->ether_dhost, sizeof(eth_hdr->ether_dhost));
	memcpy(eth_hdr2->ether_dhost, eth_hdr->ether_shost, sizeof(eth_hdr->ether_shost));

	ip_hdr2->check = 0;
	ip_hdr2->saddr = ip_hdr->daddr;
	ip_hdr2->daddr = ip_hdr->saddr;
	ip_hdr2->version = 4;
	ip_hdr2->ihl = 5;
	ip_hdr2->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
	ip_hdr2->ttl = 64;
	ip_hdr2->protocol = IPPROTO_ICMP;
	ip_hdr2->id = ip_hdr->id;
	ip_hdr2->check = checksum(ip_hdr2, sizeof(struct iphdr));
			
	complete_icmp_header(icmp_type, icmp_hdr);
	send_packet(m.interface, &pkt);
}

uint16_t checksum(void *vdata, size_t length)
 {
	// Cast the data pointer to one that can be indexed.
	char* data=(char*)vdata;

	// Initialise the accumulator.
	uint64_t acc=0xffff;

	// Handle any partial block at the start of the data.
	unsigned int offset=((uintptr_t)data)&3;
	if (offset) {
		size_t count=4-offset;
		if (count>length) count=length;
		uint32_t word=0;
		memcpy(offset+(char*)&word,data,count);
		acc+=ntohl(word);
		data+=count;
		length-=count;
	}

	// Handle any complete 32-bit blocks.
	char* data_end=data+(length&~3);
	while (data!=data_end) {
		uint32_t word;
		memcpy(&word,data,4);
		acc+=ntohl(word);
		data+=4;
	}
	length&=3;

	// Handle any partial block at the end of the data.
	if (length) {
		uint32_t word=0;
		memcpy(&word,data,length);
		acc+=ntohl(word);
	}

	// Handle deferred carries.
	acc=(acc&0xffffffff)+(acc>>32);
	while (acc>>16) {
		acc=(acc&0xffff)+(acc>>16);
	}

	// If the data began at an odd byte address
	// then reverse the byte order to compensate.
	if (offset&1) {
		acc=((acc&0xff00)>>8)|((acc&0x00ff)<<8);
	}

	// Return the checksum in network byte order.
	return htons(~acc);
}

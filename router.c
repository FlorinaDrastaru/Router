#include "skel.h"
#include "routing_table.h"
#include "arp_table.h"
#include "queue.h"
#include "functions.h"
#include <inttypes.h>

#define icmp_type_timeout 11
#define icmp_type_hostunreachable 3

struct route_table_entry *rtable;
struct arp_entry *arp_table;



int main(int argc, char *argv[])
{
	setvbuf(stdout, NULL, _IONBF, 0);
	packet m;
	int rc;

	init();

	rtable = malloc(sizeof(struct route_table_entry) * rtable_size);
	arp_table = malloc(sizeof(struct  arp_entry) * 4);
	parse_table();
	parse_arp_table();
	qsort(rtable, rtable_size, sizeof(struct route_table_entry), comparator);
	
	while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_message");
		struct ether_header *eth_hdr = (struct ether_header *)m.payload;
		struct iphdr *ip_hdr = (struct iphdr *)(m.payload + sizeof(struct ether_header));

		if (ntohs(eth_hdr->ether_type) != ETHERTYPE_IP) {
			continue;
		}

		uint16_t oldChecksum = ip_hdr->check;
		ip_hdr->check = 0;

		if (oldChecksum != checksum(ip_hdr, sizeof(struct iphdr))) {
			continue;
		}

		if (ip_hdr->ttl <= 1) {
			icmp_protocol(icmp_type_timeout, eth_hdr, ip_hdr, m);
			continue;
		}

		struct route_table_entry *route = get_best_route(rtable, 0, rtable_size-1, ip_hdr->daddr, rtable_size);
		if (route == NULL){
			icmp_protocol(icmp_type_hostunreachable, eth_hdr, ip_hdr, m);
			continue;
		}

		ip_hdr->ttl--;
		ip_hdr->check = 0;
		ip_hdr->check = checksum(ip_hdr, sizeof(struct iphdr));

		struct arp_entry *arp_entry = get_arp_entry(route->next_hop);

		if (!arp_entry){
			continue;
		}

		get_interface_mac(route->interface, (void *)&eth_hdr->ether_shost);
		memcpy(eth_hdr->ether_dhost, arp_entry->mac, sizeof(arp_entry->mac));
		send_packet(route->interface, &m);
	}
}

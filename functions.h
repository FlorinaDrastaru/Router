
#pragma once
#include <stdio.h>
#include <unistd.h>
#include "skel.h"
#include "routing_table.h"
#include "arp_table.h"

uint16_t checksum(void *vdata, size_t length);
int comparator(const void *r1, const void *r2);
struct route_table_entry *get_best_route(struct route_table_entry *table, int low, int high, uint32_t dest_ip, int n);
struct arp_entry *get_arp_entry(__u32 ip);
void complete_icmp_header(int icmp_type, struct icmphdr *icmp_hdr);
void icmp_protocol(int icmp_type, struct ether_header *eth_hdr, struct iphdr *ip_hdr, packet m);


#pragma once
#include <stdio.h>
#include <unistd.h>

struct arp_entry {
	__u32 ip;
	uint8_t mac[6];
};

extern struct arp_entry *arp_table;
#define arp_table_len 4
void parse_arp_table();


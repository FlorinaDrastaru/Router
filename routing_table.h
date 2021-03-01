#pragma once
#include <stdio.h>
#include <unistd.h>

struct route_table_entry {
	uint32_t prefix;
	uint32_t next_hop;
	uint32_t mask;
	int interface;
} __attribute__((packed));

#define rtable_size 64284
extern struct route_table_entry *rtable;


void parse_table();


#ifndef FAKEDNS_H
#define FAKEDNS_H

#include <stddef.h>
#include <stdint.h>

struct __attribute__((packed)) dns_header {
	uint16_t transaction_id;
	uint16_t flags;

	uint16_t query_count;
	uint16_t answer_count;
	uint16_t nameserver_count;
	uint16_t additional_count;
};

void fakedns_init_dns_header(uint16_t query_count, struct dns_header* header);

size_t fakedns_dns_query_record_size(const char* name, size_t name_length);
void fakedns_init_dns_query_record(const char* name, size_t name_length, uint8_t* query);

#endif

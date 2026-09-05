#include "fakedns.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <endian.h>

#include <sodium.h>

enum dns_flags {
	DEFAULT_QUERY_FLAGS = 0x0100
};

enum dns_query_types {
	QUERY_TYPE_A = 1
};

enum dns_query_classes {
	QUERY_CLASS_IN = 1
};

struct __attribute__((packed)) dns_query_footer {
	uint16_t query_type;
	uint16_t query_class;
};

void fakedns_init_dns_header(uint16_t query_count, struct dns_header* header) {
	memset(header, 0, sizeof(struct dns_header));

	header->transaction_id	= (uint16_t) randombytes_random();
	header->flags		= htobe16(DEFAULT_QUERY_FLAGS);
	header->query_count	= htobe16(query_count);
}

size_t fakedns_dns_query_record_size(const char* name, size_t name_length) {
	size_t offset = (name_length != 0 && name[name_length - 1] != '.') ? 2 : 1;
	return name_length + offset + sizeof(struct dns_query_footer);
}

void fakedns_init_dns_query_record(const char* name, size_t name_length, uint8_t* query) {
	memcpy(&query[1], name, name_length);

	size_t write_idx = 0;

	for (size_t idx = 0; idx < name_length; idx++) {
		if (name[idx] != '.') continue;

		query[write_idx] = (uint8_t) (idx - write_idx);
		write_idx = idx + 1;
	}

	if (write_idx < name_length) {
		query[write_idx] = (uint8_t) (name_length - write_idx);
		write_idx = name_length + 1;
	}

	query[write_idx] = 0;

	struct dns_query_footer footer = {
		.query_type = QUERY_TYPE_A,
		.query_class = QUERY_CLASS_IN
	};

	memcpy(&query[write_idx + 1], &footer, sizeof(struct dns_query_footer));
}

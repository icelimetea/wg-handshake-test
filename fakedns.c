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

struct __attribute__((packed)) dns_header {
	uint16_t transaction_id;
	uint16_t flags;

	uint16_t query_count;
	uint16_t answer_count;
	uint16_t nameserver_count;
	uint16_t additional_count;
};

struct __attribute__((packed)) dns_query_footer {
	uint16_t query_type;
	uint16_t query_class;
};

size_t fakedns_dns_query_size(const char* name, size_t name_length) {
	int offset = name[name_length - 1] != '.' ? 2 : 1;
	return sizeof(struct dns_header) + name_length + offset + sizeof(struct dns_query_footer);
}

void fakedns_init_dns_query(const char* name, size_t name_length, uint8_t* query) {
	size_t write_idx = 0;

	struct dns_header dns_hdr = {
		.transaction_id = (uint16_t) randombytes_random(),
		.flags = htobe16(DEFAULT_QUERY_FLAGS),
		.query_count = htobe16(1),
		.answer_count = 0,
		.nameserver_count = 0,
		.additional_count = 0
	};

	memcpy(&query[write_idx], &dns_hdr, sizeof(struct dns_header));
	write_idx += sizeof(struct dns_header);

	size_t next_label = 0;

	for (size_t idx = 0; idx < name_length; idx++) {
		if (name[idx] != '.') continue;

		query[write_idx + next_label] = (uint8_t) (idx - next_label);
		memcpy(&query[write_idx + next_label + 1], &name[next_label], idx - next_label);

		next_label = idx + 1;
	}

	if (next_label < name_length) {
		query[write_idx + next_label] = (uint8_t) (name_length - next_label);
		memcpy(&query[write_idx + next_label + 1], &name[next_label], name_length - next_label);

		write_idx += name_length + 2;
	} else {
		write_idx += name_length + 1;
	}

	query[write_idx - 1] = 0;

	struct dns_query_footer dns_ftr = {
		.query_type = htobe16(QUERY_TYPE_A),
		.query_class = htobe16(QUERY_CLASS_IN)
	};

	memcpy(&query[write_idx], &dns_ftr, sizeof(struct dns_query_footer));
}

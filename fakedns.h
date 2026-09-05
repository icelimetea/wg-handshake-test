#ifndef FAKEDNS_H
#define FAKEDNS_H

#include <stddef.h>
#include <stdint.h>

size_t fakedns_dns_query_size(const char* name, size_t name_length);

void fakedns_init_dns_query(const char* name, size_t name_length, uint8_t* query);

#endif

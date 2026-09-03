#ifndef UTILS_H
#define UTILS_H

#include <sys/socket.h>

enum time_constants {
	NANOS_PER_SECOND = 1000000000
};

int parse_long(const char* desc, const char* input, long min_value, long max_value, long* output);

int get_env_option(const char* desc, const char* name, const char** value);

int resolve_udp_address(const char* host, const char* port, socklen_t* addr_len, struct sockaddr_storage* addr_buf);

#endif

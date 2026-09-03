#include "utils.h"
#include "log.h"

#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include <sys/socket.h>
#include <netdb.h>

int parse_long(const char* desc, const char* input, long min_value, long max_value, long* output) {
	char* input_end;

	long value = strtol(input, &input_end, 10);

	if (input == input_end) {
		LOG_ERROR("%s is specified as an invalid string", desc);
		return -1;
	}

	if (errno == ERANGE || value < min_value || value > max_value) {
		LOG_ERROR("%s value is out of range", desc);
		return -1;
	}

	if (*input_end != '\0') {
		LOG_ERROR("%s value contains garbage characters", desc);
		return -1;
	}

	*output = value;

	return 0;
}

int get_env_option(const char* desc, const char* name, const char** value) {
	*value = getenv(name);

	if (*value == NULL) {
		LOG_ERROR("%s (%s) is not specified", desc, name);
		return -1;
	}

	return 0;
}

int resolve_udp_address(const char* host, const char* port, socklen_t* addr_len, struct sockaddr_storage* addr_buf) {
	struct addrinfo hints = {
		.ai_family = AF_UNSPEC,
		.ai_socktype = SOCK_DGRAM,
		.ai_protocol = IPPROTO_UDP
	};

	struct addrinfo* result;

	int err = getaddrinfo(host, port, &hints, &result);

	if (err) {
		LOG_ERROR("Cannot resolve address: %s", gai_strerror(err));
		return -1;
	}

	*addr_len = result->ai_addrlen;
	memcpy(addr_buf, result->ai_addr, result->ai_addrlen);

	freeaddrinfo(result);

	return 0;
}

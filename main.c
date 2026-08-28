#include "wg.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

struct wg_iface_options {
	struct wg_private_key	private_key;
};

struct wg_peer_options {
	struct wg_public_key	public_key;

	socklen_t		addr_len;
	struct sockaddr_storage	addr_buf;
};

struct program_options {
	int min_timeout;
	int max_timeout;
};

static int resolve_udp_address(const char* host, const char* port, socklen_t* addr_len, struct sockaddr_storage* addr_buf) {
	struct addrinfo hints = {
		.ai_family = AF_UNSPEC,
		.ai_socktype = SOCK_DGRAM,
		.ai_protocol = IPPROTO_UDP
	};

	struct addrinfo* result;

	int err = getaddrinfo(host, port, &hints, &result);

	if (err) return err;

	*addr_len = result->ai_addrlen;
	memcpy(addr_buf, result->ai_addr, result->ai_addrlen);

	freeaddrinfo(result);

	return 0;
}

static int get_env_option(const char* desc, const char* name, const char** value) {
	*value = getenv(name);

	if (*value == NULL) {
		printf("%s (%s) is not specified\n", desc, name);
		return -1;
	}

	return 0;
}

static int get_wg_iface_from_env(struct wg_iface_options* wg_iface) {
	const char* wg_iface_privkey_b64;

	if (get_env_option("WG interface's private key", "WG_PRIVKEY", &wg_iface_privkey_b64))
		return -1;

	if (wg_parse_private_key(wg_iface_privkey_b64, &wg_iface->private_key)) {
		printf("Failed to decode WG interface's private key\n");
		return -1;
	}

	return 0;
}

static int get_wg_peer_from_env(struct wg_peer_options* wg_peer) {
	const char* wg_peer_host;
	const char* wg_peer_port;
	const char* wg_peer_pubkey_b64;

	if (get_env_option("WG peer's host", "WG_HOST", &wg_peer_host))
		return -1;

	if (get_env_option("WG peer's port", "WG_PORT", &wg_peer_port))
		return -1;

	if (get_env_option("WG peer's public key", "WG_PUBKEY", &wg_peer_pubkey_b64))
		return -1;

	int err = resolve_udp_address(wg_peer_host, wg_peer_port, &wg_peer->addr_len, &wg_peer->addr_buf);

	if (err) {
		printf("Cannot resolve address: %s\n", gai_strerror(err));
		return -1;
	}

	if (wg_parse_public_key(wg_peer_pubkey_b64, &wg_peer->public_key)) {
		printf("Failed to decode WG peer's public key\n");
		return -1;
	}

	return 0;
}

static int get_program_options_from_env(struct program_options* options) {
	const char* min_timeout_value;
	const char* max_timeout_value;

	if (get_env_option("Minimum handshake timeout to test", "MIN_TIMEOUT", &min_timeout_value))
		return -1;

	if (get_env_option("Maximum handshake timeout to test", "MAX_TIMEOUT", &max_timeout_value))
		return -1;

	options->min_timeout = atoi(min_timeout_value);
	options->max_timeout = atoi(max_timeout_value);

	if (options->min_timeout <= 0 || options->max_timeout <= 0) {
		printf("Invalid timeout value\n");
		return -1;
	}

	if (options->min_timeout >= options->max_timeout) {
		printf("Minimum timeout should be smaller than the max timeout\n");
		return -1;
	}

	return 0;
}

int main(void) {
	if (wg_init()) {
		printf("Failed to initialize cryptography library\n");
		return 1;
	}

	struct wg_iface_options wg_iface;
	struct wg_peer_options wg_peer;
	struct program_options options;

	if (get_wg_iface_from_env(&wg_iface))
		return 1;

	if (get_wg_peer_from_env(&wg_peer))
		return 1;

	if (get_program_options_from_env(&options))
		return 1;

	return 0;
}

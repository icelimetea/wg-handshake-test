#include "wg.h"
#include "log.h"
#include "utils.h"

#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>

#include <sys/socket.h>
#include <unistd.h>
#include <netdb.h>
#include <fcntl.h>

struct wg_iface_options {
	struct wg_private_key	private_key;
	struct wg_public_key	public_key;
};

struct wg_peer_options {
	struct wg_public_key	public_key;
	struct wg_secret	preshared_key;

	socklen_t		addr_len;
	struct sockaddr_storage	addr_buf;
};

struct program_options {
	int min_timeout;
	int max_timeout;
};

static int get_wg_iface_from_env(struct wg_iface_options* wg_iface) {
	const char* wg_iface_privkey_b64;

	if (get_env_option("WG interface's private key", "WG_PRIVKEY", &wg_iface_privkey_b64))
		return -1;

	if (wg_parse_private_key(wg_iface_privkey_b64, &wg_iface->private_key)) {
		LOG_ERROR("Failed to decode WG interface's private key");
		return -1;
	}

	wg_derive_public_key(&wg_iface->private_key, &wg_iface->public_key);

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

	if (resolve_udp_address(wg_peer_host, wg_peer_port, &wg_peer->addr_len, &wg_peer->addr_buf))
		return -1;

	if (wg_parse_public_key(wg_peer_pubkey_b64, &wg_peer->public_key)) {
		LOG_ERROR("Failed to decode WG peer's public key");
		return -1;
	}

	memset(&wg_peer->preshared_key, 0, WG_SHARED_SECRET_LENGTH);

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
		LOG_ERROR("Invalid timeout value");
		return -1;
	}

	if (options->min_timeout >= options->max_timeout) {
		LOG_ERROR("Minimum timeout should be smaller than the max timeout");
		return -1;
	}

	return 0;
}

static int do_wg_probing(
		struct wg_context* contexts,
		const int* sockets,
		size_t sockets_count,
		const struct wg_iface_options* wg_iface,
		const struct wg_peer_options* wg_peer,
		int probing_delay
) {
	struct timespec sleep_time;
	clock_gettime(CLOCK_REALTIME, &sleep_time);

	for (size_t cnt = sockets_count; cnt > 0; cnt--) {
		// TODO: Send garbage

		sleep_time.tv_nsec += 500000000;

		sleep_time.tv_sec += sleep_time.tv_nsec / 1000000000;
		sleep_time.tv_nsec = sleep_time.tv_nsec % 1000000000;

		clock_nanosleep(CLOCK_REALTIME, TIMER_ABSTIME, &sleep_time, NULL);
	}

	sleep_time.tv_sec += probing_delay;
	clock_nanosleep(CLOCK_REALTIME, TIMER_ABSTIME, &sleep_time, NULL);

	for (size_t idx = 0; idx < sockets_count; idx++) {
		struct wg_handshake_request req;

		if (wg_create_handshake(&contexts[idx], &wg_iface->private_key, &wg_iface->public_key, &wg_peer->public_key, &req)) {
			LOG_ERROR("Unable to create a WG handshake");
			return -1;
		}

		if (write(sockets[idx], &req, sizeof(struct wg_handshake_request)) < 0) {
			LOG_ERROR("Unable to write a WG handshake to a socket");
			return -1;
		}

		sleep_time.tv_nsec += 500000000;

		sleep_time.tv_sec += sleep_time.tv_nsec / 1000000000;
		sleep_time.tv_nsec = sleep_time.tv_nsec % 1000000000;

		clock_nanosleep(CLOCK_REALTIME, TIMER_ABSTIME, &sleep_time, NULL);
	}

	for (size_t idx = 0; idx < sockets_count; idx++) {
		struct wg_handshake_response resp;

		ssize_t resp_size = read(sockets[idx], &resp, sizeof(struct wg_handshake_response));

		if (resp_size < 0) {
			LOG_INFO("FAILURE,%s", strerror(errno));
		} else if (resp_size != sizeof(struct wg_handshake_response)) {
			LOG_INFO("FAILURE,Response is too small to be a WG handshake message");
		} else if (wg_verify_handshake(&contexts[idx], &wg_iface->private_key, &wg_iface->public_key, &wg_peer->preshared_key, &resp)) {
			LOG_INFO("FAILURE,Fake handshake response");
		} else {
			LOG_INFO("SUCCESS,");
		}
	}

	return 0;
}

int main(void) {
	struct wg_iface_options	wg_iface;
	struct wg_peer_options	wg_peer;
	struct program_options	options;

	size_t			sockets_count = 0;
	int*			sockets = NULL;
	struct wg_context*	contexts = NULL;

	int err = 0;

	if (wg_init()) {
		LOG_ERROR("Failed to initialize cryptography library");
		goto error;
	}

	if (get_wg_iface_from_env(&wg_iface))
		goto error;

	if (get_wg_peer_from_env(&wg_peer))
		goto error;

	if (get_program_options_from_env(&options))
		goto error;

	sockets_count = (size_t) (options.max_timeout - options.min_timeout);
	sockets = malloc(sockets_count * sizeof(int));
	contexts = malloc(sockets_count * sizeof(struct wg_context));

	if (sockets == NULL || contexts == NULL)  {
		LOG_ERROR("Failed to allocate memory");
		goto error;
	}

	memset(sockets, -1, sockets_count * sizeof(int));

	for (size_t idx = 0; idx < sockets_count; idx++) {
		sockets[idx] = socket(wg_peer.addr_buf.ss_family, SOCK_DGRAM, IPPROTO_UDP);

		if (sockets[idx] < 0 || connect(sockets[idx], (const struct sockaddr*) &wg_peer.addr_buf, wg_peer.addr_len) < 0) {
			LOG_ERROR("Unable to create a socket: %s", strerror(errno));
			goto error;
		}

		int socket_flags = fcntl(sockets[idx], F_GETFL);

		if (socket_flags < 0 || fcntl(sockets[idx], F_SETFL, socket_flags | O_NONBLOCK) < 0) {
			LOG_ERROR("Unable to manipulate socket flags: %s", strerror(errno));
			goto error;
		}
	}

	if (do_wg_probing(contexts, sockets, sockets_count, &wg_iface, &wg_peer, options.min_timeout))
		goto error;
end:
	if (sockets != NULL) {
		for (size_t idx = 0; idx < sockets_count; idx++) {
			if (sockets[idx] >= 0)
				close(sockets[idx]);
		}
	}

	free(sockets);
	free(contexts);

	return err;
error:
	err = 1;
	goto end;
}

#include "wg.h"
#include "utils.h"
#include "fakedns.h"
#include "log.h"

#include <stddef.h>
#include <limits.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <fcntl.h>

#include <sodium.h>

enum {
	BEAUTIFUL_DOMAINS_COUNT = 14
};

static const char* BEAUTIFUL_DOMAINS[BEAUTIFUL_DOMAINS_COUNT] = {
	"www.gosuslugi.ru",
	"dom.gosuslugi.ru",
	"www.nalog.gov.ru",
	"www.mtsbank.ru",
	"alfabank.ru",
	"rutube.ru",
	"vk.com",
	"ok.ru",
	"max.ru",
	"dzen.ru",
	"ya.ru",
	"www.avito.ru",
	"www.ozon.ru",
	"www.wildberries.ru"
};

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
	const char* wg_peer_psk_b64 = getenv("WG_PRESHARED_KEY");

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

	if (wg_peer_psk_b64 == NULL) {
		wg_null_preshared_key(&wg_peer->preshared_key);
		return 0;
	}

	if (wg_parse_preshared_key(wg_peer_psk_b64, &wg_peer->preshared_key)) {
		LOG_ERROR("Failed to decode WG peer's preshared key");
		return -1;
	}

	return 0;
}

static int get_program_options_from_args(int argc, const char** argv, struct program_options* options) {
	if (argc != 3) {
		LOG_ERROR("Usage: %s [min_timeout] [max_timeout]", argv[0]);
		return -1;
	};

	long min_timeout;
	long max_timeout;

	if (parse_long("Minimum timeout", argv[1], 1, INT_MAX, &min_timeout))
		return -1;

	if (parse_long("Maximum timeout", argv[2], 1, INT_MAX, &max_timeout))
		return -1;

	options->min_timeout = (int) min_timeout;
	options->max_timeout = (int) max_timeout;

	if (options->min_timeout >= options->max_timeout) {
		LOG_ERROR("Minimum timeout should be smaller than the max timeout");
		return -1;
	}

	return 0;
}

static int setup_sockets(const struct sockaddr* socket_addr, socklen_t addr_len, int* sockets, size_t sockets_count) {
	for (size_t idx = 0; idx < sockets_count; idx++) {
		sockets[idx] = socket(socket_addr->sa_family, SOCK_DGRAM, IPPROTO_UDP);

		if (sockets[idx] < 0 || connect(sockets[idx], socket_addr, addr_len) < 0) {
			LOG_ERROR("Unable to create a socket: %s", strerror(errno));
			return -1;
		}

		int socket_flags = fcntl(sockets[idx], F_GETFL);

		if (socket_flags < 0 || fcntl(sockets[idx], F_SETFL, socket_flags | O_NONBLOCK) < 0) {
			LOG_ERROR("Unable to manipulate socket flags: %s", strerror(errno));
			return -1;
		}
	}

	return 0;
}

static void close_sockets(const int* sockets, size_t sockets_count) {
	if (sockets == NULL)
		return;

	for (size_t idx = 0; idx < sockets_count; idx++)
		if (sockets[idx] >= 0)
			close(sockets[idx]);
}

static int do_wg_probing(
		struct wg_context* contexts, const int* sockets, size_t sockets_count,
		const struct wg_iface_options* wg_iface,
		const struct wg_peer_options* wg_peer,
		int probing_delay
) {
	struct timespec sleep_time;
	clock_gettime(CLOCK_REALTIME, &sleep_time);

	for (size_t cnt = sockets_count; cnt > 0; cnt--) {
		const char* domain_name = BEAUTIFUL_DOMAINS[randombytes_uniform(BEAUTIFUL_DOMAINS_COUNT)];
		size_t domain_name_length = strlen(domain_name);

		size_t dns_query_size = fakedns_dns_query_size(domain_name, domain_name_length);
		uint8_t* dns_query_buf = malloc(dns_query_size);

		fakedns_init_dns_query(domain_name, domain_name_length, dns_query_buf);

		if (write(sockets[cnt - 1], dns_query_buf, dns_query_size) < 0) {
			LOG_ERROR("Unable to send a garbage packet");
			return -1;
		}

		free(dns_query_buf);

		sleep_time.tv_nsec += NANOS_PER_SECOND / 2;

		sleep_time.tv_sec += sleep_time.tv_nsec / NANOS_PER_SECOND;
		sleep_time.tv_nsec = sleep_time.tv_nsec % NANOS_PER_SECOND;

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

		sleep_time.tv_nsec += NANOS_PER_SECOND / 2;

		sleep_time.tv_sec += sleep_time.tv_nsec / NANOS_PER_SECOND;
		sleep_time.tv_nsec = sleep_time.tv_nsec % NANOS_PER_SECOND;

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

int main(int argc, const char** argv) {
	struct wg_iface_options	wg_iface;
	struct wg_peer_options	wg_peer;
	struct program_options	options;

	size_t			sockets_count = 0;
	int*			sockets = NULL;
	struct wg_context*	contexts = NULL;

	int err = 0;

	if (sodium_init() < 0) {
		LOG_ERROR("Failed to initialize cryptography library");
		goto error;
	}

	wg_init();

	if (get_wg_iface_from_env(&wg_iface))
		goto error;

	if (get_wg_peer_from_env(&wg_peer))
		goto error;

	if (get_program_options_from_args(argc, argv, &options))
		goto error;

	sockets_count = (size_t) (options.max_timeout - options.min_timeout);
	sockets = malloc(sockets_count * sizeof(int));
	contexts = wg_allocate_contexts(sockets_count);

	if (sockets == NULL)  {
		LOG_ERROR("Failed to allocate memory");
		goto error;
	}

	memset(sockets, -1, sockets_count * sizeof(int));

	if (contexts == NULL) {
		LOG_ERROR("Failed to allocate memory");
		goto error;
	}

	if (setup_sockets((const struct sockaddr*) &wg_peer.addr_buf, wg_peer.addr_len, sockets, sockets_count))
		goto error;

	if (do_wg_probing(contexts, sockets, sockets_count, &wg_iface, &wg_peer, options.min_timeout))
		goto error;
end:
	close_sockets(sockets, sockets_count);

	free(sockets);
	wg_free_contexts(contexts);

	return err;
error:
	err = 1;
	goto end;
}

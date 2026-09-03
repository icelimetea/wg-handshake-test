#ifndef WG_H
#define WG_H

#include <stdint.h>

#define AEAD_LENGTH(plaintext_size) ((plaintext_size) + 16)

enum wg_headers {
	WG_HANDSHAKE_REQUEST_HDR	= 1UL,
	WG_HANDSHAKE_RESPONSE_HDR	= 2UL
};

enum wg_errors {
	ERROR_CRYPTO_INIT_FAILED	= -1,
	ERROR_NOT_WG_PACKET		= -2,
	ERROR_WG_PACKET_AUTH_FAILED	= -3,
	ERROR_DH_FAILURE		= -4,
	ERROR_WRONG_BASE64		= -5
};

enum wg_structures_sizes {
	SIMD_ALIGNMENT		= 32UL,

	WG_PRIVATE_KEY_LENGTH	= 32UL,
	WG_PUBLIC_KEY_LENGTH	= 32UL,
	WG_SHARED_SECRET_LENGTH	= 32UL,
	WG_HASH_BLOCK_LENGTH	= 64UL,
	WG_HASH_LENGTH		= 32UL,
	WG_MAC_LENGTH		= 16UL,
	WG_TIMESTAMP_LENGTH	= 12UL
};

struct wg_private_key {
	alignas(SIMD_ALIGNMENT) uint8_t	material[WG_PRIVATE_KEY_LENGTH];
};

struct wg_public_key {
	alignas(SIMD_ALIGNMENT) uint8_t	material[WG_PUBLIC_KEY_LENGTH];
};

struct wg_secret {
	alignas(SIMD_ALIGNMENT) uint8_t	material[WG_SHARED_SECRET_LENGTH];
};

struct wg_kdf_key {
	alignas(SIMD_ALIGNMENT) uint8_t	material[WG_HASH_LENGTH + 1];
};

struct wg_context {
	struct wg_private_key		own_ephemeral_private;

	alignas(SIMD_ALIGNMENT) uint8_t	chaining_hash[WG_HASH_LENGTH];
	struct wg_kdf_key		chaining_key;

	alignas(SIMD_ALIGNMENT) uint8_t	key_opad[WG_HASH_BLOCK_LENGTH];
	alignas(SIMD_ALIGNMENT) uint8_t	key_ipad[WG_HASH_BLOCK_LENGTH + 1];

	uint32_t			sender_id;

	struct {
		struct wg_secret	dh_secret1;
		struct wg_secret	dh_secret2;

		struct wg_kdf_key	temporary_key;
		struct wg_kdf_key	encryption_key;
	} scratchpad;
};

struct __attribute__((packed)) wg_nonce {
	uint32_t zero;
	uint32_t counter_lo;
	uint32_t counter_hi;
};

struct __attribute__((packed)) wg_timestamp {
	uint32_t seconds_hi;
	uint32_t seconds_lo;
	uint32_t nanos;
};

struct __attribute__((packed)) wg_handshake_request {
	uint32_t packet_header;

	uint32_t sender_id;

	uint8_t msg_ephemeral[WG_PUBLIC_KEY_LENGTH];
	uint8_t msg_static[AEAD_LENGTH(WG_PUBLIC_KEY_LENGTH)];
	uint8_t msg_timestamp[AEAD_LENGTH(WG_TIMESTAMP_LENGTH)];

	uint8_t mac1[WG_MAC_LENGTH];
	uint8_t mac2[WG_MAC_LENGTH];
};

struct __attribute__((packed)) wg_handshake_response {
	uint32_t packet_header;

	uint32_t sender_id;
	uint32_t receiver_id;

	uint8_t msg_ephemeral[WG_PUBLIC_KEY_LENGTH];
	uint8_t msg_empty[AEAD_LENGTH(0)];

	uint8_t mac1[WG_MAC_LENGTH];
	uint8_t mac2[WG_MAC_LENGTH];
};

int wg_init(void);

int wg_parse_private_key(const char* input, struct wg_private_key* output);
int wg_parse_public_key(const char* input, struct wg_public_key* output);
int wg_parse_preshared_key(const char* input, struct wg_secret* output);

void wg_derive_public_key(const struct wg_private_key* private_key, struct wg_public_key* public_key);

void wg_null_preshared_key(struct wg_secret* preshared_key);

int wg_create_handshake(
		struct wg_context* ctx,
		const struct wg_private_key* own_static_private,
		const struct wg_public_key* own_static_public,
		const struct wg_public_key* peer_static_public,
		struct wg_handshake_request* req
);

int wg_verify_handshake(
		struct wg_context* ctx,
		const struct wg_private_key* own_static_private,
		const struct wg_public_key* own_static_public,
		const struct wg_secret* preshared_key,
		const struct wg_handshake_response* resp
);

#endif

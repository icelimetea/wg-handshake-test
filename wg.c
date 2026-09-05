#include "wg.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#include <sodium.h>
#include <blake2.h>

#include <endian.h>

static const uint8_t CONSTRUCTION[37] = {
	'N', 'o', 'i', 's', 'e', '_', 'I', 'K', 'p', 's', 'k', '2', '_', '2', '5', '5', '1', '9', '_', 'C', 'h', 'a', 'C', 'h', 'a', 'P', 'o', 'l', 'y', '_', 'B', 'L', 'A', 'K', 'E', '2', 's'
};

static const uint8_t IDENTIFIER[34] = {
	'W', 'i', 'r', 'e', 'G', 'u', 'a', 'r', 'd', ' ', 'v', '1', ' ', 'z', 'x', '2', 'c', '4', ' ', 'J', 'a', 's', 'o', 'n', '@', 'z', 'x', '2', 'c', '4', '.', 'c', 'o', 'm'
};

static const uint8_t LABEL_MAC1[8] = {
	'm', 'a', 'c', '1', '-', '-', '-', '-'
};

static uint8_t INITIAL_CHAINING_HASH[WG_HASH_LENGTH];
static uint8_t INITIAL_CHAINING_KEY[WG_HASH_LENGTH];

enum wg_tai64n_constants {
	TAI64N_EPOCH	= 0x400000000000000aULL,
	TAI64N_NS_MASK	= 0xFF000000UL
};

enum wg_hmac_constants {
	HMAC_IPAD_CONSTANT = 0x36,
	HMAC_OPAD_CONSTANT = 0x5C
};

// Chaining KDF and chaining hash management

static void wg_init_constants(void) {
	blake2s_state hash_state;

	blake2s_init(&hash_state, WG_HASH_LENGTH);
	blake2s_update(&hash_state, CONSTRUCTION, sizeof(CONSTRUCTION));
	blake2s_final(&hash_state, INITIAL_CHAINING_KEY, WG_HASH_LENGTH);

	blake2s_init(&hash_state, WG_HASH_LENGTH);
	blake2s_update(&hash_state, INITIAL_CHAINING_KEY, WG_HASH_LENGTH);
	blake2s_update(&hash_state, IDENTIFIER, sizeof(IDENTIFIER));
	blake2s_final(&hash_state, INITIAL_CHAINING_HASH, WG_HASH_LENGTH);
}

static void wg_chain_hash(struct wg_context* ctx, const uint8_t* input, size_t input_size) {
	blake2s_state hash_state;

	blake2s_init(&hash_state, WG_HASH_LENGTH);
	blake2s_update(&hash_state, ctx->chaining_hash, WG_HASH_LENGTH);
	blake2s_update(&hash_state, input, input_size);
	blake2s_final(&hash_state, ctx->chaining_hash, WG_HASH_LENGTH);
}

static void wg_chain_kdf(struct wg_context* ctx, const uint8_t* input, size_t input_size) {
	blake2s_state hash_state;

	// HKDF extraction step

	memset(ctx->key_ipad, HMAC_IPAD_CONSTANT, WG_HASH_BLOCK_LENGTH);
	memset(ctx->key_opad, HMAC_OPAD_CONSTANT, WG_HASH_BLOCK_LENGTH);

	for (size_t idx = 0; idx < WG_HASH_LENGTH; idx++) {
		ctx->key_ipad[idx] ^= ctx->chaining_key.material[idx];
		ctx->key_opad[idx] ^= ctx->chaining_key.material[idx];
	}

	blake2s_init(&hash_state, WG_HASH_LENGTH);
	blake2s_update(&hash_state, ctx->key_ipad, WG_HASH_BLOCK_LENGTH);
	blake2s_update(&hash_state, input, input_size);
	blake2s_final(&hash_state, ctx->chaining_key.material, WG_HASH_LENGTH);

	blake2s_init(&hash_state, WG_HASH_LENGTH);
	blake2s_update(&hash_state, ctx->key_opad, WG_HASH_BLOCK_LENGTH);
	blake2s_update(&hash_state, ctx->chaining_key.material, WG_HASH_LENGTH);
	blake2s_final(&hash_state, ctx->chaining_key.material, WG_HASH_LENGTH);

	// HKDF expansion step

	memset(ctx->key_ipad, HMAC_IPAD_CONSTANT, WG_HASH_BLOCK_LENGTH);
	memset(ctx->key_opad, HMAC_OPAD_CONSTANT, WG_HASH_BLOCK_LENGTH);

	for (size_t idx = 0; idx < WG_HASH_LENGTH; idx++) {
		ctx->key_ipad[idx] ^= ctx->chaining_key.material[idx];
		ctx->key_opad[idx] ^= ctx->chaining_key.material[idx];
	}

	ctx->key_ipad[WG_HASH_BLOCK_LENGTH] = 1;

	blake2s_init(&hash_state, WG_HASH_LENGTH);
	blake2s_update(&hash_state, ctx->key_ipad, WG_HASH_BLOCK_LENGTH + 1);
	blake2s_final(&hash_state, ctx->chaining_key.material, WG_HASH_LENGTH);

	blake2s_init(&hash_state, WG_HASH_LENGTH);
	blake2s_update(&hash_state, ctx->key_opad, WG_HASH_BLOCK_LENGTH);
	blake2s_update(&hash_state, ctx->chaining_key.material, WG_HASH_LENGTH);
	blake2s_final(&hash_state, ctx->chaining_key.material, WG_HASH_LENGTH);

	ctx->chaining_key.material[WG_HASH_LENGTH] = 2;
}

static void wg_chain_kdf_block(const struct wg_context* ctx, const struct wg_kdf_key* input, struct wg_kdf_key* output) {
	blake2s_state hash_state;

	blake2s_init(&hash_state, WG_HASH_LENGTH);
	blake2s_update(&hash_state, ctx->key_ipad, WG_HASH_BLOCK_LENGTH);
	blake2s_update(&hash_state, input->material, WG_HASH_LENGTH + 1);
	blake2s_final(&hash_state, output->material, WG_HASH_LENGTH);

	blake2s_init(&hash_state, WG_HASH_LENGTH);
	blake2s_update(&hash_state, ctx->key_opad, WG_HASH_BLOCK_LENGTH);
	blake2s_update(&hash_state, output->material, WG_HASH_LENGTH);
	blake2s_final(&hash_state, output->material, WG_HASH_LENGTH);

	output->material[WG_HASH_LENGTH] = input->material[WG_HASH_LENGTH] + 1;
}

static void wg_init_context(const struct wg_public_key* peer_static_public, struct wg_context* ctx, struct wg_handshake_request* req) {
	memset(req, 0, sizeof(struct wg_handshake_request));

	req->packet_header = htole32(WG_HANDSHAKE_REQUEST_HDR);

	ctx->sender_id = randombytes_random();
	req->sender_id = htole32(ctx->sender_id);

	randombytes_buf(ctx->own_ephemeral_private.material, WG_PRIVATE_KEY_LENGTH);
	crypto_scalarmult_base(req->msg_ephemeral, ctx->own_ephemeral_private.material);

	memcpy(ctx->chaining_hash, INITIAL_CHAINING_HASH, WG_HASH_LENGTH);
	memcpy(ctx->chaining_key.material, INITIAL_CHAINING_KEY, WG_HASH_LENGTH);

	wg_chain_hash(ctx, peer_static_public->material, WG_PUBLIC_KEY_LENGTH);

	wg_chain_kdf(ctx, req->msg_ephemeral, WG_PUBLIC_KEY_LENGTH);
	wg_chain_hash(ctx, req->msg_ephemeral, WG_PUBLIC_KEY_LENGTH);
}

// DH

static int wg_derive_dh_secret(const struct wg_private_key* private_key, const struct wg_public_key* public_key, struct wg_secret* secret) {
	return crypto_scalarmult(secret->material, private_key->material, public_key->material);
}

static int wg_derive_dh_secret_from_reply(const struct wg_private_key* private_key, const struct wg_handshake_response* resp, struct wg_secret* secret) {
	return crypto_scalarmult(secret->material, private_key->material, resp->msg_ephemeral);
}

// AEAD

static void wg_aead_encrypt(
		const struct wg_kdf_key* key, uint64_t counter,
		const uint8_t* plaintext, size_t plaintext_size,
		const uint8_t* authtext, size_t authtext_size,
		uint8_t* ciphertext, size_t ciphertext_size
) {
	unsigned long long output_size = ciphertext_size;

	struct wg_nonce nonce = {
		.zero = 0,
		.counter_lo = htole32(counter & 0xFFFFFFFF),
		.counter_hi = htole32(counter >> 32)
	};

	crypto_aead_chacha20poly1305_ietf_encrypt(
			ciphertext, &output_size,
			plaintext, plaintext_size,
			authtext, authtext_size,
			NULL,
			(const uint8_t*) &nonce, key->material
	);
}

static int wg_aead_decrypt(
		const struct wg_kdf_key* key, uint64_t counter,
		const uint8_t* ciphertext, size_t ciphertext_size,
		const uint8_t* authtext, size_t authtext_size,
		uint8_t* plaintext, size_t plaintext_size
) {
	unsigned long long output_size = plaintext_size;

	struct wg_nonce nonce = {
		.zero = 0,
		.counter_lo = htole32(counter & 0xFFFFFFFF),
		.counter_hi = htole32(counter >> 32)
	};

	return crypto_aead_chacha20poly1305_ietf_decrypt(
			plaintext, &output_size,
			NULL,
			ciphertext, ciphertext_size,
			authtext, authtext_size,
			(const uint8_t*) &nonce, key->material
	);
}

// MAC

static void wg_compute_mac1(struct wg_handshake_request* req, const struct wg_public_key* public_key) {
	blake2s_state hash_state;

	uint8_t mac_key[WG_HASH_LENGTH];

	blake2s_init(&hash_state, WG_HASH_LENGTH);
	blake2s_update(&hash_state, LABEL_MAC1, sizeof(LABEL_MAC1));
	blake2s_update(&hash_state, public_key->material, WG_PUBLIC_KEY_LENGTH);
	blake2s_final(&hash_state, mac_key, WG_HASH_LENGTH);

	blake2s_init_key(&hash_state, WG_MAC_LENGTH, mac_key, WG_HASH_LENGTH);
	blake2s_update(&hash_state, (const uint8_t*) req, sizeof(struct wg_handshake_request) - 2UL * WG_MAC_LENGTH);
	blake2s_final(&hash_state, req->mac1, WG_MAC_LENGTH);
}

static int wg_verify_mac1(const struct wg_handshake_response* resp, const struct wg_public_key* public_key) {
	blake2s_state hash_state;

	uint8_t mac_key[WG_HASH_LENGTH];
	uint8_t packet_mac1[WG_MAC_LENGTH];

	blake2s_init(&hash_state, WG_HASH_LENGTH);
	blake2s_update(&hash_state, LABEL_MAC1, sizeof(LABEL_MAC1));
	blake2s_update(&hash_state, public_key->material, WG_PUBLIC_KEY_LENGTH);
	blake2s_final(&hash_state, mac_key, WG_HASH_LENGTH);

	blake2s_init_key(&hash_state, WG_MAC_LENGTH, mac_key, WG_HASH_LENGTH);
	blake2s_update(&hash_state, (const uint8_t*) resp, sizeof(struct wg_handshake_response) - 2UL * WG_MAC_LENGTH);
	blake2s_final(&hash_state, packet_mac1, WG_MAC_LENGTH);

	return sodium_memcmp(packet_mac1, resp->mac1, WG_MAC_LENGTH);
}

// Auxiliary

static int wg_parse_base64(const char* input, uint8_t* output, size_t output_size) {
	size_t parsed_size;

	int err = sodium_base642bin(
			output, output_size,
			input, strlen(input),
			NULL,
			&parsed_size,
			NULL,
			sodium_base64_VARIANT_ORIGINAL
	);

	if (err < 0 || parsed_size != output_size) return ERROR_WRONG_BASE64;

	return 0;
}

static void wg_create_timestamp(struct wg_timestamp* timestamp) {
	struct timespec current_time;

	clock_gettime(CLOCK_REALTIME, &current_time);

	uint64_t seconds = TAI64N_EPOCH + current_time.tv_sec;

	timestamp->seconds_hi = htobe32(seconds >> 32);
	timestamp->seconds_lo = htobe32(seconds & 0xFFFFFFFF);
	timestamp->nanos = htobe32(current_time.tv_nsec & TAI64N_NS_MASK);
}

// Public API

int wg_init(void) {
	wg_init_constants();
	return sodium_init() < 0 ? ERROR_CRYPTO_INIT_FAILED : 0;
}

int wg_parse_private_key(const char* input, struct wg_private_key* output) {
	return wg_parse_base64(input, output->material, WG_PRIVATE_KEY_LENGTH);
}

int wg_parse_public_key(const char* input, struct wg_public_key* output) {
	return wg_parse_base64(input, output->material, WG_PUBLIC_KEY_LENGTH);
}

int wg_parse_preshared_key(const char* input, struct wg_secret* output) {
	return wg_parse_base64(input, output->material, WG_SHARED_SECRET_LENGTH);
}

void wg_derive_public_key(const struct wg_private_key* private_key, struct wg_public_key* public_key) {
	crypto_scalarmult_base(public_key->material, private_key->material);
}

void wg_null_preshared_key(struct wg_secret* preshared_key) {
	memset(preshared_key->material, 0, WG_SHARED_SECRET_LENGTH);
}

struct wg_context* wg_allocate_contexts(size_t count) {
	return aligned_alloc(alignof(struct wg_context), count * sizeof(struct wg_context));
}

void wg_free_contexts(struct wg_context* contexts) {
	free(contexts);
}

int wg_create_handshake(
		struct wg_context* ctx,
		const struct wg_private_key* own_static_private,
		const struct wg_public_key* own_static_public,
		const struct wg_public_key* peer_static_public,
		struct wg_handshake_request* req
) {
	struct wg_timestamp timestamp;

	wg_init_context(peer_static_public, ctx, req);

	if (wg_derive_dh_secret(&ctx->own_ephemeral_private, peer_static_public, &ctx->scratchpad.dh_secret1))
		return ERROR_DH_FAILURE;

	if (wg_derive_dh_secret(         own_static_private, peer_static_public, &ctx->scratchpad.dh_secret2))
		return ERROR_DH_FAILURE;

	// Mixing static key

	wg_chain_kdf(ctx, (const uint8_t*) &ctx->scratchpad.dh_secret1, WG_SHARED_SECRET_LENGTH);
	wg_chain_kdf_block(ctx, &ctx->chaining_key, &ctx->scratchpad.encryption_key);

	wg_aead_encrypt(
			&ctx->scratchpad.encryption_key, 0,
			(const uint8_t*) own_static_public, WG_PUBLIC_KEY_LENGTH,
			ctx->chaining_hash, WG_HASH_LENGTH,
			req->msg_static, AEAD_LENGTH(WG_PUBLIC_KEY_LENGTH)
	);

	wg_chain_hash(ctx, req->msg_static, AEAD_LENGTH(WG_PUBLIC_KEY_LENGTH));

	// Mixing timestamp

	wg_chain_kdf(ctx, (const uint8_t*) &ctx->scratchpad.dh_secret2, WG_SHARED_SECRET_LENGTH);
	wg_chain_kdf_block(ctx, &ctx->chaining_key, &ctx->scratchpad.encryption_key);

	wg_create_timestamp(&timestamp);

	wg_aead_encrypt(
			&ctx->scratchpad.encryption_key, 0,
			(const uint8_t*) &timestamp, WG_TIMESTAMP_LENGTH,
			ctx->chaining_hash, WG_HASH_LENGTH,
			req->msg_timestamp, AEAD_LENGTH(WG_TIMESTAMP_LENGTH)
	);

	wg_chain_hash(ctx, req->msg_timestamp, AEAD_LENGTH(WG_TIMESTAMP_LENGTH));

	// Compute MAC1

	wg_compute_mac1(req, peer_static_public);

	return 0;
}

int wg_verify_handshake(
		struct wg_context* ctx,
		const struct wg_private_key* own_static_private,
		const struct wg_public_key* own_static_public,
		const struct wg_secret* preshared_key,
		const struct wg_handshake_response* resp
) {
	if (le32toh(resp->packet_header) != WG_HANDSHAKE_RESPONSE_HDR)
		return ERROR_NOT_WG_PACKET;

	if (le32toh(resp->receiver_id) != ctx->sender_id)
		return ERROR_NOT_WG_PACKET;

	if (wg_verify_mac1(resp, own_static_public))
		return ERROR_NOT_WG_PACKET;

	if (wg_derive_dh_secret_from_reply(&ctx->own_ephemeral_private, resp, &ctx->scratchpad.dh_secret1))
		return ERROR_DH_FAILURE;

	if (wg_derive_dh_secret_from_reply(         own_static_private, resp, &ctx->scratchpad.dh_secret2))
		return ERROR_DH_FAILURE;

	wg_chain_kdf(ctx, resp->msg_ephemeral, WG_PUBLIC_KEY_LENGTH);
	wg_chain_hash(ctx, resp->msg_ephemeral, WG_PUBLIC_KEY_LENGTH);

	wg_chain_kdf(ctx, (const uint8_t*) &ctx->scratchpad.dh_secret1, WG_SHARED_SECRET_LENGTH);
	wg_chain_kdf(ctx, (const uint8_t*) &ctx->scratchpad.dh_secret2, WG_SHARED_SECRET_LENGTH);

	wg_chain_kdf(ctx, (const uint8_t*) preshared_key, WG_SHARED_SECRET_LENGTH);
	wg_chain_kdf_block(ctx,             &ctx->chaining_key, &ctx->scratchpad.temporary_key);
	wg_chain_kdf_block(ctx, &ctx->scratchpad.temporary_key, &ctx->scratchpad.encryption_key);

	wg_chain_hash(ctx, (const uint8_t*) &ctx->scratchpad.temporary_key, WG_HASH_LENGTH);

	int err = wg_aead_decrypt(
			&ctx->scratchpad.encryption_key, 0,
			resp->msg_empty, AEAD_LENGTH(0),
			ctx->chaining_hash, WG_HASH_LENGTH,
			NULL, 0
	);

	wg_chain_hash(ctx, resp->msg_empty, AEAD_LENGTH(0));

	if (err) return ERROR_WG_PACKET_AUTH_FAILED;

	return 0;
}

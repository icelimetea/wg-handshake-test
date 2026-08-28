#include "wg.h"

#include <stddef.h>
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

static uint8_t INITIAL_CHAINING_HASH[WG_HASH_LENGTH];
static uint8_t INITIAL_CHAINING_KEY[WG_HASH_LENGTH];

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

	if (err < 0 || parsed_size != output_size) return -1;

	return 0;
}

static void wg_init_constants(void) {
	blake2s_state hash_state;

	blake2s_init(&hash_state, WG_HASH_LENGTH);
	blake2s_update(&hash_state, CONSTRUCTION, sizeof(CONSTRUCTION));
	blake2s_final(&hash_state, INITIAL_CHAINING_HASH, WG_HASH_LENGTH);

	blake2s_init(&hash_state, WG_HASH_LENGTH);
	blake2s_update(&hash_state, INITIAL_CHAINING_HASH, WG_HASH_LENGTH);
	blake2s_update(&hash_state, IDENTIFIER, sizeof(IDENTIFIER));
	blake2s_final(&hash_state, INITIAL_CHAINING_KEY, WG_HASH_LENGTH);
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

	memset(ctx->key_ipad, 0x36, WG_HASH_BLOCK_LENGTH);
	memset(ctx->key_opad, 0x5C, WG_HASH_BLOCK_LENGTH);

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

	memset(ctx->key_ipad, 0x36, WG_HASH_BLOCK_LENGTH);
	memset(ctx->key_opad, 0x5C, WG_HASH_BLOCK_LENGTH);

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

static void wg_derive_public_key(const struct wg_private_key* private_key, struct wg_public_key* output) {
	crypto_scalarmult_base(output->material, private_key->material);
}

static int wg_derive_dh_secret(const struct wg_private_key* private_key, const struct wg_public_key* public_key, struct wg_secret* output) {
	return crypto_scalarmult(output->material, private_key->material, public_key->material);
}

static void wg_aead_encrypt(
		const struct wg_kdf_key* key, uint64_t counter,
		const uint8_t* plaintext, size_t plaintext_size,
		const uint8_t* authtext, size_t authtext_size,
		uint8_t* output, size_t output_size
) {
	unsigned long long ciphertext_size = output_size;

	struct wg_nonce nonce = {
		.zero = 0,
		.counter_lo = htole32(counter & 0xFFFFFFFF),
		.counter_hi = htole32(counter >> 32)
	};

	crypto_aead_chacha20poly1305_ietf_encrypt(
			output, &ciphertext_size,
			plaintext, plaintext_size,
			authtext, authtext_size,
			NULL,
			(const uint8_t*) &nonce, key->material
	);
}

static void wg_create_timestamp(struct wg_timestamp* output) {
	struct timespec current_time;

	clock_gettime(CLOCK_REALTIME, &current_time);

	uint64_t seconds = (1ULL << 62) + current_time.tv_sec;

	output->seconds_hi = htobe32(seconds >> 32);
	output->seconds_lo = htobe32(seconds & 0xFFFFFFFF);
	output->nanos = htobe32(current_time.tv_nsec & 0xFF000000);
}

static void wg_init_context(struct wg_context* ctx, struct wg_handshake_request* req, const struct wg_public_key* peer_static_public) {
	memset(req, 0, sizeof(struct wg_handshake_request));

	req->packet_header = htole32(1);

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

int wg_init(void) {
	wg_init_constants();
	return sodium_init() < 0 ? -1 : 0;
}

int wg_parse_private_key(const char* input, struct wg_private_key* output) {
	return wg_parse_base64(input, output->material, WG_PRIVATE_KEY_LENGTH);
}

int wg_parse_public_key(const char* input, struct wg_public_key* output) {
	return wg_parse_base64(input, output->material, WG_PUBLIC_KEY_LENGTH);
}

int wg_create_handshake(
		struct wg_context* ctx,
		const struct wg_private_key* own_static_private,
		const struct wg_public_key* peer_static_public,
		struct wg_handshake_request* req
) {
	struct wg_secret dh_secret;
	struct wg_kdf_key encryption_key;

	struct wg_public_key own_static_public;
	struct wg_timestamp timestamp;

	wg_init_context(ctx, req, peer_static_public);

	// Mixing static key

	if (wg_derive_dh_secret(&ctx->own_ephemeral_private, peer_static_public, &dh_secret))
		return -1;

	wg_chain_kdf(ctx, (const uint8_t*) &dh_secret, WG_SHARED_SECRET_LENGTH);
	wg_chain_kdf_block(ctx, &ctx->chaining_key, &encryption_key);

	wg_derive_public_key(own_static_private, &own_static_public);

	wg_aead_encrypt(
			&encryption_key, 0,
			(const uint8_t*) &own_static_public, WG_PUBLIC_KEY_LENGTH,
			ctx->chaining_hash, WG_HASH_LENGTH,
			req->msg_static, AEAD_LENGTH(WG_PUBLIC_KEY_LENGTH)
	);

	wg_chain_hash(ctx, req->msg_static, AEAD_LENGTH(WG_PUBLIC_KEY_LENGTH));

	// Mixing timestamp

	if (wg_derive_dh_secret(own_static_private, peer_static_public, &dh_secret))
		return -1;

	wg_chain_kdf(ctx, (const uint8_t*) &dh_secret, WG_SHARED_SECRET_LENGTH);
	wg_chain_kdf_block(ctx, &ctx->chaining_key, &encryption_key);

	wg_create_timestamp(&timestamp);

	wg_aead_encrypt(
			&encryption_key, 0,
			(const uint8_t*) &timestamp, WG_TIMESTAMP_LENGTH,
			ctx->chaining_hash, WG_HASH_LENGTH,
			req->msg_timestamp, AEAD_LENGTH(WG_TIMESTAMP_LENGTH)
	);

	wg_chain_hash(ctx, req->msg_timestamp, AEAD_LENGTH(WG_TIMESTAMP_LENGTH));

	return 0;
}

int wg_verify_handshake(
		struct wg_context* ctx,
		const struct wg_private_key* own_static_private,
		const struct wg_handshake_response* resp
);

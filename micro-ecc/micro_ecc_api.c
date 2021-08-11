#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <time.h>

#include <stdlib.h>

#include "micro_ecc_api.h"
#include "uECC.h"


static int rng_function(uint8_t *dest, unsigned int size);

typedef struct {
	uECC_Curve curve;
	u8 public_key[64];
	u8 private_key[32];
} ecc_context_t;

u32 ecc_get_context_size(){
	return sizeof(ecc_context_t);
}

#if defined __StratifyOS__
static int ecc_root_init(void **context) {
	ecc_context_t *c = *context;
	*c = (ecc_context_t){};
	c->curve = uECC_secp256r1();
	return 0;
}

static void ecc_root_deinit(void **context) {
	ecc_context_t *c = *context;
	if (c) {
		*c = (ecc_context_t){};
		*context = 0;
	}
}
#endif

static int ecc_init(void **context) {
	ecc_context_t *c = malloc(sizeof(ecc_context_t));
	if (c == NULL) {
		return -1;
	}

	*context = c;
	return 0;
}

static void ecc_deinit(void **context) {
	ecc_context_t *c = *context;

	if (c) {

		free(c);
		*context = 0;
	}
}

static int ecc_dh_create_key_pair(
		void *context,
		crypt_ecc_key_pair_t type,
		u8 *public_key,
		u32 *public_key_capacity) {
	ecc_context_t *c = context;

	if (type != CRYPT_ECC_KEY_PAIR_SECP256R1) {
		errno = EINVAL;
		return -1;
	}

	c->curve = uECC_secp256r1();
	uECC_set_rng(rng_function);


	if (*public_key_capacity < 64) {
		errno = EINVAL;
		return -2;
	}

	uECC_make_key(c->public_key, c->private_key, c->curve);
	memcpy(public_key, c->public_key, 64);
	*public_key_capacity = 64;

	return 0;
}

static int ecc_dh_calculate_shared_secret(
		void *context,
		const u8 *public_key,
		u32 public_key_length,
		u8 *secret,
		u32 secret_length) {
	ecc_context_t *c = context;

	if (secret_length < 32) {
		errno = EINVAL;
		return -1;
	}

	if( public_key_length != 64 ){
		errno = EINVAL;
		return -1;
	}

	c->curve = uECC_secp256r1();
	uECC_set_rng(rng_function);

	uECC_shared_secret(public_key, c->private_key, secret, c->curve);
	return 32;
}

static int ecc_dsa_create_key_pair(
		void *context,
		crypt_ecc_key_pair_t type,
		u8 *public_key,
		u32 *public_key_capacity,
		u8 *private_key,
		u32 *private_key_capacity) {
	ecc_context_t *c = context;

	if (type != CRYPT_ECC_KEY_PAIR_SECP256R1) {
		errno = EINVAL;
		return -1;
	}

	c->curve = uECC_secp256r1();
	uECC_set_rng(rng_function);

	if (*public_key_capacity < sizeof(c->public_key)) {
		errno = EINVAL;
		return -1;
	}

	if (*private_key_capacity < sizeof(c->private_key)) {
		errno = EINVAL;
		return -1;
	}

	uECC_make_key(c->public_key, c->private_key, c->curve);

	memcpy(public_key, c->public_key, sizeof(c->public_key));
	memcpy(private_key, c->private_key, sizeof(c->private_key));

	*public_key_capacity = 64;
	*private_key_capacity = 32;

	return 0;
}

static int ecc_dsa_set_key_pair(
		void *context,
		const u8 *public_key,
		u32 public_key_size,
		const u8 *private_key,
		u32 private_key_size) {
	ecc_context_t *c = context;

	if( public_key_size < sizeof(c->public_key) ){
		errno = EINVAL;
		return -1;
	}

	memcpy(c->public_key, public_key, sizeof(c->public_key));

	if( private_key_size && private_key_size < sizeof(c->private_key) ){
		errno = EINVAL;
		return -1;
	}

	if( private_key_size ){
		memcpy(c->private_key, private_key, sizeof(c->private_key));
	}

	return 0;
}

static int ecc_dsa_sign(
		void *context,
		const u8 *message_hash,
		u32 hash_size,
		u8 *signature,
		u32 *signature_length) {
	ecc_context_t *c = context;

	if (*signature_length < 64) {
		errno = EINVAL;
		return -1;
	}

	c->curve = uECC_secp256r1();
	uECC_set_rng(rng_function);

	uECC_sign(c->private_key, message_hash, hash_size, signature, c->curve);
	*signature_length = 64;
	return 0;
}

static int ecc_dsa_verify(
		void *context,
		const u8 *message_hash,
		u32 hash_size,
		const u8 *signature,
		u32 signature_length) {
	ecc_context_t *c = context;

	if( signature_length != 64 ){
		errno = EINVAL;
		return -1;
	}

	c->curve = uECC_secp256r1();
	uECC_set_rng(rng_function);

	return uECC_verify(c->public_key, message_hash, hash_size, signature, c->curve);
}

int rng_function(uint8_t *dest, unsigned int size){
#if defined __link
#if HAVE_ARC4RANDOM
	arc4random_buf(dest, size);
#else
	time_t t;
	srand((unsigned) time(&t));
	for(unsigned int i = 0; i < size; i++){
		dest[i] = rand();
	}
#endif
#else

#endif
	return size;
}

const crypt_ecc_api_t micro_ecc_api = {
	.sos_api = {.name = "micro_ecc", .version = 0x0001, .git_hash = SOS_GIT_HASH},
	.init = ecc_init,
	.deinit = ecc_deinit,
	.dh_create_key_pair = ecc_dh_create_key_pair,
	.dh_calculate_shared_secret = ecc_dh_calculate_shared_secret,
	.dsa_create_key_pair = ecc_dsa_create_key_pair,
	.dsa_set_key_pair = ecc_dsa_set_key_pair,
	.dsa_sign = ecc_dsa_sign,
	.dsa_verify = ecc_dsa_verify,
	.get_context_size = ecc_get_context_size};

#if defined __StratifyOS__
const crypt_ecc_api_t micro_ecc_root_api = {
	.sos_api = {.name = "micro_ecc_root", .version = 0x0001, .git_hash = SOS_GIT_HASH},
	.init = ecc_root_init,
	.deinit = ecc_root_deinit,
	.dh_create_key_pair = ecc_dh_create_key_pair,
	.dh_calculate_shared_secret = ecc_dh_calculate_shared_secret,
	.dsa_create_key_pair = ecc_dsa_create_key_pair,
	.dsa_set_key_pair = ecc_dsa_set_key_pair,
	.dsa_sign = ecc_dsa_sign,
	.dsa_verify = ecc_dsa_verify,
	.get_context_size = ecc_get_context_size};

const crypt_ecc_api_t micro_ecc_verify_root_api = {
	.sos_api = {.name = "micro_ecc_verify_root", .version = 0x0001, .git_hash = SOS_GIT_HASH},
	.init = ecc_root_init,
	.deinit = ecc_root_deinit,
	.dh_create_key_pair = NULL,
	.dh_calculate_shared_secret = NULL,
	.dsa_create_key_pair = NULL,
	.dsa_set_key_pair = ecc_dsa_set_key_pair,
	.dsa_sign = NULL,
	.dsa_verify = ecc_dsa_verify,
	.get_context_size = ecc_get_context_size};
#endif

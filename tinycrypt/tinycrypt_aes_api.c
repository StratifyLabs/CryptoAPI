#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <stdlib.h>

#include "tinycrypt/cbc_mode.h"
#include "tinycrypt/ctr_mode.h"
#include "tinycrypt_api.h"

typedef struct {
  struct tc_aes_key_sched_struct sched;
  unsigned char key[16];
  u32 key_bits;
} aes_context_t;

#if __StratifyOS__
static int aes_root_init(void **context) {
  aes_context_t *c = *context;
  *c = (aes_context_t){};
  return 0;
}

static void aes_root_deinit(void **context) {
  aes_context_t *c = *context;
  if (c) {
    *c = (aes_context_t){};
    *context = 0;
  }
}
#endif

static int aes_init(void **context) {
  aes_context_t *c = malloc(sizeof(aes_context_t));
  if (c == NULL) {
    return -1;
  }
  *c = (aes_context_t){};
  *context = c;
  return 0;
}

static void aes_deinit(void **context) {
  aes_context_t *c = *context;
  if (c) {
    free(c);
    *context = 0;
  }
}

static int aes_set_key(
  void *context,
  const unsigned char *key,
  u32 keybits,
  u32 bits_per_word) {
  MCU_UNUSED_ARGUMENT(bits_per_word);
  aes_context_t *c = context;
  if (keybits != 128) {
    errno = EINVAL;
    return -1;
  }
  memcpy(c->key, key, keybits / 8);
  c->key_bits = keybits;
  tc_aes128_set_encrypt_key(&c->sched, key);
  return 0;
}

static int aes_encrypt_cbc(
  void *context,
  u32 length,
  unsigned char iv[16],
  const unsigned char *input,
  unsigned char *output) {
  aes_context_t *c = context;

  return tc_cbc_mode_encrypt(output, length, input, length, iv, &c->sched);
}

static int aes_decrypt_cbc(
  void *context,
  u32 length,
  unsigned char iv[16],
  const unsigned char *input,
  unsigned char *output) {
  aes_context_t *c = context;

  return tc_cbc_mode_decrypt(output, length, input, length, iv, &c->sched);
}

static int aes_encrypt_ctr(
  void *context,
  u32 length,
  u32 *nc_off,
  unsigned char nonce_counter[16],
  unsigned char stream_block[16],
  const unsigned char *input,
  unsigned char *output) {
  MCU_UNUSED_ARGUMENT(context);
  MCU_UNUSED_ARGUMENT(length);
  MCU_UNUSED_ARGUMENT(nc_off);
  MCU_UNUSED_ARGUMENT(nonce_counter);
  MCU_UNUSED_ARGUMENT(stream_block);
  MCU_UNUSED_ARGUMENT(input);
  MCU_UNUSED_ARGUMENT(output);
  //not supported yet

  return -1;
}

static int aes_decrypt_ctr(
  void *context,
  u32 length,
  u32 *nc_off,
  unsigned char nonce_counter[16],
  unsigned char stream_block[16],
  const unsigned char *input,
  unsigned char *output) {
  MCU_UNUSED_ARGUMENT(context);
  MCU_UNUSED_ARGUMENT(length);
  MCU_UNUSED_ARGUMENT(nc_off);
  MCU_UNUSED_ARGUMENT(nonce_counter);
  MCU_UNUSED_ARGUMENT(stream_block);
  MCU_UNUSED_ARGUMENT(input);
  MCU_UNUSED_ARGUMENT(output);

  //not supported yet

  return -1;
}


const crypt_aes_api_t tinycrypt_aes_api = {
  .sos_api
  = {.name = "tinycrypt_aes", .version = 0x0001, .git_hash = CMSDK_GIT_HASH},
  .init = aes_init,
  .deinit = aes_deinit,
  .set_key = aes_set_key,
  .encrypt_ecb = NULL,
  .decrypt_ecb = NULL,
  .encrypt_cbc = aes_encrypt_cbc,
  .decrypt_cbc = aes_decrypt_cbc,
  .encrypt_ctr = aes_encrypt_ctr,
  .decrypt_ctr = aes_decrypt_ctr};

#if __StratifyOS__
const crypt_aes_api_t tinycrypt_aes_root_api = {
    .sos_api
    = {.name = "tinycrypt_aes_root", .version = 0x0001, .git_hash = CMSDK_GIT_HASH},
    .init = aes_root_init,
    .deinit = aes_root_deinit,
    .set_key = aes_set_key,
    .encrypt_ecb = NULL,
    .decrypt_ecb = NULL,
    .encrypt_cbc = aes_encrypt_cbc,
    .decrypt_cbc = aes_decrypt_cbc,
    .encrypt_ctr = aes_encrypt_ctr,
    .decrypt_ctr = aes_decrypt_ctr};
#endif



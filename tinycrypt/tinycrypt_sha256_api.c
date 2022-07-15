#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <stdlib.h>

#include "tinycrypt_api.h"
#include "tinycrypt/sha256.h"

typedef struct {
  struct tc_sha256_state_struct sha256;
} sha256_context_t;

static u32 sha256_get_context_size(){
  return sizeof(sha256_context_t);
}

#if __StratifyOS__
static int sha256_root_init(void **context) {
  TCSha256State_t c = *context;
  *c = (struct tc_sha256_state_struct){};
  return 0;
}

static void sha256_root_deinit(void **context) {
  TCSha256State_t c = *context;
  *c = (struct tc_sha256_state_struct){};
}
#endif

static int sha256_init(void **context) {
  TCSha256State_t c
    = malloc(sizeof(struct tc_sha256_state_struct));
  if (c == 0) {
    return -1;
  }
  *context = c;
  return 0;
}

static void sha256_deinit(void **context) {
  TCSha256State_t c = *context;
  if (c) {
    free(c);
    *context = 0;
  }
}

static int sha256_start(void *context) {
  TCSha256State_t c = context;
  return tc_sha256_init(c);
}

static int sha256_update(void *context, const unsigned char *input, u32 size) {
  TCSha256State_t c = context;
  return tc_sha256_update(c, input, size);
}

static int sha256_finish(void *context, unsigned char *output, u32 size) {
  if (size != 32) { // sha256 output is always 32 bytes (256 bits)
    errno = EINVAL;
    return -1;
  }
  TCSha256State_t c = context;
  return tc_sha256_final(output, c);
}

const crypt_hash_api_t tinycrypt_sha256_api = {
  .sos_api
  = {.name = "tinycrypt_sha256", .version = 0x0001, .git_hash = CMSDK_GIT_HASH},
  .init = sha256_init,
  .deinit = sha256_deinit,
  .start = sha256_start,
  .update = sha256_update,
  .finish = sha256_finish,
  .get_context_size = sha256_get_context_size };

#if __StratifyOS__
const crypt_hash_api_t tinycrypt_sha256_root_api = {
    .sos_api
    = {.name = "tinycrypt_sha256_root", .version = 0x0001, .git_hash = CMSDK_GIT_HASH},
    .init = sha256_root_init,
    .deinit = sha256_root_deinit,
    .start = sha256_start,
    .update = sha256_update,
    .finish = sha256_finish,
    .get_context_size = sha256_get_context_size };
#endif




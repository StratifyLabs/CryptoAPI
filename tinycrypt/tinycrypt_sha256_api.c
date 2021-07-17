#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <stdlib.h>

#include "tinycrypt_api.h"
#include "tinycrypt/sha256.h"

static int sha256_init(void **context);
static void sha256_deinit(void **context);
static int sha256_start(void *context);
static int sha256_update(void *context, const unsigned char *input, u32 size);
static int sha256_finish(void *context, unsigned char *output, u32 size);

const crypt_hash_api_t tinycrypt_sha256_api = {
  .sos_api
  = {.name = "tinycrypt_sha256", .version = 0x0001, .git_hash = SOS_GIT_HASH},
  .init = sha256_init,
  .deinit = sha256_deinit,
  .start = sha256_start,
  .update = sha256_update,
  .finish = sha256_finish};

typedef struct {
  struct tc_sha256_state_struct sha256;
} sha256_context_t;


int sha256_init(void **context) {
  TCSha256State_t c
    = malloc(sizeof(struct tc_sha256_state_struct));
  if (c == 0) {
    return -1;
  }
  *context = c;
  return 0;
}

void sha256_deinit(void **context) {
  TCSha256State_t c = *context;
  if (c) {
    free(c);
    *context = 0;
  }
}

int sha256_start(void *context) {
  TCSha256State_t c = context;
  return tc_sha256_init(c);
}

int sha256_update(void *context, const unsigned char *input, u32 size) {
  TCSha256State_t c = context;
  return tc_sha256_update(c, input, size);
}

int sha256_finish(void *context, unsigned char *output, u32 size) {
  if (size != 32) { // sha256 output is always 32 bytes (256 bits)
    errno = EINVAL;
    return -1;
  }
  TCSha256State_t c = context;
  return tc_sha256_final(output, c);
}





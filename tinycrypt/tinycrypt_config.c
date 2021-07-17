#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <stdlib.h>

#include "tinycrypt_api.h"
#include "tinycrypt/sha256.h"

#if defined __StratifyOS__

u32 tinycrypt_config_sha256_get_context_size(){
  return sizeof(struct tc_sha256_state_struct);
}

void tinycrypt_config_sha256_start(void * context){
  TCSha256State_t s = context;
  tc_sha256_init(s);
}

void tinycrypt_config_sha256_update(void *context, const void *input, u32 size){
  TCSha256State_t s = context;
  tc_sha256_update(s, input, size);
}

void tinycrypt_config_sha256_finish(void *context, u8 output[32]){
  TCSha256State_t s = context;
  tc_sha256_final(output, s);
}

#endif




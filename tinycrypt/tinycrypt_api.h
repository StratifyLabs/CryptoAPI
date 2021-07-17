#ifndef TINYCRYPT_API_H
#define TINYCRYPT_API_H

#include <sdk/types.h>
#include <sdk/api.h>

#if defined __cplusplus
extern "C" {
#endif


#if defined __link

#else
#define TINYCRYPT_API_REQUEST MCU_API_REQUEST_CODE('t','c','r','y')

u32 tinycrypt_config_sha256_get_context_size();
void tinycrypt_config_sha256_start(void * context);
void tinycrypt_config_sha256_update(void *context, const void *input, u32 size);
void tinycrypt_config_sha256_finish(void *context, u8 output[32]);

#endif

extern const crypt_hash_api_t tinycrypt_sha256_api;
extern const crypt_aes_api_t tinycrypt_aes_api;

#if defined __cplusplus
}
#endif


#endif // TINYCRYPT_API_H

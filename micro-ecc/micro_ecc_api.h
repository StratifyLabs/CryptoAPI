#ifndef MICRO_ECC_API_H
#define MICRO_ECC_API_H

#include <sdk/types.h>
#include <sdk/api.h>

#if defined __cplusplus
extern "C" {
#endif

extern const crypt_ecc_api_t micro_ecc_api;

#if defined __StratifyOS__
extern const crypt_ecc_api_t micro_ecc_root_api;
extern const crypt_ecc_api_t micro_ecc_verify_root_api;
#endif

#if defined __cplusplus
}
#endif


#endif // MICRO_ECC_API_H

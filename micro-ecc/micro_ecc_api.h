#ifndef MICRO_ECC_API_H
#define MICRO_ECC_API_H

#include <sdk/types.h>
#include <sdk/api.h>

#if defined __cplusplus
extern "C" {
#endif


#if defined __StratifyOS__

#include <sos/config.h>

typedef struct {
  u8 public_key[64];
  u8 private_key[32];
  u8 shared_secret[32];
} sos_config_ecc_calculate_shared_secret_t;

typedef struct {
  u8 public_key[64];
  u8 sha256[32];
  u8 signature[64];
} sos_config_ecc_verify_signature_t;

//this will be used to establish secure commnications
void micro_ecc_config_calculate_shared_secret(sos_config_ecc_calculate_shared_secret_t * args);

//this will be used by the bootloader and higher to verify signatures
int micro_ecc_config_verify_signature(const sos_config_ecc_verify_signature_t * keys);

#endif


extern const crypt_ecc_api_t micro_ecc_api;

#if defined __cplusplus
}
#endif


#endif // MICRO_ECC_API_H

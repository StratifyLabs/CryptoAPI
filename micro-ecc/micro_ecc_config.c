
#include "micro_ecc_api.h"
#include "uECC.h"

#if defined __StratifyOS__

// this will be used to establish secure commnications
void micro_ecc_config_calculate_shared_secret(
  sos_config_ecc_calculate_shared_secret_t *keys) {

  uECC_shared_secret(
    keys->public_key,
    keys->private_key,
    keys->shared_secret,
    uECC_secp256r1());
}

// this will be used by the bootloader and higher to verify signatures
int micro_ecc_config_verify_signature(
  const sos_config_ecc_verify_signature_t *keys) {
  return uECC_verify(
    keys->public_key,
    keys->sha256,
    sizeof(keys->sha256),
    keys->signature,
    uECC_secp256r1());
}

#else
u32 micro_ecc_config_no_warning = 0;
#endif

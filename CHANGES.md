# Version 1.2.0

## New Features

- Add factory methods to create `Aes::Key` from strings
- Add more ways to construct `Aes::Key` from other keys

## Bug Fixes

- None yet

# Version 1.1.0

## New Features

- Add `Sha256::from_string()` to get a `Hash` from a 64 character string
- Add config functions for StratifyOS sha256 and uECC to be used as low as the bootloader
- Add tinycrypt and uECC as subprojects
- Add `get_padded_data()` to AES which will allocate, pad, and fill a buffer with data to be encrypted
- Add support for ECC algorigthms (ECDH and ECDSA)
- Add `is_null()` and `nullify()` to `Aes::Key`

## Bug Fixes

- Change Sha256 hash to string to use `GeneralString` because `KeyString` was too small


# Version 1.0.0

Initial stable release.

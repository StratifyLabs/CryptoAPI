# Version 1.1.0

## New Features

- Add `get_padded_data()` to AES which will allocate, pad, and fill a buffer with data to be encrypted
- Add support for ECC algorigthms (ECDH and ECDSA)
- Add `is_null()` and `nullify()` to `Aes::Key`

## Bug Fixes

- Change Sha256 hash to string to use `GeneralString` because `KeyString` was too small


# Version 1.0.0

Initial stable release.

cmake_minimum_required(VERSION 3.12)
cmsdk2_minimum_required(2.1.2)
project(CryptoAPI
  LANGUAGES CXX
  VERSION 1.4.1)
option(CRYPTO_API_IS_TINYCRYPT "Enable building tinycrypt library" ON)
option(CRYPTO_API_IS_MICRO_ECC "Enable building micro-ecc library" ON)
add_subdirectory(library)
if (CRYPTO_API_IS_TINYCRYPT)
  add_subdirectory(tinycrypt)
endif ()
if (CRYPTO_API_IS_MICRO_ECC)
  add_subdirectory(micro-ecc)
endif ()
option(CRYPTO_API_IS_TEST "Enable test build for CryptoAPI" OFF)
if (CRYPTO_API_IS_TEST)
  add_subdirectory(tests)
endif ()

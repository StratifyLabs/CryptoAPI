// Copyright 2020-2021 Tyler Gilbert and Stratify Labs, Inc; see LICENSE.md

#ifndef SAPI_CRYPTO_SHA256_HPP_
#define SAPI_CRYPTO_SHA256_HPP_

#include <sdk/api.h>

#if defined __link && !defined CRYPT_SHA256_API_REQUEST
#include <mbedtls_api.h>
#define CRYPT_SHA256_API_REQUEST &mbedtls_crypt_sha256_api
#endif

#include "api/api.hpp"
#include "fs/File.hpp"
#include "var/Array.hpp"
#include "var/View.hpp"

namespace crypto {

class Sha256 : public api::ExecutionContext, public var::Transformer {
public:
  Sha256();
  ~Sha256();

  Sha256(const Sha256 &) = delete;
  Sha256 &operator=(const Sha256 &) = delete;

  Sha256(Sha256 &&a) noexcept {
    std::swap(m_context, a.m_context);
  }

  Sha256 &operator=(Sha256 &&a) noexcept {
    std::swap(m_context, a.m_context);
    return *this;
  }

  using Hash = var::Array<u8, 32>;

  static Hash from_string(const var::StringView value){
    API_ASSERT(value.length() == 64);
    Hash result;
    var::View(result).from_string(value);
    return result;
  }

  const Sha256 &update(const var::View &data) const;
  const Hash &output() const {
    finish();
    return m_output;
  }

  int transform(const Transform &options) const override {
    update(options.input());
    var::View(options.output()).copy(options.input());
    return options.input().size();
  }

  var::GeneralString to_string() const {
    finish();
    return var::View(m_output).to_string<var::GeneralString>();
  }

  static Hash get_hash(const fs::FileObject & file){
    Sha256 hash;
    fs::NullFile().write(file, hash);
    return hash.output();
  }

  API_NO_DISCARD static Hash append_aligned_hash(const fs::FileObject &file_object,
                                  u8 fill = 0xff);

  API_NO_DISCARD static bool check_aligned_hash(const fs::FileObject &file_object);


  API_NO_DISCARD static constexpr size_t page_size() {
#if defined __link
    return 4096;
#else
    return 256;
#endif
  }

private:
  using Api = api::Api<crypt_hash_api_t, CRYPT_SHA256_API_REQUEST>;
  static Api m_api;

  void *m_context = nullptr;
  mutable bool m_is_finished = false;
  Hash m_output{};

  void finish() const;
  static Api &api() { return m_api; }
};

} // namespace crypto

#endif // SAPI_CRYPTO_SHA256_HPP_

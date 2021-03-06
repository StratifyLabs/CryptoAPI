// Copyright 2020-2021 Tyler Gilbert and Stratify Labs, Inc; see LICENSE.md

#include <errno.h>
#include <printer/Printer.hpp>
#include <var.hpp>

#include "crypto/Aes.hpp"
#include "crypto/Random.hpp"

namespace printer {
class Printer;
Printer &operator<<(Printer &printer, const crypto::Aes::Key &a) {
  printer.key("key128", a.get_key128_string().string_view());
  printer.key("key256", a.get_key256_string().string_view());
  printer.key("initializationVector",
              a.get_initialization_vector_string().string_view());
  return printer;
}
} // namespace printer

using namespace crypto;
Aes::Api Aes::m_api;

Aes::Aes() {
  if (api().is_valid() == false) {
    API_RETURN_ASSIGN_ERROR("missing api", ENOTSUP);
  }
  API_RETURN_IF_ERROR();
  API_SYSTEM_CALL("", api()->init(&m_context));
}

Aes::~Aes() {
  m_initialization_vector.fill(0);
  if (m_context != nullptr) {
    api()->deinit(&m_context);
  }
}

Aes &Aes::set_initialization_vector(const var::View &value) {
  API_RETURN_VALUE_IF_ERROR(*this);

  if (value.size() != m_initialization_vector.count()) {
    API_SYSTEM_CALL("set_initialization_vector", -1);
    return *this;
  }

  for (u32 i = 0; i < m_initialization_vector.count(); i++) {
    m_initialization_vector.at(i) = value.to_const_u8()[i];
  }

  return *this;
}

Aes &Aes::set_key128(const var::View &key) {
  API_ASSERT(key.size() == 16);
  API_RETURN_VALUE_IF_ERROR(*this);
  API_SYSTEM_CALL(
      "set_key128", api()->set_key(m_context, key.to_const_u8(), key.size() * 8, 8));
  return *this;
}

Aes &Aes::set_key256(const var::View &key) {
  API_ASSERT(key.size() == 32);
  API_RETURN_VALUE_IF_ERROR(*this);
  API_SYSTEM_CALL(
      "set_key256", api()->set_key(m_context, key.to_const_u8(), key.size() * 8, 8));
  return *this;
}

const Aes &Aes::encrypt_ecb(const Crypt &options) const {
  API_RETURN_VALUE_IF_ERROR(*this);
  API_ASSERT(options.cipher().size() == options.plain().size());
  API_ASSERT(options.cipher().size() % 16 == 0);

  for (u32 i = 0; i < options.plain().size(); i += 16) {
    if (api()->encrypt_ecb(m_context, options.plain().to_const_u8() + i,
                           View(options.cipher()).to_u8() + i) < 0) {
      API_SYSTEM_CALL("encrypt_ecb", -1);
      return *this;
    }
  }

  return *this;
}

const Aes &Aes::decrypt_ecb(const Crypt &options) const {
  API_RETURN_VALUE_IF_ERROR(*this);
  API_ASSERT(options.cipher().size() == options.plain().size());
  API_ASSERT(options.cipher().size() % 16 == 0);

  for (u32 i = 0; i < options.cipher().size(); i += 16) {

    if (API_SYSTEM_CALL("decrypt_ecb", api()->decrypt_ecb(
                                m_context, options.cipher().to_const_u8() + i,
                                View(options.plain()).to_u8() + i)) < 0) {
      return *this;
    }
  }

  return *this;
}

const Aes &Aes::encrypt_cbc(const Crypt &options) const {
  API_RETURN_VALUE_IF_ERROR(*this);
  API_ASSERT(options.cipher().size() == options.plain().size());
  API_ASSERT(options.cipher().size() % 16 == 0);

  API_SYSTEM_CALL(
      "encrypt_cbc", api()->encrypt_cbc(m_context, options.plain().size(),
                             m_initialization_vector.data(), // init vector
                             options.plain().to_const_u8(),
                             View(options.cipher()).to_u8()));

  return *this;
}

const Aes &Aes::decrypt_cbc(const Crypt &options) const {
  API_RETURN_VALUE_IF_ERROR(*this);
  API_ASSERT(options.cipher().size() == options.plain().size());
  API_ASSERT(options.cipher().size() % 16 == 0);

  API_SYSTEM_CALL(
      "decrypt_cbc", api()->decrypt_cbc(m_context, options.plain().size(),
                             m_initialization_vector.data(), // init vector
                             options.cipher().to_const_u8(),
                             View(options.plain()).to_u8()));

  return *this;
}

int AesCbcEncrypter::transform(
    const var::Transformer::Transform &options) const {
  encrypt_cbc(Crypt().set_plain(options.input()).set_cipher(options.output()));
  API_RETURN_VALUE_IF_ERROR(-1);
  return options.input().size();
}

int AesCbcDecrypter::transform(
    const var::Transformer::Transform &options) const {
  decrypt_cbc(Crypt().set_cipher(options.input()).set_plain(options.output()));
  API_RETURN_VALUE_IF_ERROR(-1);
  return options.input().size();
}

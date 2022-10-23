// Copyright 2020-2021 Tyler Gilbert and Stratify Labs, Inc; see LICENSE.md

#include <printer/Printer.hpp>

#include "crypto/Aes.hpp"

namespace printer {
class Printer;
Printer &operator<<(Printer &printer, const crypto::Aes::Key &a) {
  printer.key("key128", a.get_key128_string().string_view());
  printer.key("key256", a.get_key256_string().string_view());
  printer.key(
    "initializationVector",
    a.get_initialization_vector_string().string_view());
  return printer;
}
} // namespace printer

using namespace crypto;
using namespace var;

namespace {
auto &aes_api() {
  static api::Api<crypt_aes_api_t, CRYPT_AES_API_REQUEST> instance;
  return instance;
}
} // namespace


Aes::Key::Key() {
  // 256-bit key length
  Random().seed().randomize(var::View(m_key));
  Random().seed().randomize(var::View(m_initialization_vector));
}

Aes::Key &Aes::Key::nullify() & {
  m_key.fill(0);
  m_initialization_vector.fill(0);
  return *this;
}
bool Aes::Key::is_key_null() const {
  for (auto value : m_key) {
    if (value != 0) {
      return false;
    }
  }
  return true;
}
bool Aes::Key::is_iv_null() const {
  for (auto value : m_initialization_vector) {
    if (value != 0) {
      return false;
    }
  }
  return true;
}

Aes::Key128 Aes::Key::get_key128() const {
  Key128 result;
  var::View(result).copy(m_key);
  return result;
}
Aes::Key &Aes::Key::set_key(const Aes::Key128 &key) {
  var::View(m_key).fill(0).copy(var::View(key));
  return *this;
}

Aes::Aes() {
  if (!aes_api().is_valid()) {
    API_RETURN_ASSIGN_ERROR("missing api", ENOTSUP);
  }
  API_RETURN_IF_ERROR();
  void *result = nullptr;
  API_SYSTEM_CALL("", aes_api()->init(&result));
  API_RETURN_IF_ERROR();
  m_state = {{result}, &deleter};
}

void Aes::deleter(State *state) {
  state->initialization_vector.fill(0);
  if (state->context != nullptr) {
    aes_api()->deinit(&state->context);
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
    "set_key128",
    aes_api()->set_key(m_state->context, key.to_const_u8(), key.size() * 8, 8));
  return *this;
}

Aes &Aes::set_key256(const var::View &key) {
  API_ASSERT(key.size() == 32);
  API_RETURN_VALUE_IF_ERROR(*this);
  API_SYSTEM_CALL(
    "set_key256",
    aes_api()->set_key(m_state->context, key.to_const_u8(), key.size() * 8, 8));
  return *this;
}

const Aes &Aes::encrypt_ecb(const Crypt &options) const {
  API_RETURN_VALUE_IF_ERROR(*this);
  API_ASSERT(options.cipher().size() == options.plain().size());
  API_ASSERT(options.cipher().size() % 16 == 0);

  for (u32 i = 0; i < options.plain().size(); i += 16) {
    if (
      aes_api()->encrypt_ecb(
        m_state->context,
        options.plain().to_const_u8() + i,
        View(options.cipher()).to_u8() + i)
      < 0) {
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

    if (
      API_SYSTEM_CALL(
        "decrypt_ecb",
        aes_api()->decrypt_ecb(
          m_state->context,
          options.cipher().to_const_u8() + i,
          View(options.plain()).to_u8() + i))
      < 0) {
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
    "encrypt_cbc",
    aes_api()->encrypt_cbc(
      m_state->context,
      options.plain().size(),
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
    "decrypt_cbc",
    aes_api()->decrypt_cbc(
      m_state->context,
      options.plain().size(),
      m_initialization_vector.data(), // init vector
      options.cipher().to_const_u8(),
      View(options.plain()).to_u8()));

  return *this;
}
var::Data Aes::encrypt_cbc(var::View input) const {
  var::Data result(input.size());
  encrypt_cbc(Crypt().set_plain(input).set_cipher(var::View(result)));
  return result;
}
var::Data Aes::decrypt_cbc(var::View input) const {
  var::Data result(input.size());
  decrypt_cbc(Crypt().set_cipher(input).set_plain(var::View(result)));
  return result;
}
var::Data Aes::decrypt_ecb(var::View input) const {
  var::Data result(input.size());
  decrypt_ecb(Crypt().set_cipher(input).set_plain(var::View(result)));
  return result;
}
var::Data Aes::encrypt_ecb(var::View input) const {
  var::Data result(input.size());
  encrypt_ecb(Crypt().set_plain(input).set_cipher(var::View(result)));
  return result;
}

var::Data Aes::get_padded_data(const var::View input, u8 padding_value) {
  const auto padding_size = get_padding(input.size());
  auto result = var::Data(input.size() + padding_size);
  var::View(result).fill<u8>(padding_value).copy(input);
  return result;
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

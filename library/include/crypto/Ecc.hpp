// Copyright 2020-2021 Tyler Gilbert and Stratify Labs, Inc; see LICENSE.md

#ifndef CRYPTOAPI_CRYPTO_ECC_HPP_
#define CRYPTOAPI_CRYPTO_ECC_HPP_

#include <sdk/api.h>

#include <api/api.hpp>
#include <fs/File.hpp>
#include <var/Data.hpp>
#include <var/StackString.hpp>

#if defined __link && !defined CRYPT_AES_ECC_REQUEST
#include <mbedtls_api.h>
#define CRYPT_AES_ECC_REQUEST &mbedtls_crypt_ecc_api
#endif

#include "Random.hpp"

namespace crypto {

class Ecc : public api::ExecutionContext{
  using Api = api::Api<crypt_ecc_api_t, CRYPT_AES_ECC_REQUEST>;
  static Api m_api;

public:
  enum class Curve {
    secp192r1 = CRYPT_ECC_KEY_PAIR_SECP192R1,
    secp224r1 = CRYPT_ECC_KEY_PAIR_SECP224R1,

    // supported by tinycrypt and mbedtls
    secp256r1 = CRYPT_ECC_KEY_PAIR_SECP256R1,

    // mbedtls only
    secp384r1 = CRYPT_ECC_KEY_PAIR_SECP384R1,
    secp521r1 = CRYPT_ECC_KEY_PAIR_SECP521R1,
    bp256r1 = CRYPT_ECC_KEY_PAIR_BP256R1,
    bp384r1 = CRYPT_ECC_KEY_PAIR_BP384R1,
    bp512r1 = CRYPT_ECC_KEY_PAIR_BP512R1,
    curve25519 = CRYPT_ECC_KEY_PAIR_CURVE25519,
    secp192k1 = CRYPT_ECC_KEY_PAIR_SECP192K1,
    secp24k1 = CRYPT_ECC_KEY_PAIR_SECP224K1,
    secp256k1 = CRYPT_ECC_KEY_PAIR_SECP256K1,
    curve448 = CRYPT_ECC_KEY_PAIR_CURVE448
  };

  class Key {
  public:
    using Buffer = var::Array<u8, 256>;

    Key() : m_size(0){
      m_buffer.fill(0);
    }

    Key(const var::StringView value) {
      m_size = value.length() / 2;
      API_ASSERT(m_size <= sizeof(Buffer));
      var::View(m_buffer).from_string(value);
    }

    Key(Buffer buffer, size_t size) : m_buffer(buffer), m_size(size) {
    }

    bool operator ==(const Key & a) const {
      return data() == a.data();
    }

    bool operator !=(const Key & a) const {
      return data() != a.data();
    }

    var::View data() const { return var::View(m_buffer).truncate(m_size); }
    var::View data() { return var::View(m_buffer).truncate(m_size); }

    auto to_string() const {
      return data().to_string<var::GeneralString>();
    }

  private:
    Buffer m_buffer;
    API_AF(Key, size_t, size, 0);
  };

  Ecc();
  ~Ecc();

protected:
  void *m_context = nullptr;
  static Api &api() { return m_api; }


};


class SecretExchange : public Ecc {
public:

  using SharedSecret = var::Array<u8, 32>;
  SecretExchange(Curve curve = Curve::secp256r1);
  ~SecretExchange();

  const Key & public_key() const {
    return m_public_key;
  }

  SharedSecret get_shared_secret(const Key & public_key) const;

private:

  Key m_public_key;

};

class DigitalSignature : public Ecc {
public:
  using Signature = Key;
  using SharedSecret = Key;

  class KeyPair {
  public:
    class Construct {
      API_AC(Construct, var::StringView, public_key);
      API_AC(Construct, var::StringView, private_key);
    };

    explicit KeyPair(const Construct &options)
      : m_public_key(options.public_key()),
        m_private_key(options.private_key()) {}

    KeyPair() = default;

    KeyPair &set_public_key(const Key &value) {
      m_public_key = value;
      return *this;
    }

    KeyPair &set_private_key(const Key &value) {
      m_private_key = value;
      return *this;
    }

    const Key &public_key() const { return m_public_key; }
    const Key &private_key() const { return m_private_key; }

  private:
    Key m_public_key;
    Key m_private_key;
  };

  DigitalSignature() = default;

  KeyPair create_key_pair(Curve value);
  DigitalSignature & set_key_pair(const KeyPair & value);

  Signature sign(
    const var::StringView message_hash);

  bool verify(
    const Signature &signature,
    const var::StringView message_hash);

};

} // namespace crypto

namespace printer {
class Printer;
Printer &operator<<(Printer &printer, const crypto::DigitalSignature::KeyPair &a);
Printer &operator<<(Printer &printer, const crypto::SecretExchange::SharedSecret &a);
} // namespace printer

#endif // CRYPTOAPI_CRYPTO_ECC_HPP_

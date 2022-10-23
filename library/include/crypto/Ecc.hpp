// Copyright 2020-2021 Tyler Gilbert and Stratify Labs, Inc; see LICENSE.md

#ifndef CRYPTOAPI_CRYPTO_ECC_HPP_
#define CRYPTOAPI_CRYPTO_ECC_HPP_

#include <sdk/api.h>

#include <api/api.hpp>
#include <fs/File.hpp>
#include <var/Data.hpp>
#include <var/StackString.hpp>

#if defined __link && !defined CRYPT_ECC_API_REQUEST
#include <micro_ecc_api.h>
#define CRYPT_ECC_API_REQUEST &micro_ecc_api
#endif

#include "Random.hpp"

namespace crypto {

class Ecc : public api::ExecutionContext {
  using Api = api::Api<crypt_ecc_api_t, CRYPT_ECC_API_REQUEST>;
  static Api m_api;

protected:
  enum class KeyObjectType {
    public_key,
    private_key,
    signature,
    shared_secret
  };

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

  template <size_t KeySize, KeyObjectType Type> class KeyObject {
  public:
    using Buffer = var::Array<u8, KeySize>;

    KeyObject() { m_buffer.fill(0); }

    explicit KeyObject(const var::StringView value) {
      API_ASSERT(value.length() / 2 == sizeof(Buffer));
      var::View(m_buffer).from_string(value);
    }

    explicit KeyObject(Buffer buffer) : m_buffer(buffer) {}
    explicit KeyObject(var::View value) {
      API_ASSERT(value.size() == KeySize);
      var::View(m_buffer).copy(value);
    }

    API_NO_DISCARD size_t size() const { return KeySize; }

    API_NO_DISCARD bool is_valid() const {
      for (u32 i = 0; i < KeySize; i++) {
        if (m_buffer.at(i) != 0) {
          return true;
        }
      }
      return false;
    }

    bool operator==(const KeyObject &a) const { return data() == a.data(); }

    bool operator!=(const KeyObject &a) const { return data() != a.data(); }

    API_NO_DISCARD var::View data() const { return m_buffer; }
    var::View data() { return m_buffer; }

    API_NO_DISCARD auto to_string() const {
      return var::View(m_buffer).to_string<var::GeneralString>();
    }

  private:
    Buffer m_buffer;
  };

  using PublicKey = KeyObject<64, KeyObjectType::public_key>;
  using PrivateKey = KeyObject<32, KeyObjectType::private_key>;

  Ecc();

protected:
  struct State {
    void *context = nullptr;
  };
  static void deleter(State *context);
  api::SystemResource<State, decltype(&deleter)> m_state;
};

class SecretExchange : public Ecc {
public:
  using SharedSecret = var::Array<u8, 32>;
  explicit SecretExchange(Curve curve = Curve::secp256r1);
  API_NO_DISCARD const PublicKey &public_key() const { return m_public_key; }
  API_NO_DISCARD SharedSecret
  get_shared_secret(const PublicKey &public_key) const;

private:
  PublicKey m_public_key;
};

class DigitalSignatureAlgorithm : public Ecc {
public:
  using Signature = KeyObject<64, KeyObjectType::signature>;

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

    KeyPair &set_public_key(const PublicKey &value) {
      m_public_key = value;
      return *this;
    }

    KeyPair &set_private_key(const PrivateKey &value) {
      m_private_key = value;
      return *this;
    }

    API_NO_DISCARD const PublicKey &public_key() const { return m_public_key; }
    API_NO_DISCARD const PrivateKey &private_key() const {
      return m_private_key;
    }

  private:
    PublicKey m_public_key;
    PrivateKey m_private_key;
  };

  explicit DigitalSignatureAlgorithm(Curve value = Curve::secp256r1) {
    m_key_pair = create_key_pair(value);
  }

  explicit DigitalSignatureAlgorithm(const KeyPair &key_pair) {
    set_key_pair(key_pair);
  }

  API_NO_DISCARD Signature sign(var::View message_hash) const;

  bool verify(const Signature &signature, var::View message_hash);

  API_NO_DISCARD const KeyPair &key_pair() const { return m_key_pair; }

private:
  KeyPair create_key_pair(Curve value);
  void set_key_pair(const KeyPair &value);
  KeyPair m_key_pair;
};

using Dsa = DigitalSignatureAlgorithm;

} // namespace crypto

namespace printer {
class Printer;
Printer &operator<<(
  Printer &printer,
  const crypto::DigitalSignatureAlgorithm::KeyPair &a);
Printer &
operator<<(Printer &printer, const crypto::SecretExchange::SharedSecret &a);
} // namespace printer

#endif // CRYPTOAPI_CRYPTO_ECC_HPP_
